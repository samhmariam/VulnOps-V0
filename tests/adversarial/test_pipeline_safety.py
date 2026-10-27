"""Malformed scanner/context files must fail before risk decisions or output."""

import csv
import io
import json
from unittest.mock import patch

import pytest

import vulnops


HEADER = "scanner_machine_id,asset_id,asset_criticality,internet_exposed,owner_team\n"
VALID_CONTEXT = "machine-001,payments-api-01,critical,true,payments-platform\n"
OBSERVATION = {"machineId": "machine-001", "cveId": "CVE-2026-1001", "severity": "Critical"}


def _assert_main_rejects(root, observations, context_csv, message):
    (root / "data").mkdir()
    (root / "state").mkdir()
    (root / "output").mkdir()
    scanner_path = root / "data" / "mock_scanner_output.json"
    scanner_path.write_text(json.dumps({"value": observations}), encoding="utf-8")
    context_path = root / "data" / "asset_context.csv"
    context_path.write_text(context_csv, encoding="utf-8")
    state_path = root / "state" / "remediation_status.csv"
    state_path.write_text("asset_id,cve,remediation_status\n", encoding="utf-8")
    evidence_path = root / "data" / "verification_results.csv"
    evidence_path.write_text("asset_id,cve,vulnerability_present\n", encoding="utf-8")
    originals = {path: path.read_bytes() for path in (scanner_path, context_path, state_path, evidence_path)}
    queue_path = root / "output" / "remediation_queue.csv"
    queue_path.write_text(
        "asset_id,criticality,cve,internet_exposed,owner_team,kev,epss_score,epss_percentile,priority,reason,remediation_status\n"
        "payments-api-01,critical,CVE-2026-1001,true,payments-platform,true,0.01,0.1,P0,"
        "Rule 1: CVE is in CISA KEV and asset criticality is critical.,open\n",
        encoding="utf-8",
    )
    previous_queue = queue_path.read_bytes()

    # Keep all input validation real. Spies prove malformed input cannot reach
    # intelligence retrieval, classification, or queue replacement.
    with (
        patch("vulnops.ROOT", root),
        patch("vulnops.load_kev") as kev,
        patch("vulnops.load_epss") as epss,
        patch("vulnops.prioritize", wraps=vulnops.prioritize) as classify,
        patch("vulnops.write_queue", wraps=vulnops.write_queue) as write,
        patch("vulnops.urlopen", side_effect=RuntimeError("Unexpected network request")) as network,
        patch("sys.stdout", new_callable=io.StringIO) as stdout,
        patch("sys.stderr", new_callable=io.StringIO) as stderr,
    ):
        assert vulnops.main() == 1

    assert stderr.getvalue().startswith("VulnOps failed:")
    assert message in stderr.getvalue()
    assert stdout.getvalue() == ""
    kev.assert_not_called()
    epss.assert_not_called()
    classify.assert_not_called()
    write.assert_not_called()
    network.assert_not_called()
    assert queue_path.read_bytes() == previous_queue
    with queue_path.open(newline="") as source:
        rows = list(csv.DictReader(source))
    assert len(rows) == 1
    assert rows[0]["priority"] == "P0"
    assert rows[0]["criticality"] == "critical"
    assert rows[0]["owner_team"] == "payments-platform"
    assert {path: path.read_bytes() for path in originals} == originals
    assert list((root / "output").iterdir()) == [queue_path]


def test_unknown_scanner_machine_fails_without_partial_or_default_findings(tmp_path):
    observations = [OBSERVATION, {**OBSERVATION, "machineId": "unconfigured-machine"}]
    _assert_main_rejects(tmp_path, observations, HEADER + VALID_CONTEXT, "no matching asset context")


@pytest.mark.parametrize("reverse", [False, True], ids=["critical-first", "low-first"])
def test_conflicting_scanner_duplicate_fails_in_either_order(tmp_path, reverse):
    observations = [OBSERVATION, {**OBSERVATION, "severity": "Low"}]
    if reverse:
        observations.reverse()
    _assert_main_rejects(tmp_path, observations, HEADER + VALID_CONTEXT, "conflicting severity")


@pytest.mark.parametrize(("duplicate", "message"), [
    (VALID_CONTEXT, "Duplicate scanner_machine_id"),
    ("machine-001,another-asset,low,false,identity\n", "Duplicate scanner_machine_id"),
    (" machine-001 ,another-asset,low,false,identity\n", "Duplicate scanner_machine_id"),
    ("machine-002,payments-api-01,low,false,identity\n", "Duplicate asset_id"),
    ("machine-002, payments-api-01 ,low,false,identity\n", "Duplicate asset_id"),
], ids=["identical-row", "one-machine-two-assets", "padded-machine", "two-machines-one-asset", "padded-asset"])
def test_ambiguous_asset_context_mapping_fails(tmp_path, duplicate, message):
    _assert_main_rejects(tmp_path, [OBSERVATION], HEADER + VALID_CONTEXT + duplicate, message)


@pytest.mark.parametrize(("context_csv", "message"), [
    (HEADER + "machine-001,,critical,true,payments-platform\n", "empty asset_id"),
    (HEADER + "machine-001,   ,critical,true,payments-platform\n", "empty asset_id"),
    ("scanner_machine_id,asset_criticality,internet_exposed,owner_team\n"
     "machine-001,critical,true,payments-platform\n", "must contain exactly"),
], ids=["blank", "whitespace", "missing-column"])
def test_missing_asset_id_fails_without_inventing_an_identity(tmp_path, context_csv, message):
    _assert_main_rejects(tmp_path, [OBSERVATION], context_csv, message)


@pytest.mark.parametrize("criticality", ["unknown", "urgent", "5"])
def test_invalid_asset_criticality_fails_without_defaulting_to_low(tmp_path, criticality):
    context_csv = HEADER + f"machine-001,payments-api-01,{criticality},true,payments-platform\n"
    _assert_main_rejects(tmp_path, [OBSERVATION], context_csv, "invalid asset_criticality")


@pytest.mark.parametrize("exposure", ["yes", "maybe", "True", "FALSE"])
def test_invalid_internet_exposed_fails_without_defaulting_to_unknown(tmp_path, exposure):
    context_csv = HEADER + f"machine-001,payments-api-01,critical,{exposure},payments-platform\n"
    _assert_main_rejects(tmp_path, [OBSERVATION], context_csv, "invalid internet_exposed")
