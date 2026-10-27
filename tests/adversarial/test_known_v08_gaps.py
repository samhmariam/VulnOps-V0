"""Desired safety properties outside V0.8; strict XFAILs are intentional.

These tests do not add evidence qualification or cross-scan reconciliation.
An unexpected pass requires reviewing whether the underlying gap is now closed.
"""

import csv
import io
import json
from unittest.mock import patch

import pytest

import vulnops


ASSET = "payments-api-01"
CVE = "CVE-2026-1001"
OBSERVATION = {"machineId": "machine-001", "cveId": CVE, "severity": "Critical"}


def _write_inputs(root, claim, observations, present):
    (root / "data").mkdir()
    (root / "state").mkdir()
    (root / "data" / "verification_scan.json").write_text(
        json.dumps({"status": "succeeded", "covered_asset_ids": [ASSET]}), encoding="utf-8")
    (root / "data" / "mock_scanner_output.json").write_text(
        json.dumps({"value": observations}), encoding="utf-8")
    (root / "data" / "asset_context.csv").write_text(
        "scanner_machine_id,asset_id,asset_criticality,internet_exposed,owner_team\n"
        f"machine-001,{ASSET},critical,true,payments-platform\n", encoding="utf-8")
    (root / "state" / "remediation_status.csv").write_text(
        f"asset_id,cve,remediation_status\n{ASSET},{CVE},{claim}\n", encoding="utf-8")
    (root / "data" / "verification_results.csv").write_text(
        "asset_id,cve,vulnerability_present\n" +
        (f"{ASSET},{CVE},{str(present).lower()}\n" if present is not None else ""), encoding="utf-8")


def _active_queue(root):
    epss = {CVE: {"epss_score": 0.01, "epss_percentile": 0.1}}
    with patch("vulnops.ROOT", root), patch("vulnops.load_kev", return_value={CVE}):
        with patch("vulnops.load_epss", return_value=epss):
            with patch("vulnops.urlopen", side_effect=RuntimeError("Unexpected network request")):
                with patch("sys.stdout", new_callable=io.StringIO):
                    if vulnops.main() != 0:
                        raise RuntimeError("Fixture pipeline failed before the safety assertion")
    with (root / "output" / "remediation_queue.csv").open(newline="") as output:
        return list(csv.DictReader(output))


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="V0.8 has no verification-run success, observation time, asset coverage, or provenance.",
)
def test_unqualified_absence_evidence_cannot_establish_passed_verification(tmp_path):
    _write_inputs(tmp_path, "resolved", [OBSERVATION], False)
    findings = vulnops.build_findings(
        vulnops.normalize_scanner_observations(vulnops.load_scanner_output(tmp_path / "data" / "mock_scanner_output.json")),
        vulnops.load_asset_context(tmp_path / "data" / "asset_context.csv"),
    )
    findings = vulnops.apply_remediation_status(
        findings, vulnops.load_remediation_statuses(tmp_path / "state" / "remediation_status.csv"))
    findings = vulnops.apply_verification_status(
        findings, vulnops.load_verification_results(tmp_path / "data" / "verification_results.csv"))
    # The bare false value carries no evidence-quality qualification in V0.8.
    assert findings[0]["verification_status"] == "unverified", "Unqualified false evidence must not authorize closure"


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="V0.8 cannot distinguish successful absence from incomplete, failed, or non-covering observation.",
)
def test_missing_scanner_observation_does_not_remove_previously_open_work(tmp_path):
    _write_inputs(tmp_path, "open", [OBSERVATION], None)
    initial = _active_queue(tmp_path)
    assert [(row["asset_id"], row["cve"]) for row in initial] == [(ASSET, CVE)]
    state_path = tmp_path / "state" / "remediation_status.csv"
    original_state = state_path.read_bytes()
    (tmp_path / "data" / "mock_scanner_output.json").write_text('{"value": []}', encoding="utf-8")
    later = _active_queue(tmp_path)
    assert state_path.read_bytes() == original_state
    # V0.8 does not mark this passed; it loses queue visibility because only
    # current observations enter the pipeline. Absence alone cannot justify that.
    assert (ASSET, CVE) in [(row["asset_id"], row["cve"]) for row in later], "Unqualified absence must not remove open work"


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="V0.8 has no cross-scan reconciliation or regression concept to invalidate an earlier pass.",
)
def test_previously_passed_finding_becomes_active_when_observed_again(tmp_path):
    _write_inputs(tmp_path, "resolved", [OBSERVATION], False)
    key = (ASSET, CVE)
    statuses = vulnops.load_remediation_statuses(tmp_path / "state" / "remediation_status.csv")
    evidence = vulnops.load_verification_results(tmp_path / "data" / "verification_results.csv")
    finding = {"asset_id": ASSET, "cve": CVE, "remediation_status": statuses[key]}
    assert vulnops.apply_verification_status([finding], evidence)[0]["verification_status"] == "passed"
    assert _active_queue(tmp_path) == []
    # An intervening absence followed by a new observation must eventually be
    # recognized as reintroduction; V0.8 cannot qualify observations across runs.
    scanner_path = tmp_path / "data" / "mock_scanner_output.json"
    scanner_path.write_text('{"value": []}', encoding="utf-8")
    assert _active_queue(tmp_path) == []
    scanner_path.write_text(json.dumps({"value": [OBSERVATION]}), encoding="utf-8")
    state_path = tmp_path / "state" / "remediation_status.csv"
    evidence_path = tmp_path / "data" / "verification_results.csv"
    originals = {path: path.read_bytes() for path in (state_path, evidence_path)}
    later = _active_queue(tmp_path)
    assert {path: path.read_bytes() for path in originals} == originals
    assert (ASSET, CVE) in [(row["asset_id"], row["cve"]) for row in later], "An earlier pass must not hide a reappearing vulnerability"
