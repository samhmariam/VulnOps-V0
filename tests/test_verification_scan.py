"""Verification scan input and evidence filtering, without lifecycle derivation."""

from copy import deepcopy
import csv
import io
import json
from unittest.mock import patch

import pytest

import vulnops


def _assert_qualified_pipeline(
        tmp_path, claim, scan_status, covered, present, resolved_verification):
    (tmp_path / "data").mkdir()
    (tmp_path / "state").mkdir()
    asset, cve = "payments-api-01", "CVE-2026-1001"
    scanner_path = tmp_path / "data" / "mock_scanner_output.json"
    scanner_path.write_text(json.dumps({"value": [
        {"machineId": "machine-001", "cveId": cve, "severity": "Critical"}]}), encoding="utf-8")
    context_path = tmp_path / "data" / "asset_context.csv"
    context_path.write_text("scanner_machine_id,asset_id,asset_criticality,internet_exposed,owner_team\n"
                            f"machine-001,{asset},critical,true,payments-platform\n", encoding="utf-8")
    state_path = tmp_path / "state" / "remediation_status.csv"
    state_path.write_text(f"asset_id,cve,remediation_status\n{asset},{cve},{claim}\n", encoding="utf-8")
    evidence_path = tmp_path / "data" / "verification_results.csv"
    evidence_path.write_text("asset_id,cve,vulnerability_present\n" +
                             (f"{asset},{cve},{str(present).lower()}\n" if present is not None else ""), encoding="utf-8")
    scan = {"status": scan_status, "covered_asset_ids": [asset] if covered else ["hr-app-01"]}
    scan_path = tmp_path / "data" / "verification_scan.json"
    scan_path.write_text(json.dumps(scan), encoding="utf-8")
    originals = {path: path.read_bytes() for path in (scanner_path, context_path, state_path, evidence_path, scan_path)}
    epss = {cve: {"epss_score": 0.01, "epss_percentile": 0.1}}
    with (
        patch("vulnops.ROOT", tmp_path),
        patch("vulnops.load_kev", return_value={cve}),
        patch("vulnops.load_epss", return_value=epss),
        patch("vulnops.load_verification_scan", wraps=vulnops.load_verification_scan) as load_scan,
        patch("vulnops.qualify_verification_results", wraps=vulnops.qualify_verification_results) as qualify,
        patch("vulnops.apply_verification_status", wraps=vulnops.apply_verification_status) as verify,
        patch("vulnops.write_queue", wraps=vulnops.write_queue) as write,
        patch("vulnops.urlopen", side_effect=RuntimeError("Unexpected network request")),
        patch("sys.stdout", new_callable=io.StringIO),
    ):
        assert vulnops.main() == 0
    load_scan.assert_called_once_with(scan_path)
    raw = {(asset, cve): present} if present is not None else {}
    qualify.assert_called_once_with(raw, scan)
    verify.assert_called_once()
    expected_evidence = raw if scan_status == "succeeded" and covered else {}
    assert verify.call_args.args[1] == expected_evidence
    derived = vulnops.apply_verification_status(*verify.call_args.args)
    expected_verification = "not_applicable" if claim == "open" else resolved_verification
    assert derived[0]["remediation_status"] == claim
    assert derived[0]["verification_status"] == expected_verification
    active = not (claim == "resolved" and expected_verification == "passed")
    rows = write.call_args.args[1]
    assert len(rows) == int(active)
    if active:
        assert rows[0]["verification_status"] == expected_verification
        assert rows[0]["remediation_status"] == claim
        assert rows[0]["priority"] == "P0"
        assert rows[0]["reason"] == "Rule 1: CVE is in CISA KEV and asset criticality is critical."
        assert rows[0]["owner_team"] == "payments-platform"
    with (tmp_path / "output" / "remediation_queue.csv").open(newline="") as output:
        csv_rows = list(csv.DictReader(output))
    assert len(csv_rows) == int(active)
    assert {path: path.read_bytes() for path in originals} == originals


@pytest.mark.parametrize("claim", ["open", "resolved"])
@pytest.mark.parametrize(("scan_status", "covered", "present", "resolved_verification"), [
    ("succeeded", True, None, "unverified"),
    ("succeeded", True, True, "failed"),
    ("succeeded", True, False, "passed"),
    ("succeeded", False, None, "unverified"),
    ("succeeded", False, True, "unverified"),
    ("succeeded", False, False, "unverified"),
    ("failed", True, None, "unverified"),
    ("failed", True, True, "unverified"),
    ("failed", True, False, "unverified"),
    ("failed", False, None, "unverified"),
    ("failed", False, True, "unverified"),
    ("failed", False, False, "unverified"),
])
def test_main_qualifies_evidence_before_deriving_status_and_filtering_queue(
        tmp_path, claim, scan_status, covered, present, resolved_verification):
    _assert_qualified_pipeline(tmp_path, claim, scan_status, covered, present, resolved_verification)


@pytest.mark.parametrize(("scan_status", "covered", "present", "expected_verification"), [
    pytest.param("failed", True, False, "unverified", id="A-failed-scan-false-remains-active"),
    pytest.param("succeeded", False, False, "unverified", id="B-uncovered-asset-false-remains-active"),
    pytest.param("succeeded", True, False, "passed", id="C-successful-covered-false-leaves-queue"),
    pytest.param("succeeded", True, True, "failed", id="D-successful-covered-true-remains-active"),
])
def test_v09_requires_successful_scan_and_asset_coverage_before_accepting_presence_evidence(
        tmp_path, scan_status, covered, present, expected_verification):
    asset, cve = "payments-api-01", "CVE-2026-1001"
    finding = {"asset_id": asset, "cve": cve, "remediation_status": "resolved"}
    # This unchanged interpreter demonstrates the V0.8 behaviour when bare
    # evidence reaches it directly: false is sufficient to derive passed.
    unqualified = vulnops.apply_verification_status([finding], {(asset, cve): present})[0]
    assert unqualified["verification_status"] == ("failed" if present else "passed")
    # Exercise the actual main() path with explicit scan metadata. The shared
    # assertions check derived state, active CSV membership, and unchanged inputs.
    _assert_qualified_pipeline(tmp_path, "resolved", scan_status, covered, present, expected_verification)


@pytest.mark.parametrize(("scan_status", "covered", "present"), [
    pytest.param("succeeded", True, True, id="successful-covered-present"),
    pytest.param("succeeded", True, False, id="successful-covered-absent"),
    pytest.param("failed", True, True, id="failed-scan-present"),
    pytest.param("failed", True, False, id="failed-scan-absent"),
    pytest.param("succeeded", False, True, id="uncovered-present"),
    pytest.param("succeeded", False, False, id="uncovered-absent"),
])
def test_v09_open_findings_ignore_verification_evidence_and_never_become_resolved(
        tmp_path, scan_status, covered, present):
    # Shared pipeline assertions check actual derived status is not_applicable,
    # the finding stays active/open, and every input file remains byte-identical.
    _assert_qualified_pipeline(tmp_path, "open", scan_status, covered, present, "not_applicable")
    with (tmp_path / "output" / "remediation_queue.csv").open(newline="") as output:
        rows = list(csv.DictReader(output))
    assert len(rows) == 1
    assert rows[0]["asset_id"] == "payments-api-01"
    assert rows[0]["cve"] == "CVE-2026-1001"
    assert rows[0]["remediation_status"] == "open"
    assert vulnops.load_remediation_statuses(tmp_path / "state" / "remediation_status.csv") == {
        ("payments-api-01", "CVE-2026-1001"): "open"}


@pytest.mark.parametrize("scan_contents", [None, "not JSON", '{"status": "succeeded"}'])
def test_main_rejects_missing_or_malformed_scan_without_applying_verification_or_replacing_queue(tmp_path, scan_contents):
    (tmp_path / "data").mkdir()
    (tmp_path / "state").mkdir()
    (tmp_path / "output").mkdir()
    (tmp_path / "data" / "mock_scanner_output.json").write_text(json.dumps({"value": [
        {"machineId": "machine-001", "cveId": "CVE-2026-1001", "severity": "Critical"}]}))
    (tmp_path / "data" / "asset_context.csv").write_text(
        "scanner_machine_id,asset_id,asset_criticality,internet_exposed,owner_team\n"
        "machine-001,payments-api-01,critical,true,payments-platform\n")
    (tmp_path / "state" / "remediation_status.csv").write_text("asset_id,cve,remediation_status\n")
    (tmp_path / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\n")
    if scan_contents is not None:
        (tmp_path / "data" / "verification_scan.json").write_text(scan_contents)
    queue = tmp_path / "output" / "remediation_queue.csv"
    queue.write_text("previous queue\n")
    with (
        patch("vulnops.ROOT", tmp_path),
        patch("vulnops.apply_verification_status") as verify,
        patch("vulnops.load_kev") as kev,
        patch("sys.stderr", new_callable=io.StringIO) as stderr,
    ):
        assert vulnops.main() == 1
    verify.assert_not_called()
    kev.assert_not_called()
    assert stderr.getvalue().startswith("VulnOps failed:")
    assert queue.read_text() == "previous queue\n"


def test_successful_scan_retains_covered_evidence_with_original_boolean_values():
    results = {("asset-a", "CVE-1"): False, ("asset-a", "CVE-2"): True,
               ("asset-b", "CVE-1"): True, ("asset-b", "CVE-2"): False}
    scan = {"status": "succeeded", "covered_asset_ids": {"asset-a"}}
    with patch("vulnops.apply_verification_status", side_effect=AssertionError("Qualification must not derive status")) as derive:
        qualified = vulnops.qualify_verification_results(results, scan)
    derive.assert_not_called()
    assert qualified == {("asset-a", "CVE-1"): False, ("asset-a", "CVE-2"): True}
    assert qualified[("asset-a", "CVE-1")] is False
    assert qualified[("asset-a", "CVE-2")] is True


@pytest.mark.parametrize("coverage", [[], ["another-asset"]])
def test_successful_scan_removes_evidence_for_uncovered_assets(coverage):
    results = {("asset-a", "CVE-1"): False, ("asset-b", "CVE-2"): True}
    scan = {"status": "succeeded", "covered_asset_ids": coverage}
    assert vulnops.qualify_verification_results(results, scan) == {}


@pytest.mark.parametrize("coverage", [[], ["asset-a", "asset-b"]])
def test_failed_scan_removes_all_evidence_even_if_assets_are_listed_as_covered(coverage):
    results = {("asset-a", "CVE-1"): False, ("asset-b", "CVE-2"): True}
    scan = {"status": "failed", "covered_asset_ids": coverage}
    assert vulnops.qualify_verification_results(results, scan) == {}


@pytest.mark.parametrize("status", ["succeeded", "failed"])
def test_empty_verification_results_qualify_to_empty_result(status):
    assert vulnops.qualify_verification_results({}, {"status": status, "covered_asset_ids": ["asset-a"]}) == {}


@pytest.mark.parametrize("status", ["succeeded", "failed"])
@pytest.mark.parametrize("coverage", [["asset-a"], {"asset-a"}])
def test_qualification_does_not_mutate_results_or_scan_and_returns_a_new_dictionary(status, coverage):
    results = {("asset-a", "CVE-1"): False, ("asset-b", "CVE-2"): True}
    scan = {"status": status, "covered_asset_ids": coverage}
    original_results = deepcopy(results)
    original_scan = deepcopy(scan)
    qualified = vulnops.qualify_verification_results(results, scan)
    assert results == original_results
    assert scan == original_scan
    assert qualified is not results
    qualified.clear()
    assert results == original_results
    assert scan == original_scan


@pytest.mark.parametrize("status", ["succeeded", "failed"])
def test_valid_verification_scan_returns_plain_dictionary(tmp_path, status):
    path = tmp_path / "verification_scan.json"
    payload = {"status": status, "covered_asset_ids": ["payments-api-01", "hr-app-01"]}
    path.write_text(json.dumps(payload), encoding="utf-8")
    original = path.read_bytes()
    assert vulnops.load_verification_scan(path) == payload
    assert path.read_bytes() == original


@pytest.mark.parametrize("status", ["succeeded", "failed"])
def test_empty_covered_asset_list_is_valid(tmp_path, status):
    path = tmp_path / "verification_scan.json"
    path.write_text(json.dumps({"status": status, "covered_asset_ids": []}), encoding="utf-8")
    assert vulnops.load_verification_scan(path) == {"status": status, "covered_asset_ids": []}


@pytest.mark.parametrize("status", ["", "unknown", "Succeeded", "succeeded ", None, True, 1])
def test_invalid_scan_status_is_rejected(tmp_path, status):
    path = tmp_path / "verification_scan.json"
    path.write_text(json.dumps({"status": status, "covered_asset_ids": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="status must be succeeded or failed"):
        vulnops.load_verification_scan(path)


@pytest.mark.parametrize("payload", [{}, {"status": "succeeded"}, {"covered_asset_ids": []}])
def test_missing_scan_fields_are_rejected(tmp_path, payload):
    path = tmp_path / "verification_scan.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="exactly status and covered_asset_ids"):
        vulnops.load_verification_scan(path)


@pytest.mark.parametrize("extra", ["scan_run_id", "timestamp", "provenance"])
def test_extra_scan_fields_are_rejected(tmp_path, extra):
    path = tmp_path / "verification_scan.json"
    payload = {"status": "succeeded", "covered_asset_ids": [], extra: "outside-contract"}
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="exactly status and covered_asset_ids"):
        vulnops.load_verification_scan(path)


@pytest.mark.parametrize("covered", [None, {}, "payments-api-01", 1, True])
def test_non_list_covered_asset_ids_are_rejected(tmp_path, covered):
    path = tmp_path / "verification_scan.json"
    path.write_text(json.dumps({"status": "succeeded", "covered_asset_ids": covered}), encoding="utf-8")
    with pytest.raises(ValueError, match="covered_asset_ids must be a list"):
        vulnops.load_verification_scan(path)


@pytest.mark.parametrize("asset_id", ["", " \t ", None, 1, True, {}, []])
def test_blank_or_non_string_asset_ids_are_rejected(tmp_path, asset_id):
    path = tmp_path / "verification_scan.json"
    payload = {"status": "succeeded", "covered_asset_ids": ["payments-api-01", asset_id]}
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="asset IDs must be non-empty strings"):
        vulnops.load_verification_scan(path)


@pytest.mark.parametrize("duplicate", ["payments-api-01", " payments-api-01 "])
def test_duplicate_asset_ids_are_rejected_after_whitespace_trimming(tmp_path, duplicate):
    path = tmp_path / "verification_scan.json"
    payload = {"status": "succeeded", "covered_asset_ids": ["payments-api-01", duplicate]}
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate verification scan asset_id"):
        vulnops.load_verification_scan(path)


def test_asset_ids_use_existing_whitespace_semantics_and_preserve_order(tmp_path):
    path = tmp_path / "verification_scan.json"
    payload = {"status": "succeeded", "covered_asset_ids": [" hr-app-01 ", "payments-api-01"]}
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert vulnops.load_verification_scan(path) == {
        "status": "succeeded", "covered_asset_ids": ["hr-app-01", "payments-api-01"]}


@pytest.mark.parametrize("payload", [None, [], "succeeded"])
def test_scan_top_level_must_be_an_object(tmp_path, payload):
    path = tmp_path / "verification_scan.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="exactly status and covered_asset_ids"):
        vulnops.load_verification_scan(path)


def test_missing_file_and_invalid_json_fail_instead_of_inventing_scan_evidence(tmp_path):
    path = tmp_path / "verification_scan.json"
    with pytest.raises(FileNotFoundError):
        vulnops.load_verification_scan(path)
    path.write_text("not JSON", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        vulnops.load_verification_scan(path)
