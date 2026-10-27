"""The complete claim/evidence truth table and its active-queue consequences."""

import csv
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import vulnops


CASES = (
    ("open-no-evidence", "open", None, "not_applicable"),
    ("open-present", "open", True, "not_applicable"),
    ("open-absent", "open", False, "not_applicable"),
    ("resolved-no-evidence", "resolved", None, "unverified"),
    ("resolved-present", "resolved", True, "failed"),
    ("resolved-absent", "resolved", False, "passed"),
)


def test_complete_verification_truth_table_preserves_claims_and_existing_fields():
    cve = "CVE-2026-1001"
    findings = [{
        "asset_id": asset,
        "cve": cve,
        "severity": "critical",
        "asset_criticality": "critical",
        "internet_exposed": "true",
        "owner_team": "payments-platform",
        "kev": "true",
        "epss_score": 0.01,
        "epss_percentile": 0.1,
        "priority": "P0",
        "reason": "Rule 1: CVE is in CISA KEV and asset criticality is critical.",
        "remediation_status": claim,
    } for asset, claim, present, expected in CASES]
    evidence = {(asset, cve): present for asset, claim, present, expected in CASES if present is not None}
    originals = [finding.copy() for finding in findings]
    original_evidence = evidence.copy()

    results = vulnops.apply_verification_status(findings, evidence)

    assert len(results) == 6
    for original, result, (asset, claim, present, expected) in zip(originals, results, CASES):
        assert result == {**original, "verification_status": expected}, (asset, result)
        assert result["remediation_status"] == claim
        assert result is not findings[originals.index(original)]
    assert findings == originals
    assert evidence == original_evidence


def test_only_resolved_with_passed_verification_leaves_the_active_queue():
    cve = "CVE-2026-1001"
    # Put the excluded finding first, so stable order of remaining findings is checked too.
    cases = (CASES[-1], *CASES[:-1])
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "data").mkdir()
        (root / "state").mkdir()
        (root / "data" / "verification_scan.json").write_text(json.dumps({
            "status": "succeeded", "covered_asset_ids": [case[0] for case in cases]}))
        scanner_path = root / "data" / "mock_scanner_output.json"
        scanner_path.write_text(json.dumps({"value": [
            {"machineId": f"machine-{asset}", "cveId": cve, "severity": "Critical"}
            for asset, claim, present, expected in cases
        ]}), encoding="utf-8")
        context_path = root / "data" / "asset_context.csv"
        context_path.write_text(
            "scanner_machine_id,asset_id,asset_criticality,internet_exposed,owner_team\n" +
            "".join(f"machine-{asset},{asset},critical,true,payments-platform\n"
                    for asset, claim, present, expected in cases), encoding="utf-8")
        state_path = root / "state" / "remediation_status.csv"
        state_path.write_text("asset_id,cve,remediation_status\n" +
                              "".join(f"{asset},{cve},{claim}\n" for asset, claim, present, expected in cases),
                              encoding="utf-8")
        evidence_path = root / "data" / "verification_results.csv"
        evidence_path.write_text("asset_id,cve,vulnerability_present\n" +
                                 "".join(f"{asset},{cve},{str(present).lower()}\n"
                                         for asset, claim, present, expected in cases if present is not None),
                                 encoding="utf-8")
        originals = {path: path.read_bytes() for path in (scanner_path, context_path, state_path, evidence_path)}
        feeds = [{"vulnerabilities": [{"cveID": cve}]},
                 {"status": "OK", "status-code": 200, "total": 1, "data": [
                     {"cve": cve, "epss": "0.01", "percentile": "0.1"}]}]
        responses = [io.BytesIO(json.dumps(feed).encode()) for feed in feeds]
        with patch("vulnops.ROOT", root), patch("vulnops.urlopen", side_effect=responses) as get:
            with patch("vulnops.apply_verification_status", wraps=vulnops.apply_verification_status) as verify:
                with patch("vulnops.write_queue", wraps=vulnops.write_queue) as write:
                    with patch("sys.stdout", new_callable=io.StringIO):
                        assert vulnops.main() == 0
        assert get.call_count == 2
        verify.assert_called_once()
        derived = vulnops.apply_verification_status(*verify.call_args.args)
        assert [(row["asset_id"], row["remediation_status"], row["verification_status"]) for row in derived] == [
            (asset, claim, expected) for asset, claim, present, expected in cases
        ]
        expected_active = ["open-no-evidence", "open-present", "open-absent", "resolved-no-evidence", "resolved-present"]
        rows = write.call_args.args[1]
        assert [row["asset_id"] for row in rows] == expected_active
        assert [row["verification_status"] for row in rows] == [
            "not_applicable", "not_applicable", "not_applicable", "unverified", "failed"
        ]
        assert [row["remediation_status"] for row in rows] == ["open", "open", "open", "resolved", "resolved"]
        assert all(row["priority"] == "P0" for row in rows)
        with (root / "output" / "remediation_queue.csv").open(newline="") as output:
            csv_rows = list(csv.DictReader(output))
        assert [row["asset_id"] for row in csv_rows] == expected_active
        assert [row["remediation_status"] for row in csv_rows] == ["open", "open", "open", "resolved", "resolved"]
        # Passing verification changes membership, never the claim or the risk class.
        passed = next(row for row in derived if row["asset_id"] == "resolved-absent")
        assert passed["remediation_status"] == "resolved"
        assert passed["verification_status"] == "passed"
        assert vulnops.prioritize([passed], {cve})[0]["priority"] == "P0"
        assert {path: path.read_bytes() for path in originals} == originals


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(unittest.FunctionTestCase(test) for test in (
        test_complete_verification_truth_table_preserves_claims_and_existing_fields,
        test_only_resolved_with_passed_verification_leaves_the_active_queue,
    ))
