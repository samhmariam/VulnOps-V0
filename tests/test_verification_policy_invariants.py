"""Verification qualification changes queue membership, never risk policy."""

import csv
import io
from itertools import product
import json
from unittest.mock import patch

import pytest

import vulnops


def test_verification_qualification_has_no_classification_authority_before_filtering():
    expected = {
        (True, "critical"): "P0", (True, "high"): "P1",
        (True, "medium"): "P1", (True, "low"): "P1",
        (False, "critical"): "P2", (False, "high"): "P2",
        (False, "medium"): "P2", (False, "low"): "P2",
    }
    asset, cve = "payments-api-01", "CVE-2026-1001"
    key = (asset, cve)
    checked = 0
    for (kev, criticality), priority in expected.items():
        kev_cves = {cve} if kev else set()
        for scan_status, covered, present, claim, exposure, score, owner in product(
                ("succeeded", "failed"), (True, False), (True, False, None), ("open", "resolved"),
                ("true", "unknown", "false"), (None, 0.0, 0.01, 0.99), ("payments-platform", "unknown")):
            finding = {"asset_id": asset, "cve": cve, "severity": "critical", "asset_criticality": criticality,
                       "internet_exposed": exposure, "owner_team": owner}
            enriched = vulnops.enrich_with_epss([finding], {cve: {"epss_score": score, "epss_percentile": 0.5}})
            baseline = vulnops.prioritize(enriched, kev_cves)[0]
            scan = {"status": scan_status, "covered_asset_ids": [asset] if covered else []}
            raw_evidence = {key: present} if present is not None else {}
            qualified = vulnops.qualify_verification_results(raw_evidence, scan)
            findings = vulnops.apply_remediation_status(enriched, {key: claim})
            findings = vulnops.apply_verification_status(findings, qualified)
            # Deliberately classify before filtering, even if verification passed.
            result = vulnops.prioritize(findings, kev_cves)[0]
            assert result["priority"] == priority, (scan, claim, present, finding, result)
            assert {field: result[field] for field in baseline} == baseline
            assert set(result) - set(baseline) == {"remediation_status", "verification_status"}
            assert result["remediation_status"] == claim
            assert result["owner_team"] == owner
            assert "verification_status" not in enriched[0]
            assert "remediation_status" not in enriched[0]
            assert raw_evidence == ({key: present} if present is not None else {})
            checked += 1
    assert checked == 4608


@pytest.mark.parametrize("claim", ["open", "resolved"])
@pytest.mark.parametrize(("scan_status", "covered", "present", "resolved_status"), [
    ("succeeded", True, True, "failed"),
    ("succeeded", True, False, "passed"),
    ("succeeded", True, None, "unverified"),
    ("succeeded", False, True, "unverified"),
    ("succeeded", False, False, "unverified"),
    ("succeeded", False, None, "unverified"),
    ("failed", True, True, "unverified"),
    ("failed", True, False, "unverified"),
    ("failed", True, None, "unverified"),
    ("failed", False, True, "unverified"),
    ("failed", False, False, "unverified"),
    ("failed", False, None, "unverified"),
])
def test_qualified_verification_changes_only_membership_not_risk_or_relative_queue_order(
        tmp_path, claim, scan_status, covered, present, resolved_status):
    # Asset, criticality, KEV membership, exposure, EPSS. Input is intentionally interleaved.
    cases = [
        ("false-high", "critical", False, "false", 0.99),
        ("p1-first", "medium", True, "false", 0.001),
        ("unknown-high", "critical", False, "unknown", 0.99),
        ("p0-first", "critical", True, "false", 0.001),
        ("true-low", "critical", False, "true", 0.10),
        ("true-high", "critical", False, "true", 0.90),
        ("p0-second", "critical", True, "true", 0.99),
        ("p1-second", "medium", True, "true", 0.99),
        ("true-missing", "critical", False, "true", None),
        ("true-zero", "critical", False, "true", 0.0),
        ("unknown-missing", "critical", False, "unknown", None),
        ("false-missing", "critical", False, "false", None),
    ]
    expected_order = ["p0-first", "p0-second", "p1-first", "p1-second", "true-high", "true-low",
                      "true-zero", "true-missing", "unknown-high", "unknown-missing", "false-high", "false-missing"]
    (tmp_path / "data").mkdir()
    (tmp_path / "state").mkdir()
    scanner = [{"machineId": f"machine-{index}", "cveId": f"CVE-2026-{1000 + index}", "severity": "Critical"}
               for index in range(len(cases))]
    scanner_path = tmp_path / "data" / "mock_scanner_output.json"
    scanner_path.write_text(json.dumps({"value": scanner}))
    kev_cves = {record["cveId"] for record, case in zip(scanner, cases) if case[2]}
    epss = {record["cveId"]: {"epss_score": case[4], "epss_percentile": 0.5} for record, case in zip(scanner, cases)}
    target_cves = {case[0]: record["cveId"] for case, record in zip(cases, scanner)}

    for owner_swap in (0, 1):
        context_path = tmp_path / "data" / "asset_context.csv"
        with context_path.open("w", newline="") as output:
            writer = csv.writer(output)
            writer.writerow(["scanner_machine_id", "asset_id", "asset_criticality", "internet_exposed", "owner_team"])
            for index, (asset, criticality, kev, exposure, score) in enumerate(cases):
                owner = ("unknown", "payments-platform")[(index + owner_swap) % 2]
                writer.writerow([f"machine-{index}", asset, criticality, exposure, owner])
        initial = vulnops.build_findings(vulnops.normalize_scanner_observations(scanner), vulnops.load_asset_context(context_path))
        baseline = {row["asset_id"]: row for row in vulnops.prioritize(vulnops.enrich_with_epss(initial, epss), kev_cves)}

        # Removing a member of any class must not change the order or risk of others.
        for target in ("p0-first", "p1-first", "true-high"):
            cve = target_cves[target]
            state_path = tmp_path / "state" / "remediation_status.csv"
            state_path.write_text(f"asset_id,cve,remediation_status\n{target},{cve},{claim}\n")
            evidence_path = tmp_path / "data" / "verification_results.csv"
            evidence_path.write_text("asset_id,cve,vulnerability_present\n" +
                                     (f"{target},{cve},{str(present).lower()}\n" if present is not None else ""))
            scan_path = tmp_path / "data" / "verification_scan.json"
            scan_path.write_text(json.dumps({"status": scan_status, "covered_asset_ids": [target] if covered else []}))
            originals = {path: path.read_bytes() for path in (scanner_path, context_path, state_path, evidence_path, scan_path)}
            with (
                patch("vulnops.ROOT", tmp_path),
                patch("vulnops.load_kev", return_value=kev_cves),
                patch("vulnops.load_epss", return_value=epss),
                patch("vulnops.apply_verification_status", wraps=vulnops.apply_verification_status) as verify,
                patch("vulnops.write_queue", wraps=vulnops.write_queue) as write,
                patch("vulnops.urlopen", side_effect=RuntimeError("Unexpected network request")),
                patch("sys.stdout", new_callable=io.StringIO),
            ):
                assert vulnops.main() == 0
            derived = vulnops.apply_verification_status(*verify.call_args.args)
            before_filter = vulnops.prioritize(vulnops.enrich_with_epss(derived, epss), kev_cves)
            for row in before_filter:
                original = baseline[row["asset_id"]]
                assert {field: row[field] for field in original} == original
            target_state = next(row for row in before_filter if row["asset_id"] == target)
            verification = "not_applicable" if claim == "open" else resolved_status
            assert target_state["remediation_status"] == claim
            assert target_state["verification_status"] == verification
            closed = claim == "resolved" and verification == "passed"
            expected_active = [asset for asset in expected_order if not (closed and asset == target)]
            rows = write.call_args.args[1]
            assert [row["asset_id"] for row in rows] == expected_active
            for row in rows:
                original = baseline[row["asset_id"]]
                assert {field: row[field] for field in original} == original
            with (tmp_path / "output" / "remediation_queue.csv").open(newline="") as output:
                assert [row["asset_id"] for row in csv.DictReader(output)] == expected_active
            assert {path: path.read_bytes() for path in originals} == originals
