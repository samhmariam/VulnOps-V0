"""Exercise main's real queue ordering with local fixtures and controlled feeds."""

import csv
import io
from itertools import permutations, product
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import vulnops


def _run_queue(cases):
    """Cases contain asset ID, criticality, KEV membership, exposure, score, percentile."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "data").mkdir()
        (root / "state").mkdir()
        scanner = []
        context = []
        kev_cves = set()
        epss = {}
        for index, (asset, criticality, kev, exposure, score, percentile) in enumerate(cases):
            machine = f"machine-{index}"
            cve = f"CVE-2026-{1000 + index}"
            scanner.append({"machineId": machine, "cveId": cve, "severity": "Critical"})
            context.append({"scanner_machine_id": machine, "asset_id": asset, "asset_criticality": criticality,
                            "internet_exposed": exposure, "owner_team": "payments-platform"})
            if kev:
                kev_cves.add(cve)
            epss[cve] = {"epss_score": score, "epss_percentile": percentile}
        scanner_path = root / "data" / "mock_scanner_output.json"
        scanner_path.write_text(json.dumps({"value": scanner}), encoding="utf-8")
        context_path = root / "data" / "asset_context.csv"
        with context_path.open("w", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(output, fieldnames=["scanner_machine_id", "asset_id", "asset_criticality",
                                                       "internet_exposed", "owner_team"])
            writer.writeheader()
            writer.writerows(context)
        (root / "state" / "remediation_status.csv").write_text("asset_id,cve,remediation_status\n")
        (root / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\n")
        findings = vulnops.build_findings(
            vulnops.normalize_scanner_observations(vulnops.load_scanner_output(scanner_path)),
            vulnops.load_asset_context(context_path),
        )
        baseline = {row["asset_id"]: row for row in vulnops.prioritize(findings, kev_cves)}
        with patch("vulnops.ROOT", root), patch("vulnops.load_kev", return_value=kev_cves):
            with patch("vulnops.load_epss", return_value=epss), patch("vulnops.urlopen") as network:
                with patch("vulnops.write_queue", wraps=vulnops.write_queue) as write:
                    with patch("sys.stdout", new_callable=io.StringIO):
                        assert vulnops.main() == 0
        network.assert_not_called()
        rows = write.call_args.args[1]
        assert len(rows) == len(cases)
        for row in rows:
            original = baseline[row["asset_id"]]
            assert row["priority"] == original["priority"]
            assert row["reason"] == original["reason"]
            assert row["epss_score"] == epss[row["cve"]]["epss_score"]
            assert row["epss_percentile"] == epss[row["cve"]]["epss_percentile"]
        with (root / "output" / "remediation_queue.csv").open(newline="") as output:
            csv_rows = list(csv.DictReader(output))
        assert [row["asset_id"] for row in csv_rows] == [row["asset_id"] for row in rows]
        return rows


def test_p0_and_p1_keep_input_order_despite_epss_and_exposure():
    cases = [
        ("P2", "critical", False, "true", 1.0, 1.0),
        ("A", "critical", True, "false", 0.10, 0.1),
        ("D", "medium", True, "false", 0.001, 0.1),
        ("B", "critical", True, "true", 0.99, 0.99),
        ("E", "high", True, "true", 0.95, 0.95),
        ("C", "critical", True, "unknown", 0.50, 0.5),
        ("F", "low", True, "unknown", 0.40, 0.4),
        ("P0-missing", "critical", True, "true", None, None),
        ("P1-missing", "medium", True, "true", None, None),
    ]
    rows = _run_queue(cases)
    assert [row["asset_id"] for row in rows] == ["A", "B", "C", "P0-missing", "D", "E", "F", "P1-missing", "P2"]
    assert [row["priority"] for row in rows] == ["P0"] * 4 + ["P1"] * 4 + ["P2"]


def test_p2_exposure_groups_win_over_much_higher_epss_in_every_input_order():
    for exposed_score, unknown_score in product((0.01, None), (0.001, None)):
        cases = [
            ("exposed", "critical", False, "true", exposed_score, 0.01),
            ("unknown", "critical", False, "unknown", unknown_score, 0.5),
            ("non-exposed", "critical", False, "false", 0.99, 0.99),
        ]
        for input_order in permutations(cases):
            rows = _run_queue(input_order)
            assert [row["asset_id"] for row in rows] == ["exposed", "unknown", "non-exposed"], input_order
            assert all(row["priority"] == "P2" for row in rows)
            assert rows[0]["epss_score"] == exposed_score
            assert rows[1]["epss_score"] == unknown_score


def test_p2_epss_descending_zero_before_missing_and_stable_ties_in_each_exposure_group():
    pattern = [
        ("missing-first", None, None),
        ("high-first", 0.90, 0.1),
        ("low", 0.10, 0.99),
        ("high-second", 0.90, 0.9),
        ("zero", 0.0, 0.0),
        ("missing-second", None, None),
        ("middle", 0.50, 0.5),
    ]
    # Interleave groups and start with false so input order alone cannot pass.
    cases = [(f"{exposure}-{label}", "critical", False, exposure, score, percentile)
             for label, score, percentile in pattern for exposure in ("false", "unknown", "true")]
    rows = _run_queue(cases)
    labels = ["high-first", "high-second", "middle", "low", "zero", "missing-first", "missing-second"]
    assert [row["asset_id"] for row in rows] == [
        f"{exposure}-{label}" for exposure in ("true", "unknown", "false") for label in labels
    ]
    for exposure in ("true", "unknown", "false"):
        group = [row for row in rows if row["internet_exposed"] == exposure]
        assert [row["epss_score"] for row in group] == [0.9, 0.9, 0.5, 0.1, 0.0, None, None]
        assert group[4]["epss_score"] == 0.0
        assert group[5]["epss_score"] is None
        assert group[6]["epss_score"] is None
    assert all(row["priority"] == "P2" for row in rows)


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(unittest.FunctionTestCase(test) for test in (
        test_p0_and_p1_keep_input_order_despite_epss_and_exposure,
        test_p2_exposure_groups_win_over_much_higher_epss_in_every_input_order,
        test_p2_epss_descending_zero_before_missing_and_stable_ties_in_each_exposure_group,
    ))
