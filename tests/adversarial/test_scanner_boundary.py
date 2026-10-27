"""Adversarial checks of the existing scanner/context boundary; no network access."""

import json
from pathlib import Path
import tempfile
import unittest

import vulnops


def test_vendor_fields_do_not_leak_into_internal_finding():
    raw = {
        "machineId": "machine-001",
        "cveId": "CVE-2026-1001",
        "severity": "Critical",
        "id": "vendor-finding-id",
        "productName": "example-product",
        "productVersion": "1.2.3",
        "productVendor": "example-vendor",
        "fixingKbId": "KB123",
        "asset_id": "scanner-must-not-choose-the-asset",
        "asset_criticality": "low",
        "internet_exposed": "false",
        "owner_team": "scanner-must-not-choose-the-owner",
        "priority": "P2",
    }
    original = raw.copy()
    with tempfile.TemporaryDirectory() as directory:
        scanner_path = Path(directory) / "scanner.json"
        scanner_path.write_text(json.dumps({"value": [raw]}), encoding="utf-8")
        context_path = Path(directory) / "asset_context.csv"
        context_path.write_text(
            "scanner_machine_id,asset_id,asset_criticality,internet_exposed,owner_team\n"
            "machine-001,payments-api-01,critical,true,payments-platform\n",
            encoding="utf-8",
        )
        observations = vulnops.normalize_scanner_observations(vulnops.load_scanner_output(scanner_path))
        assert observations == [
            {"scanner_machine_id": "machine-001", "cve": "CVE-2026-1001", "severity": "critical"}
        ]
        findings = vulnops.build_findings(observations, vulnops.load_asset_context(context_path))
    assert findings == [{
        "asset_id": "payments-api-01",
        "cve": "CVE-2026-1001",
        "severity": "critical",
        "asset_criticality": "critical",
        "internet_exposed": "true",
        "owner_team": "payments-platform",
    }]
    assert raw == original


def test_exact_duplicates_collapse_deterministically_preserving_first_occurrence_order():
    first = {"machineId": "machine-001", "cveId": "CVE-2026-1001", "severity": "High"}
    second = {**first, "cveId": "CVE-2026-1002"}
    other_machine = {**first, "machineId": "machine-002"}
    records = [first, second, first.copy(), other_machine, second.copy(), first.copy()]
    originals = [record.copy() for record in records]
    expected = [
        {"scanner_machine_id": "machine-001", "cve": "CVE-2026-1001", "severity": "high"},
        {"scanner_machine_id": "machine-001", "cve": "CVE-2026-1002", "severity": "high"},
        {"scanner_machine_id": "machine-002", "cve": "CVE-2026-1001", "severity": "high"},
    ]
    assert vulnops.normalize_scanner_observations(records) == expected
    assert vulnops.normalize_scanner_observations(records) == expected
    assert records == originals


def test_conflicting_duplicates_fail_in_both_orders_after_identity_normalization():
    high = {"machineId": "machine-001", "cveId": "CVE-2026-1001", "severity": "High"}
    low = {"machineId": " machine-001 ", "cveId": " cve-2026-1001 ", "severity": "low"}
    for records in ([high, low], [low, high]):
        with unittest.TestCase().assertRaisesRegex(ValueError, "conflicting severity.*same machine/CVE"):
            vulnops.normalize_scanner_observations(records)


def test_missing_asset_context_fails_instead_of_returning_partial_findings_or_defaults():
    observations = vulnops.normalize_scanner_observations([
        {"machineId": "machine-001", "cveId": "CVE-2026-1001", "severity": "High"},
        {"machineId": "unconfigured-machine", "cveId": "CVE-2026-1002", "severity": "Low"},
    ])
    context = {"machine-001": {
        "asset_id": "payments-api-01", "asset_criticality": "critical",
        "internet_exposed": "true", "owner_team": "payments-platform",
    }}
    with unittest.TestCase().assertRaisesRegex(ValueError, "unconfigured-machine.*no matching asset context"):
        vulnops.build_findings(observations, context)
    assert context["machine-001"]["owner_team"] == "payments-platform"
    assert "unconfigured-machine" not in context


def test_duplicate_or_ambiguous_asset_mappings_fail_even_when_identical_or_whitespace_padded():
    first = "machine-001,payments-api-01,critical,true,payments-platform\n"
    cases = [
        (first, "Duplicate scanner_machine_id"),
        ("machine-001,another-asset,low,false,identity\n", "Duplicate scanner_machine_id"),
        (" machine-001 ,another-asset,low,false,identity\n", "Duplicate scanner_machine_id"),
        ("machine-002,payments-api-01,low,false,identity\n", "Duplicate asset_id"),
        ("machine-002, payments-api-01 ,low,false,identity\n", "Duplicate asset_id"),
    ]
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "asset_context.csv"
        for duplicate, message in cases:
            path.write_text(
                "scanner_machine_id,asset_id,asset_criticality,internet_exposed,owner_team\n"
                + first + duplicate,
                encoding="utf-8",
            )
            with unittest.TestCase().assertRaisesRegex(ValueError, message):
                vulnops.load_asset_context(path)


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(unittest.FunctionTestCase(test) for test in (
        test_vendor_fields_do_not_leak_into_internal_finding,
        test_exact_duplicates_collapse_deterministically_preserving_first_occurrence_order,
        test_conflicting_duplicates_fail_in_both_orders_after_identity_normalization,
        test_missing_asset_context_fails_instead_of_returning_partial_findings_or_defaults,
        test_duplicate_or_ambiguous_asset_mappings_fail_even_when_identical_or_whitespace_padded,
    ))
