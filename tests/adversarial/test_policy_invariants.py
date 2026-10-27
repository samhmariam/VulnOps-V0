"""Classification depends only on KEV membership and local asset criticality."""

import ast
import inspect
from itertools import product
import unittest

import vulnops


def test_classification_is_invariant_across_non_policy_signals():
    reasons = {
        "P0": "Rule 1: CVE is in CISA KEV and asset criticality is critical.",
        "P1": "Rule 2: CVE is in CISA KEV; asset criticality is not critical.",
        "P2": "Rule 3: CVE is not in CISA KEV.",
    }
    expected_priorities = {
        (True, "critical"): "P0",
        (True, "high"): "P1",
        (True, "medium"): "P1",
        (True, "low"): "P1",
        (False, "critical"): "P2",
        (False, "high"): "P2",
        (False, "medium"): "P2",
        (False, "low"): "P2",
    }
    severities = ("critical", "high", "medium", "low")
    scores = (None, 0.0, 0.001, 0.25, 0.5, 0.99, 1.0)
    percentiles = (None, 0.0, 0.5, 1.0)
    exposures = ("true", "false", "unknown")
    owners = ("unknown", "payments-platform", "identity", "workplace-it", "data-platform")
    cve = "CVE-2026-1001"
    checked = 0

    for (in_kev, criticality), expected_priority in expected_priorities.items():
        kev_cves = {cve} if in_kev else set()
        for severity, score, percentile, exposure, owner in product(
                severities, scores, percentiles, exposures, owners):
            finding = {
                "asset_id": "payments-api-01",
                "cve": cve,
                "severity": severity,
                "asset_criticality": criticality,
                "internet_exposed": exposure,
                "owner_team": owner,
                "epss_score": score,
                "epss_percentile": percentile,
            }
            original = finding.copy()
            results = vulnops.prioritize([finding], kev_cves)
            assert results == [{
                **original,
                "kev": str(in_kev).lower(),
                "priority": expected_priority,
                "reason": reasons[expected_priority],
            }], (in_kev, original, results)
            assert finding == original
            assert results[0] is not finding
            assert kev_cves == ({cve} if in_kev else set())
            checked += 1

    assert checked == 13440


def test_classifier_does_not_read_non_policy_signals():
    # EPSS and team names have unbounded possible values. Guard the implementation
    # as well as exercising the finite value matrix above: these fields are unread.
    tree = ast.parse(inspect.getsource(vulnops.prioritize))
    input_fields = {
        node.slice.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Name)
        and node.value.id == "finding"
        and isinstance(node.slice, ast.Constant)
    }
    assert input_fields == {"cve", "asset_criticality"}
    string_literals = {node.value for node in ast.walk(tree)
                       if isinstance(node, ast.Constant) and isinstance(node.value, str)}
    assert string_literals.isdisjoint({
        "severity", "epss_score", "epss_percentile", "internet_exposed", "owner_team",
    })


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(unittest.FunctionTestCase(test) for test in (
        test_classification_is_invariant_across_non_policy_signals,
        test_classifier_does_not_read_non_policy_signals,
    ))
