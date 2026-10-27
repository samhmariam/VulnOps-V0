import ast
import csv
import inspect
import io
import json
import os
from pathlib import Path
import tempfile
import traceback
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse

import vulnops


class VulnOpsTests(unittest.TestCase):
    def test_live_smoke_mode_reports_safe_counts_and_runs_normal_pipeline_including_zero_findings(self):
        token = "controlled-secret-never-print"
        for raw_count in (0, 2):
            with self.subTest(raw_count=raw_count), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "data").mkdir()
                (root / "state").mkdir()
                (root / "data" / "asset_context.csv").write_text(
                    "defender_machine_id,asset_id,asset_criticality,internet_exposed,owner_team\n"
                    "abc123,payments-api-01,critical,true,payments-platform\n")
                (root / "state" / "remediation_status.csv").write_text("asset_id,cve,remediation_status\n")
                (root / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\n")
                observation = {"machineId": "abc123", "cveId": "CVE-2026-1234", "severity": "Critical",
                               "productName": "do-not-print-payload"}
                payloads = [{"value": [observation] * raw_count},
                            {"vulnerabilities": [{"cveID": "CVE-2026-1234"}]}]
                if raw_count:
                    payloads.append({"status": "OK", "status-code": 200, "total": 1, "data": [
                        {"cve": "CVE-2026-1234", "epss": "0.01", "percentile": "0.1"}]})
                responses = [io.BytesIO(json.dumps(payload).encode()) for payload in payloads]
                with patch("vulnops.ROOT", root), patch.dict(os.environ, {"MDE_ACCESS_TOKEN": token}):
                    with patch("vulnops.urlopen", side_effect=responses) as get:
                        with patch("sys.stdout", new_callable=io.StringIO) as stdout:
                            with patch("sys.stderr", new_callable=io.StringIO) as stderr:
                                self.assertEqual(vulnops.main(live_smoke=True), 0)
                normalized_count = int(raw_count > 0)
                self.assertEqual(stdout.getvalue().splitlines(), [
                    "assets queried: 1", f"raw observations: {raw_count}",
                    f"normalized findings: {normalized_count}",
                    f"Wrote {normalized_count} findings to output/remediation_queue.csv"])
                self.assertEqual(stderr.getvalue(), "")
                for secret in (token, "Authorization", "Bearer", "do-not-print-payload"):
                    self.assertNotIn(secret, stdout.getvalue() + stderr.getvalue())
                self.assertEqual(get.call_count, len(payloads))
                with (root / "output" / "remediation_queue.csv").open(newline="") as output:
                    rows = list(csv.DictReader(output))
                self.assertEqual(len(rows), normalized_count)
                if rows:
                    self.assertEqual(rows[0]["priority"], "P0")
                    self.assertEqual(rows[0]["owner_team"], "payments-platform")
                    self.assertEqual(rows[0]["remediation_status"], "open")

    def test_live_smoke_rejects_missing_or_blank_token_before_reading_context_or_requesting(self):
        for token in (None, "", "   "):
            with self.subTest(token=token), patch.dict(os.environ, {}, clear=True):
                if token is not None:
                    os.environ["MDE_ACCESS_TOKEN"] = token
                with patch("vulnops.load_asset_context") as context, patch("vulnops.urlopen") as get:
                    with patch("sys.stderr", new_callable=io.StringIO) as stderr:
                        with patch("sys.stdout", new_callable=io.StringIO) as stdout:
                            self.assertEqual(vulnops.main(live_smoke=True), 1)
                self.assertIn("non-empty MDE_ACCESS_TOKEN", stderr.getvalue())
                self.assertEqual(stdout.getvalue(), "")
                context.assert_not_called()
                get.assert_not_called()

    def test_live_smoke_does_not_report_success_when_later_pipeline_stage_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir()
            (root / "state").mkdir()
            (root / "output").mkdir()
            (root / "data" / "asset_context.csv").write_text(
                "defender_machine_id,asset_id,asset_criticality,internet_exposed,owner_team\n"
                "abc123,payments-api-01,critical,true,payments-platform\n")
            (root / "state" / "remediation_status.csv").write_text("asset_id,cve,remediation_status\n")
            (root / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\n")
            queue = root / "output" / "remediation_queue.csv"
            queue.write_text("previous queue\n")
            with patch("vulnops.ROOT", root), patch.dict(os.environ, {"MDE_ACCESS_TOKEN": "controlled-test-token"}):
                with patch("vulnops.urlopen", side_effect=[io.BytesIO(b'{"value": []}'), URLError("controlled KEV outage")]):
                    with patch("sys.stdout", new_callable=io.StringIO) as stdout:
                        with patch("sys.stderr", new_callable=io.StringIO) as stderr:
                            self.assertEqual(vulnops.main(live_smoke=True), 1)
            self.assertNotIn("Wrote", stdout.getvalue())
            self.assertIn("VulnOps failed", stderr.getvalue())
            self.assertEqual(queue.read_text(), "previous queue\n")

    def test_scanner_and_equivalent_csv_findings_have_identical_downstream_results(self):
        cve = "CVE-2026-1234"  # Valid stand-in for the request's CVE-X.
        observation = {"defender_machine_id": "abc123", "cve": cve, "severity": "critical"}
        context = {"abc123": {"asset_id": "payments-api-01", "asset_criticality": "critical",
                              "internet_exposed": "true", "owner_team": "payments-platform"}}
        scanner_finding = vulnops.build_findings([observation], context)[0]
        peers = [{"asset_id": asset, "cve": peer_cve, "severity": "critical", "criticality": criticality,
                  "internet_exposed": exposure, "owner_team": "identity"}
                 for asset, peer_cve, criticality, exposure in (
                     ("false", "CVE-2026-2001", "critical", "false"),
                     ("unknown", "CVE-2026-2002", "critical", "unknown"),
                     ("low", "CVE-2026-2003", "critical", "true"),
                     ("high", "CVE-2026-2004", "critical", "true"),
                     ("p1", "CVE-2026-9999", "medium", "false"),
                     ("p0", "CVE-2026-9999", "critical", "false"))]
        lifecycle_cases = [(None, None, "open", "not_applicable", True),
                           ("open", False, "open", "not_applicable", True),
                           ("resolved", None, "resolved", "unverified", True),
                           ("resolved", True, "resolved", "failed", True),
                           ("resolved", False, "resolved", "passed", False)]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir()
            (root / "state").mkdir()
            fixture = root / "data" / "finding_fixture.csv"
            with fixture.open("w", newline="") as output:
                writer = csv.DictWriter(output, fieldnames=list(scanner_finding))
                writer.writeheader()
                writer.writerow({"asset_id": "payments-api-01", "cve": cve, "severity": "critical",
                                 "criticality": "critical", "internet_exposed": "true", "owner_team": "payments-platform"})
                writer.writerows(peers)
            csv_findings = self.read_fixture_findings(fixture)
            self.assertEqual(scanner_finding, csv_findings[0])
            for in_kev in (True, False):
                for score, percentile in ((0.75, 0.98), (0.0, 0.0), (None, None)):
                    for claim, present, remediation, verification, active in lifecycle_cases:
                        with self.subTest(kev=in_kev, score=score, claim=claim, present=present):
                            (root / "state" / "remediation_status.csv").write_text(
                                "asset_id,cve,remediation_status\n" +
                                (f"payments-api-01,{cve},{claim}\n" if claim else ""))
                            (root / "data" / "verification_results.csv").write_text(
                                "asset_id,cve,vulnerability_present\n" +
                                (f"payments-api-01,{cve},{str(present).lower()}\n" if present is not None else ""))
                            kev = {"CVE-2026-9999"} | ({cve} if in_kev else set())
                            epss = {peer["cve"]: {"epss_score": 0.99, "epss_percentile": 0.9} for peer in peers}
                            epss["CVE-2026-2003"] = {"epss_score": 0.1, "epss_percentile": 0.2}
                            epss[cve] = {"epss_score": score, "epss_percentile": percentile}
                            snapshots = []
                            for source in ("csv", "scanner"):
                                initial = csv_findings if source == "csv" else [scanner_finding, *peers]
                                with patch("vulnops.ROOT", root), patch("vulnops.load_asset_context", return_value=context):
                                    with patch("vulnops.load_defender_findings", return_value=[observation]):
                                        with patch("vulnops.build_findings", return_value=initial):
                                            with patch("vulnops.load_kev", return_value=kev) as load_kev:
                                                with patch("vulnops.load_epss", return_value=epss) as load_epss:
                                                    with patch("vulnops.apply_verification_status", wraps=vulnops.apply_verification_status) as verify:
                                                        with patch("vulnops.write_queue", wraps=vulnops.write_queue) as write:
                                                            with patch("sys.stdout", new_callable=io.StringIO):
                                                                self.assertEqual(vulnops.main(), 0)
                                load_kev.assert_called_once_with()
                                derived = vulnops.apply_verification_status(*verify.call_args.args)
                                target = derived[0]
                                self.assertEqual(target["remediation_status"], remediation)
                                self.assertEqual(target["verification_status"], verification)
                                classified = vulnops.prioritize(vulnops.enrich_with_epss([target], epss), kev)[0]
                                self.assertEqual(classified["priority"], "P0" if in_kev else "P2")
                                self.assertEqual(classified["kev"], str(in_kev).lower())
                                self.assertEqual(classified["epss_score"], score)
                                self.assertEqual(classified["epss_percentile"], percentile)
                                self.assertEqual(classified["owner_team"], "payments-platform")
                                self.assertEqual(classified["reason"],
                                                 "Rule 1: CVE is in CISA KEV and asset criticality is critical." if in_kev
                                                 else "Rule 3: CVE is not in CISA KEV.")
                                queue = write.call_args.args[1]
                                self.assertEqual(any(row["asset_id"] == "payments-api-01" for row in queue), active)
                                p2 = [row["asset_id"] for row in queue if row["priority"] == "P2"]
                                expected = ["high", "low", "unknown", "false"]
                                if active and not in_kev:
                                    expected.insert(1 if score == 0.75 else 2, "payments-api-01")
                                self.assertEqual(p2, expected)
                                snapshots.append((derived, classified, queue, load_epss.call_args,
                                                  (root / "output" / "remediation_queue.csv").read_bytes()))
                            self.assertEqual(snapshots[0], snapshots[1])

    def test_priority_logic_contains_no_scanner_specific_references(self):
        source = inspect.getsource(vulnops.prioritize).lower()
        for term in ("defender", "machineid", "mde", "microsoft"):
            with self.subTest(term=term):
                self.assertNotIn(term, source)

    def test_ranking_contains_no_scanner_specific_logic(self):
        tree = ast.parse(inspect.getsource(vulnops.main))
        # Inspect the actual ranking statements, excluding the acquisition boundary in main().
        ranking = [node for node in ast.walk(tree)
                   if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "sort"]
        ranking += [node for node in ast.walk(tree) if isinstance(node, ast.ListComp)]
        self.assertTrue(ranking)
        for node in ranking:
            for term in ("defender", "machineid", "mde", "microsoft"):
                with self.subTest(term=term, expression=ast.unparse(node)):
                    self.assertNotIn(term, ast.unparse(node).lower())

    def test_main_uses_defender_without_findings_csv_and_preserves_v07_behaviour(self):
        assets = [("machine-a", "passed", "critical", "false", "identity", "CVE-2026-1234"),
                  ("machine-b", "failed", "critical", "false", "payments-platform", "CVE-2026-1234"),
                  ("machine-c", "p1", "medium", "false", "identity", "CVE-2026-1234"),
                  ("machine-d", "unverified", "low", "true", "unknown", "CVE-2026-1235"),
                  ("machine-e", "unknown-exposure", "critical", "unknown", "data-platform", "CVE-2026-1236"),
                  ("machine-f", "non-exposed", "critical", "false", "workplace-it", "CVE-2026-1237")]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir()
            (root / "state").mkdir()
            context_path = root / "data" / "asset_context.csv"
            context_path.write_text("defender_machine_id,asset_id,asset_criticality,internet_exposed,owner_team\n" +
                                    "".join(",".join(asset[:5]) + "\n" for asset in assets))
            state_path = root / "state" / "remediation_status.csv"
            state_path.write_text("asset_id,cve,remediation_status\n"
                                  "passed,CVE-2026-1234,resolved\nfailed,CVE-2026-1234,resolved\n"
                                  "unverified,CVE-2026-1235,resolved\n")
            evidence_path = root / "data" / "verification_results.csv"
            evidence_path.write_text("asset_id,cve,vulnerability_present\n"
                                     "passed,CVE-2026-1234,false\nfailed,CVE-2026-1234,true\n")
            originals = {path: path.read_bytes() for path in (context_path, state_path, evidence_path)}
            payloads = [{"value": [{"machineId": asset[0], "cveId": asset[5], "severity": "High",
                                    "productName": "ignored", "id": "ignored"}]} for asset in assets]
            payloads += [{"vulnerabilities": [{"cveID": "CVE-2026-1234"}]},
                         {"status": "OK", "status-code": 200, "total": 4, "data": [
                             {"cve": cve, "epss": score, "percentile": "0.9"}
                             for cve, score in (("CVE-2026-1234", "0.001"), ("CVE-2026-1235", "0.01"),
                                                ("CVE-2026-1236", "0.99"), ("CVE-2026-1237", "0.99"))]}]
            outputs = []
            for run in range(2):
                with self.subTest(run=run):
                    responses = [io.BytesIO(json.dumps(payload).encode()) for payload in payloads]
                    with patch("vulnops.ROOT", root), patch.dict(os.environ, {"MDE_ACCESS_TOKEN": "controlled-test-token"}):
                        with patch("vulnops.urlopen", side_effect=responses) as get:
                            with patch("vulnops.write_queue", wraps=vulnops.write_queue) as write:
                                with patch("sys.stdout", new_callable=io.StringIO):
                                    self.assertEqual(vulnops.main(), 0)
                    self.assertEqual(get.call_count, 8)
                    for asset, call in zip(assets, get.call_args_list[:6]):
                        self.assertEqual(parse_qs(urlparse(call.args[0].full_url).query)["$filter"],
                                         [f"machineId eq '{asset[0]}'"])
                    internal = write.call_args.args[1]
                    self.assertEqual([row["asset_id"] for row in internal],
                                     ["failed", "p1", "unverified", "unknown-exposure", "non-exposed"])
                    self.assertEqual([row["verification_status"] for row in internal],
                                     ["failed", "not_applicable", "unverified", "not_applicable", "not_applicable"])
                    self.assertTrue(all(row["severity"] == "high" for row in internal))
                    self.assertTrue(all("defender_machine_id" not in row and "productName" not in row for row in internal))
                    output_path = root / "output" / "remediation_queue.csv"
                    with output_path.open(newline="") as output:
                        reader = csv.DictReader(output)
                        self.assertEqual(reader.fieldnames, ["asset_id", "criticality", "cve", "internet_exposed",
                                                            "owner_team", "kev", "epss_score", "epss_percentile",
                                                            "priority", "reason", "remediation_status"])
                        rows = list(reader)
                    self.assertEqual([row["priority"] for row in rows], ["P0", "P1", "P2", "P2", "P2"])
                    self.assertEqual([row["remediation_status"] for row in rows], ["resolved", "open", "resolved", "open", "open"])
                    self.assertEqual([row["owner_team"] for row in rows],
                                     ["payments-platform", "identity", "unknown", "data-platform", "workplace-it"])
                    self.assertEqual(rows[0]["reason"], "Rule 1: CVE is in CISA KEV and asset criticality is critical.")
                    self.assertTrue(all(row["reason"] == "Rule 3: CVE is not in CISA KEV." for row in rows[2:]))
                    self.assertEqual({path: path.read_bytes() for path in originals}, originals)
                    self.assertFalse((root / "data" / "findings.csv").exists())
                    outputs.append(output_path.read_bytes())
            self.assertEqual(outputs[0], outputs[1])
            self.assertFalse(hasattr(vulnops, "load_findings"))

    def test_main_defender_failure_preserves_previous_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir()
            (root / "output").mkdir()
            (root / "data" / "asset_context.csv").write_text(
                "defender_machine_id,asset_id,asset_criticality,internet_exposed,owner_team\n"
                "abc123,payments-api-01,critical,true,payments-platform\n")
            output_path = root / "output" / "remediation_queue.csv"
            output_path.write_text("previous queue\n")
            error = HTTPError(vulnops.DEFENDER_URL, 401, "controlled-secret", {}, None)
            with patch("vulnops.ROOT", root), patch.dict(os.environ, {"MDE_ACCESS_TOKEN": "controlled-secret"}):
                with patch("vulnops.urlopen", side_effect=error) as get:
                    with patch("sys.stderr", new_callable=io.StringIO) as stderr:
                        self.assertEqual(vulnops.main(), 1)
            get.assert_called_once()
            self.assertIn("Defender authentication failure", stderr.getvalue())
            self.assertNotIn("controlled-secret", stderr.getvalue())
            self.assertEqual(output_path.read_text(), "previous queue\n")

    def read_fixture_findings(self, path):
        """Read inline test data; this is not a production ingestion path."""
        with path.open(newline="") as source:
            rows = [{key: value.strip() for key, value in row.items()} for row in csv.DictReader(source)]
        for row in rows:
            row["cve"] = row["cve"].upper()
            row["criticality"] = row["criticality"].lower()
        return rows

    def run_fixture_main(self):
        """Supply deterministic findings at the acquisition boundary for policy regressions."""
        findings = self.read_fixture_findings(vulnops.ROOT / "data" / "finding_fixture.csv")
        with patch("vulnops.load_asset_context", return_value={}):
            with patch("vulnops.load_defender_findings", return_value=[]):
                with patch("vulnops.build_findings", return_value=findings):
                    return vulnops.main()

    def test_build_findings_joins_csv_context_using_existing_internal_field_names(self):
        observations = [{"defender_machine_id": "abc123", "cve": "CVE-2026-1234", "severity": "low"}]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "asset_context.csv"
            source.write_text("defender_machine_id,asset_id,asset_criticality,internet_exposed,owner_team\n"
                              "abc123,payments-api-01,critical,true,payments-platform\n")
            context = vulnops.load_asset_context(source)
        results = vulnops.build_findings(observations, context)
        self.assertEqual(results, [{"asset_id": "payments-api-01", "cve": "CVE-2026-1234", "severity": "low",
                                    "criticality": "critical", "internet_exposed": "true", "owner_team": "payments-platform"}])
        self.assertEqual(observations, [{"defender_machine_id": "abc123", "cve": "CVE-2026-1234", "severity": "low"}])
        self.assertEqual(context["abc123"], {"asset_id": "payments-api-01", "asset_criticality": "critical",
                                            "internet_exposed": "true", "owner_team": "payments-platform"})
        self.assertIsNot(results[0], observations[0])
        self.assertIsNot(results[0], context["abc123"])

    def test_build_findings_keeps_vendor_fields_out_of_existing_downstream_stages(self):
        observation = {"defender_machine_id": "abc123", "cve": "CVE-2026-1234", "severity": "low",
                       "machineId": "abc123", "cveId": "CVE-2026-1234", "id": "vendor-id",
                       "productName": "product", "productVersion": "1", "productVendor": "vendor", "fixingKbId": "KB123"}
        context = {"abc123": {"asset_id": "payments-api-01", "asset_criticality": "critical",
                              "internet_exposed": "unknown", "owner_team": "unknown", "defender_machine_id": "abc123"}}
        findings = vulnops.build_findings([observation], context)
        expected_fields = {"asset_id", "cve", "severity", "criticality", "internet_exposed", "owner_team"}
        self.assertEqual(set(findings[0]), expected_fields)
        key = ("payments-api-01", "CVE-2026-1234")
        findings = vulnops.apply_remediation_status(findings, {key: "resolved"})
        findings = vulnops.apply_verification_status(findings, {key: True})
        findings = vulnops.enrich_with_epss(findings, {key[1]: {"epss_score": 0.01, "epss_percentile": 0.1}})
        findings = vulnops.prioritize(findings, {key[1]})
        result = findings[0]
        self.assertEqual(result["priority"], "P0")
        self.assertEqual(result["remediation_status"], "resolved")
        self.assertEqual(result["verification_status"], "failed")
        self.assertEqual(result["owner_team"], "unknown")
        self.assertEqual(result["internet_exposed"], "unknown")
        self.assertEqual(set(result), expected_fields | {"remediation_status", "verification_status", "epss_score",
                                                       "epss_percentile", "kev", "priority", "reason"})

    def test_build_findings_rejects_missing_context_without_inventing_values(self):
        observations = [{"defender_machine_id": "unconfigured", "cve": "CVE-2026-1234", "severity": "high"}]
        with self.assertRaisesRegex(ValueError, "no matching asset context"):
            vulnops.build_findings(observations, {})

    def test_build_findings_preserves_order_and_reuses_context_for_multiple_cves(self):
        context = {"abc123": {"asset_id": "payments-api-01", "asset_criticality": "critical",
                              "internet_exposed": "true", "owner_team": "payments-platform"},
                   "def456": {"asset_id": "hr-web-01", "asset_criticality": "medium",
                              "internet_exposed": "false", "owner_team": "workplace-it"}}
        observations = [{"defender_machine_id": machine, "cve": cve, "severity": "high"}
                        for machine, cve in (("abc123", "CVE-2026-1234"), ("def456", "CVE-2026-1234"),
                                             ("abc123", "CVE-2026-5678"))]
        findings = vulnops.build_findings(observations, context)
        self.assertEqual([(row["asset_id"], row["cve"]) for row in findings],
                         [("payments-api-01", "CVE-2026-1234"), ("hr-web-01", "CVE-2026-1234"),
                          ("payments-api-01", "CVE-2026-5678")])
        self.assertEqual(vulnops.build_findings([], context), [])

    def test_normalize_defender_single_observation_keeps_only_scanner_fields(self):
        entry = {"machineId": "abc123", "cveId": "CVE-2026-1234", "severity": "Critical",
                 "productName": "product", "productVersion": "1", "productVendor": "vendor",
                 "fixingKbId": "KB123", "id": "defender-finding-id"}
        original = entry.copy()
        self.assertEqual(vulnops.normalize_defender_findings([entry]), [
            {"defender_machine_id": "abc123", "cve": "CVE-2026-1234", "severity": "critical"}])
        self.assertEqual(entry, original)

    def test_normalize_defender_collapses_exact_and_different_software_duplicates(self):
        entry = {"machineId": "abc123", "cveId": "CVE-2026-1234", "severity": "High"}
        for duplicate in (entry.copy(), {**entry, "productName": "another-product", "productVersion": "2",
                                         "productVendor": "another-vendor", "id": "different-id"},
                          {**entry, "machineId": " abc123 ", "cveId": " cve-2026-1234 ", "severity": "high"}):
            with self.subTest(duplicate=duplicate):
                self.assertEqual(vulnops.normalize_defender_findings([entry, duplicate]), [
                    {"defender_machine_id": "abc123", "cve": "CVE-2026-1234", "severity": "high"}])

    def test_normalize_defender_fails_on_conflicting_severity_in_either_order(self):
        high = {"machineId": "abc123", "cveId": "CVE-2026-1234", "severity": "High"}
        low = {**high, "severity": "Low"}
        for entries in ([high, low], [low, high]):
            with self.subTest(entries=entries):
                with self.assertRaisesRegex(ValueError, "conflicting severity.*same machine/CVE"):
                    vulnops.normalize_defender_findings(entries)

    def test_normalize_defender_rejects_missing_fields_and_unknown_severity(self):
        entry = {"machineId": "abc123", "cveId": "CVE-2026-1234", "severity": "High"}
        for field in entry:
            for value in (None, "", "   "):
                with self.subTest(field=field, value=value):
                    invalid = {key: item for key, item in entry.items() if key != field}
                    if value is not None:
                        invalid[field] = value
                    with self.assertRaisesRegex(ValueError, "requires non-empty"):
                        vulnops.normalize_defender_findings([invalid])
        with self.assertRaisesRegex(ValueError, "unexpected severity"):
            vulnops.normalize_defender_findings([{**entry, "severity": "unknown"}])

    def test_normalize_defender_preserves_distinct_keys_and_first_occurrence_order(self):
        a = {"machineId": "abc123", "cveId": "CVE-2026-1234", "severity": "High"}
        b = {**a, "machineId": "def456"}
        c = {**a, "cveId": "CVE-2026-5678"}
        results = vulnops.normalize_defender_findings([a, b, a, c, b])
        self.assertEqual([(row["defender_machine_id"], row["cve"]) for row in results],
                         [("abc123", "CVE-2026-1234"), ("def456", "CVE-2026-1234"), ("abc123", "CVE-2026-5678")])
        self.assertEqual(vulnops.normalize_defender_findings([]), [])

    def test_defender_deduplicates_across_pages_and_rejects_cross_page_conflicts(self):
        entry = {"machineId": "abc123", "cveId": "CVE-2026-1234", "severity": "High"}
        for severity in ("high", "Low"):
            with self.subTest(severity=severity):
                responses = [io.BytesIO(json.dumps({"value": [entry] * 10000}).encode()),
                             io.BytesIO(json.dumps({"value": [{**entry, "severity": severity}]}).encode())]
                with patch.dict(os.environ, {"MDE_ACCESS_TOKEN": "controlled-test-token"}):
                    with patch("vulnops.urlopen", side_effect=responses) as get:
                        if severity == "Low":
                            with self.assertRaisesRegex(ValueError, "conflicting severity"):
                                vulnops.load_defender_findings({"abc123": {}})
                        else:
                            self.assertEqual(vulnops.load_defender_findings({"abc123": {}}), [
                                {"defender_machine_id": "abc123", "cve": "CVE-2026-1234", "severity": "high"}])
                self.assertEqual(get.call_count, 2)

    def test_defender_paginates_until_a_page_has_fewer_than_10000_rows(self):
        for page_sizes in ((0,), (1,), (9999,), (10000, 0), (10000, 500)):
            with self.subTest(page_sizes=page_sizes):
                responses = [io.BytesIO(json.dumps({"value": [
                    {"machineId": "abc123", "cveId": f"CVE-2026-{1000 + page * 10000 + index}", "severity": "High"}
                    for index in range(size)]}).encode()) for page, size in enumerate(page_sizes)]
                with patch.dict(os.environ, {"MDE_ACCESS_TOKEN": "controlled-test-token"}):
                    with patch("vulnops.urlopen", side_effect=responses) as get:
                        findings = vulnops.load_defender_findings({"abc123": {}})
                self.assertEqual(get.call_count, len(page_sizes))
                self.assertEqual(len(findings), sum(page_sizes))
                offset = 0
                for page, (size, call) in enumerate(zip(page_sizes, get.call_args_list)):
                    self.assertEqual(parse_qs(urlparse(call.args[0].full_url).query), {
                        "$filter": ["machineId eq 'abc123'"], "$top": ["10000"], "$skip": [str(page * 10000)]})
                    self.assertEqual(call.args[0].get_header("Authorization"), "Bearer controlled-test-token")
                    self.assertEqual(findings[offset:offset + size], [
                        {"defender_machine_id": "abc123", "cve": f"CVE-2026-{1000 + page * 10000 + index}", "severity": "high"}
                        for index in range(size)])
                    offset += size

    def test_defender_fails_instead_of_truncating_after_10_full_pages(self):
        full_page = json.dumps({"value": [
            {"machineId": "abc123", "cveId": "CVE-2026-1234", "severity": "High"}
        ] * 10000}).encode()
        responses = [io.BytesIO(full_page) for _ in range(10)]
        with patch.dict(os.environ, {"MDE_ACCESS_TOKEN": "controlled-test-token"}):
            with patch("vulnops.urlopen", side_effect=responses) as get:
                with self.assertRaisesRegex(ValueError, "maximum 10 pages per machine.*refusing to truncate"):
                    vulnops.load_defender_findings({"abc123": {}})
        self.assertEqual(get.call_count, 10)
        self.assertEqual([parse_qs(urlparse(call.args[0].full_url).query)["$skip"]
                          for call in get.call_args_list], [[str(page * 10000)] for page in range(10)])

    def test_defender_allows_a_short_tenth_page_and_resets_skip_for_next_machine(self):
        full_page = json.dumps({"value": [
            {"machineId": "abc123", "cveId": "CVE-2026-1234", "severity": "High"}
        ] * 10000}).encode()
        responses = [io.BytesIO(full_page) for _ in range(9)]
        responses += [io.BytesIO(b'{"value": []}'), io.BytesIO(b'{"value": []}')]
        with patch.dict(os.environ, {"MDE_ACCESS_TOKEN": "controlled-test-token"}):
            with patch("vulnops.urlopen", side_effect=responses) as get:
                findings = vulnops.load_defender_findings({"abc123": {}, "def456": {}})
        self.assertEqual(findings, [{"defender_machine_id": "abc123", "cve": "CVE-2026-1234", "severity": "high"}])
        self.assertEqual(get.call_count, 11)
        self.assertEqual(parse_qs(urlparse(get.call_args_list[9].args[0].full_url).query), {
            "$filter": ["machineId eq 'abc123'"], "$top": ["10000"], "$skip": ["90000"]})
        self.assertEqual(parse_qs(urlparse(get.call_args_list[10].args[0].full_url).query), {
            "$filter": ["machineId eq 'def456'"], "$top": ["10000"], "$skip": ["0"]})

    def test_defender_page_failure_does_not_return_partial_findings(self):
        full_page = io.BytesIO(json.dumps({"value": [
            {"machineId": "abc123", "cveId": "CVE-2026-1234", "severity": "High"}
        ] * 10000}).encode())
        with patch.dict(os.environ, {"MDE_ACCESS_TOKEN": "controlled-test-token"}):
            with patch("vulnops.urlopen", side_effect=[full_page, URLError("network unavailable")]) as get:
                with self.assertRaisesRegex(ValueError, "Defender network retrieval failed"):
                    vulnops.load_defender_findings({"abc123": {}})
        self.assertEqual(get.call_count, 2)

    def test_defender_queries_only_machines_configured_in_asset_context(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "asset_context.csv"
            source.write_text("defender_machine_id,asset_id,asset_criticality,internet_exposed,owner_team\n"
                              "abc123,payments-api-01,critical,true,payments-platform\n"
                              "def456,hr-web-01,medium,false,workplace-it\n")
            context = vulnops.load_asset_context(source)
            responses = [io.BytesIO(json.dumps({"value": [
                {"machineId": machine, "cveId": "CVE-2026-1234", "severity": "High"}]}).encode())
                         for machine in ("abc123", "def456")]
            with patch.dict(os.environ, {"MDE_ACCESS_TOKEN": "controlled-test-token"}):
                with patch("vulnops.urlopen", side_effect=responses) as get:
                    findings = vulnops.load_defender_findings(context)
        self.assertEqual(get.call_count, 2)
        filters = [parse_qs(urlparse(call.args[0].full_url).query) for call in get.call_args_list]
        self.assertEqual(filters, [{"$filter": ["machineId eq 'abc123'"], "$top": ["10000"], "$skip": ["0"]},
                                   {"$filter": ["machineId eq 'def456'"], "$top": ["10000"], "$skip": ["0"]}])
        self.assertEqual([row["defender_machine_id"] for row in findings], ["abc123", "def456"])
        self.assertNotIn("unconfigured-machine", str(filters))

    def test_defender_rejects_21_configured_assets_before_retrieval(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "asset_context.csv"
            source.write_text("defender_machine_id,asset_id,asset_criticality,internet_exposed,owner_team\n" +
                              "".join(f"machine-{i},asset-{i},low,unknown,unknown\n" for i in range(21)))
            context = vulnops.load_asset_context(source)
            with patch.dict(os.environ, {}, clear=True), patch("vulnops.urlopen") as get:
                with self.assertRaisesRegex(ValueError, "V0.8.*pilot.*20 assets.*bulk ingestion.*not yet"):
                    vulnops.load_defender_findings(context)
                get.assert_not_called()

    def test_defender_accepts_20_configured_assets(self):
        context = {f"machine-{i}": {} for i in range(20)}
        responses = [io.BytesIO(b'{"value": []}') for _ in context]
        with patch.dict(os.environ, {"MDE_ACCESS_TOKEN": "controlled-test-token"}):
            with patch("vulnops.urlopen", side_effect=responses) as get:
                self.assertEqual(vulnops.load_defender_findings(context), [])
        self.assertEqual(get.call_count, 20)

    def test_defender_empty_pilot_scope_makes_no_request(self):
        with patch.dict(os.environ, {}, clear=True), patch("vulnops.urlopen") as get:
            self.assertEqual(vulnops.load_defender_findings({}), [])
            get.assert_not_called()

    def test_defender_filter_encodes_reserved_characters_and_escapes_odata_quotes(self):
        machine = "machine' &/+#?"
        with patch.dict(os.environ, {"MDE_ACCESS_TOKEN": "controlled-test-token"}):
            with patch("vulnops.urlopen", return_value=io.BytesIO(b'{"value": []}')) as get:
                self.assertEqual(vulnops.load_defender_findings({machine: {}}), [])
        url = urlparse(get.call_args.args[0].full_url)
        self.assertEqual(url.fragment, "")
        self.assertEqual(parse_qs(url.query), {"$filter": ["machineId eq 'machine'' &/+#?'"], "$top": ["10000"], "$skip": ["0"]})

    def test_defender_rejects_results_outside_requested_machine_even_if_configured(self):
        for returned_machine in ("unconfigured-machine", "def456"):
            with self.subTest(returned_machine=returned_machine):
                payload = {"value": [{"machineId": returned_machine, "cveId": "CVE-2026-1234", "severity": "High"}]}
                with patch.dict(os.environ, {"MDE_ACCESS_TOKEN": "controlled-test-token"}):
                    with patch("vulnops.urlopen", return_value=io.BytesIO(json.dumps(payload).encode())) as get:
                        with self.assertRaisesRegex(ValueError, "outside.*pilot machine scope"):
                            vulnops.load_defender_findings({"abc123": {}, "def456": {}})
                get.assert_called_once()

    def test_defender_loads_one_observation_with_bearer_auth_and_discards_unused_fields(self):
        payload = {"value": [{"machineId": "abc123", "cveId": "CVE-2026-1234", "severity": "Critical",
                              "id": "unused", "fixingKbId": None, "productName": "unused",
                              "productVendor": "unused", "productVersion": "unused"}]}
        with patch.dict(os.environ, {"MDE_ACCESS_TOKEN": "controlled-test-token"}):
            with patch("vulnops.urlopen", return_value=io.BytesIO(json.dumps(payload).encode())) as get:
                self.assertEqual(vulnops.load_defender_findings({"abc123": {}}), [
                    {"defender_machine_id": "abc123", "cve": "CVE-2026-1234", "severity": "critical"}])
        get.assert_called_once()
        request = get.call_args.args[0]
        self.assertEqual(request.full_url.split("?")[0], vulnops.DEFENDER_URL)
        self.assertEqual(parse_qs(urlparse(request.full_url).query), {"$filter": ["machineId eq 'abc123'"], "$top": ["10000"], "$skip": ["0"]})
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.get_header("Authorization"), "Bearer controlled-test-token")
        self.assertEqual(get.call_args.kwargs, {"timeout": 30})

    def test_defender_accepts_empty_value_list(self):
        with patch.dict(os.environ, {"MDE_ACCESS_TOKEN": "controlled-test-token"}):
            with patch("vulnops.urlopen", return_value=io.BytesIO(b'{"value": []}')):
                self.assertEqual(vulnops.load_defender_findings({"abc123": {}}), [])

    def test_defender_rejects_missing_or_blank_token_without_network_request(self):
        for token in (None, "", "   "):
            with self.subTest(token=token), patch.dict(os.environ, {}, clear=True):
                if token is not None:
                    os.environ["MDE_ACCESS_TOKEN"] = token
                with patch("vulnops.urlopen") as get:
                    with self.assertRaisesRegex(ValueError, "non-empty MDE_ACCESS_TOKEN"):
                        vulnops.load_defender_findings({"abc123": {}})
                    get.assert_not_called()

    def test_defender_http_failures_are_clear_and_do_not_expose_token(self):
        cases = [(401, "authentication failure"), (403, "authorization/permission failure"),
                 (429, "rate limiting"), (500, "service failure"), (503, "service failure"),
                 (400, "unexpected HTTP response")]
        token = "controlled-secret-not-for-errors"
        for code, message in cases:
            with self.subTest(code=code), patch.dict(os.environ, {"MDE_ACCESS_TOKEN": token}):
                error = HTTPError(vulnops.DEFENDER_URL, code, token, {}, None)
                with patch("vulnops.urlopen", side_effect=error) as get:
                    with patch("sys.stdout", new_callable=io.StringIO) as stdout:
                        with patch("sys.stderr", new_callable=io.StringIO) as stderr:
                            with self.assertRaisesRegex(ValueError, message) as caught:
                                vulnops.load_defender_findings({"abc123": {}})
                get.assert_called_once()
                self.assertNotIn(token, "".join(traceback.format_exception(caught.exception)))
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(stderr.getvalue(), "")

    def test_defender_network_failure_does_not_return_empty_or_expose_token(self):
        token = "controlled-secret-not-for-errors"
        for error in (URLError(token), TimeoutError(token), ValueError(token)):
            with self.subTest(error_type=type(error)), patch.dict(os.environ, {"MDE_ACCESS_TOKEN": token}):
                with patch("vulnops.urlopen", side_effect=error) as get:
                    with self.assertRaisesRegex(ValueError, "Defender .*failed") as caught:
                        vulnops.load_defender_findings({"abc123": {}})
                get.assert_called_once()
                self.assertNotIn(token, "".join(traceback.format_exception(caught.exception)))

    def test_defender_rejects_invalid_json(self):
        with patch.dict(os.environ, {"MDE_ACCESS_TOKEN": "controlled-test-token"}):
            for body in (b"not json", b"", b"\xff"):
                with self.subTest(body=body), patch("vulnops.urlopen", return_value=io.BytesIO(body)):
                    with self.assertRaisesRegex(ValueError, "invalid JSON"):
                        vulnops.load_defender_findings({"abc123": {}})

    def test_defender_rejects_missing_value_and_invalid_response_shapes(self):
        with patch.dict(os.environ, {"MDE_ACCESS_TOKEN": "controlled-test-token"}):
            for payload in ({}, [], None, {"value": None}, {"value": {}}, {"value": ""}):
                with self.subTest(payload=payload):
                    with patch("vulnops.urlopen", return_value=io.BytesIO(json.dumps(payload).encode())):
                        with self.assertRaisesRegex(ValueError, "Defender response.*value"):
                            vulnops.load_defender_findings({"abc123": {}})

    def test_defender_rejects_malformed_observations_and_unexpected_severity(self):
        valid = {"machineId": "abc123", "cveId": "CVE-2026-1234", "severity": "Critical"}
        entries = [None, {}, {**valid, "severity": "informational"}, {**valid, "cveId": "invalid"}]
        for field in valid:
            entries.extend({**valid, field: value} for value in (None, "", "   ", 1))
        with patch.dict(os.environ, {"MDE_ACCESS_TOKEN": "controlled-test-token"}):
            for entry in entries:
                with self.subTest(entry=entry):
                    body = json.dumps({"value": [valid, entry]}).encode()
                    with patch("vulnops.urlopen", return_value=io.BytesIO(body)):
                        with self.assertRaisesRegex(ValueError, "Defender observation"):
                            vulnops.load_defender_findings({"abc123": {}})

    def test_defender_normalizes_supported_severities_and_cve(self):
        entries = [{"machineId": " abc123 ", "cveId": f" cve-2026-{1234 + index} ", "severity": severity}
                   for index, severity in enumerate(("Critical", "High", "Medium", " Low "))]
        with patch.dict(os.environ, {"MDE_ACCESS_TOKEN": "controlled-test-token"}):
            with patch("vulnops.urlopen", return_value=io.BytesIO(json.dumps({"value": entries}).encode())):
                findings = vulnops.load_defender_findings({"abc123": {}})
        self.assertEqual([row["severity"] for row in findings], ["critical", "high", "medium", "low"])
        for index, row in enumerate(findings):
            self.assertEqual(row["cve"], f"CVE-2026-{1234 + index}")
            self.assertEqual(row["defender_machine_id"], "abc123")

    def test_asset_context_loads_valid_rows_and_preserves_unknown_values(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "asset_context.csv"
            source.write_text("defender_machine_id,asset_id,asset_criticality,internet_exposed,owner_team\n"
                              " abc123 , payments-api-01 , Critical ,true,payments-platform\n"
                              "def456,hr-web-01,medium,false,workplace-it\n"
                              "ghi789,unmapped-team-01,low,unknown,unknown\n"
                              "jkl012,identity-01,high,true,identity\n")
            self.assertEqual(vulnops.load_asset_context(source), {
                "abc123": {"asset_id": "payments-api-01", "asset_criticality": "critical",
                           "internet_exposed": "true", "owner_team": "payments-platform"},
                "def456": {"asset_id": "hr-web-01", "asset_criticality": "medium",
                           "internet_exposed": "false", "owner_team": "workplace-it"},
                "ghi789": {"asset_id": "unmapped-team-01", "asset_criticality": "low",
                           "internet_exposed": "unknown", "owner_team": "unknown"},
                "jkl012": {"asset_id": "identity-01", "asset_criticality": "high",
                           "internet_exposed": "true", "owner_team": "identity"},
            })

    def test_asset_context_rejects_duplicate_machine_or_asset_ids(self):
        cases = [("abc123,other-asset,low,false,identity", "defender_machine_id"),
                 ("abc123,payments-api-01,critical,true,payments-platform", "defender_machine_id"),
                 ("other-machine,payments-api-01,low,false,identity", "asset_id"),
                 (" abc123 , other-asset ,low,false,identity", "defender_machine_id"),
                 ("other-machine, payments-api-01 ,low,false,identity", "asset_id")]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "asset_context.csv"
            for duplicate, field in cases:
                with self.subTest(duplicate=duplicate):
                    source.write_text("defender_machine_id,asset_id,asset_criticality,internet_exposed,owner_team\n"
                                      f"abc123,payments-api-01,critical,true,payments-platform\n{duplicate}\n")
                    with self.assertRaisesRegex(ValueError, f"Duplicate {field}"):
                        vulnops.load_asset_context(source)

    def test_asset_context_rejects_blank_required_fields(self):
        columns = ["defender_machine_id", "asset_id", "asset_criticality", "internet_exposed", "owner_team"]
        values = ["abc123", "payments-api-01", "critical", "true", "payments-platform"]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "asset_context.csv"
            for index, column in enumerate(columns):
                for blank in ("", "   "):
                    with self.subTest(column=column, blank=blank):
                        row = values.copy()
                        row[index] = blank
                        source.write_text(",".join(columns) + "\n" + ",".join(row) + "\n")
                        with self.assertRaisesRegex(ValueError, f"empty {column}"):
                            vulnops.load_asset_context(source)

    def test_asset_context_rejects_invalid_exposure_and_criticality(self):
        cases = [("critical", value, "internet_exposed") for value in ("yes", "maybe", "True", "FALSE")]
        cases += [(value, "true", "asset_criticality") for value in ("unknown", "urgent", "5")]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "asset_context.csv"
            for criticality, exposure, field in cases:
                with self.subTest(criticality=criticality, exposure=exposure):
                    source.write_text("defender_machine_id,asset_id,asset_criticality,internet_exposed,owner_team\n"
                                      f"abc123,payments-api-01,{criticality},{exposure},payments-platform\n")
                    with self.assertRaisesRegex(ValueError, f"invalid {field}"):
                        vulnops.load_asset_context(source)

    def test_asset_context_rejects_missing_duplicate_and_extra_columns(self):
        columns = ["defender_machine_id", "asset_id", "asset_criticality", "internet_exposed", "owner_team"]
        headers = [columns[:index] + columns[index + 1:] for index in range(len(columns))]
        headers += [[], columns + ["extra"], columns[:-1] + ["asset_id"]]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "asset_context.csv"
            for header in headers:
                with self.subTest(header=header):
                    source.write_text(",".join(header) + "\n")
                    with self.assertRaisesRegex(ValueError, "must contain exactly"):
                        vulnops.load_asset_context(source)

    def test_asset_context_rejects_malformed_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "asset_context.csv"
            for row in ("abc123,payments-api-01,critical,true",
                        "abc123,payments-api-01,critical,true,payments-platform,extra"):
                with self.subTest(row=row):
                    source.write_text("defender_machine_id,asset_id,asset_criticality,internet_exposed,owner_team\n"
                                      f"{row}\n")
                    with self.assertRaisesRegex(ValueError, "wrong number of fields"):
                        vulnops.load_asset_context(source)

    def test_asset_context_accepts_header_only_and_reordered_columns(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "asset_context.csv"
            source.write_text("owner_team,internet_exposed,asset_criticality,asset_id,defender_machine_id\n")
            self.assertEqual(vulnops.load_asset_context(source), {})
            with source.open("a") as output:
                output.write("unknown,unknown,low,server,abc123\n")
            self.assertEqual(vulnops.load_asset_context(source), {
                "abc123": {"asset_id": "server", "asset_criticality": "low",
                           "internet_exposed": "unknown", "owner_team": "unknown"}})

    def test_apply_verification_status_derives_four_outcomes_and_preserves_fields(self):
        fields = {"cve": "CVE-2026-1234", "criticality": "critical", "asset_criticality": "critical",
                  "severity": "high", "internet_exposed": "false", "owner_team": "payments-platform",
                  "kev": "true", "epss_score": 0.01, "epss_percentile": 0.1, "priority": "P0",
                  "reason": "Rule 1: CVE is in CISA KEV and asset criticality is critical."}
        findings = [{**fields, "asset_id": asset, "remediation_status": remediation}
                    for asset, remediation in (("A", "open"), ("B", "resolved"), ("C", "resolved"), ("D", "resolved"))]
        verification_results = {("C", "CVE-2026-1234"): True, ("D", "CVE-2026-1234"): False}
        originals = [finding.copy() for finding in findings]
        original_evidence = verification_results.copy()

        results = vulnops.apply_verification_status(findings, verification_results)

        self.assertEqual([row["asset_id"] for row in results], ["A", "B", "C", "D"])
        for finding, result, expected in zip(findings, results, ("not_applicable", "unverified", "failed", "passed")):
            with self.subTest(asset_id=finding["asset_id"]):
                self.assertEqual(result, {**finding, "verification_status": expected})
                self.assertEqual(set(result) - set(finding), {"verification_status"})
                self.assertIsNot(result, finding)
        self.assertEqual(findings, originals)
        self.assertEqual(verification_results, original_evidence)
        self.assertEqual(vulnops.apply_verification_status([], verification_results), [])

    def test_identical_kev_critical_finding_stays_p0_for_all_verification_outcomes(self):
        cases = [("A", "open", None, "not_applicable", True),
                 ("B", "resolved", None, "unverified", True),
                 ("C", "resolved", True, "failed", True),
                 ("D", "resolved", False, "passed", False)]
        cve = "CVE-2026-1234"
        key = ("critical-server", cve)
        epss = {cve: {"epss_score": 0.01, "epss_percentile": 0.1}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir()
            (root / "state").mkdir()
            input_path = root / "data" / "finding_fixture.csv"
            input_path.write_text("asset_id,criticality,cve,internet_exposed,owner_team\n"
                                  "critical-server,critical,CVE-2026-1234,false,payments-platform\n")
            baseline = vulnops.prioritize(vulnops.enrich_with_epss(self.read_fixture_findings(input_path), epss), {cve})[0]
            self.assertEqual(baseline["priority"], "P0")
            for case, remediation, present, verification, active in cases:
                with self.subTest(case=case):
                    state_path = root / "state" / "remediation_status.csv"
                    evidence_path = root / "data" / "verification_results.csv"
                    state_path.write_text(f"asset_id,cve,remediation_status\ncritical-server,{cve},{remediation}\n")
                    evidence_path.write_text("asset_id,cve,vulnerability_present\n" +
                                             ("" if present is None else f"critical-server,{cve},{str(present).lower()}\n"))
                    findings = vulnops.apply_remediation_status(self.read_fixture_findings(input_path),
                                                                vulnops.load_remediation_statuses(state_path))
                    findings = vulnops.apply_verification_status(findings, vulnops.load_verification_results(evidence_path))
                    findings = vulnops.enrich_with_epss(findings, epss)

                    # Classification is tested before queue filtering, including passed case D.
                    result = vulnops.prioritize(findings, {cve})[0]

                    self.assertEqual(result["priority"], "P0")
                    self.assertEqual(result["remediation_status"], remediation)
                    self.assertEqual(result["verification_status"], verification)
                    self.assertEqual({field: result[field] for field in baseline}, baseline)
                    with patch("vulnops.ROOT", root), patch("vulnops.load_kev", return_value={cve}):
                        with patch("vulnops.load_epss", return_value=epss), patch("sys.stdout", new_callable=io.StringIO):
                            self.assertEqual(self.run_fixture_main(), 0)
                    with (root / "output" / "remediation_queue.csv").open(newline="") as output:
                        rows = list(csv.DictReader(output))
                    self.assertEqual(len(rows), 1 if active else 0)
                    if active:
                        self.assertEqual(rows[0]["priority"], "P0")
                        self.assertEqual(rows[0]["reason"], baseline["reason"])
                    self.assertEqual(vulnops.load_remediation_statuses(state_path)[key], remediation)

    def test_open_finding_never_infers_verification_success_or_failure(self):
        finding = {"asset_id": "A", "cve": "CVE-2026-1234", "remediation_status": "open"}
        for present in (True, False):
            with self.subTest(vulnerability_present=present):
                results = vulnops.apply_verification_status([finding], {("A", "CVE-2026-1234"): present})
                self.assertEqual(results, [{**finding, "verification_status": "not_applicable"}])

    def test_apply_verification_status_rejects_unsupported_cases(self):
        finding = {"asset_id": "A", "cve": "CVE-2026-1234", "remediation_status": "resolved"}
        with self.assertRaisesRegex(ValueError, "Invalid remediation_status"):
            vulnops.apply_verification_status([{**finding, "remediation_status": "closed"}], {})
        for invalid in (None, "false", 0, 1):
            with self.subTest(evidence=invalid):
                with self.assertRaisesRegex(ValueError, "expected a boolean"):
                    vulnops.apply_verification_status([finding], {("A", "CVE-2026-1234"): invalid})

    def test_verification_results_load_true_and_false_as_booleans(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "verification_results.csv"
            source.write_text("asset_id,cve,vulnerability_present\n"
                              "payments-api-01,CVE-2026-1234,false\n"
                              "hr-web-01,CVE-2026-1234,true\n")
            results = vulnops.load_verification_results(source)
            self.assertEqual(set(results), {("payments-api-01", "CVE-2026-1234"), ("hr-web-01", "CVE-2026-1234")})
            self.assertIs(results[("payments-api-01", "CVE-2026-1234")], False)
            self.assertIs(results[("hr-web-01", "CVE-2026-1234")], True)

    def test_verification_results_reject_blank_fields_and_invalid_values(self):
        rows = [",CVE-2026-1234,true", "server,,false", "server,CVE-2026-1234,",
                "server,CVE-2026-1234,   ", "server,CVE-2026-1234,unknown",
                "server,CVE-2026-1234,yes", "server,CVE-2026-1234,True",
                "server,CVE-2026-1234,FALSE", "server,CVE-2026-1234,0"]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "verification_results.csv"
            for row in rows:
                with self.subTest(row=row):
                    source.write_text(f"asset_id,cve,vulnerability_present\n{row}\n")
                    with self.assertRaisesRegex(ValueError, "Verification record.*(empty|invalid)"):
                        vulnops.load_verification_results(source)

    def test_verification_results_reject_duplicate_keys_even_after_false(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "verification_results.csv"
            for duplicate in ("server,CVE-2026-1234,false", "server,CVE-2026-1234,true",
                              " server , cve-2026-1234 ,true"):
                with self.subTest(duplicate=duplicate):
                    source.write_text("asset_id,cve,vulnerability_present\n"
                                      f"server,CVE-2026-1234,false\n{duplicate}\n")
                    with self.assertRaisesRegex(ValueError, "Duplicate verification result.*server.*CVE-2026-1234"):
                        vulnops.load_verification_results(source)

    def test_verification_results_reject_missing_or_invalid_columns(self):
        headers = ["", "cve,vulnerability_present", "asset_id,vulnerability_present", "asset_id,cve",
                   "asset_id,cve,cve", "asset_id,cve,vulnerability_present,extra"]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "verification_results.csv"
            for header in headers:
                with self.subTest(header=header):
                    source.write_text(header + "\n")
                    with self.assertRaisesRegex(ValueError, "must contain exactly"):
                        vulnops.load_verification_results(source)

    def test_verification_results_reject_malformed_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "verification_results.csv"
            for row in ("server,CVE-2026-1234", "server,CVE-2026-1234,false,extra"):
                with self.subTest(row=row):
                    source.write_text(f"asset_id,cve,vulnerability_present\n{row}\n")
                    with self.assertRaisesRegex(ValueError, "wrong number of fields"):
                        vulnops.load_verification_results(source)

    def test_verification_results_accept_empty_evidence_and_normalize_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "verification_results.csv"
            source.write_text("vulnerability_present,cve,asset_id\n")
            self.assertEqual(vulnops.load_verification_results(source), {})
            source.write_text("vulnerability_present,cve,asset_id\nfalse, cve-2026-1234 , server \n")
            self.assertEqual(vulnops.load_verification_results(source), {("server", "CVE-2026-1234"): False})

    def test_remediation_statuses_accept_open_and_resolved_for_separate_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "remediation_status.csv"
            source.write_text("asset_id,cve,remediation_status\n"
                              "payments-api-01,CVE-2026-1234,resolved\n"
                              "hr-web-01,CVE-2026-1234,open\n")
            self.assertEqual(vulnops.load_remediation_statuses(source), {
                ("payments-api-01", "CVE-2026-1234"): "resolved",
                ("hr-web-01", "CVE-2026-1234"): "open",
            })

    def test_remediation_statuses_reject_blank_fields_and_invalid_status(self):
        rows = [",CVE-2026-1234,open", "server,,open", "server,CVE-2026-1234,",
                "server,CVE-2026-1234,   ", "server,CVE-2026-1234,closed",
                "server,CVE-2026-1234,Open"]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "remediation_status.csv"
            for row in rows:
                with self.subTest(row=row):
                    source.write_text(f"asset_id,cve,remediation_status\n{row}\n")
                    with self.assertRaisesRegex(ValueError, "Remediation state.*(empty|invalid)"):
                        vulnops.load_remediation_statuses(source)

    def test_remediation_statuses_reject_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "remediation_status.csv"
            for duplicate in ("server,CVE-2026-1234,open", "server,CVE-2026-1234,resolved",
                              " server , cve-2026-1234 ,resolved"):
                with self.subTest(duplicate=duplicate):
                    source.write_text("asset_id,cve,remediation_status\n"
                                      f"server,CVE-2026-1234,open\n{duplicate}\n")
                    with self.assertRaisesRegex(ValueError, "Duplicate remediation state.*server.*CVE-2026-1234"):
                        vulnops.load_remediation_statuses(source)

    def test_remediation_statuses_reject_missing_or_invalid_columns(self):
        headers = ["", "cve,remediation_status", "asset_id,remediation_status", "asset_id,cve",
                   "asset_id,cve,cve", "asset_id,cve,remediation_status,extra"]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "remediation_status.csv"
            for header in headers:
                with self.subTest(header=header):
                    source.write_text(header + "\n")
                    with self.assertRaisesRegex(ValueError, "must contain exactly"):
                        vulnops.load_remediation_statuses(source)

    def test_remediation_statuses_reject_malformed_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "remediation_status.csv"
            for row in ("server,CVE-2026-1234", "server,CVE-2026-1234,open,extra"):
                with self.subTest(row=row):
                    source.write_text(f"asset_id,cve,remediation_status\n{row}\n")
                    with self.assertRaisesRegex(ValueError, "wrong number of fields"):
                        vulnops.load_remediation_statuses(source)

    def test_remediation_statuses_accept_empty_state_and_normalize_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "remediation_status.csv"
            source.write_text("remediation_status,cve,asset_id\n")
            self.assertEqual(vulnops.load_remediation_statuses(source), {})
            source.write_text("remediation_status,cve,asset_id\n open , cve-2026-1234 , server \n")
            self.assertEqual(vulnops.load_remediation_statuses(source), {("server", "CVE-2026-1234"): "open"})

    def test_apply_remediation_status_defaults_open_and_preserves_existing_fields(self):
        fields = {"criticality": "critical", "asset_criticality": "critical", "severity": "high",
                  "internet_exposed": "true", "owner_team": "payments-platform", "kev": "true",
                  "epss_score": 0.99, "epss_percentile": 0.999, "priority": "P0",
                  "reason": "Rule 1: CVE is in CISA KEV and asset criticality is critical."}
        findings = [
            {**fields, "asset_id": "A", "cve": "CVE-2026-1234"},
            {**fields, "asset_id": "B", "cve": "CVE-2026-1234"},
            {**fields, "asset_id": "C", "cve": "CVE-2026-1234"},
            {**fields, "asset_id": "B", "cve": "CVE-2026-5678"},
        ]
        originals = [finding.copy() for finding in findings]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "remediation_status.csv"
            source.write_text("asset_id,cve,remediation_status\n"
                              "A,CVE-2026-1234,open\n"
                              "B,CVE-2026-1234,resolved\n")
            statuses = vulnops.load_remediation_statuses(source)
        original_statuses = statuses.copy()

        results = vulnops.apply_remediation_status(findings, statuses)

        self.assertEqual([row["remediation_status"] for row in results], ["open", "resolved", "open", "open"])
        for original, finding, result in zip(originals, findings, results):
            with self.subTest(asset_id=finding["asset_id"], cve=finding["cve"]):
                self.assertEqual({key: result[key] for key in original}, original)
                self.assertEqual(set(result) - set(original), {"remediation_status"})
                self.assertIsNot(result, finding)
        self.assertEqual(findings, originals)
        self.assertEqual(statuses, original_statuses)
        self.assertEqual(vulnops.apply_remediation_status([], statuses), [])

    def test_failed_verification_keeps_resolved_payments_p0_active_without_rewriting_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir()
            (root / "state").mkdir()
            (root / "data" / "finding_fixture.csv").write_text(
                "asset_id,criticality,cve,internet_exposed,owner_team\n"
                "payments-api-01,critical,CVE-2026-1234,false,payments-platform\n")
            state_path = root / "state" / "remediation_status.csv"
            state_path.write_text("asset_id,cve,remediation_status\npayments-api-01,CVE-2026-1234,resolved\n")
            evidence_path = root / "data" / "verification_results.csv"
            evidence_path.write_text("asset_id,cve,vulnerability_present\npayments-api-01,CVE-2026-1234,true\n")
            original_state = state_path.read_bytes()
            original_evidence = evidence_path.read_bytes()
            kev = {"vulnerabilities": [{"cveID": "CVE-2026-1234"}]}
            epss = {"status": "OK", "status-code": 200, "total": 1, "data": [
                {"cve": "CVE-2026-1234", "epss": "0.01", "percentile": "0.1"},
            ]}
            responses = [io.BytesIO(json.dumps(feed).encode()) for feed in (kev, epss)]
            with patch("vulnops.ROOT", root), patch("vulnops.urlopen", side_effect=responses):
                with patch("vulnops.write_queue", wraps=vulnops.write_queue) as write:
                    with patch("sys.stdout", new_callable=io.StringIO):
                        self.assertEqual(self.run_fixture_main(), 0)
            queue = write.call_args.args[1]
            self.assertEqual(len(queue), 1)
            finding = queue[0]
            self.assertEqual(finding["asset_id"], "payments-api-01")
            self.assertEqual(finding["remediation_status"], "resolved")
            self.assertEqual(finding["verification_status"], "failed")
            self.assertEqual(finding["priority"], "P0")
            with (root / "output" / "remediation_queue.csv").open(newline="") as output:
                rows = list(csv.DictReader(output))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["asset_id"], "payments-api-01")
            self.assertEqual(rows[0]["remediation_status"], "resolved")
            self.assertEqual(rows[0]["priority"], "P0")
            self.assertEqual(rows[0]["reason"], "Rule 1: CVE is in CISA KEV and asset criticality is critical.")
            self.assertEqual(state_path.read_bytes(), original_state)
            self.assertEqual(evidence_path.read_bytes(), original_evidence)
            self.assertEqual(vulnops.load_remediation_statuses(state_path)[("payments-api-01", "CVE-2026-1234")], "resolved")

    def test_successful_verification_excludes_payments_finding_without_deleting_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir()
            (root / "state").mkdir()
            input_path = root / "data" / "finding_fixture.csv"
            state_path = root / "state" / "remediation_status.csv"
            evidence_path = root / "data" / "verification_results.csv"
            input_path.write_text("asset_id,criticality,cve,internet_exposed,owner_team\n"
                                  "payments-api-01,critical,CVE-2026-1234,false,payments-platform\n")
            state_path.write_text("asset_id,cve,remediation_status\npayments-api-01,CVE-2026-1234,resolved\n")
            evidence_path.write_text("asset_id,cve,vulnerability_present\npayments-api-01,CVE-2026-1234,false\n")
            original_inputs = {path: path.read_bytes() for path in (input_path, state_path, evidence_path)}
            kev_cves = {"CVE-2026-1234"}
            baseline = vulnops.prioritize(self.read_fixture_findings(input_path), kev_cves)[0]
            kev = io.BytesIO(b'{"vulnerabilities": [{"cveID": "CVE-2026-1234"}]}')
            with patch("vulnops.ROOT", root), patch("vulnops.urlopen", return_value=kev):
                with patch("vulnops.apply_verification_status", wraps=vulnops.apply_verification_status) as verify:
                    with patch("vulnops.load_epss", wraps=vulnops.load_epss) as epss:
                        with patch("vulnops.prioritize", wraps=vulnops.prioritize) as classify:
                            with patch("sys.stdout", new_callable=io.StringIO):
                                self.assertEqual(self.run_fixture_main(), 0)
            verify.assert_called_once()
            derived = vulnops.apply_verification_status(*verify.call_args.args)
            self.assertEqual(len(derived), 1)
            self.assertEqual(derived[0]["remediation_status"], "resolved")
            self.assertEqual(derived[0]["verification_status"], "passed")
            # Closure removes queue membership; it does not downgrade the underlying risk class.
            classified = vulnops.prioritize(derived, kev_cves)[0]
            self.assertEqual(classified["priority"], "P0")
            self.assertEqual({field: classified[field] for field in baseline}, baseline)
            classify.assert_called_once_with([], kev_cves)
            epss.assert_called_once_with([])
            with (root / "output" / "remediation_queue.csv").open(newline="") as output:
                self.assertEqual(list(csv.DictReader(output)), [])
            self.assertEqual({path: path.read_bytes() for path in original_inputs}, original_inputs)
            self.assertEqual(len(self.read_fixture_findings(input_path)), 1)
            key = ("payments-api-01", "CVE-2026-1234")
            self.assertEqual(vulnops.load_remediation_statuses(state_path)[key], "resolved")
            self.assertIs(vulnops.load_verification_results(evidence_path)[key], False)

    def test_one_finding_completes_v07_verification_control_loop(self):
        phases = [("discovery", None, None, "open", "not_applicable", True),
                  ("remediation claim", "resolved", None, "resolved", "unverified", True),
                  ("failed verification", "resolved", "true", "resolved", "failed", True),
                  ("successful verification", "resolved", "false", "resolved", "passed", False)]
        cve = "CVE-2026-1234"
        epss = {cve: {"epss_score": 0.9, "epss_percentile": 0.98}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir()
            (root / "state").mkdir()
            input_path = root / "data" / "finding_fixture.csv"
            state_path = root / "state" / "remediation_status.csv"
            evidence_path = root / "data" / "verification_results.csv"
            input_path.write_text("asset_id,criticality,cve,internet_exposed,owner_team\n"
                                  f"payments-api-01,critical,{cve},true,payments-platform\n")
            original_input = input_path.read_bytes()
            baseline = vulnops.prioritize(
                vulnops.enrich_with_epss(self.read_fixture_findings(input_path), epss), set())[0]
            self.assertEqual(baseline["priority"], "P2")
            for phase, claim, evidence, status, verification, active in phases:
                with self.subTest(phase=phase):
                    state_path.write_text("asset_id,cve,remediation_status\n" +
                                          (f"payments-api-01,{cve},{claim}\n" if claim else ""))
                    evidence_path.write_text("asset_id,cve,vulnerability_present\n" +
                                             (f"payments-api-01,{cve},{evidence}\n" if evidence else ""))
                    originals = {path: path.read_bytes() for path in (state_path, evidence_path)}
                    with patch("vulnops.ROOT", root), patch("vulnops.load_kev", return_value=set()):
                        with patch("vulnops.load_epss", return_value=epss):
                            with patch("vulnops.apply_verification_status", wraps=vulnops.apply_verification_status) as verify:
                                with patch("vulnops.write_queue", wraps=vulnops.write_queue) as write:
                                    with patch("sys.stdout", new_callable=io.StringIO):
                                        self.assertEqual(self.run_fixture_main(), 0)
                    derived = vulnops.apply_verification_status(*verify.call_args.args)
                    self.assertEqual(len(derived), 1)
                    self.assertEqual(derived[0]["remediation_status"], status)
                    self.assertEqual(derived[0]["verification_status"], verification)
                    # Closure affects membership, not the finding's underlying classification or context.
                    classified = vulnops.prioritize(vulnops.enrich_with_epss(derived, epss), set())[0]
                    self.assertEqual({field: classified[field] for field in baseline}, baseline)
                    self.assertEqual(write.call_args.args[1], [classified] if active else [])
                    with (root / "output" / "remediation_queue.csv").open(newline="") as output:
                        rows = list(csv.DictReader(output))
                    self.assertEqual(len(rows), int(active))
                    if active:
                        self.assertEqual(rows[0]["cve"], cve)
                        self.assertEqual(rows[0]["priority"], baseline["priority"])
                        self.assertEqual(rows[0]["reason"], baseline["reason"])
                        self.assertEqual(rows[0]["owner_team"], baseline["owner_team"])
                        self.assertEqual(rows[0]["remediation_status"], status)
                    self.assertEqual(input_path.read_bytes(), original_input)
                    self.assertEqual({path: path.read_bytes() for path in originals}, originals)

    def test_premature_closure_without_verification_keeps_finding_active_and_rank_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir()
            (root / "state").mkdir()
            input_path = root / "data" / "finding_fixture.csv"
            state_path = root / "state" / "remediation_status.csv"
            evidence_path = root / "data" / "verification_results.csv"
            input_path.write_text(
                "asset_id,criticality,cve,internet_exposed,owner_team\n"
                "payments-api-01,critical,CVE-2026-1234,true,payments-platform\n"
                "lower-score,critical,CVE-2026-1235,true,identity\n"
                "higher-score,critical,CVE-2026-1236,true,data-platform\n")
            evidence_path.write_text("asset_id,cve,vulnerability_present\n")
            original_evidence = evidence_path.read_bytes()
            original_findings = input_path.read_bytes()
            epss = {cve: {"epss_score": score, "epss_percentile": 0.9}
                    for cve, score in (("CVE-2026-1234", 0.5), ("CVE-2026-1235", 0.1),
                                       ("CVE-2026-1236", 0.9))}
            queues = {}
            for status in ("open", "resolved"):
                with self.subTest(remediation_status=status):
                    state_path.write_text("asset_id,cve,remediation_status\n"
                                          f"payments-api-01,CVE-2026-1234,{status}\n")
                    original_state = state_path.read_bytes()
                    with patch("vulnops.ROOT", root), patch("vulnops.load_kev", return_value=set()):
                        with patch("vulnops.load_epss", return_value=epss):
                            with patch("vulnops.write_queue", wraps=vulnops.write_queue) as write:
                                with patch("sys.stdout", new_callable=io.StringIO):
                                    self.assertEqual(self.run_fixture_main(), 0)
                    internal = write.call_args.args[1]
                    target = next(row for row in internal if row["asset_id"] == "payments-api-01")
                    self.assertEqual(target["remediation_status"], status)
                    self.assertEqual(target["verification_status"],
                                     "unverified" if status == "resolved" else "not_applicable")
                    with (root / "output" / "remediation_queue.csv").open(newline="") as output:
                        queues[status] = list(csv.DictReader(output))
                    self.assertEqual([row["asset_id"] for row in queues[status]],
                                     ["higher-score", "payments-api-01", "lower-score"])
                    target_output = queues[status][1]
                    self.assertEqual(target_output["remediation_status"], status)
                    self.assertEqual(target_output["priority"], "P2")
                    self.assertEqual(target_output["owner_team"], "payments-platform")
                    self.assertEqual(target_output["reason"], "Rule 3: CVE is not in CISA KEV.")
                    self.assertEqual(state_path.read_bytes(), original_state)
                    self.assertEqual(evidence_path.read_bytes(), original_evidence)
                    self.assertEqual(input_path.read_bytes(), original_findings)
                    self.assertEqual(vulnops.load_verification_results(evidence_path), {})
            # Changing only the operator claim preserves every other output field and row position.
            for before, after in zip(queues["open"], queues["resolved"]):
                self.assertEqual({key: value for key, value in before.items() if key != "remediation_status"},
                                 {key: value for key, value in after.items() if key != "remediation_status"})

    def test_active_queue_excludes_only_resolved_findings_with_passed_verification(self):
        source = ("asset_id,criticality,cve,internet_exposed,owner_team\n"
                  "D,critical,CVE-2026-1234,true,payments-platform\n"
                  "C,critical,CVE-2026-5678,true,payments-platform\n"
                  "B,medium,CVE-2026-1234,false,payments-platform\n"
                  "A,critical,CVE-2026-1234,false,payments-platform\n")
        state = ("asset_id,cve,remediation_status\n"
                 "A,CVE-2026-1234,open\nB,CVE-2026-1234,resolved\n"
                 "C,CVE-2026-5678,resolved\nD,CVE-2026-1234,resolved\n")
        evidence = ("asset_id,cve,vulnerability_present\n"
                    "A,CVE-2026-1234,false\nC,CVE-2026-5678,true\nD,CVE-2026-1234,false\n")
        epss = {"CVE-2026-1234": {"epss_score": 0.01, "epss_percentile": 0.1},
                "CVE-2026-5678": {"epss_score": 0.99, "epss_percentile": 0.999}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir()
            (root / "state").mkdir()
            paths = {root / "data" / "finding_fixture.csv": source,
                     root / "state" / "remediation_status.csv": state,
                     root / "data" / "verification_results.csv": evidence}
            for path, content in paths.items():
                path.write_text(content)
            original_inputs = {path: path.read_bytes() for path in paths}
            outputs = []
            for run in range(2):
                with self.subTest(run=run + 1):
                    with patch("vulnops.ROOT", root), patch("vulnops.load_kev", return_value={"CVE-2026-1234"}):
                        with patch("vulnops.load_epss", return_value=epss):
                            with patch("vulnops.prioritize", wraps=vulnops.prioritize) as classify:
                                with patch("sys.stdout", new_callable=io.StringIO):
                                    self.assertEqual(self.run_fixture_main(), 0)
                    active = classify.call_args.args[0]
                    self.assertEqual({row["asset_id"]: (row["remediation_status"], row["verification_status"])
                                      for row in active}, {
                        "A": ("open", "not_applicable"),
                        "B": ("resolved", "unverified"),
                        "C": ("resolved", "failed"),
                    })
                    output_path = root / "output" / "remediation_queue.csv"
                    with output_path.open(newline="") as output:
                        reader = csv.DictReader(output)
                        self.assertEqual(reader.fieldnames, ["asset_id", "criticality", "cve", "internet_exposed", "owner_team",
                                                            "kev", "epss_score", "epss_percentile", "priority", "reason", "remediation_status"])
                        rows = list(reader)
                    self.assertEqual([row["asset_id"] for row in rows], ["A", "B", "C"])
                    self.assertEqual([row["priority"] for row in rows], ["P0", "P1", "P2"])
                    self.assertEqual([row["remediation_status"] for row in rows], ["open", "resolved", "resolved"])
                    self.assertEqual({path: path.read_bytes() for path in paths}, original_inputs)
                    self.assertEqual(list(output_path.parent.iterdir()), [output_path])
                    outputs.append(output_path.read_bytes())
            self.assertEqual(outputs[0], outputs[1])

    def test_active_queue_keeps_open_and_unrecorded_findings_but_excludes_verified_resolved(self):
        source = ("asset_id,criticality,cve,internet_exposed,owner_team\n"
                  "B,critical,CVE-2026-1234,true,payments-platform\n"
                  "A,critical,CVE-2026-1234,true,payments-platform\n"
                  "C,medium,CVE-2026-1234,true,unknown\n")
        state = ("asset_id,cve,remediation_status\n"
                 "A,CVE-2026-1234,open\n"
                 "B,CVE-2026-1234,resolved\n")
        kev = {"vulnerabilities": [{"cveID": "CVE-2026-1234"}]}
        epss = {"status": "OK", "status-code": 200, "total": 1, "data": [
            {"cve": "CVE-2026-1234", "epss": "0.5", "percentile": "0.9"},
        ]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir(exist_ok=True)
            (root / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\n")
            (root / "data").mkdir(exist_ok=True)
            (root / "state").mkdir()
            input_path = root / "data" / "finding_fixture.csv"
            state_path = root / "state" / "remediation_status.csv"
            input_path.write_text(source)
            state_path.write_text(state)
            (root / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\nB,CVE-2026-1234,false\n")
            original_state = state_path.read_bytes()
            original_findings = input_path.read_bytes()
            outputs = []
            for run in range(2):
                with self.subTest(run=run + 1):
                    responses = [io.BytesIO(json.dumps(feed).encode()) for feed in (kev, epss)]
                    with patch("vulnops.ROOT", root), patch("vulnops.urlopen", side_effect=responses):
                        with patch("vulnops.prioritize", wraps=vulnops.prioritize) as classify:
                            with patch("sys.stdout", new_callable=io.StringIO):
                                self.assertEqual(self.run_fixture_main(), 0)
                    before_classification = classify.call_args.args[0]
                    self.assertEqual([row["asset_id"] for row in before_classification], ["A", "C"])
                    self.assertTrue(all(row["remediation_status"] == "open" for row in before_classification))
                    self.assertTrue(all("priority" not in row for row in before_classification))
                    output_path = root / "output" / "remediation_queue.csv"
                    with output_path.open(newline="") as output:
                        reader = csv.DictReader(output)
                        self.assertEqual(reader.fieldnames, ["asset_id", "criticality", "cve", "internet_exposed", "owner_team",
                                                            "kev", "epss_score", "epss_percentile", "priority", "reason", "remediation_status"])
                        rows = list(reader)
                    self.assertEqual([row["asset_id"] for row in rows], ["A", "C"])
                    self.assertEqual([row["priority"] for row in rows], ["P0", "P1"])
                    self.assertEqual([row["remediation_status"] for row in rows], ["open", "open"])
                    self.assertEqual(list(output_path.parent.iterdir()), [output_path])
                    self.assertEqual(state_path.read_bytes(), original_state)
                    self.assertEqual(input_path.read_bytes(), original_findings)
                    self.assertEqual(vulnops.load_remediation_statuses(state_path)[("B", "CVE-2026-1234")], "resolved")
                    outputs.append(output_path.read_bytes())
            self.assertEqual(outputs[0], outputs[1])

    def test_active_queue_is_header_only_when_every_finding_is_verified_resolved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir(exist_ok=True)
            (root / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\n")
            (root / "data").mkdir(exist_ok=True)
            (root / "state").mkdir()
            (root / "data" / "finding_fixture.csv").write_text(
                "asset_id,criticality,cve,internet_exposed,owner_team\n"
                "B,critical,CVE-2026-1234,true,unknown\n")
            state_path = root / "state" / "remediation_status.csv"
            state_path.write_text("asset_id,cve,remediation_status\nB,CVE-2026-1234,resolved\n")
            (root / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\nB,CVE-2026-1234,false\n")
            original_state = state_path.read_bytes()
            with patch("vulnops.ROOT", root), patch("vulnops.load_kev", return_value={"CVE-2026-1234"}):
                with patch("vulnops.load_epss", wraps=vulnops.load_epss) as epss:
                    with patch("vulnops.urlopen") as request, patch("sys.stdout", new_callable=io.StringIO):
                        self.assertEqual(self.run_fixture_main(), 0)
            epss.assert_called_once_with([])
            request.assert_not_called()
            with (root / "output" / "remediation_queue.csv").open(newline="") as output:
                self.assertEqual(list(csv.DictReader(output)), [])
            self.assertEqual(state_path.read_bytes(), original_state)

    def test_remediation_status_cannot_change_risk_classification(self):
        source = ("asset_id,criticality,cve,internet_exposed,owner_team\n"
                  "A,critical,CVE-2026-1234,false,payments-platform\n"
                  "B,critical,CVE-2026-1234,false,payments-platform\n"
                  "C,critical,CVE-2026-5678,true,payments-platform\n"
                  "D,critical,CVE-2026-5678,true,payments-platform\n")
        state = ("asset_id,cve,remediation_status\n"
                 "A,CVE-2026-1234,open\nB,CVE-2026-1234,resolved\n"
                 "C,CVE-2026-5678,open\nD,CVE-2026-5678,resolved\n")
        kev_cves = {"CVE-2026-1234"}
        epss = {"CVE-2026-1234": {"epss_score": 0.01, "epss_percentile": None},
                "CVE-2026-5678": {"epss_score": 0.99, "epss_percentile": None}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir(exist_ok=True)
            (root / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\n")
            (root / "data").mkdir(exist_ok=True)
            (root / "state").mkdir()
            input_path = root / "data" / "finding_fixture.csv"
            state_path = root / "state" / "remediation_status.csv"
            input_path.write_text(source)
            state_path.write_text(state)
            (root / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\nB,CVE-2026-1234,false\nD,CVE-2026-5678,false\n")
            original_state = state_path.read_bytes()
            findings = self.read_fixture_findings(input_path)
            findings = vulnops.apply_remediation_status(findings, vulnops.load_remediation_statuses(state_path))
            findings = vulnops.enrich_with_epss(findings, epss)

            # Classify all four directly to test policy independently of lifecycle filtering.
            classified = vulnops.prioritize(findings, kev_cves)

            self.assertEqual([(row["asset_id"], row["priority"], row["remediation_status"]) for row in classified], [
                ("A", "P0", "open"), ("B", "P0", "resolved"),
                ("C", "P2", "open"), ("D", "P2", "resolved"),
            ])
            by_asset = {row["asset_id"]: row for row in classified}
            self.assertEqual(by_asset["A"]["reason"], by_asset["B"]["reason"])
            self.assertEqual(by_asset["C"]["reason"], by_asset["D"]["reason"])
            with patch("vulnops.ROOT", root), patch("vulnops.load_kev", return_value=kev_cves):
                with patch("vulnops.load_epss", return_value=epss):
                    with patch("vulnops.prioritize", wraps=vulnops.prioritize) as classify:
                        with patch("sys.stdout", new_callable=io.StringIO):
                            self.assertEqual(self.run_fixture_main(), 0)
            self.assertEqual([row["asset_id"] for row in classify.call_args.args[0]], ["A", "C"])
            with (root / "output" / "remediation_queue.csv").open(newline="") as output:
                rows = list(csv.DictReader(output))
            self.assertEqual([(row["asset_id"], row["priority"]) for row in rows], [("A", "P0"), ("C", "P2")])
            for row in rows:
                self.assertEqual(row["reason"], by_asset[row["asset_id"]]["reason"])
            self.assertEqual(state_path.read_bytes(), original_state)

    def test_verified_resolved_findings_do_not_change_active_p0_p1_or_p2_order(self):
        source = ("asset_id,criticality,cve,internet_exposed,owner_team\n"
                  "C,critical,CVE-2026-10002,false,payments-platform\n"
                  "p0-first,critical,CVE-2026-10003,false,payments-platform\n"
                  "p1-first,medium,CVE-2026-10003,false,payments-platform\n"
                  "B,critical,CVE-2026-10002,unknown,payments-platform\n"
                  "p0-second,critical,CVE-2026-10004,true,payments-platform\n"
                  "p1-second,medium,CVE-2026-10004,true,payments-platform\n"
                  "A,critical,CVE-2026-10001,true,payments-platform\n")
        resolved = "D,critical,CVE-2026-10005,true,payments-platform\n"
        epss = {cve: {"epss_score": score, "epss_percentile": None} for cve, score in (
            ("CVE-2026-10001", 0.10), ("CVE-2026-10002", 0.99),
            ("CVE-2026-10003", 0.01), ("CVE-2026-10004", 0.99), ("CVE-2026-10005", 0.99),
        )}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir(exist_ok=True)
            (root / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\n")
            (root / "data").mkdir(exist_ok=True)
            (root / "state").mkdir()
            input_path = root / "data" / "finding_fixture.csv"
            input_path.write_text(source)
            findings = self.read_fixture_findings(input_path)
            state_path = root / "state" / "remediation_status.csv"
            state_path.write_text("asset_id,cve,remediation_status\n" +
                                  "".join(f"{row['asset_id']},{row['cve']},open\n" for row in findings) +
                                  "D,CVE-2026-10005,resolved\n")
            (root / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\nD,CVE-2026-10005,false\n")
            original_state = state_path.read_bytes()
            outputs = []
            for include_resolved in (False, True):
                with self.subTest(include_resolved=include_resolved):
                    # Insert D ahead of every other finding; it must be filtered, not ranked.
                    header, body = source.split("\n", 1)
                    input_path.write_text(header + "\n" + (resolved if include_resolved else "") + body)
                    with patch("vulnops.ROOT", root), patch("vulnops.load_kev", return_value={"CVE-2026-10003", "CVE-2026-10004"}):
                        with patch("vulnops.load_epss", return_value=epss):
                            with patch("vulnops.prioritize", wraps=vulnops.prioritize) as classify:
                                with patch("sys.stdout", new_callable=io.StringIO):
                                    self.assertEqual(self.run_fixture_main(), 0)
                    self.assertNotIn("D", [row["asset_id"] for row in classify.call_args.args[0]])
                    with (root / "output" / "remediation_queue.csv").open(newline="") as output:
                        rows = list(csv.DictReader(output))
                    for priority, expected in (("P0", ["p0-first", "p0-second"]),
                                               ("P1", ["p1-first", "p1-second"]), ("P2", ["A", "B", "C"])):
                        self.assertEqual([row["asset_id"] for row in rows if row["priority"] == priority], expected)
                    self.assertEqual([row["asset_id"] for row in rows],
                                     ["p0-first", "p0-second", "p1-first", "p1-second", "A", "B", "C"])
                    self.assertTrue(all(row["remediation_status"] == "open" for row in rows))
                    self.assertEqual(state_path.read_bytes(), original_state)
                    outputs.append(rows)
            self.assertEqual(outputs[0], outputs[1])

    def test_p2_sort_key_does_not_reference_remediation_status(self):
        tree = ast.parse(inspect.getsource(vulnops.main))
        sorts = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and node.func.attr == "sort"]
        self.assertEqual(len(sorts), 1)
        self.assertNotIn("remediation_status", ast.dump(sorts[0]))

    def test_prioritize_does_not_reference_lifecycle_or_verification_fields(self):
        source = inspect.getsource(vulnops.prioritize)
        for field in ("remediation_status", "verification_status", "vulnerability_present"):
            with self.subTest(field=field):
                self.assertNotIn(field, source)

    def test_rules_reasons_and_stable_priority_order(self):
        findings = [
            {"asset_id": "other-critical", "criticality": "critical", "cve": "CVE-2099-99999"},
            {"asset_id": "kev-high", "criticality": "high", "cve": "CVE-2021-44228"},
            {"asset_id": "kev-critical", "criticality": "critical", "cve": "CVE-2021-44228"},
            {"asset_id": "other-low", "criticality": "low", "cve": "CVE-2099-88888"},
        ]
        results = vulnops.prioritize(findings, {"CVE-2021-44228"})
        self.assertEqual([row["asset_id"] for row in results],
                         ["kev-critical", "kev-high", "other-critical", "other-low"])
        self.assertEqual([row["priority"] for row in results], ["P0", "P1", "P2", "P2"])
        self.assertEqual([row["kev"] for row in results], ["true", "true", "false", "false"])
        for row, rule in zip(results, [1, 2, 3, 3]):
            self.assertIn(f"Rule {rule}:", row["reason"])
        self.assertNotIn("priority", findings[0])

    def test_epss_cannot_change_v0_priorities_or_reasons(self):
        cases = [
            ("A", True, "critical", 0.001, "P0"),
            ("B", True, "medium", 0.001, "P1"),
            ("C", False, "critical", 0.99, "P2"),
            ("D", False, "critical", None, "P2"),
        ]
        for case, kev, criticality, score, expected in cases:
            with self.subTest(case=case):
                # V0 reads criticality and derives KEV membership from the CVE set.
                finding = {"asset_id": case, "cve": "CVE-2021-44228",
                           "criticality": criticality, "asset_criticality": criticality,
                           "kev": kev}
                kev_cves = {finding["cve"]} if kev else set()
                baseline = vulnops.prioritize([finding], kev_cves)[0]
                enriched = vulnops.enrich_with_epss([finding], {
                    finding["cve"]: {"epss_score": score, "epss_percentile": None},
                })

                result = vulnops.prioritize(enriched, kev_cves)[0]

                self.assertEqual(baseline["priority"], expected)
                self.assertEqual(result["priority"], expected)
                self.assertEqual(result["epss_score"], score)
                self.assertEqual(result["reason"], baseline["reason"])
                self.assertEqual({key: result[key] for key in baseline}, baseline)

    def test_exposure_and_epss_cannot_change_priority_classification(self):
        cases = [
            ("A", True, "critical", "false", 0.001, "P0"),
            ("B", True, "medium", "false", 0.001, "P1"),
            ("C", False, "critical", "true", 0.99, "P2"),
            ("D", False, "critical", "unknown", 0.99, "P2"),
            ("E", False, "critical", "false", 0.99, "P2"),
        ]
        for case, kev, criticality, exposure, score, expected in cases:
            with self.subTest(case=case):
                # The existing application calls asset criticality "criticality".
                finding = {"asset_id": case, "cve": "CVE-2099-10001", "criticality": criticality}
                kev_cves = {finding["cve"]} if kev else set()
                baseline = vulnops.prioritize([finding], kev_cves)[0]
                contextual = {**finding, "internet_exposed": exposure,
                              "epss_score": score, "epss_percentile": None}

                result = vulnops.prioritize([contextual], kev_cves)[0]

                self.assertEqual(result["priority"], expected)
                self.assertEqual(result["reason"], baseline["reason"])
                self.assertEqual({key: result[key] for key in baseline}, baseline)
                self.assertEqual(result["internet_exposed"], exposure)
                self.assertEqual(result["epss_score"], score)

    def test_owner_team_cannot_change_priority_or_reason(self):
        cases = [
            ("A", True, "critical", "false", 0.01, "unknown", "P0"),
            ("B", True, "medium", "false", 0.01, "unknown", "P1"),
            ("C", False, "critical", "true", 0.99, "payments-platform", "P2"),
            ("D", False, "critical", "true", 0.99, "unknown", "P2"),
        ]
        for asset, kev, criticality, exposure, score, team, expected in cases:
            with self.subTest(asset_id=asset, owner_team=team):
                finding = {"asset_id": asset, "cve": "CVE-2099-10001", "criticality": criticality,
                           "internet_exposed": exposure, "epss_score": score, "epss_percentile": None}
                kev_cves = {finding["cve"]} if kev else set()
                baseline = vulnops.prioritize([finding], kev_cves)[0]

                result = vulnops.prioritize([{**finding, "owner_team": team}], kev_cves)[0]

                self.assertEqual(result["priority"], expected)
                self.assertEqual(result["owner_team"], team)
                self.assertEqual(result["reason"], baseline["reason"])
                self.assertEqual({key: result[key] for key in baseline}, baseline)
                for ownership_term in ("owner", "team", "unknown", "payments-platform"):
                    self.assertNotIn(ownership_term, result["reason"].lower())

    def test_prioritize_does_not_reference_owner_team(self):
        self.assertNotIn("owner_team", inspect.getsource(vulnops.prioritize))

    def test_prioritize_does_not_reference_internet_exposed(self):
        self.assertNotIn("internet_exposed", inspect.getsource(vulnops.prioritize))

    def test_csv_pipeline_normalizes_and_writes_fixed_columns(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "finding_fixture.csv"
            source.write_text("cve,asset_id,criticality,internet_exposed,owner_team\n cve-2021-44228 ,\"server, UK\", Critical ,unknown,unknown\n")
            findings = self.read_fixture_findings(source)
            destination = Path(directory) / "output" / "remediation_queue.csv"
            vulnops.write_queue(destination, vulnops.prioritize(findings, {"CVE-2021-44228"}))
            with destination.open(newline="") as output:
                reader = csv.DictReader(output)
                self.assertEqual(reader.fieldnames, ["asset_id", "criticality", "cve", "internet_exposed", "owner_team", "kev",
                                                    "epss_score", "epss_percentile", "priority", "reason", "remediation_status"])
                rows = list(reader)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["priority"], "P0")
            self.assertEqual(rows[0]["asset_id"], "server, UK")
            self.assertEqual(rows[0]["cve"], "CVE-2021-44228")
            self.assertEqual(rows[0]["internet_exposed"], "unknown")

    def test_owner_team_cannot_change_p2_queue_order(self):
        cases = [
            ([("A", "true", 0.10, "unknown"),
              ("B", "unknown", 0.99, "payments-platform"),
              ("C", "false", 0.99, "identity")], ["A", "B", "C"]),
            ([("D", "true", 0.90, "unknown"),
              ("E", "true", 0.20, "payments-platform")], ["D", "E"]),
        ]
        for cases_by_asset, expected in cases:
            owners = [case[3] for case in cases_by_asset]
            for teams in (owners, list(reversed(owners))):
                with self.subTest(expected=expected, teams=teams), tempfile.TemporaryDirectory() as directory:
                    findings = [{"asset_id": asset, "criticality": "critical", "cve": f"CVE-2099-{1000 + index}",
                                 "internet_exposed": exposure, "owner_team": team}
                                for index, ((asset, exposure, score, original_team), team)
                                in enumerate(zip(cases_by_asset, teams))]
                    epss = {finding["cve"]: {"epss_score": case[2], "epss_percentile": None}
                            for finding, case in zip(findings, cases_by_asset)}
                    root = Path(directory)
                    (root / "data").mkdir(exist_ok=True)
                    (root / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\n")
                    (root / "state").mkdir()
                    (root / "state" / "remediation_status.csv").write_text("asset_id,cve,remediation_status\n")
                    (root / "data").mkdir(exist_ok=True)
                    with (root / "data" / "finding_fixture.csv").open("w", newline="") as source:
                        writer = csv.DictWriter(source, fieldnames=["asset_id", "criticality", "cve",
                                                                   "internet_exposed", "owner_team"])
                        writer.writeheader()
                        # Reverse input so preserving its order cannot accidentally pass.
                        writer.writerows(reversed(findings))
                    with patch("vulnops.ROOT", root), patch("vulnops.load_kev", return_value=set()):
                        with patch("vulnops.load_epss", return_value=epss), patch("sys.stdout", new_callable=io.StringIO):
                            self.assertEqual(self.run_fixture_main(), 0)
                    with (root / "output" / "remediation_queue.csv").open(newline="") as output:
                        rows = list(csv.DictReader(output))
                    self.assertEqual([row["asset_id"] for row in rows], expected)
                    self.assertTrue(all(row["priority"] == "P2" for row in rows))
                    self.assertEqual({row["asset_id"]: row["owner_team"] for row in rows},
                                     {row["asset_id"]: row["owner_team"] for row in findings})

    def test_queue_sorting_does_not_reference_owner_team(self):
        # Queue sorting is implemented directly in main().
        self.assertNotIn("owner_team", inspect.getsource(vulnops.main))

    def test_owner_team_accepts_team_name_and_explicit_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "finding_fixture.csv"
            for value in ("payments-platform", "unknown"):
                with self.subTest(owner_team=value):
                    source.write_text(f"asset_id,criticality,cve,internet_exposed,owner_team\nserver,critical,CVE-2021-44228,true,{value}\n")
                    finding = self.read_fixture_findings(source)[0]
                    self.assertEqual(finding["owner_team"], value)
                    self.assertIsInstance(finding["owner_team"], str)

    def test_unknown_ownership_is_valid_for_p0_p1_and_p2(self):
        epss = {"CVE-2099-10001": {"epss_score": 0.01, "epss_percentile": 0.1},
                "CVE-2099-10002": {"epss_score": 0.99, "epss_percentile": 0.999}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir(exist_ok=True)
            (root / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\n")
            (root / "state").mkdir()
            (root / "state" / "remediation_status.csv").write_text("asset_id,cve,remediation_status\n")
            (root / "data").mkdir(exist_ok=True)
            outputs = []
            for team in ("payments-platform", "unknown"):
                with self.subTest(owner_team=team):
                    source = ("asset_id,criticality,cve,internet_exposed,owner_team\n"
                              f"C,critical,CVE-2099-10002,true,{team}\n"
                              f"B,medium,CVE-2099-10001,false,{team}\n"
                              f"A,critical,CVE-2099-10001,false,{team}\n")
                    (root / "data" / "finding_fixture.csv").write_text(source)
                    with patch("vulnops.ROOT", root), patch("vulnops.load_kev", return_value={"CVE-2099-10001"}):
                        with patch("vulnops.load_epss", return_value=epss), patch("sys.stdout", new_callable=io.StringIO):
                            self.assertEqual(self.run_fixture_main(), 0)
                    with (root / "output" / "remediation_queue.csv").open(newline="") as output:
                        rows = list(csv.DictReader(output))
                    self.assertEqual([row["asset_id"] for row in rows], ["A", "B", "C"])
                    self.assertEqual([row["priority"] for row in rows], ["P0", "P1", "P2"])
                    for row in rows:
                        with self.subTest(asset_id=row["asset_id"]):
                            self.assertEqual(row["owner_team"], team)
                    outputs.append(rows)
            known, unknown = outputs
            self.assertEqual([{key: value for key, value in row.items() if key != "owner_team"} for row in unknown],
                             [{key: value for key, value in row.items() if key != "owner_team"} for row in known])

    def test_owner_team_is_the_only_change_to_v04_csv_output(self):
        source = ("asset_id,criticality,cve,internet_exposed,owner_team\n"
                  "database-01,critical,CVE-2099-10002,true,data-platform\n"
                  "payments-api-01,critical,CVE-2099-10001,false,payments-platform\n"
                  "identity-01,medium,CVE-2099-10001,true,identity\n"
                  "unowned-01,critical,CVE-2099-10001,unknown,unknown\n")
        epss = {"CVE-2099-10001": {"epss_score": 0.01, "epss_percentile": 0.1},
                "CVE-2099-10002": {"epss_score": 0.99, "epss_percentile": 0.999}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir(exist_ok=True)
            (root / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\n")
            (root / "state").mkdir()
            (root / "state" / "remediation_status.csv").write_text("asset_id,cve,remediation_status\n")
            (root / "data").mkdir(exist_ok=True)
            input_path = root / "data" / "finding_fixture.csv"
            input_path.write_text(source)
            findings = self.read_fixture_findings(input_path)
            baseline_findings = [{key: value for key, value in row.items() if key != "owner_team"}
                                 for row in findings]
            outputs = []
            for inputs in (baseline_findings, findings):
                with patch("vulnops.ROOT", root), patch.object(self, "read_fixture_findings", return_value=inputs):
                    with patch("vulnops.load_kev", return_value={"CVE-2099-10001"}):
                        with patch("vulnops.load_epss", return_value=epss), patch("sys.stdout", new_callable=io.StringIO):
                            self.assertEqual(self.run_fixture_main(), 0)
                with (root / "output" / "remediation_queue.csv").open(newline="") as output:
                    reader = csv.DictReader(output)
                    self.assertEqual(reader.fieldnames, ["asset_id", "criticality", "cve", "internet_exposed", "owner_team",
                                                        "kev", "epss_score", "epss_percentile", "priority", "reason", "remediation_status"])
                    outputs.append(list(reader))
            baseline, rows = outputs
            self.assertEqual([{key: value for key, value in row.items() if key != "owner_team"} for row in rows],
                             [{key: value for key, value in row.items() if key != "owner_team"} for row in baseline])
            self.assertEqual([row["asset_id"] for row in rows],
                             ["payments-api-01", "unowned-01", "identity-01", "database-01"])
            self.assertEqual([(row["priority"], row["owner_team"]) for row in rows], [
                ("P0", "payments-platform"), ("P0", "unknown"), ("P1", "identity"), ("P2", "data-platform"),
            ])
            self.assertEqual({row["asset_id"]: row["owner_team"] for row in rows},
                             {row["asset_id"]: row["owner_team"] for row in findings})

    def test_owner_team_survives_every_pipeline_stage(self):
        for team in ("payments-platform", "unknown"):
            for is_kev in (True, False):
                with self.subTest(owner_team=team, kev=is_kev), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / "data").mkdir(exist_ok=True)
                    (root / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\n")
                    (root / "state").mkdir()
                    (root / "state" / "remediation_status.csv").write_text("asset_id,cve,remediation_status\n")
                    (root / "data").mkdir(exist_ok=True)
                    source = ("asset_id,criticality,cve,internet_exposed,owner_team\n"
                              f"payments-api-01,critical,CVE-2099-10001,true,{team}\n"
                              "higher-epss,critical,CVE-2099-10002,true,identity\n"
                              "known-kev,critical,CVE-2099-10003,false,data-platform\n")
                    (root / "data" / "finding_fixture.csv").write_text(source)
                    kev_cves = {"CVE-2099-10003"}
                    if is_kev:
                        kev_cves.add("CVE-2099-10001")
                    kev = {"vulnerabilities": [{"cveID": cve} for cve in sorted(kev_cves)]}
                    epss = {"status": "OK", "status-code": 200, "total": 3, "data": [
                        {"cve": "CVE-2099-10001", "epss": "0.1", "percentile": "0.2"},
                        {"cve": "CVE-2099-10002", "epss": "0.9", "percentile": "0.99"},
                        {"cve": "CVE-2099-10003", "epss": "0.001", "percentile": "0.1"},
                    ]}
                    responses = [io.BytesIO(json.dumps(feed).encode()) for feed in (kev, epss)]
                    with patch("vulnops.ROOT", root), patch("vulnops.urlopen", side_effect=responses):
                        with patch("vulnops.enrich_with_epss", wraps=vulnops.enrich_with_epss) as enrich:
                            with patch("vulnops.prioritize", wraps=vulnops.prioritize) as classify:
                                with patch("vulnops.write_queue", wraps=vulnops.write_queue) as write:
                                    with patch("sys.stdout", new_callable=io.StringIO):
                                        self.assertEqual(self.run_fixture_main(), 0)
                    after_epss = classify.call_args.args[0]
                    # KEV enrichment and classification occur together in prioritize().
                    classified = vulnops.prioritize(after_epss, kev_cves)
                    with (root / "output" / "remediation_queue.csv").open(newline="") as output:
                        csv_rows = list(csv.DictReader(output))
                    stages = {
                        "load and KEV retrieval": enrich.call_args.args[0],
                        "EPSS enrichment": after_epss,
                        "KEV enrichment and classification": classified,
                        "queue ordering": write.call_args.args[1],
                        "CSV output": csv_rows,
                    }
                    for stage, rows in stages.items():
                        with self.subTest(stage=stage):
                            finding = next(row for row in rows if row["asset_id"] == "payments-api-01")
                            self.assertEqual(finding["owner_team"], team)
                            self.assertIsInstance(finding["owner_team"], str)
                    target = next(row for row in csv_rows if row["asset_id"] == "payments-api-01")
                    self.assertEqual(target["kev"], "true" if is_kev else "false")
                    self.assertEqual(target["priority"], "P0" if is_kev else "P2")
                    self.assertEqual(csv_rows[0 if is_kev else -1]["asset_id"], "payments-api-01")



    def test_internet_exposed_accepts_and_retains_three_strings(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "finding_fixture.csv"
            for value in ("true", "false", "unknown"):
                with self.subTest(value=value):
                    source.write_text(f"asset_id,criticality,cve,internet_exposed,owner_team\nserver,critical,CVE-2021-44228,{value},unknown\n")
                    finding = self.read_fixture_findings(source)[0]
                    self.assertEqual(finding["internet_exposed"], value)
                    self.assertIsInstance(finding["internet_exposed"], str)

    def test_internet_exposed_survives_every_pipeline_stage(self):
        source = ("asset_id,criticality,cve,internet_exposed,owner_team\n"
                  "p2-low,critical,CVE-2099-10001,true,unknown\n"
                  "p1,medium,CVE-2099-10002,false,unknown\n"
                  "p2-missing,low,CVE-2099-10003,false,unknown\n"
                  "p0,critical,CVE-2099-10002,unknown,unknown\n"
                  "p2-high,medium,CVE-2099-10004,unknown,unknown\n"
                  "p2-zero,low,CVE-2099-10005,true,unknown\n")
        expected = {"p2-low": "true", "p1": "false", "p2-missing": "false",
                    "p0": "unknown", "p2-high": "unknown", "p2-zero": "true"}
        kev = {"vulnerabilities": [{"cveID": "CVE-2099-10002"}]}
        epss = {"status": "OK", "status-code": 200, "total": 4, "data": [
            {"cve": "CVE-2099-10001", "epss": "0.1", "percentile": "0.2"},
            {"cve": "CVE-2099-10002", "epss": "0.01", "percentile": "0.1"},
            {"cve": "CVE-2099-10004", "epss": "0.9", "percentile": "0.99"},
            {"cve": "CVE-2099-10005", "epss": "0", "percentile": "0"},
        ]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir(exist_ok=True)
            (root / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\n")
            (root / "state").mkdir()
            (root / "state" / "remediation_status.csv").write_text("asset_id,cve,remediation_status\n")
            (root / "data").mkdir(exist_ok=True)
            (root / "data" / "finding_fixture.csv").write_text(source)
            responses = [io.BytesIO(json.dumps(feed).encode()) for feed in (kev, epss)]
            with patch("vulnops.ROOT", root), patch("vulnops.urlopen", side_effect=responses):
                with patch("vulnops.enrich_with_epss", wraps=vulnops.enrich_with_epss) as enrich:
                    with patch("vulnops.prioritize", wraps=vulnops.prioritize) as classify:
                        with patch("vulnops.write_queue", wraps=vulnops.write_queue) as write:
                            with patch("sys.stdout", new_callable=io.StringIO):
                                self.assertEqual(self.run_fixture_main(), 0)
            after_epss = classify.call_args.args[0]
            # KEV is attached inside prioritize(), rather than a separate enrichment stage.
            after_classification = vulnops.prioritize(after_epss, {"CVE-2099-10002"})
            with (root / "output" / "remediation_queue.csv").open(newline="") as output:
                csv_rows = list(csv.DictReader(output))
            stages = {
                "load and KEV retrieval": enrich.call_args.args[0],
                "EPSS enrichment": after_epss,
                "KEV enrichment and prioritization": after_classification,
                "queue ordering": write.call_args.args[1],
                "CSV output": csv_rows,
            }
            for stage, rows in stages.items():
                for value in ("true", "false", "unknown"):
                    with self.subTest(stage=stage, internet_exposed=value):
                        for asset_id, exposure in expected.items():
                            if exposure == value:
                                row = next(row for row in rows if row["asset_id"] == asset_id)
                                self.assertEqual(row["internet_exposed"], value)
                                self.assertIsInstance(row["internet_exposed"], str)
            self.assertEqual([row["asset_id"] for row in csv_rows],
                             ["p0", "p1", "p2-low", "p2-zero", "p2-high", "p2-missing"])
            self.assertEqual([row["kev"] for row in csv_rows],
                             ["true", "true", "false", "false", "false", "false"])

    def test_exposure_changes_p2_order_without_changing_policy_or_output_fields(self):
        source = ("asset_id,criticality,cve,internet_exposed,owner_team\n"
                  "p2-false,critical,CVE-2099-10001,false,unknown\n"
                  "p1,medium,CVE-2099-10002,true,unknown\n"
                  "p2-unknown,critical,CVE-2099-10003,unknown,unknown\n"
                  "p0,critical,CVE-2099-10002,false,unknown\n"
                  "p2-true,critical,CVE-2099-10004,true,unknown\n")
        epss = {cve: {"epss_score": score, "epss_percentile": None} for cve, score in (
            ("CVE-2099-10001", 0.9), ("CVE-2099-10002", 0.01),
            ("CVE-2099-10003", 0.4), ("CVE-2099-10004", 0.1),
        )}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir(exist_ok=True)
            (root / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\n")
            (root / "state").mkdir()
            (root / "state" / "remediation_status.csv").write_text("asset_id,cve,remediation_status\n")
            (root / "data").mkdir(exist_ok=True)
            input_path = root / "data" / "finding_fixture.csv"
            input_path.write_text(source)
            findings = self.read_fixture_findings(input_path)
            baseline_findings = [{**row, "internet_exposed": "unknown"} for row in findings]
            outputs = []
            for inputs in (baseline_findings, findings):
                with patch("vulnops.ROOT", root), patch.object(self, "read_fixture_findings", return_value=inputs):
                    with patch("vulnops.load_kev", return_value={"CVE-2099-10002"}):
                        with patch("vulnops.load_epss", return_value=epss), patch("sys.stdout", new_callable=io.StringIO):
                            self.assertEqual(self.run_fixture_main(), 0)
                with (root / "output" / "remediation_queue.csv").open(newline="") as output:
                    reader = csv.DictReader(output)
                    self.assertEqual(reader.fieldnames, ["asset_id", "criticality", "cve", "internet_exposed", "owner_team",
                                                        "kev", "epss_score", "epss_percentile", "priority", "reason", "remediation_status"])
                    outputs.append(list(reader))
            baseline, rows = outputs
            self.assertEqual({row["asset_id"]: {key: value for key, value in row.items() if key != "internet_exposed"}
                              for row in rows},
                             {row["asset_id"]: {key: value for key, value in row.items() if key != "internet_exposed"}
                              for row in baseline})
            self.assertEqual([row["asset_id"] for row in baseline], ["p0", "p1", "p2-false", "p2-unknown", "p2-true"])
            self.assertEqual([row["asset_id"] for row in rows], ["p0", "p1", "p2-true", "p2-unknown", "p2-false"])
            self.assertEqual([(row["priority"], row["internet_exposed"]) for row in rows], [
                ("P0", "false"), ("P1", "true"), ("P2", "true"), ("P2", "unknown"), ("P2", "false"),
            ])




    def test_header_only_input_produces_header_only_output(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "finding_fixture.csv"
            source.write_text("asset_id,criticality,cve,internet_exposed,owner_team\n")
            findings = self.read_fixture_findings(source)
            destination = Path(directory) / "queue.csv"
            vulnops.write_queue(destination, vulnops.prioritize(findings, {"CVE-2021-44228"}))
            self.assertEqual(destination.read_text().strip(),
                             "asset_id,criticality,cve,internet_exposed,owner_team,kev,epss_score,epss_percentile,priority,reason,remediation_status")

    def test_kev_feed_is_loaded(self):
        feed = io.BytesIO(b'{"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}')
        with patch("vulnops.urlopen", return_value=feed):
            self.assertEqual(vulnops.load_kev(), {"CVE-2021-44228"})

    def test_invalid_kev_feed_is_rejected(self):
        feeds = [b'{}', b'[]', b'{"vulnerabilities": []}',
                 b'{"vulnerabilities": [{}]}', b'{"vulnerabilities": [{"cveID": "invalid"}]}',
                 b'not json']
        for feed in feeds:
            with self.subTest(feed=feed):
                with patch("vulnops.urlopen", return_value=io.BytesIO(feed)):
                    with self.assertRaises(ValueError):
                        vulnops.load_kev()

    def test_epss_numeric_values_deduplication_and_missing_cve(self):
        payload = {"status": "OK", "status-code": 200, "total": 1, "data": [
            {"cve": "CVE-2021-44228", "epss": "0.123", "percentile": "0.876"},
        ]}
        with patch("vulnops.urlopen", return_value=io.BytesIO(json.dumps(payload).encode())) as request:
            results = vulnops.load_epss(["CVE-2099-99999", "CVE-2021-44228", "CVE-2021-44228"])
        self.assertEqual(results, {
            "CVE-2021-44228": {"epss_score": 0.123, "epss_percentile": 0.876},
            "CVE-2099-99999": {"epss_score": None, "epss_percentile": None},
        })
        request.assert_called_once()
        url = urlparse(request.call_args.args[0])
        self.assertEqual(f"{url.scheme}://{url.netloc}{url.path}", vulnops.EPSS_URL)
        self.assertEqual(parse_qs(url.query), {
            "cve": ["CVE-2021-44228,CVE-2099-99999"], "limit": ["2"],
        })

    def test_epss_network_failure_raises(self):
        with patch("vulnops.urlopen", side_effect=URLError("simulated outage")):
            with self.assertRaisesRegex(ValueError, "FIRST EPSS retrieval failed.*simulated outage"):
                vulnops.load_epss(["CVE-2021-44228"])

    def test_epss_invalid_responses_raise(self):
        valid = {"cve": "CVE-2021-44228", "epss": "0.123", "percentile": "0.876"}
        payloads = [
            {}, [], {"status": "ERROR", "status-code": 503, "total": 0, "data": []},
            {"status": "OK", "status-code": 200, "total": 1, "data": []},
        ]
        for entries in ([{}], [valid, valid], [{**valid, "cve": "CVE-2099-99999"}],
                        [{**valid, "epss": None}], [{**valid, "epss": "NaN"}],
                        [{**valid, "epss": "Infinity"}], [{**valid, "epss": "invalid"}],
                        [{**valid, "epss": True}], [{**valid, "epss": "-0.1"}],
                        [{**valid, "percentile": "1.1"}], [{"cve": "CVE-2021-44228", "epss": "0.1"}]):
            payloads.append({"status": "OK", "status-code": 200, "total": len(entries), "data": entries})
        for payload in payloads:
            with self.subTest(payload=payload):
                with patch("vulnops.urlopen", return_value=io.BytesIO(json.dumps(payload).encode())):
                    with self.assertRaisesRegex(ValueError, "FIRST EPSS retrieval failed"):
                        vulnops.load_epss(["CVE-2021-44228"])
        with patch("vulnops.urlopen", return_value=io.BytesIO(b"not json")):
            with self.assertRaisesRegex(ValueError, "FIRST EPSS retrieval failed"):
                vulnops.load_epss(["CVE-2021-44228"])

    def test_epss_zero_and_one_are_scores(self):
        payload = {"status": "OK", "status-code": 200, "total": 1, "data": [
            {"cve": "CVE-2021-44228", "epss": "0", "percentile": "1"},
        ]}
        with patch("vulnops.urlopen", return_value=io.BytesIO(json.dumps(payload).encode())):
            self.assertEqual(vulnops.load_epss(["CVE-2021-44228"]), {
                "CVE-2021-44228": {"epss_score": 0.0, "epss_percentile": 1.0},
            })

    def test_epss_success_without_results_returns_none(self):
        payload = {"status": "OK", "status-code": 200, "total": 0, "data": []}
        with patch("vulnops.urlopen", return_value=io.BytesIO(json.dumps(payload).encode())):
            self.assertEqual(vulnops.load_epss(["CVE-2099-99999"]), {
                "CVE-2099-99999": {"epss_score": None, "epss_percentile": None},
            })

    def test_epss_query_limit_and_empty_input(self):
        # One CVE prefix is 9 characters; commas count toward the FIRST limit.
        at_limit = "CVE-2021-" + "1" * 1991
        with patch("vulnops.urlopen") as request:
            self.assertEqual(vulnops.load_epss([]), {})
            with self.assertRaisesRegex(ValueError, "2000 characters.*does not implement batching"):
                vulnops.load_epss([at_limit, "CVE-2021-44228"])
            request.assert_not_called()
        payload = {"status": "OK", "status-code": 200, "total": 0, "data": []}
        with patch("vulnops.urlopen", return_value=io.BytesIO(json.dumps(payload).encode())) as request:
            results = vulnops.load_epss([at_limit, at_limit])
            request.assert_called_once()
            self.assertIsNone(results[at_limit]["epss_score"])

    def test_epss_enrichment_preserves_every_existing_field(self):
        findings = [
            {"asset_id": "A", "cve": "CVE-2021-44228", "severity": "high",
             "asset_criticality": "critical", "criticality": "critical", "kev": True,
             "priority": "P0", "reason": "Existing reason A"},
            {"asset_id": "B", "cve": "CVE-2099-99999", "severity": "medium",
             "asset_criticality": "low", "criticality": "low", "kev": False,
             "priority": "P2", "reason": "Existing reason B"},
        ]
        originals = [finding.copy() for finding in findings]
        epss_by_cve = {"CVE-2021-44228": {"epss_score": 0.75, "epss_percentile": 0.98}}

        enriched = vulnops.enrich_with_epss(findings, epss_by_cve)

        self.assertEqual(enriched, [
            {**originals[0], "epss_score": 0.75, "epss_percentile": 0.98},
            {**originals[1], "epss_score": None, "epss_percentile": None},
        ])
        self.assertEqual(findings, originals)
        for original, result in zip(originals, enriched):
            self.assertEqual({key: result[key] for key in original}, original)
        self.assertEqual(epss_by_cve, {
            "CVE-2021-44228": {"epss_score": 0.75, "epss_percentile": 0.98},
        })

    def test_epss_enrichment_preserves_zero_and_explicit_none(self):
        finding = {"asset_id": "A", "cve": "CVE-2021-44228", "kev": False}
        for score, percentile in ((0.0, 0.0), (None, None)):
            with self.subTest(score=score):
                epss = {"epss_score": score, "epss_percentile": percentile}
                enriched = vulnops.enrich_with_epss([finding], {finding["cve"]: epss})
                self.assertEqual(enriched, [{**finding, **epss}])

    def test_epss_preserves_p0_and_p1_order_but_ranks_p2(self):
        cases = [
            ("A", "critical", True, 0.10),
            ("B", "critical", True, 0.99),
            ("C", "critical", True, 0.50),
            ("D", "medium", True, 0.20),
            ("E", "medium", True, 0.95),
            ("F", "medium", True, 0.40),
            ("G", "medium", False, 0.20),
            ("H", "medium", False, 0.95),
            ("I", "medium", False, 0.40),
        ]
        findings = [{"asset_id": asset, "criticality": criticality, "cve": f"CVE-2099-{1000 + index}",
                     "internet_exposed": "unknown"}
                    for index, (asset, criticality, kev, score) in enumerate(cases)]
        kev_cves = {finding["cve"] for finding, case in zip(findings, cases) if case[2]}
        epss = {finding["cve"]: {"epss_score": case[3], "epss_percentile": None}
                for finding, case in zip(findings, cases)}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir(exist_ok=True)
            (root / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\n")
            (root / "state").mkdir()
            (root / "state" / "remediation_status.csv").write_text("asset_id,cve,remediation_status\n")
            with patch("vulnops.ROOT", root), patch.object(self, "read_fixture_findings", return_value=findings):
                with patch("vulnops.load_kev", return_value=kev_cves), patch("vulnops.load_epss", return_value=epss):
                    with patch("sys.stdout", new_callable=io.StringIO):
                        self.assertEqual(self.run_fixture_main(), 0)
            with (root / "output" / "remediation_queue.csv").open(newline="") as output:
                rows = list(csv.DictReader(output))

        self.assertEqual([row["asset_id"] for row in rows], ["A", "B", "C", "D", "E", "F", "H", "I", "G"])
        for priority, expected in (("P0", ["A", "B", "C"]),
                                   ("P1", ["D", "E", "F"]),
                                   ("P2", ["H", "I", "G"])):
            with self.subTest(priority=priority):
                self.assertEqual([row["asset_id"] for row in rows if row["priority"] == priority], expected)
        self.assertEqual([float(row["epss_score"]) for row in rows],
                         [0.10, 0.99, 0.50, 0.20, 0.95, 0.40, 0.95, 0.40, 0.20])

    def test_low_epss_p1_precedes_high_epss_p2(self):
        # V0's input field is named criticality; KEV comes from the CVE set.
        findings = [
            {"asset_id": "A", "cve": "CVE-2099-10001", "criticality": "critical", "internet_exposed": "false"},
            {"asset_id": "B", "cve": "CVE-2099-10002", "criticality": "medium", "internet_exposed": "false"},
            {"asset_id": "C", "cve": "CVE-2099-10003", "criticality": "critical", "internet_exposed": "true"},
            {"asset_id": "D", "cve": "CVE-2099-10004", "criticality": "medium", "internet_exposed": "true"},
            {"asset_id": "E", "cve": "CVE-2099-10005", "criticality": "low", "internet_exposed": "true"},
        ]
        kev_cves = {findings[0]["cve"], findings[1]["cve"]}
        epss = {finding["cve"]: {"epss_score": score, "epss_percentile": None}
                for finding, score in zip(findings, [0.001, 0.001, 0.99, 0.80, 0.20])}
        baseline = {row["asset_id"]: row for row in vulnops.prioritize(findings, kev_cves)}
        # Shuffle input so neither priority grouping nor P2 ranking passes by accident.
        shuffled = [findings[index] for index in [4, 2, 1, 3, 0]]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir(exist_ok=True)
            (root / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\n")
            (root / "state").mkdir()
            (root / "state" / "remediation_status.csv").write_text("asset_id,cve,remediation_status\n")
            with patch("vulnops.ROOT", root), patch.object(self, "read_fixture_findings", return_value=shuffled):
                with patch("vulnops.load_kev", return_value=kev_cves), patch("vulnops.load_epss", return_value=epss):
                    with patch("sys.stdout", new_callable=io.StringIO):
                        self.assertEqual(self.run_fixture_main(), 0)
            with (root / "output" / "remediation_queue.csv").open(newline="") as output:
                rows = list(csv.DictReader(output))

        queue = [row["asset_id"] for row in rows]
        self.assertEqual(queue, ["A", "B", "C", "D", "E"])
        self.assertEqual([row["priority"] for row in rows], ["P0", "P1", "P2", "P2", "P2"])
        self.assertEqual([row["kev"] for row in rows], ["true", "true", "false", "false", "false"])
        self.assertEqual([float(row["epss_score"]) for row in rows], [0.001, 0.001, 0.99, 0.80, 0.20])
        self.assertLess(queue.index("B"), queue.index("C"))
        self.assertLess(queue.index("C"), queue.index("D"))
        self.assertLess(queue.index("D"), queue.index("E"))
        for row in rows:
            self.assertEqual(row["reason"], baseline[row["asset_id"]]["reason"])

    def test_p2_exposure_groups_take_precedence_over_epss(self):
        cases = [
            ([("A", "false", 0.99), ("B", "true", 0.10), ("C", "unknown", 0.90)], ["B", "C", "A"]),
            ([("D", "true", 0.20), ("E", "true", 0.90), ("F", "true", 0.50)], ["E", "F", "D"]),
            ([("G", "unknown", 0.10), ("H", "unknown", 0.80)], ["H", "G"]),
            ([("I", "false", 0.30), ("J", "false", 0.70)], ["J", "I"]),
            ([("K", "true", None), ("L", "false", 0.01)], ["K", "L"]),
            ([("A", "true", None), ("B", "unknown", 0.99), ("C", "false", 0.99)], ["A", "B", "C"]),
            ([("E", "true", None), ("D", "true", 0.01)], ["D", "E"]),
            ([("G", "unknown", None), ("F", "unknown", 0.00)], ["F", "G"]),
        ]
        for inputs, expected in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "data").mkdir(exist_ok=True)
                (root / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\n")
                (root / "state").mkdir()
                (root / "state" / "remediation_status.csv").write_text("asset_id,cve,remediation_status\n")
                (root / "data").mkdir(exist_ok=True)
                findings = [{"asset_id": asset, "criticality": "critical",
                             "cve": f"CVE-2099-{1000 + index}", "internet_exposed": exposure, "owner_team": "unknown"}
                            for index, (asset, exposure, score) in enumerate(inputs)]
                with (root / "data" / "finding_fixture.csv").open("w", newline="") as source:
                    writer = csv.DictWriter(source, fieldnames=["asset_id", "criticality", "cve", "internet_exposed", "owner_team"])
                    writer.writeheader()
                    writer.writerows(findings)
                epss = {finding["cve"]: {"epss_score": case[2], "epss_percentile": None}
                        for finding, case in zip(findings, inputs)}
                with patch("vulnops.ROOT", root), patch("vulnops.load_kev", return_value=set()):
                    with patch("vulnops.load_epss", return_value=epss):
                        with patch("vulnops.write_queue", wraps=vulnops.write_queue) as write:
                            with patch("sys.stdout", new_callable=io.StringIO):
                                self.assertEqual(self.run_fixture_main(), 0)
                in_memory = {row["asset_id"]: row for row in write.call_args.args[1]}
                for asset, exposure, score in inputs:
                    self.assertEqual(in_memory[asset]["internet_exposed"], exposure)
                    if score is None:
                        self.assertIsNone(in_memory[asset]["epss_score"])
                    else:
                        self.assertEqual(in_memory[asset]["epss_score"], score)
                        self.assertIsInstance(in_memory[asset]["epss_score"], float)
                with (root / "output" / "remediation_queue.csv").open(newline="") as output:
                    rows = list(csv.DictReader(output))
                self.assertEqual([row["asset_id"] for row in rows], expected)
                self.assertTrue(all(row["priority"] == "P2" for row in rows))
                self.assertTrue(all(row["kev"] == "false" for row in rows))
                self.assertTrue(all(row["reason"] == "Rule 3: CVE is not in CISA KEV." for row in rows))
                by_asset = {row["asset_id"]: row for row in rows}
                for asset, exposure, score in inputs:
                    self.assertEqual(by_asset[asset]["internet_exposed"], exposure)
                    self.assertEqual(by_asset[asset]["epss_score"], "" if score is None else str(score))

    def test_unknown_exposure_remains_distinct_from_false_through_sorting(self):
        cases = [
            ([("A", "true", 0.10), ("B", "unknown", 0.10), ("C", "false", 0.10)], ["A", "B", "C"]),
            # Reversed input catches an implementation that treats unknown and false as equal.
            ([("C", "false", 0.10), ("B", "unknown", 0.10), ("A", "true", 0.10)], ["A", "B", "C"]),
            ([("D", "unknown", 0.01), ("E", "false", 0.99)], ["D", "E"]),
        ]
        for inputs, expected in cases:
            with self.subTest(inputs=inputs), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "data").mkdir(exist_ok=True)
                (root / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\n")
                (root / "state").mkdir()
                (root / "state" / "remediation_status.csv").write_text("asset_id,cve,remediation_status\n")
                (root / "data").mkdir(exist_ok=True)
                findings = [{"asset_id": asset, "criticality": "critical", "cve": f"CVE-2099-{1000 + index}",
                             "internet_exposed": exposure, "owner_team": "unknown"} for index, (asset, exposure, score) in enumerate(inputs)]
                with (root / "data" / "finding_fixture.csv").open("w", newline="") as source:
                    writer = csv.DictWriter(source, fieldnames=["asset_id", "criticality", "cve", "internet_exposed", "owner_team"])
                    writer.writeheader()
                    writer.writerows(findings)
                epss = {row["cve"]: {"epss_score": case[2], "epss_percentile": None}
                        for row, case in zip(findings, inputs)}
                with patch("vulnops.ROOT", root), patch("vulnops.load_kev", return_value=set()):
                    with patch("vulnops.load_epss", return_value=epss):
                        with patch("vulnops.enrich_with_epss", wraps=vulnops.enrich_with_epss) as enrich:
                            with patch("vulnops.prioritize", wraps=vulnops.prioritize) as classify:
                                with patch("vulnops.write_queue", wraps=vulnops.write_queue) as write:
                                    with patch("sys.stdout", new_callable=io.StringIO):
                                        self.assertEqual(self.run_fixture_main(), 0)
                with (root / "output" / "remediation_queue.csv").open(newline="") as output:
                    rows = list(csv.DictReader(output))
                expected_exposures = {asset: exposure for asset, exposure, score in inputs}
                for stage in (enrich.call_args.args[0], classify.call_args.args[0], write.call_args.args[1], rows):
                    self.assertEqual({row["asset_id"]: row["internet_exposed"] for row in stage}, expected_exposures)
                self.assertEqual([row["asset_id"] for row in rows], expected)
                self.assertTrue(all(row["priority"] == "P2" for row in rows))

    def test_p2_epss_order_and_stability_within_each_exposure_group(self):
        cases = [("missing-first", None), ("tie-first", 0.5), ("zero", 0.0),
                 ("high", 0.9), ("tie-second", 0.5), ("missing-second", None), ("low", 0.1)]
        findings = []
        epss = {}
        for label, score in cases:
            for exposure in ("false", "unknown", "true"):
                cve = f"CVE-2099-{1000 + len(findings)}"
                findings.append({"asset_id": f"{exposure}-{label}", "criticality": "critical",
                                 "cve": cve, "internet_exposed": exposure, "owner_team": "unknown"})
                # Percentiles deliberately oppose score ordering and tie stability.
                epss[cve] = {"epss_score": score, "epss_percentile": 1.0 if label == "tie-second" else 0.0}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir(exist_ok=True)
            (root / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\n")
            (root / "state").mkdir()
            (root / "state" / "remediation_status.csv").write_text("asset_id,cve,remediation_status\n")
            with patch("vulnops.ROOT", root), patch.object(self, "read_fixture_findings", return_value=findings):
                with patch("vulnops.load_kev", return_value=set()), patch("vulnops.load_epss", return_value=epss):
                    with patch("vulnops.write_queue", wraps=vulnops.write_queue) as write:
                        with patch("sys.stdout", new_callable=io.StringIO):
                            self.assertEqual(self.run_fixture_main(), 0)
            results = write.call_args.args[1]
            expected = [f"{exposure}-{label}" for exposure in ("true", "unknown", "false")
                        for label in ("high", "tie-first", "tie-second", "low", "zero", "missing-first", "missing-second")]
            self.assertEqual([row["asset_id"] for row in results], expected)
            originals = {row["asset_id"]: row for row in findings}
            for row in results:
                original = originals[row["asset_id"]]
                self.assertEqual(row, {**original, **epss[row["cve"]], "kev": "false", "priority": "P2",
                                       "reason": "Rule 3: CVE is not in CISA KEV.", "remediation_status": "open",
                                       "verification_status": "not_applicable"})
            with (root / "output" / "remediation_queue.csv").open(newline="") as output:
                reader = csv.DictReader(output)
                self.assertEqual(reader.fieldnames, ["asset_id", "criticality", "cve", "internet_exposed", "owner_team",
                                                    "kev", "epss_score", "epss_percentile", "priority", "reason", "remediation_status"])
                self.assertEqual([row["asset_id"] for row in reader], expected)

    def test_p2_missing_epss_sorts_after_numeric_zero_without_changing_values(self):
        scores = {"A": 0.80, "B": None, "C": 0.00, "D": 0.10}
        for assets, expected in (("ABC", ["A", "C", "B"]), ("ABCD", ["A", "D", "C", "B"])):
            with self.subTest(assets=assets), tempfile.TemporaryDirectory() as directory:
                findings = [{"asset_id": asset, "criticality": "critical", "cve": f"CVE-2099-{1000 + index}",
                             "internet_exposed": "unknown"}
                            for index, asset in enumerate(assets)]
                epss = {row["cve"]: {"epss_score": scores[row["asset_id"]], "epss_percentile": None}
                        for row in findings}
                root = Path(directory)
                (root / "data").mkdir(exist_ok=True)
                (root / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\n")
                (root / "state").mkdir()
                (root / "state" / "remediation_status.csv").write_text("asset_id,cve,remediation_status\n")
                with patch("vulnops.ROOT", root), patch.object(self, "read_fixture_findings", return_value=findings):
                    with patch("vulnops.load_kev", return_value=set()), patch("vulnops.load_epss", return_value=epss):
                        with patch("vulnops.write_queue", wraps=vulnops.write_queue) as write:
                            with patch("sys.stdout", new_callable=io.StringIO):
                                self.assertEqual(self.run_fixture_main(), 0)
                output = write.call_args.args[1]
                self.assertEqual([row["asset_id"] for row in output], expected)
                self.assertTrue(all(row["priority"] == "P2" for row in output))
                by_asset = {row["asset_id"]: row for row in output}
                self.assertEqual(by_asset["C"]["epss_score"], 0.00)
                self.assertIsInstance(by_asset["C"]["epss_score"], float)
                self.assertIsNone(by_asset["B"]["epss_score"])
                self.assertIsNone(epss[findings[1]["cve"]]["epss_score"])
                with (root / "output" / "remediation_queue.csv").open(newline="") as csv_file:
                    rows = list(csv.DictReader(csv_file))
                self.assertEqual([row["asset_id"] for row in rows], expected)
                csv_by_asset = {row["asset_id"]: row for row in rows}
                self.assertEqual(csv_by_asset["C"]["epss_score"], "0.0")
                self.assertEqual(csv_by_asset["B"]["epss_score"], "")

    def test_main_preserves_v0_classification_and_ranks_only_p2_by_epss(self):
        source = ("asset_id,criticality,cve,internet_exposed,owner_team\n"
                  "zero,critical,CVE-2099-10000,true,unknown\n"
                  "p1,medium,CVE-2021-44228,false,unknown\n"
                  "missing,critical,CVE-2099-10001,unknown,unknown\n"
                  "p0,critical,CVE-2021-44228,false,unknown\n"
                  "tie-first,low,CVE-2099-10003,false,unknown\n"
                  "p0-high,critical,CVE-2021-44229,true,unknown\n"
                  "p1-high,medium,CVE-2021-44229,true,unknown\n"
                  "tie-second,critical,CVE-2099-10004,true,unknown\n"
                  "missing-second,low,CVE-2099-10005,unknown,unknown\n"
                  "p0-missing,critical,CVE-2021-44230,unknown,unknown\n"
                  "p1-missing,medium,CVE-2021-44230,unknown,unknown\n"
                  "high-epss,critical,CVE-2099-10002,false,unknown\n")
        kev_cves = {"CVE-2021-44228", "CVE-2021-44229", "CVE-2021-44230"}
        kev = {"vulnerabilities": [{"cveID": cve} for cve in sorted(kev_cves)]}
        epss = {"status": "OK", "status-code": 200, "total": 6, "data": [
            {"cve": "CVE-2021-44228", "epss": "0.001", "percentile": "0.25"},
            {"cve": "CVE-2021-44229", "epss": "0.99", "percentile": "0.999"},
            {"cve": "CVE-2099-10000", "epss": "0", "percentile": "0"},
            {"cve": "CVE-2099-10002", "epss": "0.99", "percentile": "0.001"},
            {"cve": "CVE-2099-10003", "epss": "0.5", "percentile": "0.9"},
            {"cve": "CVE-2099-10004", "epss": "0.5", "percentile": "0.1"},
        ]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir(exist_ok=True)
            (root / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\n")
            (root / "state").mkdir()
            (root / "state" / "remediation_status.csv").write_text("asset_id,cve,remediation_status\n")
            (root / "data").mkdir(exist_ok=True)
            input_path = root / "data" / "finding_fixture.csv"
            input_path.write_text(source)
            baseline = vulnops.prioritize(self.read_fixture_findings(input_path), kev_cves)
            outputs = []
            for run in range(2):
                with self.subTest(run=run + 1):
                    responses = [io.BytesIO(json.dumps(feed).encode()) for feed in (kev, epss)]
                    with patch("vulnops.ROOT", root), patch("vulnops.urlopen", side_effect=responses) as request:
                        with patch("sys.stdout", new_callable=io.StringIO):
                            self.assertEqual(self.run_fixture_main(), 0)
                    self.assertEqual(request.call_count, 2)
                    self.assertEqual(request.call_args_list[0].args[0], vulnops.KEV_URL)
                    self.assertEqual(urlparse(request.call_args_list[1].args[0]).path, "/data/v1/epss")
                    outputs.append((root / "output" / "remediation_queue.csv").read_bytes())
            self.assertEqual(outputs[0], outputs[1])
            with (root / "output" / "remediation_queue.csv").open(newline="") as output:
                reader = csv.DictReader(output)
                self.assertEqual(reader.fieldnames, ["asset_id", "criticality", "cve", "internet_exposed", "owner_team", "kev",
                                                    "epss_score", "epss_percentile", "priority", "reason", "remediation_status"])
                rows = list(reader)
            baseline_by_asset = {row["asset_id"]: row for row in baseline}
            self.assertEqual(len(rows), len(baseline))
            for row in rows:
                original = baseline_by_asset[row["asset_id"]]
                self.assertEqual({key: row[key] for key in original}, original)
            self.assertEqual([row["asset_id"] for row in rows], [
                "p0", "p0-high", "p0-missing", "p1", "p1-high", "p1-missing",
                "tie-second", "zero", "missing", "missing-second", "high-epss", "tie-first",
            ])
            self.assertEqual([row["priority"] for row in rows], ["P0"] * 3 + ["P1"] * 3 + ["P2"] * 6)
            self.assertEqual([row["epss_score"] for row in rows], [
                "0.001", "0.99", "", "0.001", "0.99", "", "0.5", "0.0", "", "", "0.99", "0.5",
            ])
            self.assertEqual([row["epss_percentile"] for row in rows], [
                "0.25", "0.999", "", "0.25", "0.999", "", "0.1", "0.0", "", "", "0.001", "0.9",
            ])

    def test_epss_failure_stops_run_and_preserves_existing_queue(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir(exist_ok=True)
            (root / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\n")
            (root / "state").mkdir()
            (root / "state" / "remediation_status.csv").write_text("asset_id,cve,remediation_status\n")
            (root / "data").mkdir(exist_ok=True)
            (root / "output").mkdir()
            (root / "data" / "finding_fixture.csv").write_text("asset_id,criticality,cve,internet_exposed,owner_team\nserver,critical,CVE-2021-44228,unknown,unknown\n")
            queue = root / "output" / "remediation_queue.csv"
            queue.write_text("previous output\n")
            for failure in (URLError("simulated outage"), io.BytesIO(b"invalid json")):
                with self.subTest(failure=failure):
                    kev = io.BytesIO(b'{"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}')
                    with patch("vulnops.ROOT", root), patch("vulnops.urlopen", side_effect=[kev, failure]):
                        with patch("sys.stderr", new_callable=io.StringIO) as stderr:
                            self.assertEqual(self.run_fixture_main(), 1)
                    self.assertIn("FIRST EPSS retrieval failed", stderr.getvalue())
                    self.assertEqual(queue.read_text(), "previous output\n")

    def test_failed_download_leaves_existing_queue_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir(exist_ok=True)
            (root / "data" / "verification_results.csv").write_text("asset_id,cve,vulnerability_present\n")
            (root / "state").mkdir()
            (root / "state" / "remediation_status.csv").write_text("asset_id,cve,remediation_status\n")
            (root / "data").mkdir(exist_ok=True)
            (root / "output").mkdir()
            (root / "data" / "finding_fixture.csv").write_text("asset_id,criticality,cve,internet_exposed,owner_team\nserver,critical,CVE-2021-44228,unknown,unknown\n")
            queue = root / "output" / "remediation_queue.csv"
            queue.write_text("previous output\n")
            with patch("vulnops.ROOT", root), patch("vulnops.urlopen", side_effect=URLError("download failed")):
                with patch("sys.stderr", new_callable=io.StringIO) as stderr:
                    self.assertEqual(self.run_fixture_main(), 1)
            self.assertIn("download failed", stderr.getvalue())
            self.assertEqual(queue.read_text(), "previous output\n")


if __name__ == "__main__":
    unittest.main()
