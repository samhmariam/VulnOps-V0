import csv
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import URLError
from urllib.parse import parse_qs, urlparse

import vulnops


class VulnOpsTests(unittest.TestCase):
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

    def test_csv_pipeline_normalizes_and_writes_fixed_columns(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "findings.csv"
            source.write_text('cve,asset_id,criticality\n cve-2021-44228 ,"server, UK", Critical \n')
            findings = vulnops.load_findings(source)
            destination = Path(directory) / "output" / "remediation_queue.csv"
            vulnops.write_queue(destination, vulnops.prioritize(findings, {"CVE-2021-44228"}))
            with destination.open(newline="") as output:
                reader = csv.DictReader(output)
                self.assertEqual(reader.fieldnames, ["asset_id", "criticality", "cve", "kev",
                                                    "epss_score", "epss_percentile", "priority", "reason"])
                rows = list(reader)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["priority"], "P0")
            self.assertEqual(rows[0]["asset_id"], "server, UK")
            self.assertEqual(rows[0]["cve"], "CVE-2021-44228")

    def test_invalid_inputs_are_rejected(self):
        invalid_csvs = [
            "",
            "asset_id,cve\nserver,CVE-2021-44228\n",
            "asset_id,criticality,cve,cve\n",
            "asset_id,criticality,cve,priority\n",
            "asset_id,criticality,cve,owner\nserver,critical,CVE-2021-44228,Ops\n",
            "asset_id,criticality,cve\n,critical,CVE-2021-44228\n",
            "asset_id,criticality,cve\nserver,,CVE-2021-44228\n",
            "asset_id,criticality,cve\nserver,critical,invalid\n",
            "asset_id,criticality,cve\nserver,critical\n",
            "asset_id,criticality,cve\nserver,critical,CVE-2021-44228,extra\n",
        ]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "findings.csv"
            for content in invalid_csvs:
                with self.subTest(content=content):
                    source.write_text(content)
                    with self.assertRaises(ValueError):
                        vulnops.load_findings(source)

    def test_header_only_input_produces_header_only_output(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "findings.csv"
            source.write_text("asset_id,criticality,cve\n")
            findings = vulnops.load_findings(source)
            destination = Path(directory) / "queue.csv"
            vulnops.write_queue(destination, vulnops.prioritize(findings, {"CVE-2021-44228"}))
            self.assertEqual(destination.read_text().strip(),
                             "asset_id,criticality,cve,kev,epss_score,epss_percentile,priority,reason")

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

    def test_main_writes_epss_without_changing_v0_queue(self):
        source = ("asset_id,criticality,cve\n"
                  "zero,critical,CVE-2099-10000\n"
                  "p1,medium,CVE-2021-44228\n"
                  "missing,critical,CVE-2099-10001\n"
                  "p0,critical,CVE-2021-44228\n"
                  "high-epss,critical,CVE-2099-10002\n")
        kev = {"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}
        epss = {"status": "OK", "status-code": 200, "total": 3, "data": [
            {"cve": "CVE-2021-44228", "epss": "0.001", "percentile": "0.25"},
            {"cve": "CVE-2099-10000", "epss": "0", "percentile": "0"},
            {"cve": "CVE-2099-10002", "epss": "0.99", "percentile": "0.999"},
        ]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir()
            input_path = root / "data" / "findings.csv"
            input_path.write_text(source)
            baseline = vulnops.prioritize(vulnops.load_findings(input_path), {"CVE-2021-44228"})
            outputs = []
            for run in range(2):
                with self.subTest(run=run + 1):
                    responses = [io.BytesIO(json.dumps(feed).encode()) for feed in (kev, epss)]
                    with patch("vulnops.ROOT", root), patch("vulnops.urlopen", side_effect=responses) as request:
                        with patch("sys.stdout", new_callable=io.StringIO):
                            self.assertEqual(vulnops.main(), 0)
                    self.assertEqual(request.call_count, 2)
                    self.assertEqual(request.call_args_list[0].args[0], vulnops.KEV_URL)
                    self.assertEqual(urlparse(request.call_args_list[1].args[0]).path, "/data/v1/epss")
                    outputs.append((root / "output" / "remediation_queue.csv").read_bytes())
            self.assertEqual(outputs[0], outputs[1])
            with (root / "output" / "remediation_queue.csv").open(newline="") as output:
                reader = csv.DictReader(output)
                self.assertEqual(reader.fieldnames, ["asset_id", "criticality", "cve", "kev",
                                                    "epss_score", "epss_percentile", "priority", "reason"])
                rows = list(reader)
            self.assertEqual([{key: row[key] for key in original} for row, original in zip(rows, baseline)], baseline)
            self.assertEqual([row["asset_id"] for row in rows], ["p0", "p1", "zero", "missing", "high-epss"])
            self.assertEqual([row["priority"] for row in rows], ["P0", "P1", "P2", "P2", "P2"])
            self.assertEqual([row["epss_score"] for row in rows], ["0.001", "0.001", "0.0", "", "0.99"])
            self.assertEqual([row["epss_percentile"] for row in rows], ["0.25", "0.25", "0.0", "", "0.999"])

    def test_epss_failure_stops_run_and_preserves_existing_queue(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir()
            (root / "output").mkdir()
            (root / "data" / "findings.csv").write_text("asset_id,criticality,cve\nserver,critical,CVE-2021-44228\n")
            queue = root / "output" / "remediation_queue.csv"
            queue.write_text("previous output\n")
            for failure in (URLError("simulated outage"), io.BytesIO(b"invalid json")):
                with self.subTest(failure=failure):
                    kev = io.BytesIO(b'{"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}')
                    with patch("vulnops.ROOT", root), patch("vulnops.urlopen", side_effect=[kev, failure]):
                        with patch("sys.stderr", new_callable=io.StringIO) as stderr:
                            self.assertEqual(vulnops.main(), 1)
                    self.assertIn("FIRST EPSS retrieval failed", stderr.getvalue())
                    self.assertEqual(queue.read_text(), "previous output\n")

    def test_failed_download_leaves_existing_queue_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir()
            (root / "output").mkdir()
            (root / "data" / "findings.csv").write_text("asset_id,criticality,cve\nserver,critical,CVE-2021-44228\n")
            queue = root / "output" / "remediation_queue.csv"
            queue.write_text("previous output\n")
            with patch("vulnops.ROOT", root), patch("vulnops.urlopen", side_effect=URLError("download failed")):
                with patch("sys.stderr", new_callable=io.StringIO) as stderr:
                    self.assertEqual(vulnops.main(), 1)
            self.assertIn("download failed", stderr.getvalue())
            self.assertEqual(queue.read_text(), "previous output\n")


if __name__ == "__main__":
    unittest.main()
