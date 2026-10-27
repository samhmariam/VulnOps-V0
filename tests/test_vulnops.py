import csv
import inspect
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

    def test_prioritize_does_not_reference_internet_exposed(self):
        self.assertNotIn("internet_exposed", inspect.getsource(vulnops.prioritize))

    def test_csv_pipeline_normalizes_and_writes_fixed_columns(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "findings.csv"
            source.write_text('cve,asset_id,criticality,internet_exposed\n cve-2021-44228 ,"server, UK", Critical ,unknown\n')
            findings = vulnops.load_findings(source)
            destination = Path(directory) / "output" / "remediation_queue.csv"
            vulnops.write_queue(destination, vulnops.prioritize(findings, {"CVE-2021-44228"}))
            with destination.open(newline="") as output:
                reader = csv.DictReader(output)
                self.assertEqual(reader.fieldnames, ["asset_id", "criticality", "cve", "internet_exposed", "kev",
                                                    "epss_score", "epss_percentile", "priority", "reason"])
                rows = list(reader)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["priority"], "P0")
            self.assertEqual(rows[0]["asset_id"], "server, UK")
            self.assertEqual(rows[0]["cve"], "CVE-2021-44228")
            self.assertEqual(rows[0]["internet_exposed"], "unknown")

    def test_internet_exposed_accepts_and_retains_three_strings(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "findings.csv"
            for value in ("true", "false", "unknown"):
                with self.subTest(value=value):
                    source.write_text(f"asset_id,criticality,cve,internet_exposed\nserver,critical,CVE-2021-44228,{value}\n")
                    finding = vulnops.load_findings(source)[0]
                    self.assertEqual(finding["internet_exposed"], value)
                    self.assertIsInstance(finding["internet_exposed"], str)

    def test_internet_exposed_survives_every_pipeline_stage(self):
        source = ("asset_id,criticality,cve,internet_exposed\n"
                  "p2-low,critical,CVE-2099-10001,true\n"
                  "p1,medium,CVE-2099-10002,false\n"
                  "p2-missing,low,CVE-2099-10003,false\n"
                  "p0,critical,CVE-2099-10002,unknown\n"
                  "p2-high,medium,CVE-2099-10004,unknown\n"
                  "p2-zero,low,CVE-2099-10005,true\n")
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
            (root / "data").mkdir()
            (root / "data" / "findings.csv").write_text(source)
            responses = [io.BytesIO(json.dumps(feed).encode()) for feed in (kev, epss)]
            with patch("vulnops.ROOT", root), patch("vulnops.urlopen", side_effect=responses):
                with patch("vulnops.enrich_with_epss", wraps=vulnops.enrich_with_epss) as enrich:
                    with patch("vulnops.prioritize", wraps=vulnops.prioritize) as classify:
                        with patch("vulnops.write_queue", wraps=vulnops.write_queue) as write:
                            with patch("sys.stdout", new_callable=io.StringIO):
                                self.assertEqual(vulnops.main(), 0)
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
                             ["p0", "p1", "p2-high", "p2-low", "p2-zero", "p2-missing"])
            self.assertEqual([row["kev"] for row in csv_rows],
                             ["true", "true", "false", "false", "false", "false"])

    def test_exposure_is_the_only_change_to_v02_csv_output(self):
        source = ("asset_id,criticality,cve,internet_exposed\n"
                  "p2-false,critical,CVE-2099-10001,false\n"
                  "p1,medium,CVE-2099-10002,true\n"
                  "p2-unknown,critical,CVE-2099-10003,unknown\n"
                  "p0,critical,CVE-2099-10002,false\n"
                  "p2-true,critical,CVE-2099-10004,true\n")
        epss = {cve: {"epss_score": score, "epss_percentile": None} for cve, score in (
            ("CVE-2099-10001", 0.1), ("CVE-2099-10002", 0.01),
            ("CVE-2099-10003", 0.4), ("CVE-2099-10004", 0.9),
        )}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir()
            input_path = root / "data" / "findings.csv"
            input_path.write_text(source)
            findings = vulnops.load_findings(input_path)
            baseline_findings = [{key: value for key, value in row.items() if key != "internet_exposed"}
                                 for row in findings]
            outputs = []
            for inputs in (baseline_findings, findings):
                with patch("vulnops.ROOT", root), patch("vulnops.load_findings", return_value=inputs):
                    with patch("vulnops.load_kev", return_value={"CVE-2099-10002"}):
                        with patch("vulnops.load_epss", return_value=epss), patch("sys.stdout", new_callable=io.StringIO):
                            self.assertEqual(vulnops.main(), 0)
                with (root / "output" / "remediation_queue.csv").open(newline="") as output:
                    reader = csv.DictReader(output)
                    self.assertEqual(reader.fieldnames, ["asset_id", "criticality", "cve", "internet_exposed",
                                                        "kev", "epss_score", "epss_percentile", "priority", "reason"])
                    outputs.append(list(reader))
            baseline, rows = outputs
            self.assertEqual([{key: value for key, value in row.items() if key != "internet_exposed"} for row in rows],
                             [{key: value for key, value in row.items() if key != "internet_exposed"} for row in baseline])
            self.assertEqual([row["asset_id"] for row in rows], ["p0", "p1", "p2-true", "p2-unknown", "p2-false"])
            self.assertEqual([(row["priority"], row["internet_exposed"]) for row in rows], [
                ("P0", "false"), ("P1", "true"), ("P2", "true"), ("P2", "unknown"), ("P2", "false"),
            ])

    def test_internet_exposed_rejects_invalid_values(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "findings.csv"
            for value in ("yes", "", "maybe", "True", "FALSE", "Unknown"):
                with self.subTest(value=value):
                    source.write_text(f"asset_id,criticality,cve,internet_exposed\nserver,critical,CVE-2021-44228,{value}\n")
                    with self.assertRaisesRegex(ValueError, "internet_exposed"):
                        vulnops.load_findings(source)

    def test_internet_exposed_column_is_required(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "findings.csv"
            source.write_text("asset_id,criticality,cve\nserver,critical,CVE-2021-44228\n")
            with self.assertRaisesRegex(ValueError, "internet_exposed"):
                vulnops.load_findings(source)

    def test_invalid_inputs_are_rejected(self):
        invalid_csvs = [
            "",
            "asset_id,cve,internet_exposed\nserver,CVE-2021-44228,unknown\n",
            "asset_id,criticality,cve,cve,internet_exposed\n",
            "asset_id,criticality,cve,internet_exposed,priority\n",
            "asset_id,criticality,cve,internet_exposed,owner\nserver,critical,CVE-2021-44228,unknown,Ops\n",
            "asset_id,criticality,cve,internet_exposed\n,critical,CVE-2021-44228,unknown\n",
            "asset_id,criticality,cve,internet_exposed\nserver,,CVE-2021-44228,unknown\n",
            "asset_id,criticality,cve,internet_exposed\nserver,critical,invalid,unknown\n",
            "asset_id,criticality,cve,internet_exposed\nserver,critical\n",
            "asset_id,criticality,cve,internet_exposed\nserver,critical,CVE-2021-44228,unknown,extra\n",
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
            source.write_text("asset_id,criticality,cve,internet_exposed\n")
            findings = vulnops.load_findings(source)
            destination = Path(directory) / "queue.csv"
            vulnops.write_queue(destination, vulnops.prioritize(findings, {"CVE-2021-44228"}))
            self.assertEqual(destination.read_text().strip(),
                             "asset_id,criticality,cve,internet_exposed,kev,epss_score,epss_percentile,priority,reason")

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
        findings = [{"asset_id": asset, "criticality": criticality, "cve": f"CVE-2099-{1000 + index}"}
                    for index, (asset, criticality, kev, score) in enumerate(cases)]
        kev_cves = {finding["cve"] for finding, case in zip(findings, cases) if case[2]}
        epss = {finding["cve"]: {"epss_score": case[3], "epss_percentile": None}
                for finding, case in zip(findings, cases)}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch("vulnops.ROOT", root), patch("vulnops.load_findings", return_value=findings):
                with patch("vulnops.load_kev", return_value=kev_cves), patch("vulnops.load_epss", return_value=epss):
                    with patch("sys.stdout", new_callable=io.StringIO):
                        self.assertEqual(vulnops.main(), 0)
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
            {"asset_id": "A", "cve": "CVE-2099-10001", "criticality": "critical"},
            {"asset_id": "B", "cve": "CVE-2099-10002", "criticality": "medium"},
            {"asset_id": "C", "cve": "CVE-2099-10003", "criticality": "critical"},
            {"asset_id": "D", "cve": "CVE-2099-10004", "criticality": "medium"},
            {"asset_id": "E", "cve": "CVE-2099-10005", "criticality": "low"},
        ]
        kev_cves = {findings[0]["cve"], findings[1]["cve"]}
        epss = {finding["cve"]: {"epss_score": score, "epss_percentile": None}
                for finding, score in zip(findings, [0.001, 0.001, 0.99, 0.80, 0.20])}
        baseline = {row["asset_id"]: row for row in vulnops.prioritize(findings, kev_cves)}
        # Shuffle input so neither priority grouping nor P2 ranking passes by accident.
        shuffled = [findings[index] for index in [4, 2, 1, 3, 0]]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch("vulnops.ROOT", root), patch("vulnops.load_findings", return_value=shuffled):
                with patch("vulnops.load_kev", return_value=kev_cves), patch("vulnops.load_epss", return_value=epss):
                    with patch("sys.stdout", new_callable=io.StringIO):
                        self.assertEqual(vulnops.main(), 0)
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

    def test_internet_exposure_cannot_change_p2_epss_ranking(self):
        cases = [
            # Reverse the first input to prove EPSS sorting actually occurs.
            ([('C', 'unknown', 0.40), ('B', 'true', 0.70), ('A', 'false', 0.90)], ['A', 'B', 'C']),
            ([('D', 'true', None), ('E', 'false', 0.01)], ['E', 'D']),
        ]
        for inputs, expected in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "data").mkdir()
                findings = [{"asset_id": asset, "criticality": "critical",
                             "cve": f"CVE-2099-{1000 + index}", "internet_exposed": exposure}
                            for index, (asset, exposure, score) in enumerate(inputs)]
                with (root / "data" / "findings.csv").open("w", newline="") as source:
                    writer = csv.DictWriter(source, fieldnames=["asset_id", "criticality", "cve", "internet_exposed"])
                    writer.writeheader()
                    writer.writerows(findings)
                epss = {finding["cve"]: {"epss_score": case[2], "epss_percentile": None}
                        for finding, case in zip(findings, inputs)}
                with patch("vulnops.ROOT", root), patch("vulnops.load_kev", return_value=set()):
                    with patch("vulnops.load_epss", return_value=epss):
                        with patch("sys.stdout", new_callable=io.StringIO):
                            self.assertEqual(vulnops.main(), 0)
                with (root / "output" / "remediation_queue.csv").open(newline="") as output:
                    rows = list(csv.DictReader(output))
                self.assertEqual([row["asset_id"] for row in rows], expected)
                self.assertTrue(all(row["priority"] == "P2" for row in rows))
                by_asset = {row["asset_id"]: row for row in rows}
                for asset, exposure, score in inputs:
                    self.assertEqual(by_asset[asset]["internet_exposed"], exposure)
                    self.assertEqual(by_asset[asset]["epss_score"], "" if score is None else str(score))

    def test_queue_sorting_does_not_reference_internet_exposed(self):
        # Queue sorting currently lives directly in main().
        self.assertNotIn("internet_exposed", inspect.getsource(vulnops.main))

    def test_p2_missing_epss_sorts_after_numeric_zero_without_changing_values(self):
        scores = {"A": 0.80, "B": None, "C": 0.00, "D": 0.10}
        for assets, expected in (("ABC", ["A", "C", "B"]), ("ABCD", ["A", "D", "C", "B"])):
            with self.subTest(assets=assets), tempfile.TemporaryDirectory() as directory:
                findings = [{"asset_id": asset, "criticality": "critical", "cve": f"CVE-2099-{1000 + index}"}
                            for index, asset in enumerate(assets)]
                epss = {row["cve"]: {"epss_score": scores[row["asset_id"]], "epss_percentile": None}
                        for row in findings}
                root = Path(directory)
                with patch("vulnops.ROOT", root), patch("vulnops.load_findings", return_value=findings):
                    with patch("vulnops.load_kev", return_value=set()), patch("vulnops.load_epss", return_value=epss):
                        with patch("vulnops.write_queue", wraps=vulnops.write_queue) as write:
                            with patch("sys.stdout", new_callable=io.StringIO):
                                self.assertEqual(vulnops.main(), 0)
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
        source = ("asset_id,criticality,cve,internet_exposed\n"
                  "zero,critical,CVE-2099-10000,true\n"
                  "p1,medium,CVE-2021-44228,false\n"
                  "missing,critical,CVE-2099-10001,unknown\n"
                  "p0,critical,CVE-2021-44228,false\n"
                  "tie-first,low,CVE-2099-10003,false\n"
                  "p0-high,critical,CVE-2021-44229,true\n"
                  "p1-high,medium,CVE-2021-44229,true\n"
                  "tie-second,critical,CVE-2099-10004,true\n"
                  "missing-second,low,CVE-2099-10005,unknown\n"
                  "p0-missing,critical,CVE-2021-44230,unknown\n"
                  "p1-missing,medium,CVE-2021-44230,unknown\n"
                  "high-epss,critical,CVE-2099-10002,false\n")
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
            (root / "data").mkdir()
            input_path = root / "data" / "findings.csv"
            input_path.write_text(source)
            baseline = vulnops.prioritize(vulnops.load_findings(input_path), kev_cves)
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
                self.assertEqual(reader.fieldnames, ["asset_id", "criticality", "cve", "internet_exposed", "kev",
                                                    "epss_score", "epss_percentile", "priority", "reason"])
                rows = list(reader)
            baseline_by_asset = {row["asset_id"]: row for row in baseline}
            self.assertEqual(len(rows), len(baseline))
            for row in rows:
                original = baseline_by_asset[row["asset_id"]]
                self.assertEqual({key: row[key] for key in original}, original)
            self.assertEqual([row["asset_id"] for row in rows], [
                "p0", "p0-high", "p0-missing", "p1", "p1-high", "p1-missing",
                "high-epss", "tie-first", "tie-second", "zero", "missing", "missing-second",
            ])
            self.assertEqual([row["priority"] for row in rows], ["P0"] * 3 + ["P1"] * 3 + ["P2"] * 6)
            self.assertEqual([row["epss_score"] for row in rows], [
                "0.001", "0.99", "", "0.001", "0.99", "", "0.99", "0.5", "0.5", "0.0", "", "",
            ])
            self.assertEqual([row["epss_percentile"] for row in rows], [
                "0.25", "0.999", "", "0.25", "0.999", "", "0.001", "0.9", "0.1", "0.0", "", "",
            ])

    def test_epss_failure_stops_run_and_preserves_existing_queue(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir()
            (root / "output").mkdir()
            (root / "data" / "findings.csv").write_text("asset_id,criticality,cve,internet_exposed\nserver,critical,CVE-2021-44228,unknown\n")
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
            (root / "data" / "findings.csv").write_text("asset_id,criticality,cve,internet_exposed\nserver,critical,CVE-2021-44228,unknown\n")
            queue = root / "output" / "remediation_queue.csv"
            queue.write_text("previous output\n")
            with patch("vulnops.ROOT", root), patch("vulnops.urlopen", side_effect=URLError("download failed")):
                with patch("sys.stderr", new_callable=io.StringIO) as stderr:
                    self.assertEqual(vulnops.main(), 1)
            self.assertIn("download failed", stderr.getvalue())
            self.assertEqual(queue.read_text(), "previous output\n")


if __name__ == "__main__":
    unittest.main()
