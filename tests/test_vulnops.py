import csv
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import URLError

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

    def test_csv_pipeline_normalizes_and_writes_fixed_columns(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "findings.csv"
            source.write_text('cve,asset_id,criticality\n cve-2021-44228 ,"server, UK", Critical \n')
            findings = vulnops.load_findings(source)
            destination = Path(directory) / "output" / "remediation_queue.csv"
            vulnops.write_queue(destination, vulnops.prioritize(findings, {"CVE-2021-44228"}))
            with destination.open(newline="") as output:
                reader = csv.DictReader(output)
                self.assertEqual(reader.fieldnames, ["asset_id", "criticality", "cve", "kev", "priority", "reason"])
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
            self.assertEqual(destination.read_text().strip(), "asset_id,criticality,cve,kev,priority,reason")

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
