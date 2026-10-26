"""Load findings, enrich with CISA KEV, prioritize, explain, and write a CSV."""

import csv
import json
from pathlib import Path
import re
import sys
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parent
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REQUIRED_COLUMNS = ("asset_id", "criticality", "cve")
RESULT_COLUMNS = ("kev", "priority", "reason")


def load_findings(path):
    with path.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        columns = reader.fieldnames
        if not columns or len(columns) != 3 or set(columns) != set(REQUIRED_COLUMNS):
            raise ValueError("Findings CSV must contain exactly asset_id, criticality, and cve columns.")
        findings = []
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise ValueError(f"CSV record ending at line {reader.line_num} has the wrong number of fields.")
            for column in REQUIRED_COLUMNS:
                row[column] = row[column].strip()
                if not row[column]:
                    raise ValueError(f"CSV record ending at line {reader.line_num} has an empty {column}.")
            row["cve"] = row["cve"].upper()
            row["criticality"] = row["criticality"].lower()
            if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", row["cve"]):
                raise ValueError(f"CSV record ending at line {reader.line_num} has an invalid CVE: {row['cve']}.")
            findings.append(row)
    return findings


def load_kev():
    with urlopen(KEV_URL, timeout=30) as response:
        catalogue = json.load(response)
    if not isinstance(catalogue, dict) or not isinstance(catalogue.get("vulnerabilities"), list):
        raise ValueError("CISA KEV catalogue must contain a vulnerabilities list.")
    cves = set()
    for entry in catalogue["vulnerabilities"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("cveID"), str):
            raise ValueError("CISA KEV catalogue contains an entry without a valid cveID.")
        cve = entry["cveID"].strip().upper()
        if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cve):
            raise ValueError("CISA KEV catalogue contains an invalid cveID.")
        cves.add(cve)
    if not cves:
        raise ValueError("CISA KEV catalogue is empty; cannot reliably prioritize findings.")
    return cves


def prioritize(findings, kev_cves):
    results = []
    for finding in findings:
        is_kev = finding["cve"] in kev_cves
        if is_kev and finding["criticality"] == "critical":
            priority = "P0"
            reason = "Rule 1: CVE is in CISA KEV and asset criticality is critical."
        elif is_kev:
            priority = "P1"
            reason = "Rule 2: CVE is in CISA KEV; asset criticality is not critical."
        else:
            priority = "P2"
            reason = "Rule 3: CVE is not in CISA KEV."
        results.append({**finding, "kev": str(is_kev).lower(), "priority": priority, "reason": reason})
    return sorted(results, key=lambda row: row["priority"])


def write_queue(path, results):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=[*REQUIRED_COLUMNS, *RESULT_COLUMNS])
        writer.writeheader()
        writer.writerows(results)


def main():
    try:
        findings = load_findings(ROOT / "data" / "findings.csv")
        kev_cves = load_kev()
        results = prioritize(findings, kev_cves)
        write_queue(ROOT / "output" / "remediation_queue.csv", results)
    except (OSError, ValueError, csv.Error) as error:
        print(f"VulnOps failed: {error}", file=sys.stderr)
        return 1
    print(f"Wrote {len(results)} findings to output/remediation_queue.csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
