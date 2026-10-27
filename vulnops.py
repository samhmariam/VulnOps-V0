"""Load findings, enrich with KEV and EPSS, prioritize, explain, and write a CSV."""

import csv
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlencode
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parent
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
FINDING_COLUMNS = ("asset_id", "criticality", "cve", "internet_exposed", "owner_team")
RESULT_COLUMNS = ("kev", "epss_score", "epss_percentile", "priority", "reason", "remediation_status")


def load_scanner_output(path):
    """Read scanner records, validating structure without changing their values."""
    with path.open(encoding="utf-8-sig") as source:
        payload = json.load(source)
    if not isinstance(payload, dict) or "value" not in payload:
        raise ValueError("Scanner output must be a JSON object containing a value list.")
    if not isinstance(payload["value"], list):
        raise ValueError("Scanner output value must be a list.")
    for index, record in enumerate(payload["value"], start=1):
        if not isinstance(record, dict):
            raise ValueError(f"Scanner observation {index} must be an object.")
        for field in ("machineId", "cveId", "severity"):
            if not isinstance(record.get(field), str) or not record[field].strip():
                raise ValueError(f"Scanner observation {index} requires a non-empty {field} string.")
    return payload["value"]


def normalize_scanner_observations(records):
    """Keep one scanner observation per machine/CVE, rejecting severity conflicts."""
    observations = {}
    for entry in records:
        if not isinstance(entry, dict) or any(
                not isinstance(entry.get(field), str) or not entry[field].strip()
                for field in ("machineId", "cveId", "severity")):
            raise ValueError("Scanner observation requires non-empty machineId, cveId, and severity strings.")
        machine_id = entry["machineId"].strip()
        cve = entry["cveId"].strip().upper()
        if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cve):
            raise ValueError("Scanner observation contains an invalid CVE.")
        severity = entry["severity"].strip().lower()
        if severity not in ("critical", "high", "medium", "low"):
            raise ValueError("Scanner observation has unexpected severity; expected critical, high, medium, or low.")
        key = (machine_id, cve)
        if key in observations:
            if observations[key]["severity"] != severity:
                raise ValueError("Scanner observations have conflicting severity for the same machine/CVE.")
            continue
        observations[key] = {"scanner_machine_id": machine_id, "cve": cve, "severity": severity}
    return list(observations.values())


def load_asset_context(path):
    """Load a one-to-one scanner machine to local asset context mapping."""
    required = ("scanner_machine_id", "asset_id", "asset_criticality", "internet_exposed", "owner_team")
    context = {}
    asset_ids = set()
    with path.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        columns = reader.fieldnames
        if not columns or len(columns) != len(required) or set(columns) != set(required):
            raise ValueError("Asset context CSV must contain exactly scanner_machine_id, asset_id, asset_criticality, internet_exposed, and owner_team columns.")
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise ValueError(f"Asset context record ending at line {reader.line_num} has the wrong number of fields.")
            for column in required:
                row[column] = row[column].strip()
                if not row[column]:
                    raise ValueError(f"Asset context record ending at line {reader.line_num} has an empty {column}.")
            row["asset_criticality"] = row["asset_criticality"].lower()
            if row["asset_criticality"] not in ("critical", "high", "medium", "low"):
                raise ValueError(f"Asset context record ending at line {reader.line_num} has invalid asset_criticality; expected critical, high, medium, or low.")
            if row["internet_exposed"] not in ("true", "false", "unknown"):
                raise ValueError(f"Asset context record ending at line {reader.line_num} has invalid internet_exposed; expected true, false, or unknown.")
            machine_id = row.pop("scanner_machine_id")
            if machine_id in context:
                raise ValueError(f"Duplicate scanner_machine_id {machine_id!r} at line {reader.line_num}.")
            if row["asset_id"] in asset_ids:
                raise ValueError(f"Duplicate asset_id {row['asset_id']!r} at line {reader.line_num}.")
            context[machine_id] = row
            asset_ids.add(row["asset_id"])
    return context


def build_findings(observations, asset_context):
    """Join scanner facts and local context, leaving scanner identifiers behind."""
    findings = []
    for observation in observations:
        machine_id = observation["scanner_machine_id"]
        if machine_id not in asset_context:
            raise ValueError(f"Scanner observation for {machine_id!r} has no matching asset context; check asset_context.csv.")
        context = asset_context[machine_id]
        findings.append({
            "asset_id": context["asset_id"],
            "cve": observation["cve"],
            "severity": observation["severity"],
            "asset_criticality": context["asset_criticality"],
            "internet_exposed": context["internet_exposed"],
            "owner_team": context["owner_team"],
        })
    return findings


def load_remediation_statuses(path):
    """Load one open/resolved status per (asset_id, cve), rejecting duplicates."""
    required = ("asset_id", "cve", "remediation_status")
    statuses = {}
    with path.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        columns = reader.fieldnames
        if not columns or len(columns) != 3 or set(columns) != set(required):
            raise ValueError("Remediation state CSV must contain exactly asset_id, cve, and remediation_status columns.")
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise ValueError(f"Remediation state record ending at line {reader.line_num} has the wrong number of fields.")
            for column in required:
                row[column] = row[column].strip()
                if not row[column]:
                    raise ValueError(f"Remediation state record ending at line {reader.line_num} has an empty {column}.")
            row["cve"] = row["cve"].upper()
            if row["remediation_status"] not in ("open", "resolved"):
                raise ValueError(f"Remediation state record ending at line {reader.line_num} has invalid remediation_status; expected open or resolved.")
            key = (row["asset_id"], row["cve"])
            if key in statuses:
                raise ValueError(f"Duplicate remediation state for {key!r} at line {reader.line_num}.")
            statuses[key] = row["remediation_status"]
    return statuses


def load_verification_results(path):
    """Load explicit presence evidence as booleans keyed by (asset_id, cve)."""
    required = ("asset_id", "cve", "vulnerability_present")
    results = {}
    with path.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        columns = reader.fieldnames
        if not columns or len(columns) != 3 or set(columns) != set(required):
            raise ValueError("Verification CSV must contain exactly asset_id, cve, and vulnerability_present columns.")
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise ValueError(f"Verification record ending at line {reader.line_num} has the wrong number of fields.")
            for column in required:
                row[column] = row[column].strip()
                if not row[column]:
                    raise ValueError(f"Verification record ending at line {reader.line_num} has an empty {column}.")
            row["cve"] = row["cve"].upper()
            if row["vulnerability_present"] not in ("true", "false"):
                raise ValueError(f"Verification record ending at line {reader.line_num} has invalid vulnerability_present; expected true or false.")
            key = (row["asset_id"], row["cve"])
            if key in results:
                raise ValueError(f"Duplicate verification result for {key!r} at line {reader.line_num}.")
            results[key] = row["vulnerability_present"] == "true"
    return results


def apply_remediation_status(findings, statuses):
    """Attach recorded asset/CVE state, defaulting unrecorded findings to open."""
    return [
        {**finding, "remediation_status": statuses.get((finding["asset_id"], finding["cve"]), "open")}
        for finding in findings
    ]


def apply_verification_status(findings, verification_results):
    """Attach verification evidence without changing the remediation claim."""
    results = []
    for finding in findings:
        key = (finding["asset_id"], finding["cve"])
        if finding["remediation_status"] == "open":
            status = "not_applicable"
        elif finding["remediation_status"] != "resolved":
            raise ValueError(f"Invalid remediation_status for {key!r}; expected open or resolved.")
        elif key not in verification_results:
            status = "unverified"
        elif verification_results[key] is True:
            status = "failed"
        elif verification_results[key] is False:
            status = "passed"
        else:
            raise ValueError(f"Invalid verification evidence for {key!r}; expected a boolean.")
        results.append({**finding, "verification_status": status})
    return results


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


def load_epss(cves):
    """Return FIRST probabilities as floats; absent CVEs have two None values."""
    cves = sorted(set(cves))
    if not cves:
        return {}
    if any(not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cve) for cve in cves):
        raise ValueError("EPSS lookup requires valid, uppercase CVE IDs.")
    cve_query = ",".join(cves)
    if len(cve_query) > 2000:
        raise ValueError("FIRST EPSS cve parameter exceeds 2000 characters; V0.1 does not implement batching.")
    query = urlencode({"cve": cve_query, "limit": len(cves)})
    results = {cve: {"epss_score": None, "epss_percentile": None} for cve in cves}
    try:
        with urlopen(f"{EPSS_URL}?{query}", timeout=30) as response:
            payload = json.load(response)
        if (not isinstance(payload, dict) or payload.get("status") != "OK"
                or payload.get("status-code") != 200
                or not isinstance(payload.get("data"), list)):
            raise ValueError("expected a successful FIRST response with a data list")
        entries = payload["data"]
        if type(payload.get("total")) is not int or payload["total"] != len(entries):
            raise ValueError("FIRST response has an invalid total or incomplete results")
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("cve"), str):
                raise ValueError("FIRST response contains an invalid CVE record")
            cve = entry["cve"]
            if cve not in results or results[cve]["epss_score"] is not None:
                raise ValueError("FIRST response contains an unrequested or duplicate CVE")
            values = {}
            for source, target in (("epss", "epss_score"), ("percentile", "epss_percentile")):
                raw = entry[source]
                if isinstance(raw, bool):
                    raise ValueError(f"invalid {source} for {cve}")
                value = float(raw)
                if not 0 <= value <= 1:
                    raise ValueError(f"{source} for {cve} must be between 0 and 1")
                values[target] = value
            results[cve] = values
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise ValueError(f"FIRST EPSS retrieval failed: {error}") from error
    return results


def enrich_with_epss(findings, epss_by_cve):
    """Return finding copies with EPSS values, preserving all other fields."""
    enriched = []
    for finding in findings:
        epss = epss_by_cve.get(finding["cve"], {})
        enriched.append({
            **finding,
            "epss_score": epss.get("epss_score"),
            "epss_percentile": epss.get("epss_percentile"),
        })
    return enriched


def prioritize(findings, kev_cves):
    results = []
    for finding in findings:
        is_kev = finding["cve"] in kev_cves
        if is_kev and finding["asset_criticality"] == "critical":
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
        writer = csv.DictWriter(destination, fieldnames=[*FINDING_COLUMNS, *RESULT_COLUMNS])
        writer.writeheader()
        writer.writerows({column: row.get("asset_criticality" if column == "criticality" else column)
                          for column in writer.fieldnames} for row in results)


def main():
    try:
        raw_scanner = load_scanner_output(ROOT / "data" / "mock_scanner_output.json")
        observations = normalize_scanner_observations(raw_scanner)
        asset_context = load_asset_context(ROOT / "data" / "asset_context.csv")
        findings = build_findings(observations, asset_context)
        statuses = load_remediation_statuses(ROOT / "state" / "remediation_status.csv")
        findings = apply_remediation_status(findings, statuses)
        verification_results = load_verification_results(ROOT / "data" / "verification_results.csv")
        findings = apply_verification_status(findings, verification_results)
        findings = [finding for finding in findings
                    if not (finding["remediation_status"] == "resolved" and finding["verification_status"] == "passed")]
        kev_cves = load_kev()
        cves = [finding["cve"] for finding in findings]
        epss_by_cve = load_epss(cves)
        findings = enrich_with_epss(findings, epss_by_cve)
        results = prioritize(findings, kev_cves)
        p2 = [row for row in results if row["priority"] == "P2"]
        p2.sort(key=lambda row: (
            {"true": 0, "unknown": 1, "false": 2}[row["internet_exposed"]],
            row["epss_score"] is None,
            -row["epss_score"] if row["epss_score"] is not None else 0,
        ))
        results = [row for row in results if row["priority"] != "P2"] + p2
        write_queue(ROOT / "output" / "remediation_queue.csv", results)
    except (OSError, ValueError, csv.Error) as error:
        print(f"VulnOps failed: {error}", file=sys.stderr)
        return 1
    print(f"Wrote {len(results)} findings to output/remediation_queue.csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
