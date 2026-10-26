# VulnOps V0

Load findings → enrich with CISA KEV membership → prioritize → explain → output.

One Python script, no external dependencies. Requires Python 3.10 or newer and
internet access to download the official CISA KEV catalogue on each run.

## Run

From the repository root:

```sh
python3 vulnops.py
```

The script reads `data/findings.csv` and writes `output/remediation_queue.csv`.
Paths are relative to the script, so running it from another directory also works.
The output directory is created automatically. A successful run replaces the CSV.

## Input

```csv
asset_id,criticality,cve
web-server-01,high,CVE-2021-44228
identity-server-01,critical,CVE-2021-44228
workstation-01,medium,CVE-2099-99999
```

These are sample assets. `CVE-2099-99999` is a synthetic example for the non-KEV
case, not a claim about a real vulnerability.

The input must contain exactly these three columns, in any order, and their
values must be nonempty. CVEs must have
the format `CVE-YYYY-NNNN` with at least four digits in the final part. Required
values are trimmed; CVEs are uppercased and criticality is lowercased.
Only `critical` triggers the critical-asset rule; other nonempty criticality
values follow the remaining rules. Extra, missing, or duplicate columns and
malformed rows are rejected.

## Policy and output

Rules are evaluated in this order:

| Rule | Condition | Priority |
| --- | --- | --- |
| 1 | CVE is in CISA KEV and asset criticality is `critical` | P0 |
| 2 | CVE is in CISA KEV | P1 |
| 3 | CVE is not in CISA KEV | P2 |

The output always uses `asset_id,criticality,cve,kev,priority,reason` in that order.
`kev` is `true` or `false`; `reason` names and explains the rule that fired.
Rows are sorted P0,
P1, P2; original input order is preserved within each priority. Findings are not
deduplicated. A header-only input produces a header-only output.

The catalogue comes from the [official CISA JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json).
A CVE absent from KEV receives P2; absence does not establish that it is safe.
Input or catalogue errors print a message to stderr and exit with status 1.
Input validation and catalogue loading finish before the output is opened, so
those failures leave an existing output untouched. An existing output is from
an earlier run if the current run fails; check the exit status.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

Tests use inline catalogue examples and make no network requests.

## Scope

V0 contains one application Python file with simple functions. It has no LLMs,
agents, frameworks, classes, databases, APIs, web UI, background queues,
deployment infrastructure, CVSS/EPSS scoring, package applicability analysis,
or remediation execution.
