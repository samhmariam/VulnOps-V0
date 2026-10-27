# VulnOps V0.2

```text
findings.csv ──────┐
                   │
CISA KEV ──────────┼──> enrich
                   │
FIRST EPSS ────────┘
                         ↓
                     classify
                   P0 / P1 / P2
                         ↓
                 rank P2 by EPSS
                         ↓
              remediation_queue.csv
```

VulnOps reads findings, enriches them with KEV and EPSS, assigns an explainable priority, and writes a remediation CSV using one Python script with no external dependencies.
[CISA KEV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) records known exploitation, while [FIRST EPSS](https://api.first.org/epss/) estimates exploitation activity in the next 30 days and supplies a percentile showing the score’s relative position among scored CVEs.
EPSS scores and percentiles remain numeric values between 0 and 1, with no multiplication by 100 or combined risk calculation.

## Run

Requirements: Python 3.10 or newer; internet access to CISA and FIRST

From the repository root:

```sh
python3 vulnops.py
```

- Input: `data/findings.csv`
- Output: `output/remediation_queue.csv`
- Paths: relative to `vulnops.py`; output directory created automatically

## Input

```csv
asset_id,criticality,cve
web-server-01,high,CVE-2021-44228
identity-server-01,critical,CVE-2021-44228
workstation-01,medium,CVE-2099-99999
application-server-01,critical,CVE-2026-43500
```

- Sample assets; `CVE-2099-99999` is a synthetic missing-score example
- Exactly these three columns, in any order; nonempty values
- Whitespace trimmed; CVEs uppercased; criticality lowercased
- CVE format: `CVE-YYYY-NNNN`, with at least four final digits
- Extra, missing, or duplicate columns and malformed rows rejected

## Priority policy and output

| Condition, evaluated in order | Priority |
| --- | --- |
| CVE in KEV and asset criticality `critical` | P0 |
| CVE in KEV | P1 |
| Otherwise | P2 |

CSV columns, unchanged from V0.1:

```csv
asset_id,criticality,cve,kev,epss_score,epss_percentile,priority,reason
```

Every finding retains its rule explanation; unavailable EPSS values remain `None` internally and empty in the CSV, while numeric zero is written as `0.0`.

## QUEUE ORDERING

The queue lists P0 first, P1 next, and P2 last.
Within P2, higher EPSS scores appear first, missing EPSS appears after scored vulnerabilities, and equal scores or multiple missing scores preserve their existing relative order.
EPSS does not change priority.
EPSS is not currently used to reorder P0 or P1 because those findings already have confirmed exploitation evidence through CISA KEV.
EPSS cannot promote P2 to P1.

## Retrieval and failures

A retrieval failure or invalid intelligence response stops the run with a clear stderr error and exit status 1 before overwriting the output; a valid FIRST response omitting a CVE instead produces missing EPSS values for that finding.

- FIRST lookup: one request for unique finding CVEs using the `cve` parameter
- Maximum `cve` parameter: 2,000 characters including commas; clear failure beyond that limit; no batching
- Successful run: replaces the output CSV
- Failed run: any previous output remains from an earlier run
- Header-only input: header-only output

## Tests

```sh
python3 -m unittest discover -s tests -v
```

Controlled KEV and EPSS responses; no network requests; coverage for unchanged priorities and reasons, preserved P0/P1 ordering, descending P2 scores, stable ties, missing scores, and zero
