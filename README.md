# VulnOps V0.1

Load findings → enrich with KEV and EPSS → prioritize → explain → output.

One Python script, no external dependencies. Requires Python 3.10 or newer and
internet access to retrieve the official CISA KEV catalogue and FIRST EPSS
values on each run.

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
application-server-01,critical,CVE-2026-43500
```

These are sample assets. `CVE-2099-99999` is a synthetic example for the non-KEV
case, not a claim about a real vulnerability.
The additional application server demonstrates a high-EPSS, non-KEV P2 finding
in the sample generated on 2026-10-26. Live source values and membership can change.

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

The output always uses
`asset_id,criticality,cve,kev,epss_score,epss_percentile,priority,reason` in that order.
These are the six V0 columns plus exactly two EPSS columns. Missing EPSS values
are empty CSV fields; a numeric zero is written as `0.0`.
`kev` is `true` or `false`; `reason` names and explains the rule that fired.
Rows are sorted P0,
P1, P2; original input order is preserved within each priority, regardless of
EPSS values. Priority rules and reason text are unchanged. Findings are not
deduplicated. A header-only input produces a header-only output.

The catalogue comes from the [official CISA JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json).
A CVE absent from KEV receives P2; absence does not establish that it is safe.
Input or intelligence-source errors print a message to stderr and exit with status 1.
Input validation and KEV/EPSS retrieval finish before the output is opened, so
those failures leave an existing output untouched. An existing output is from
an earlier run if the current run fails; check the exit status.

## EPSS retrieval (V0.1)

`load_epss(cves)` in `vulnops.py` retrieves only the requested CVEs from the
[official FIRST EPSS API](https://api.first.org/epss/). The command-line run calls
it after loading KEV and before EPSS enrichment and prioritization.

```python
from vulnops import load_epss

scores = load_epss(["CVE-2021-44228"])
```

The returned dictionary maps each requested CVE to `epss_score` and
`epss_percentile`, stored as floats between 0 and 1 without multiplication by
100. EPSS estimates exploitation activity in the next 30 days; its percentile
is the score's relative position among scored CVEs. KEV records known
exploitation. These are complementary signals, and EPSS does not change V0
priorities.

The function deduplicates CVEs and makes one request using the comma-separated
`cve` parameter. It requests enough results for the unique CVEs. Queries exceeding
2,000 characters, including commas, raise a clear error: V0.1 does not implement
batching. Empty input returns `{}` without a request.

Network errors, API errors, malformed or incomplete responses, and scores outside
0–1 raise `ValueError` identifying FIRST EPSS retrieval failure. Exceptions are
not converted into scores. When a valid response omits a requested CVE, that CVE
maps to `{"epss_score": None, "epss_percentile": None}`. Zero is a valid score;
`None` means FIRST returned no score.

## EPSS enrichment (V0.1)

`enrich_with_epss(findings, epss_by_cve)` returns a list of finding copies with
only `epss_score` and `epss_percentile` added. It preserves finding order and
every other field, including existing priorities and reasons. Neither input
is modified. A CVE absent from the EPSS dictionary receives `None` for both
fields; explicit `None` and numeric zero values are preserved.

```python
from vulnops import enrich_with_epss

enriched = enrich_with_epss(findings, scores)
```

Enrichment attaches information without interpreting it. It applies no thresholds,
risk bands, or priority changes. The command-line run enriches findings before
calling the existing priority function, which does not read EPSS values.

Raw values let operators observe both signals without introducing a new policy:
a high EPSS score can appear alongside P2 and the unchanged non-KEV reason.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

Tests use controlled KEV and EPSS responses and make no network requests. They
compare the generated queue with V0 priorities, reasons, and ordering, including
a P2 finding with EPSS 0.99, and distinguish a missing score from zero.

## Scope

V0.1 contains one application Python file with simple functions. It has no LLMs,
agents, frameworks, classes, databases, APIs, web UI, background queues,
deployment infrastructure, CVSS scoring, EPSS-based prioritization, package applicability analysis,
or remediation execution.
