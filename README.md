# VulnOps V0.6

One Python script, no external dependencies: filter by lifecycle state, classify urgency, rank active P2 findings, and retain team accountability in one CSV.

```text
                   CURRENT FINDING
                         │
                  lifecycle state
                    open/resolved
                         │
                resolved │ open
                    ┌────┴─────┐
                    ↓          ↓
                  STOP      CLASSIFY
                           P0/P1/P2
                               │
                    ┌──────────┼──────────┐
                    ↓          ↓          ↓
                   P0         P1         P2
                                      exposure
                                         ↓
                                        EPSS
                                         ↓
                                   ranked queue
                                         ↓
                                     owner_team
                                         ↓
                              remediation_queue.csv
```

[CISA KEV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) records known exploitation. [FIRST EPSS](https://api.first.org/epss/) estimates exploitation activity in the next 30 days; its percentile describes the score’s relative position among scored CVEs. Scores and percentiles remain numeric values between 0 and 1, without multiplication by 100; percentile is informational and never used for ordering.

## Run

Requirements: Python 3.10 or newer; internet access to CISA and FIRST

```sh
python3 vulnops.py
```

- Input: `data/findings.csv`
- Local lifecycle state: `state/remediation_status.csv`
- Output: `output/remediation_queue.csv`
- Paths: relative to `vulnops.py`; output directory created automatically

## Input

```csv
asset_id,criticality,cve,internet_exposed,owner_team
web-server-01,high,CVE-2021-44228,true,payments-platform
identity-server-01,critical,CVE-2021-44228,unknown,identity
workstation-01,medium,CVE-2099-99999,false,workplace-it
application-server-01,critical,CVE-2026-43500,true,unknown
```

- Sample assets; `CVE-2099-99999` is a synthetic missing-score example
- Exactly these five columns, in any order; nonempty values
- Whitespace trimmed; CVEs uppercased; criticality lowercased
- CVE format: `CVE-YYYY-NNNN`, with at least four final digits
- Extra, missing, or duplicate columns and malformed rows rejected

`internet_exposed` is a coarse asset-level signal: `true` means a service/interface is known to be publicly reachable; `false` means known non-exposure; `unknown` means insufficient evidence. Only these lowercase strings are accepted. `internet_exposed=true` does not prove the vulnerable component is remotely exploitable; `false` does not prove the vulnerability is safe.

## CLASSIFICATION

Answers: "How urgent is this?"

Priority is determined only by KEV and asset criticality:

| Condition, evaluated in order | Priority |
| --- | --- |
| KEV + critical asset | P0 |
| KEV | P1 |
| Otherwise | P2 |

Internet exposure does NOT change P0/P1/P2. EPSS does NOT change P0/P1/P2. Existing rule explanations remain unchanged.

## RANKING

Answers: "Among P2 findings, which should be examined first?"

The queue lists P0 first, P1 second, and P2 last. P0 and P1 retain their existing relative order, regardless of exposure or EPSS, because they already have confirmed exploitation evidence through CISA KEV.

P2 uses exposure first:

```text
internet exposed → unknown exposure → known non-internet-exposed
      true              unknown                 false
```

Within each exposure group:

```text
higher EPSS → lower EPSS → missing EPSS
```

Equal scores and multiple missing scores preserve their existing relative order within the group. `unknown` is intentionally ranked ahead of `false` because it represents missing evidence rather than confirmed non-exposure.

KEV priorities always precede P2; within P2, exposure takes precedence over EPSS. No combined risk score exists: this is explicit deterministic operational policy.

## ACCOUNTABILITY

Answers: "Which team owns remediation?"

`owner_team` names the team operating and remediating the asset, such as `payments-platform`, `identity`, or `workplace-it`. It comes directly from findings, is preserved throughout, and is never inferred or assigned automatically.

`unknown` explicitly records incomplete ownership information; it does not mean nobody owns the asset or Security owns it. Blank ownership is malformed input.

owner_team does NOT affect priority. owner_team does NOT affect ranking. unknown ownership does NOT reduce vulnerability urgency: a P0 with unknown ownership remains P0.

## LIFECYCLE

Answers: "Does this finding still require remediation?"

`findings.csv` supplies current vulnerability observations; the separate local file `state/remediation_status.csv` records operator-declared lifecycle state:

```csv
asset_id,cve,remediation_status
payments-api-01,CVE-2026-1234,resolved
hr-web-01,CVE-2026-5678,open
```

Finding identity is `(asset_id, cve)`, not CVE alone: different assets can have different statuses for the same CVE. The state file requires exactly these three columns, nonempty values, and status `open` or `resolved`; duplicate keys fail clearly.

- Missing matching state entry → `open`
- Recorded `open` → included in the active remediation queue
- Recorded `resolved` → excluded from the active remediation queue

Edit the state CSV to record `open` or `resolved`; VulnOps does not rewrite it. Resolved records remain stored so they do not default back to open on the next run. A missing or malformed state file is an error, distinct from a valid file with no matching entry.

`remediation_status` does not affect P0/P1/P2 or P2 ranking. Filtering determines which findings remain active; ranking determines their order. A resolved P0 still conceptually classifies as P0, but leaves the active queue.

V0.6 resolved status is operator-declared. VulnOps does not yet verify that remediation was successful or detect reintroduction of a vulnerability.

No tickets, assigned people, SLAs, due dates, acknowledgements, remediation progress tracking, or patch execution.

## Output

One active queue; physical row order expresses ranking, and `owner_team` supplies accountability:

```csv
asset_id,criticality,cve,internet_exposed,owner_team,kev,epss_score,epss_percentile,priority,reason,remediation_status
```

Every active row has `remediation_status=open`. Missing EPSS remains `None` internally and empty in CSV; numeric zero is a valid score, written as `0.0`.

## Retrieval and failures

FIRST receives one request for unique active CVEs; the `cve` parameter is limited to 2,000 characters including commas, with a clear error beyond that limit and no batching. Input/state errors, retrieval failures, or invalid responses stop the run with a stderr error and exit status 1 before overwriting output; valid missing CVEs instead receive missing EPSS values. A successful run replaces the CSV; a failed run leaves any earlier output in place. No active findings produces header-only output.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

Controlled responses; no network requests; coverage for classification, ranking, missing data, ownership preservation, state validation, default-open behaviour, resolved exclusion, and unchanged ordering among active findings
