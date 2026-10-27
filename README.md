# VulnOps V0.7

One Python script, no external dependencies: combine remediation claims with verification evidence, classify active findings, rank P2, and retain team accountability in one CSV.

```text
                     FINDING
                        │
                        ▼
                 remediation_status
                  open / resolved
                        │
              ┌─────────┴──────────┐
              │                    │
             open               resolved
              │                    │
              ↓                    ▼
       not_applicable         verification
              │               ┌────┼─────┐
              │               ↓    ↓     ↓
              │          unverified failed passed
              │               │    │      │
              │               └─┬──┘      │
              └─────────────────┤         │
                                │         │
                              ACTIVE     EXIT
                                │
                                ▼
                            CLASSIFY
                           P0/P1/P2
                                │
                                ▼
                       existing ranking
                                │
                                ▼
                           owner_team
                                │
                                ▼
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
- Local verification evidence: `data/verification_results.csv`
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

## 1. IS THE FINDING STILL ACTIVE?

Activity depends on `remediation_status` plus derived `verification_status`. Only `resolved` + `passed` leaves the active queue; every other valid combination remains active.

`state/remediation_status.csv` records the operator's claim, separately from current observations in `data/findings.csv`:

```csv
asset_id,cve,remediation_status
payments-api-01,CVE-2026-1234,resolved
hr-web-01,CVE-2026-5678,open
```

Finding identity is `(asset_id, cve)`, not CVE alone. Allowed statuses are `open` and `resolved`; no matching state entry defaults to `open`. Both local state and verification files require exactly their documented columns, nonempty fields, and unique asset/CVE keys. Duplicate keys and malformed or missing files fail clearly; header-only files are valid.

`data/verification_results.csv` supplies the latest targeted post-remediation verification evidence:

```csv
asset_id,cve,vulnerability_present
payments-api-01,CVE-2026-1234,false
hr-web-01,CVE-2026-5678,true
```

Only lowercase `true` and `false` are accepted. `true` means the supplied evidence still observes the vulnerability; `false` means that evidence did not find it present. Absence from an arbitrary findings CSV is not verification evidence.

| Remediation claim | Verification evidence | Derived verification status | Active? |
| --- | --- | --- | --- |
| open | Any or none | not_applicable | Yes |
| resolved | No matching entry | unverified | Yes |
| resolved | vulnerability_present=true | failed | Yes |
| resolved | vulnerability_present=false | passed | No |

An open finding has no remediation claim to verify. Missing evidence means `unverified`, never `passed` or `failed`. VulnOps does not rewrite claims, evidence, or findings: `resolved` + `failed` preserves the diagnostic distinction between what was claimed and what was observed.

## 2. HOW URGENT IS IT?

Priority is determined only by KEV and asset criticality:

| Condition, evaluated in order | Priority |
| --- | --- |
| KEV + critical asset | P0 |
| KEV | P1 |
| Otherwise | P2 |

Internet exposure does NOT change P0/P1/P2. EPSS does NOT change P0/P1/P2. Existing rule explanations remain unchanged.

Remediation and verification statuses do not change classification. A passed P0 remains conceptually P0; it leaves the active queue because the closure condition is satisfied.

## 3. WHAT P2 COMES FIRST?

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

Lifecycle filtering changes membership, not ranking among the remaining active findings.

## 4. WHO OWNS IT?

`owner_team` names the team operating and remediating the asset, such as `payments-platform`, `identity`, or `workplace-it`. It comes directly from findings, is preserved throughout, and is never inferred or assigned automatically.

`unknown` explicitly records incomplete ownership information; it does not mean nobody owns the asset or Security owns it. Blank ownership is malformed input.

owner_team does NOT affect priority. owner_team does NOT affect ranking. unknown ownership does NOT reduce vulnerability urgency: a P0 with unknown ownership remains P0.

## 5. WHAT ALLOWS CLOSURE?

A resolved remediation claim **and** passed verification. V0.6 trusted the declaration; V0.7 requires supporting evidence.

VulnOps V0.7 does not consider an operator's resolved declaration sufficient evidence for closure.

Verification is only as trustworthy as the supplied verification scan/evidence. V0.7 does not yet validate scanner coverage, freshness, authentication, or provenance.

Scanner identity, signature version, and scan completeness are also not validated. A passing result describes the supplied evidence, not absolute proof of successful patching or that a vulnerability can never recur. V0.7 does not detect reintroduction or automatically rewrite `resolved` to `open`.

No tickets, assigned people, SLAs, due dates, acknowledgements, workflow transitions, or patch execution.

## Output

One active queue; physical row order expresses ranking, and `owner_team` supplies accountability:

```csv
asset_id,criticality,cve,internet_exposed,owner_team,kev,epss_score,epss_percentile,priority,reason,remediation_status
```

Active rows may have `remediation_status=open` or `resolved`; resolved rows remain active when verification is unverified or failed. `verification_status` is currently derived internally and is not an output column. Missing EPSS remains `None` internally and empty in CSV; numeric zero is a valid score, written as `0.0`.

## Retrieval and failures

FIRST receives one request for unique active CVEs; the `cve` parameter is limited to 2,000 characters including commas, with a clear error beyond that limit and no batching. Input/state errors, retrieval failures, or invalid responses stop the run with a stderr error and exit status 1 before overwriting output; valid missing CVEs instead receive missing EPSS values. A successful run replaces the CSV; a failed run leaves any earlier output in place. No active findings produces header-only output.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

Controlled responses; no network requests. Tests cover classification, ranking, missing data, ownership, state/evidence validation, all four verification outcomes, premature closure, and the complete discovery → claim → failed verification → passed verification loop.
