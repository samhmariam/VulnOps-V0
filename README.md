# VulnOps V0.8

One Python script, no external dependencies: combine Defender observations with local context, apply verification-backed closure, classify active findings, rank P2, and write one remediation CSV. V0.8 changes the observation source, not the control policy.

## Source split

| Source | Question answered | Information supplied |
| --- | --- | --- |
| Microsoft Defender: technical observation | What CVEs does this machine currently have? | Machine ID, CVE, scanner severity |
| `data/asset_context.csv`: local context | What does this machine mean to our organization? | Stable asset ID, business criticality, exposure, ownership |

VulnOps joins them by `defender_machine_id` to build a finding, then removes Defender identifiers before policy processing. Microsoft Defender does NOT determine VulnOps priority. Microsoft Defender severity does NOT replace the current KEV-based policy.

```text
 Microsoft Defender
       │
machine + CVE + severity
       │
       ▼
   normalize
       │
       │       asset_context.csv
       │       criticality
       ├────── exposure
       │       ownership
       │
       ▼
VulnOps finding
       │
       ├──── CISA KEV
       │
       ├──── FIRST EPSS
       │
       ▼
remediation lifecycle
       │
       ▼
verification
       │
       ▼
classification
P0 / P1 / P2
       │
       ▼
P2 ranking
exposure → EPSS
       │
       ▼
owner_team
       │
       ▼
remediation_queue.csv
```

This is the conceptual flow; execution checks lifecycle and verification before fetching KEV and EPSS. Only active findings reach classification and output.

[CISA KEV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) records known exploitation. [FIRST EPSS](https://api.first.org/epss/) estimates exploitation probability over the next 30 days. Score and percentile stay between 0 and 1; percentile is informational, never used for ordering.

## Run

Requirements: Python 3.10 or newer; internet access to Microsoft Defender, CISA, and FIRST. `MDE_ACCESS_TOKEN` must be supplied as an environment variable; absent or blank credentials fail retrieval. Never commit access tokens. VulnOps does not obtain or refresh tokens.

```sh
python3 vulnops.py
```

- Scanner input: Microsoft Defender, limited to machines in `data/asset_context.csv`
- Local lifecycle state: `state/remediation_status.csv`
- Local verification evidence: `data/verification_results.csv`
- Output: `output/remediation_queue.csv`
- Paths: relative to `vulnops.py`; output directory created automatically

## MANUAL LIVE SMOKE TEST

Supply `MDE_ACCESS_TOKEN` securely through the environment, replace sample IDs in `data/asset_context.csv` with your pilot machines, and keep the local remediation and verification CSVs present. Then run:

```sh
python3 vulnops.py --live-smoke
```

The command checks the token before loading context, queries configured assets, and prints safe counts:

```text
assets queried: 2
raw observations: 7
normalized findings: 5
Wrote 4 findings to output/remediation_queue.csv
```

Raw observations count software records across pages; normalized findings count distinct machine/CVE pairs before lifecycle filtering. Exit status 0 means the entire pipeline completed. Zero vulnerabilities is valid and produces header-only output.

Tokens and request headers are never printed. This manual check requires live access; automated tests require neither real credentials nor internet.

## Local context and pilot scope

`data/asset_context.csv` defines the explicit V0.8 pilot scope. Only Defender machines explicitly configured in this file are queried. Maximum: **20 pilot assets**; exceeding this fails before retrieval because bulk ingestion is not implemented.

```csv
defender_machine_id,asset_id,asset_criticality,internet_exposed,owner_team
abc123,payments-api-01,critical,true,payments-platform
def456,hr-web-01,medium,false,workplace-it
```

- Replace sample machine IDs with actual Defender IDs
- Exactly these five columns, in any order; nonempty values
- Machine IDs and asset IDs must each be unique
- Whitespace trimmed; asset criticality lowercased and limited to `critical`, `high`, `medium`, or `low`
- Extra, missing, or duplicate columns and malformed rows rejected

Defender supplies machine ID, CVE, and severity. VulnOps queries each configured machine with an encoded filter, fetching pages of 10,000 records, up to 10 pages per machine; needing another page fails rather than truncating. Duplicate machine/CVE observations collapse when severities agree and fail when they conflict.

The join maps `asset_criticality` to internal `criticality` and retains scanner severity internally. Output columns are unchanged. `data/findings.csv` is no longer read; historical CSV data exists only in tests.

Defender machineId is NOT the VulnOps lifecycle identity. VulnOps asset_id remains the lifecycle identity: each finding's state and verification evidence are keyed by `(asset_id, cve)`.

`internet_exposed` describes the asset: `true` means a publicly reachable interface, `false` means known non-exposure, and `unknown` means insufficient evidence. Only lowercase strings are accepted. `true` does not prove the vulnerable component is remotely exploitable; `false` does not prove safety.

## 1. IS THE FINDING STILL ACTIVE?

Activity depends on `remediation_status` plus derived `verification_status`. Only `resolved` + `passed` leaves the active queue; every other valid combination remains active.

`state/remediation_status.csv` records the operator's claim, separately from current Defender observations:

```csv
asset_id,cve,remediation_status
payments-api-01,CVE-2026-1234,resolved
hr-web-01,CVE-2026-5678,open
```

No matching state entry defaults to `open`. State and verification CSVs require exactly their documented columns, nonempty fields, and unique `(asset_id, cve)` keys. Missing/malformed files and duplicates fail; header-only files are valid.

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

Missing evidence means `unverified`, never `passed` or `failed`. VulnOps preserves claims and evidence: `resolved` + `failed` means remediation was declared complete but verification still observes the vulnerability.

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

P0 first, P1 second, P2 last. P0 and P1 retain their relative order because KEV already supplies confirmed exploitation evidence.

P2 uses exposure first:

```text
internet exposed → unknown exposure → known non-internet-exposed
      true              unknown                 false
```

Within each exposure group:

```text
higher EPSS → lower EPSS → missing EPSS
```

Ties and missing scores retain relative order within each group. `unknown` precedes `false`: missing evidence is distinct from confirmed non-exposure.

Even 99% EPSS cannot put P2 before P1 or a non-exposed P2 before an exposed P2. No combined risk score exists; this is explicit operational policy.

Lifecycle filtering changes membership, not ranking among the remaining active findings.

## 4. WHO OWNS IT?

`owner_team` comes from `asset_context.csv`: the team operating and remediating the asset, such as `payments-platform`, `identity`, or `workplace-it`. VulnOps never infers ownership.

`unknown` explicitly records incomplete ownership information; it does not mean nobody owns the asset or Security owns it. Blank ownership is malformed input.

owner_team does NOT affect priority. owner_team does NOT affect ranking. unknown ownership does NOT reduce vulnerability urgency: a P0 with unknown ownership remains P0.

## 5. WHAT ALLOWS CLOSURE?

A resolved remediation claim **and** passed verification. V0.8 retains the verification-backed closure introduced in V0.7.

VulnOps V0.7 does not consider an operator's resolved declaration sufficient evidence for closure.

Verification is only as trustworthy as the supplied verification scan/evidence. V0.8 does not yet validate scanner coverage, freshness, authentication, or provenance.

Scanner identity, signature version, and completeness are also unchecked. Passing evidence does not guarantee patch success or prevent recurrence. V0.8 does not detect reintroduction or rewrite `resolved` to `open`.

No tickets, assigned people, SLAs, due dates, acknowledgements, workflow transitions, or patch execution.

## Output

One active queue; physical row order expresses ranking, and `owner_team` supplies accountability:

```csv
asset_id,criticality,cve,internet_exposed,owner_team,kev,epss_score,epss_percentile,priority,reason,remediation_status
```

Active rows may have `remediation_status=open` or `resolved`; resolved rows remain active when verification is unverified or failed. `verification_status` is currently derived internally and is not an output column. Missing EPSS remains `None` internally and empty in CSV; numeric zero is a valid score, written as `0.0`.

## Retrieval and failures

FIRST receives one request for unique active CVEs, limited to 2,000 characters including commas; exceeding this fails without batching. Input errors, retrieval failures, and invalid responses exit 1 and preserve previous output. Valid missing EPSS results remain missing. Success replaces the CSV; an empty active queue produces header-only output.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

Controlled responses; no network requests. Tests cover classification, ranking, missing data, ownership, state/evidence validation, all four verification outcomes, premature closure, and the complete discovery → claim → failed verification → passed verification loop.
