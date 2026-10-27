# VulnOps V0.9

One Python script, no external dependencies: combine mock scanner observations with local context, apply verification-backed closure, classify active findings, rank P2, and write one remediation CSV. V0.9 adds qualified remediation verification: evidence is accepted only from a successful scan that explicitly covers the asset. Classification and ranking policies are unchanged.

Before V0.8, `findings.csv` already supplied a fully formed VulnOps finding, mixing technical observations with business context. V0.8 separates those sources: scanner-shaped observations + local asset context → VulnOps finding → existing control plane.

V0.9 does NOT connect to a live scanner, require Microsoft Defender credentials, or implement authentication. The mock data proves the scanner integration contract without a live vendor dependency.

## Source split

| Source | Question answered | Information supplied |
| --- | --- | --- |
| `data/mock_scanner_output.json`: represents technical output from an external vulnerability scanner | Which vulnerability was observed on which machine? | `machineId`, `cveId`, `severity` |
| `data/asset_context.csv`: provides organization-specific context unavailable from the scanner | What does this machine mean to our organization? | `scanner_machine_id`, `asset_id`, `asset_criticality`, `internet_exposed`, `owner_team` |

VulnOps normalizes `machineId`, `cveId`, and `severity`, then joins local context by `scanner_machine_id`. Scanner identifiers disappear before policy processing. Scanner severity does NOT determine VulnOps priority or replace the KEV-based policy.

After joining, the finding contains exactly: `asset_id`, `cve`, `severity`, `asset_criticality`, `internet_exposed`, and `owner_team`. CVE and severity come from the mock scanner; asset identity, criticality, exposure, and ownership come from local context.

```text
       MOCK SCANNER
            │
    machine + CVE + severity
            │
            ▼
        NORMALIZE
            │
            │
            │       ASSET CONTEXT
            │       criticality
            ├────── exposure
            │       ownership
            │
            ▼
       VULNOPS FINDING
            │
       ┌────┴────┐
       │         │
      KEV       EPSS
       │         │
       └────┬────┘
            ▼
       lifecycle
            │
 qualified verification
            │
       classification
            │
        P0/P1/P2
            │
       P2 ranking
            │
        owner_team
            │
            ▼
 remediation_queue.csv
```

This is the conceptual flow; execution checks lifecycle and verification before fetching KEV and EPSS. Only active findings reach classification and output.

[CISA KEV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) records known exploitation. [FIRST EPSS](https://api.first.org/epss/) estimates exploitation probability over the next 30 days. Score and percentile stay between 0 and 1; percentile is informational, never used for ordering.

## Run

Requirements: Python 3.10 or newer; internet access to CISA and FIRST. Scanner input is a local mock file; no scanner account, API, or authentication is required.

```sh
python3 vulnops.py
```

- Scanner input: `data/mock_scanner_output.json`
- Local asset context: `data/asset_context.csv`
- Local lifecycle state: `state/remediation_status.csv`
- Local verification evidence: `data/verification_results.csv`
- Verification scan quality: `data/verification_scan.json`
- Output: `output/remediation_queue.csv`
- Paths: relative to `vulnops.py`; output directory created automatically

## Scanner input and local context

`data/mock_scanner_output.json` contains a `value` list of observations, each with nonblank `machineId`, `cveId`, and `severity` strings. Loading preserves raw values; normalization lowercases severity and maps IDs to `scanner_machine_id` and `cve`. Duplicate machine/CVE observations collapse when severities agree and fail when they conflict.

```json
{
  "value": [
    {"machineId": "machine-001", "cveId": "CVE-2026-1001", "severity": "Critical"}
  ]
}
```

Normalized severity must be `critical`, `high`, `medium`, or `low`; unexpected values fail.

`data/asset_context.csv` supplies the organizational context:

```csv
scanner_machine_id,asset_id,asset_criticality,internet_exposed,owner_team
machine-001,payments-api-01,critical,true,payments-platform
machine-002,hr-app-01,medium,false,workplace-it
machine-003,legacy-db-01,high,unknown,data-platform
```

- Exactly these five columns, in any order; nonempty values
- Machine IDs and asset IDs must each be unique
- Whitespace trimmed; asset criticality lowercased and limited to `critical`, `high`, `medium`, or `low`
- Extra, missing, or duplicate columns and malformed rows rejected

Every observation must have matching context; missing context fails instead of inventing defaults. An asset without scanner observations generates no finding; an empty `value` list is valid. Existing CSV columns are preserved: output `criticality` contains `asset_criticality`. `data/findings.csv` is no longer read; historical CSV data exists only in tests.

Scanner machine IDs are integration identifiers, not lifecycle identities. VulnOps state and verification remain keyed by `(asset_id, cve)`.

`internet_exposed` describes the asset: `true` means a publicly reachable interface, `false` means known non-exposure, and `unknown` means insufficient evidence. Only lowercase strings are accepted. `true` does not prove the vulnerable component is remotely exploitable; `false` does not prove safety.

## 1. IS THE FINDING STILL ACTIVE?

Activity depends on `remediation_status` plus derived `verification_status`. Only `resolved` + `passed` leaves the active queue; every other valid combination remains active.

`state/remediation_status.csv` records the operator's claim, separately from current mock scanner observations:

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

`data/verification_scan.json` supplies exactly two fields:

```json
{
  "status": "succeeded",
  "covered_asset_ids": ["payments-api-01", "hr-app-01"]
}
```

`status` must be exactly `succeeded` or `failed`. Coverage must be a list of unique, non-empty VulnOps `asset_id` strings; surrounding whitespace is trimmed. An empty list is valid. Missing, extra, or malformed fields fail the run.

### Qualified remediation verification

```text
remediation claim
        ↓
verification result + verification scan quality
        ↓
   qualification
        ↓
verification_status
```

`vulnerability_present=false` is no longer sufficient by itself. A supplied result is qualified only when **scan status == succeeded AND asset_id is explicitly covered**. Failed scans qualify no results; uncovered assets qualify no results. This applies to both `true` and `false` presence evidence. Coverage alone does not invent a missing per-CVE result.

Qualification filters evidence without changing its boolean value, the remediation claim, or the finding. The existing verification function then interprets only the claim and qualified evidence:

| Remediation claim | Qualified verification evidence | Derived verification status | Active? |
| --- | --- | --- | --- |
| open | Any or none | not_applicable | Yes |
| resolved | No qualified evidence | unverified | Yes |
| resolved | Qualified vulnerability_present=true | failed | Yes |
| resolved | Qualified vulnerability_present=false | passed | No |

Missing or disqualified evidence means `unverified` for resolved findings, never `passed` or `failed`. Open findings always remain `not_applicable` and open. VulnOps preserves claims and evidence: `resolved` + `failed` means remediation was declared complete but qualified verification still observes the vulnerability.

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

A resolved remediation claim **and** passed verification, derived from qualified evidence. Only `resolved + passed` leaves the active queue; a failed scan or unproven asset coverage cannot authorize closure.

An operator's resolved declaration alone is insufficient evidence for closure.

V0.9 checks the supplied scan outcome and asset-coverage declaration. It does not independently establish that those declarations are trustworthy. Passing evidence does not guarantee patch success or prevent recurrence; qualification does not change priority, ranking, or ownership.

V0.9 does **not** implement:

- Timestamps or freshness checks
- Scan-run IDs
- Scanner provenance
- Scanner authentication
- Historical reconciliation
- Reappearance detection
- Live scanner integration
- SLAs
- Ticketing
- Patch automation
- AI

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
uv run --no-project --with pytest python -m pytest tests -q
```

Tests use controlled responses, without scanner credentials or network requests; the first command invocation may download pytest. Coverage includes scanner inputs, existing control policies, and V0.9 scan validation, evidence qualification, closure eligibility, and unchanged open-finding behaviour.
