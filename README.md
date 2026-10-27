# VulnOps V0.4

One Python script, no external dependencies: load findings, enrich with KEV and EPSS, classify, order the queue, and write CSV.

```text
            FINDING
               │
       ┌───────┴────────┐
       │                │
      KEV       asset criticality
       └───────┬────────┘
               ↓
          CLASSIFICATION
          P0 / P1 / P2
               │
        ┌──────┼─────────┐
        ↓      ↓         ↓
       P0     P1        P2
      stable stable      │
                         ↓
                  internet exposure
                  true → unknown → false
                         │
                         ↓
                       EPSS
                  high → low → missing
                         │
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
- Output: `output/remediation_queue.csv`
- Paths: relative to `vulnops.py`; output directory created automatically

## Input

```csv
asset_id,criticality,cve,internet_exposed
web-server-01,high,CVE-2021-44228,true
identity-server-01,critical,CVE-2021-44228,unknown
workstation-01,medium,CVE-2099-99999,false
application-server-01,critical,CVE-2026-43500,true
```

- Sample assets; `CVE-2099-99999` is a synthetic missing-score example
- Exactly these four columns, in any order; nonempty values
- Whitespace trimmed; CVEs uppercased; criticality lowercased
- CVE format: `CVE-YYYY-NNNN`, with at least four final digits
- Extra, missing, or duplicate columns and malformed rows rejected

`internet_exposed` is a coarse asset-level signal: `true` means a service/interface is known to be publicly reachable; `false` means known non-exposure; `unknown` means insufficient evidence. Only these lowercase strings are accepted. `internet_exposed=true` does not prove the vulnerable component is remotely exploitable; `false` does not prove the vulnerability is safe.

## CLASSIFICATION

Priority is determined only by KEV and asset criticality:

| Condition, evaluated in order | Priority |
| --- | --- |
| KEV + critical asset | P0 |
| KEV | P1 |
| Otherwise | P2 |

Internet exposure does NOT change P0/P1/P2. EPSS does NOT change P0/P1/P2. Existing rule explanations remain unchanged.

## RANKING

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

A 99% EPSS P2 cannot precede a P1. A non-internet-facing P2 at 99% EPSS cannot precede an internet-facing P2 at 5% EPSS under V0.4. No combined risk score exists: this is an explicit deterministic operational policy, not a mathematically calculated risk ranking.

## Output

CSV schema, unchanged from V0.3; physical row order expresses ranking:

```csv
asset_id,criticality,cve,internet_exposed,kev,epss_score,epss_percentile,priority,reason
```

Missing EPSS remains `None` internally and empty in CSV; numeric zero is a valid score, written as `0.0`.

## Retrieval and failures

FIRST receives one request for unique finding CVEs; the `cve` parameter is limited to 2,000 characters including commas, with a clear error beyond that limit and no batching. Retrieval failures or invalid responses stop the run with a stderr error and exit status 1 before overwriting output; valid missing CVEs instead receive missing EPSS values. A successful run replaces the CSV; a failed run leaves any earlier output in place. Header-only input produces header-only output.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

Controlled responses; no network requests; coverage for classification, preserved P0/P1 order, P2 exposure groups, within-group EPSS ordering, stable ties, unknown exposure, missing scores, and zero
