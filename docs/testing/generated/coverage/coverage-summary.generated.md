> Generated file - do not edit manually.
>
> Generated at: `2026-07-12T18:43:55Z`
> Verified run id: `36b8dda731e3`
> Data source policy: `verified-inputs-only`
> Generator: `framework:ci/reporting/generate-case-matrix.py`
> Make target: `generate-test-matrix`
> Owner: `runtime`
> Severity: `informational`
> Connector SHA: `36b8dda731e3bdaf842449096c4ff20020459c32`
> Framework SHA: `36b8dda731e3bdaf842449096c4ff20020459c32`
> Input status: `missing`

# Generated Coverage Summary

**Language:** English | [Deutsch](coverage-summary.generated.de.md)

- Total cases: 559
- RESPONSE_BODY cases: 37
- Verified runtime cases: 0
- Non-verified runtime cases: 559

## By scope
- common: 548
- apache: 2
- nginx: 9
- unknown: 0

## By source
- ModSecurity-apache PR: 4
- mrts: 399
- owasp-modsecurity/ModSecurity-apache#78: 3
- unknown: 153

## MRTS Source Summary
- Total MRTS imported cases: **399**
- Active MRTS cases: **0**
- Pending MRTS cases: **399**
- Unclassified MRTS cases: **399**
- Phase 4 / RESPONSE_BODY MRTS cases: **110**
- Runtime-executable MRTS cases: **0**
- MRTS overlay classifications: **unclassified(399)**
- Apache observed classifications: **-**
- NGINX observed classifications: **-**
- HAProxy observed classifications: **-**

| Corpus | Category | Definitions | Golden tests | Golden rules | Framework cases | Active | Pending | Unclassified | Phase 4 / RESPONSE_BODY | Runtime-executable |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| upstream-config-tests | runnable | 16 | 157 | 15 | 383 | 0 | 383 | 383 | 110 | 0 |
| feature-demo | optional/demo | 9 | 13 | 8 | 16 | 0 | 16 | 16 | 0 | 0 |
| upstream-generated | golden-only | - | 157 | 15 | 0 | 0 | 0 | 0 | 0 | 0 |
| framework-curated | legacy/reference | 16 | - | - | 0 | 0 | 0 | 0 | 0 | 0 |

### MRTS Golden Drift
| Reference | Generated | Golden | Matched | Mismatch | Missing generated | Extra generated |
|---|---:|---:|---:|---:|---:|---:|
| upstream_tests | 157 | 157 | 157 | 0 | 0 | 0 |
| upstream_rules | 15 | 15 | 15 | 0 | 0 | 0 |
| feature_demo_tests | 13 | 13 | 0 | 0 | 13 | 13 |
| feature_demo_rules | 8 | 8 | 7 | 1 | 0 | 0 |

- Duplicate MRTS rule IDs across imported runnable/demo corpora: **13**
- Golden-only references under `tools/MRTS/generated/**` and `tools/MRTS/feature_demo/generated/**` are drift inputs only.
- Feature-demo cases are report-visible as optional/demo and pending unless `MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO=1` passes collision checks.

## By status
- active: 8
- connector-gap: 15
- imported: 133
- pending: 403

## By variable/collection
- `ARGS`: 76
- `REQUEST_COOKIES_NAMES`: 64
- `ARGS_NAMES`: 62
- `REQUEST_COOKIES`: 60
- `RESPONSE_BODY`: 28
- `ARGS:q`: 18
- `REQUEST_BODY`: 10
- `REQUEST_URI`: 7
- `XML`: 6
- `ARGS:test`: 6
- `REQUEST_HEADERS_NAMES`: 5
- `ARGS:a`: 4
- `ARGS:param1`: 4
- `MULTIPART_FILENAME`: 4
- `RESPONSE_HEADERS:Set-Cookie`: 4
- `ARGS:probe`: 4
- `ARGS:chain_a`: 3
- `ARGS:chain_b`: 3
- `FILES_NAMES`: 2
- `REQUEST_HEADERS:Content-Type`: 2
- `XML:/*`: 2
- `TX:SCORE`: 2
- `REQUEST_COOKIES:USER_TOKEN`: 2
- `RESPONSE_HEADERS:Location`: 2
- `ARGS:audit`: 1
- `REQUEST_HEADERS:X-PR70-Phase`: 1
- `ARGS_POST:arg1`: 1
- `RESPONSE_HEADERS:Last-Modified`: 1
- `ARGS:foo`: 1
- `FILES`: 1
- `ARGS:name`: 1
- `FILES_COMBINED_SIZE`: 1
- `FILES:filedata1`: 1
- `REQUEST_HEADERS:X-Missing`: 1
- `REQUEST_HEADERS:X-Phase`: 1
- `ARGS_COMBINED_SIZE`: 1
- `ARGS_GET`: 1
- `ARGS_POST_NAMES`: 1
- `ARGS_POST:test`: 1
- `REQUEST_HEADERS:User-Agent`: 1
- `REQUEST_HEADERS:X-Entity-Probe`: 1
- `RESPONSE_HEADERS:Content-Type`: 1
- `RESPONSE_HEADERS:X-Missing`: 1
- `RESPONSE_HEADERS:content-type`: 1
- `RESPONSE_HEADERS:Server`: 1

## By phase
- phase 1: 107
- phase 2: 193
- phase 3: 114
- phase 4: 126

## Verification note
- Generated summaries are reporting only and do not replace full runtime evidence from `make smoke-all`.
- RESPONSE_BODY remains non-verified/non-promoted until stable full-smoke runtime evidence exists.
- RESPONSE_BODY remains non-verified/non-promoted; legacy bounded samples and pass-through rows do not prove selected-host support.

## Data Sources

| Value | Source | Source Hash | Verified Run ID | Status |
|---|---|---|---|---|
| Declared input | `config/testing/import-status.json` | `missing` | `unknown` | missing |
| Declared input | `docs/testing/runtime-validation-snapshot.json` | `f5594b18041c8146c6ca3adc51414b56777df742eb35ae883f3e1956e7161cbe` | `36b8dda731e3` | present |

## Data Availability / Missing Information

| Input | Status | Notes |
|---|---|---|
| `config/testing/import-status.json` | missing | input file is missing |
| `docs/testing/runtime-validation-snapshot.json` | present | input file available |
