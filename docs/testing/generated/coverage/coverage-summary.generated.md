Generated file - do not edit manually.

# Generated Coverage Summary

**Language:** English | [Deutsch](coverage-summary.generated.de.md)

- Total cases: 540
- RESPONSE_BODY cases: 32
- Verified runtime cases: 0
- Non-verified runtime cases: 540

## By scope
- common: 533
- apache: 0
- nginx: 7
- unknown: 0

## By source
- ModSecurity-apache PR: 4
- mrts: 399
- owasp-modsecurity/ModSecurity-apache#78: 3
- unknown: 134

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
- imported: 133
- pending: 399

## By variable/collection
- `ARGS`: 76
- `REQUEST_COOKIES_NAMES`: 64
- `ARGS_NAMES`: 62
- `REQUEST_COOKIES`: 60
- `RESPONSE_BODY`: 28
- `ARGS:q`: 18
- `REQUEST_BODY`: 10
- `XML`: 7
- `REQUEST_URI`: 7
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
- `XML:/*`: 1
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
- phase 1: 105
- phase 2: 192
- phase 3: 114
- phase 4: 126

## Verification note
- Generated summaries are reporting only and do not replace full runtime evidence from `make smoke-all`.
- RESPONSE_BODY remains non-verified/non-promoted until stable full-smoke runtime evidence exists.
- Bounded Phase 4 / strict-abort evidence remains experimental/non-promoted; pass-through rows do not prove full RESPONSE_BODY support.
