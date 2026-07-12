> Generated file - do not edit manually.
>
> Generated at: `2026-07-12T19:40:11Z`
> Verified run id: `2026-06-16T19-12-00Z-614c8049`
> Data source policy: `verified-inputs-only`
> Generator: `framework:ci/reporting/generate-case-matrix.py`
> Make target: `generate-test-matrix`
> Owner: `runtime`
> Severity: `informational`
> Connector SHA: `91f51277e96ff9b58e6d6a3a3c737eb103b00331`
> Framework SHA: `91f51277e96ff9b58e6d6a3a3c737eb103b00331`
> Input status: `missing`

# Generated Phase Coverage

**Language:** English | [Deutsch](phase-coverage.generated.de.md)

| phase | case_count | top_variables | status_distribution |
|---|---:|---|---|
| 1 | 107 | REQUEST_COOKIES_NAMES(19), REQUEST_COOKIES(15), ARGS(10), ARGS_NAMES(8), REQUEST_URI(7) | active:2, imported:36, pending:69 |
| 2 | 193 | ARGS(34), ARGS_NAMES(22), ARGS:q(18), REQUEST_COOKIES(15), REQUEST_COOKIES_NAMES(15) | active:5, imported:70, pending:118 |
| 3 | 114 | ARGS(16), ARGS_NAMES(16), REQUEST_COOKIES(15), REQUEST_COOKIES_NAMES(15), RESPONSE_HEADERS:Set-Cookie(4) | active:1, imported:11, pending:102 |
| 4 | 126 | RESPONSE_BODY(24), ARGS(16), ARGS_NAMES(16), REQUEST_COOKIES(15), REQUEST_COOKIES_NAMES(15) | imported:20, pending:106 |

## Data Sources

| Value | Source | Source Hash | Verified Run ID | Status |
|---|---|---|---|---|
| Declared input | `config/testing/import-status.json` | `missing` | `unknown` | missing |
| Declared input | `docs/testing/runtime-validation-snapshot.json` | `f5594b18041c8146c6ca3adc51414b56777df742eb35ae883f3e1956e7161cbe` | `2026-06-16T19-12-00Z-614c8049` | present |

## Data Availability / Missing Information

| Input | Status | Notes |
|---|---|---|
| `config/testing/import-status.json` | missing | input file is missing |
| `docs/testing/runtime-validation-snapshot.json` | present | input file available |
