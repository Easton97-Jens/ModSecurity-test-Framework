# Status Model

The framework separates runtime results from import/classification status.

## Runtime Status

| Status | Meaning | Exit effect |
| --- | --- | --- |
| `pass` | Real HTTP behavior matched the YAML expectation | success |
| `fail` | Server ran but behavior differed from the YAML expectation | exit 1 |
| `blocked` | Source, download, build, or runtime prerequisite was missing | exit 77 |
| `not_executable` | Case could not be structurally materialized for the connector/runtime mode | exit 78 |
| `skipped` | Reserved for explicit future skip behavior | not used silently |

`fail` is used when a rule variable does not reach libmodsecurity or the
connector returns the wrong HTTP status. `blocked` is only for prerequisites.

## Import Status

| Status | Meaning |
| --- | --- |
| `fully-imported-common` | Source-derived case passed on Apache and NGINX real connector paths |
| `connector-specific` | Valid only for a named connector |
| `mapped-only` | Source is documented but not executable as an active smoke |
| `blocked` | Relevant source exists but current harness cannot execute it |
| `former_xfail` | Historical migration metadata for cases now evaluated through normal runtime evidence |

`config/testing/import-status.json` is the machine-readable manifest for import status
counts. Connector summaries copy those counts into `import_status`.

## Result Metadata

Every connector summary JSON includes:

- `connector_path: "real-world"`
- `validation_mode: "real-world-connector-path"`
- `environment`: `SMOKE_ENVIRONMENT`, otherwise `github-actions` or `local`
- `audit_behavior`: `stable`, `unstable`, or `unexpected`
- `verified_variables`: derived only from passing active cases

Former XFAIL cases keep migration metadata, but PASS/FAIL/BLOCKED/NOT_EXECUTABLE
now comes only from live runtime evidence.
