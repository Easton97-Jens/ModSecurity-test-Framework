# Testing Docs

Status: implemented

Testing docs describe the source-derived YAML case model, compatibility
evidence, xfail/mapped-only decisions, and connector-free API smoke boundary.

## Documents

| Document | Use |
| --- | --- |
| `compatibility.md` | Current connector compatibility matrix and proven capability areas |
| `test-import-plan.md` | Policy for deriving YAML cases from upstream tests |
| `case-matrix.md` | Generated case inventory and latest observed connector statuses |
| `response-body-blocking-investigation.md` | Evidence for keeping `RESPONSE_BODY` blocking xfail/mapped-only |
| `pr70-audit-phase-coverage-plan.md` | Plan for mapping ModSecurity-apache PR #70 audit/phase tests into framework-owned YAML coverage |
| `pr377-test-import-map.md` | Source-derived map for ModSecurity-nginx PR #377 phase-4 tests |
| `v2-vs-v3-compatibility.md` | Architecture and API differences between ModSecurity v2 and v3 |
| `v2-vs-v3-test-compatibility.md` | V2/V3 test import evidence |
| `v3-api-smoke-test.md` | Connector-free libmodsecurity v3 API smoke notes |

## Rule

`pass` means real observed behavior. `xfail` and `mapped-only` cases remain
outside normal `smoke-all` until Apache and NGINX both prove the expected
behavior through real connector paths.
