# PR #377 Test Import Map

Status: implemented

This document maps ModSecurity-nginx PR #377 tests to this repository's
source-derived YAML probes. The PR was reviewed from a temporary checkout under
`$BUILD_ROOT`, not by changing any parent-workspace reference checkout.

Upstream PR: https://github.com/owasp-modsecurity/ModSecurity-nginx/pull/377

Observed PR head: `3d72b004ff27a78ea19c6b945870e2cae62a97ac`

## Import Decisions

| original_path | purpose | phase4_mode | request | response fixture | expected behavior | portable | target_location | status | reason | required_capabilities | known_limitations |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `tests/modsecurity-phase4-modes.t` | Minimal mode logs late phase-4 intervention without changing client response | `minimal` | `GET /m` | `Hello minimal` | HTTP 200 body preserved; phase4 log has `actual_action=log_only`, `reason=mode_minimal`, and no response body data | no | `tests/cases/connector-specific/nginx/nginx_phase4_minimal_log_only.yaml` | imported, latest NGINX smoke PASS | Latest NGINX source-built run returned HTTP 200 after the harness permission fix; this is NGINX-specific phase-4 log-only evidence, not response-body blocking proof | response-body, phase4, logging, pass-through | Not a `RESPONSE_BODY` blocking promotion |
| `tests/modsecurity-phase4-modes.t` | Safe mode logs late phase-4 intervention without changing client response | `safe` | `GET /s` | `Hello safe` | HTTP 200 body preserved; phase4 log has `actual_action=log_only`, `reason=mode_safe`, and no response body data | no | `tests/cases/connector-specific/nginx/nginx_phase4_safe_log_only.yaml` | imported, latest NGINX smoke PASS | Latest NGINX source-built run returned HTTP 200 after the harness permission fix; this is NGINX-specific phase-4 log-only evidence, not response-body blocking proof | response-body, phase4, logging, pass-through | Not a `RESPONSE_BODY` blocking promotion |
| `tests/modsecurity-phase4-modes.t` | Strict mode aborts after headers were already sent | `strict` | `GET /x` | `Hello strict` | Test::Nginx expects empty reply and phase4 log has `actual_action=connection_abort` | no | `tests/cases/connector-specific/nginx/nginx_phase4_strict_connection_abort.yaml` | imported | Current smoke schema records empty-reply evidence without promoting RESPONSE_BODY blocking | response-body, phase4, intervention, logging | Needs explicit empty-reply/connection-abort assertion before promotion |
| `tests/modsecurity-phase4-content-types.t` | In-scope content type with strict mode aborts | `strict` | `GET /json` | `HIT JSON` with `default_type application/json` | Empty reply; phase4 log records `content_type=application/json` and `actual_action=connection_abort` | no | mapped-only | mapped-only | Requires strict-mode connection-abort assertions; not imported as active YAML | response-body, phase4, logging | Not a stable HTTP response assertion |
| `tests/modsecurity-phase4-content-types.t` | Out-of-scope content type logs but preserves response | `strict` | `GET /unknown` | `HIT UNKNOWN` with `default_type image/png` | HTTP 200 body preserved; phase4 log has `reason=content_type_not_in_scope` and no response body data | no | `tests/cases/connector-specific/nginx/nginx_phase4_content_type_out_of_scope.yaml` | imported, latest NGINX smoke PASS | Latest NGINX source-built run returned HTTP 200 after the harness permission fix; this is NGINX-specific phase-4 log-only evidence, not response-body blocking proof | response-body, phase4, logging, pass-through | Does not prove response-body blocking |
| `tests/modsecurity-phase4-content-types.t` | Empty content type is out of scope | `strict` | `GET /emptytype` | `HIT EMPTY` with empty default type | HTTP 200 body preserved; phase4 log records out-of-scope behavior | no | mapped-only | mapped-only | Similar to the imported out-of-scope case; left mapped to avoid redundant connector-specific coverage until schema grows | response-body, phase4, logging | No new behavior beyond imported out-of-scope probe |
| `tests/modsecurity-phase4-invalid-config.t` | Reject invalid content-type glob entry | n/a | `nginx -t` config test | `phase4-invalid.conf` with `text/*` | Config test output mentions invalid content-type entry | no | mapped-only | mapped-only | Current YAML runner is HTTP-smoke oriented and does not model expected config-test failures | config, response-body | Needs dedicated config-validation harness |
| `tests/modsecurity-phase4-regression.t` | Large response remains intact in minimal mode and log does not leak body | `minimal` | `GET /big` | 70,000 `A` bytes plus `TAIL` | HTTP 200, body prefix and tail preserved, phase4 log contains `log_only` but no large body data | no | mapped-only | mapped-only | Large fixture/log-leak coverage is useful but needs dedicated fixture ergonomics before active import | response-body, phase4, logging, pass-through | Current minimal YAML can express it awkwardly; deferred to avoid brittle huge fixtures |
| `tests/modsecurity-response-body.t` | Existing response-body blocking TODO | implicit response phase | `GET /body1` | `BAD BODY` | Upstream test remains TODO for HTTP 403 response-body blocking | partial | `tests/cases/response/body/response_body_basic_block.yaml` | non-promoted/mapped-only | Shared response-body blocking probe still does not produce stable HTTP 403 through Apache and NGINX | response-body, phase4, intervention | `RESPONSE_BODY` stays excluded from `verified_variables` |

## Promotion Boundary

The three imported NGINX-only PR #377 probes are intended to validate phase-4
logging/mode behavior and pass-through response preservation. In the latest
local NGINX source-built run they returned HTTP 200 after the harness permission
fix. They still do not count as `RESPONSE_BODY` blocking validation because
they intentionally expect HTTP 200.

Promotion of `RESPONSE_BODY` requires a separate evidence step with a defined
blocking case, stable real HTTP semantics, and an explicit Apache/NGINX common
or NGINX-only classification decision.
