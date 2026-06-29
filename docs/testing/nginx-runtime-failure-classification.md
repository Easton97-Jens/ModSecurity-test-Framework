# NGINX Runtime Permission Resolution

**Language:** English | [Deutsch](nginx-runtime-failure-classification.de.md)

Date: 2026-05-21

This note updates the previous 2026-05-20 NGINX runtime classification. It does
not change connector code under `connectors/nginx/src/`, YAML expectations,
XFAIL status, or RESPONSE_BODY verification.

## Summary

The previous local NGINX source-build smoke returned 43 PASS, 11 FAIL, and
0 BLOCKED. Every failure expected HTTP 200 and observed HTTP 403. The case-level
NGINX error logs showed:

```text
htdocs/index.html is forbidden (13: Permission denied)
```

The generated files were readable, but the runtime tree lived below a parent
directory that the NGINX worker could not traverse. That made the 11 cases
**harness/filesystem blocked**, not connector-gap, runtime-difference, or likely
bug evidence.

The harness now stages NGINX worker-facing runtime files under a readable local
harness work root for this environment (`/tmp/ModSecurity-conector-nginx-runtime-0`
during the root-run validation). It sets permissions only inside that generated
harness work root and does not require system-wide NGINX configuration changes,
global installs, or broad chmod hacks.

A later `make smoke-nginx` runtime pass over freshly produced source-build
artifacts completed with **54 PASS, 0 FAIL, 0 BLOCKED**. No
`htdocs/index.html` permission denial was observed in the runtime logs.

## Case Classification

| Case | Area | Previous actual | Latest actual | Latest classification |
| --- | --- | ---: | ---: | --- |
| `phase2_args_pass` | Phase 2 `ARGS` pass-through | 403 | 200 | PASS in current local NGINX smoke |
| `action_allow_phase1_pass` | Phase 1 `allow` pass-through | 403 | 200 | PASS in current local NGINX smoke |
| `response_body_pass` | RESPONSE_BODY pass-through | 403 | 200 | PASS-through evidence only; RESPONSE_BODY remains non-promoted |
| `v2_transformation_url_decode_pass_no_match` | `t:urlDecode` no-match pass-through | 403 | 200 | PASS in current local NGINX smoke |
| `v3_args_names_get_pass_no_match` | `ARGS_NAMES` no-match pass-through | 403 | 200 | PASS in current local NGINX smoke |
| `v3_request_cookies_names_pass_no_match` | `REQUEST_COOKIES_NAMES` no-match pass-through | 403 | 200 | PASS in current local NGINX smoke |
| `v3_request_cookies_pass_no_match` | `REQUEST_COOKIES` no-match pass-through | 403 | 200 | PASS in current local NGINX smoke |
| `v3_request_headers_names_pass_no_match` | `REQUEST_HEADERS_NAMES` no-match pass-through | 403 | 200 | PASS in current local NGINX smoke |
| `nginx_phase4_content_type_out_of_scope` | NGINX phase-4 content-type log-only probe | 403 | 200 | PASS in current local NGINX phase-4 log-only smoke; not RESPONSE_BODY promotion |
| `nginx_phase4_minimal_log_only` | NGINX phase-4 minimal log-only probe | 403 | 200 | PASS in current local NGINX phase-4 log-only smoke; not RESPONSE_BODY promotion |
| `nginx_phase4_safe_log_only` | NGINX phase-4 safe log-only probe | 403 | 200 | PASS in current local NGINX phase-4 log-only smoke; not RESPONSE_BODY promotion |

## Interpretation

- The 11 previous 403 results are now classified as resolved harness permission
  blockers.
- The current local NGINX run provides runtime pass-through evidence for those
  cases in this source-build environment.
- `response_body_pass` and the NGINX phase-4 log-only probes are **not**
  RESPONSE_BODY verification or stable response-body compatibility proof.
- No XFAIL/PASS promotion is made for response-body blocking support.
- `make smoke-all` was not run for this snapshot, so no full-smoke PASS count is
  claimed.

## Harness Notes

The NGINX harness needs generated runtime, log, and `htdocs` trees that the
worker process can traverse and read. In root-run environments the default
harness work root is under `${TMPDIR:-/tmp}`; non-root runs use
`${RUNNER_TEMP:-${TMPDIR:-/tmp}}` unless `NGINX_HARNESS_WORK_ROOT` is set.

The fix is intentionally local to generated harness paths:

- no global/system NGINX configuration changes
- no global installation prerequisite
- no chmod outside the generated harness work root
- no `chmod 777`
- no changes under `connectors/nginx/src/`
