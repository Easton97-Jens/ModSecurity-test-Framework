# Compatibility

Status: scaffolded

## Version Position

The scaffold targets libmodsecurity v3 public APIs. v2 artifacts are not used as
architecture for new connectors.

## Current Compatibility Matrix

| Area | Status | Notes |
| --- | --- | --- |
| Common headers | implemented | Connector-neutral C-compatible data shapes only |
| libmodsecurity v3 API mapping | planned | Public API sequence documented, not wrapped |
| Apache connector | scaffolded | Local source-built PoC observed expected HTTP behavior for all current shared minimal cases |
| NGINX connector | scaffolded | Local source-built PoC observed expected HTTP behavior for all current shared minimal cases |
| Apache real-world connector path | implemented | Smoke summaries record source-built httpd, `mod_security3.so`, libmodsecurity, and verified variables |
| NGINX real-world connector path | implemented | Smoke summaries record source-built NGINX, dynamic module, libmodsecurity, and verified variables |
| HAProxy connector | unknown | SPOE/Lua/native options documented, implementation undecided |
| Envoy connector | unknown | HTTP filter/ext_authz/Wasm options documented, implementation undecided |
| Lighttpd connector | unknown | Native plugin and mod_magnet options documented, implementation undecided |
| Traefik connector | unknown | Yaegi/Wasm plugin options documented, implementation undecided |
| v2 regression reuse | planned | Only portable rule/engine semantics may enter `tests/common/` |
| v2-derived common imports | implemented | Operator and transformation cases including `@streq`, `@contains`, `@beginsWith`, `@endsWith`, `@pm`, `@containsWord`, `t:lowercase`, `t:trim`, `t:urlDecode`, and `t:htmlEntityDecode` pass locally on Apache and NGINX |
| v3-derived common imports | implemented | Multipart FILES, XML body processor, operator, transformation, action, cookie/header-name/ARGS_NAMES, and stable audit cases pass locally on Apache and NGINX |
| Source-derived Apache/NGINX test import | implemented | Imported YAML cases are derived, not copied; origin and portability are documented |

## Capability Rule

Tests and connector docs must name required capabilities. If a behavior depends
on hook timing, buffering, streaming, log artifacts, reload semantics, or server
configuration, it is connector-specific unless proven portable.

## Shared Minimal Cases

The files under `tests/common/cases/minimal/` are portable rule/request models.
They are not proof that a connector supports the behavior until that
connector's runtime harness observes the expected HTTP response.

Observed locally on 2026-05-15 with `BUILD_ROOT=/src/ModSecurity-test-Framework-build`:

| Case | Capability area | Apache | NGINX |
| --- | --- | --- | --- |
| `audit_log_phase1_block.yaml` | query args, phase 1, audit log | pass, HTTP 403 plus audit fields | pass, HTTP 403 plus audit fields |
| `phase1_header_block.yaml` | request headers, phase 1 | pass, HTTP 403 | pass, HTTP 403 |
| `phase2_args_block.yaml` | query args, phase 2 | pass, HTTP 403 | pass, HTTP 403 |
| `phase2_args_pass.yaml` | query args, phase 2, pass-through | pass, HTTP 200 plus origin body | pass, HTTP 200 plus origin body |
| `request_body_json_block.yaml` | request body, JSON content type, raw body match | pass, HTTP 403 | pass, HTTP 403 |
| `request_body_urlencoded_block.yaml` | form body, `ARGS_POST` | pass, HTTP 403 | pass, HTTP 403 |
| `response_header_basic.yaml` | response headers, phase 3 | pass, HTTP 403 | pass, HTTP 403 |

This proves only these PoC behaviors in this workspace, not full connector
compatibility, CRS support, multipart handling, streaming behavior, HTTP/2, or
complete response-body behavior.

## Imported Case Scopes

| Scope | Location | Compatibility meaning |
| --- | --- | --- |
| common minimal | `tests/common/cases/minimal/` | Already proven locally for both PoCs before the import step |
| common imported | `tests/common/cases/imported/` | Portable candidates derived from Apache/NGINX tests; compatibility is claimed only after both connector smokes pass |
| v2 imported | `tests/common/cases/v2-imported/` | Portable v2 semantics candidates adapted to HTTP behavior and proven on both connector PoCs |
| v3 imported | `tests/common/cases/v3-imported/` | Portable v3 regression candidates adapted to HTTP behavior and proven on both connector PoCs |
| Apache imported | `tests/apache/cases/imported/` | Apache-only until a common equivalent is proven |
| NGINX imported | `tests/nginx/cases/imported/` | NGINX-only until a common equivalent is proven |

Mapped-only categories include HTTP/2, proxy, multipart parser edge cases,
response-body blocking, external-file operators, debug logs, and connector
config inheritance.

Observed locally on 2026-05-15, the current imported common cases all passed on
Apache and NGINX through `make smoke-all`; the NGINX-specific imported cases
passed only on NGINX and remain `portable: false`.

## Body And Filter Compatibility

| Case or category | Apache | NGINX | Status |
| --- | --- | --- | --- |
| `json_request_body_block.yaml` | pass, HTTP 403 | pass, HTTP 403 | fully-imported-common |
| `multipart_basic_block.yaml` | pass, HTTP 403 | pass, HTTP 403 | fully-imported-common |
| `response_body_pass.yaml` | pass, HTTP 200 | pass, HTTP 200 | fully-imported-common |
| `response_body_basic_block` | fail, HTTP 200 and no audit hit | fail, `RESPONSE_BODY` audit/error hit but client observed `000` empty reply | xfail/mapped-only |

The response-body block row is intentionally not an active smoke. The NGINX
reference test marks the behavior TODO. A local three-repeat probe did not
produce stable HTTP 403 on either connector, so this repository documents the
evidence without claiming connector parity.

## V2/V3-Derived Compatibility

Observed locally on 2026-05-15 with `BUILD_ROOT=/src/ModSecurity-test-Framework-build`:

| Case group | Apache | NGINX | Status |
| --- | --- | --- | --- |
| V2 operator semantics (`@streq`, `@contains`, `@beginsWith`, `@endsWith`, `@pm`, `@containsWord`) | pass, HTTP 403 | pass, HTTP 403 | fully-imported-common |
| V2 transformation semantics (`t:lowercase`, `t:trim`, `t:urlDecode`, `t:htmlEntityDecode`) | pass, HTTP 403 | pass, HTTP 403 | fully-imported-common |
| V3 multipart FILES variables | pass, HTTP 403 | pass, HTTP 403 | fully-imported-common |
| V3 XML body processor basic case | pass, HTTP 403 | pass, HTTP 403 | fully-imported-common |
| V3 `@rx`, trim, and `SecAction` basics | pass, HTTP 403 | pass, HTTP 403 | fully-imported-common |
| V3 `@pm`, cookies, header names, ARGS_NAMES, and serial audit basics | pass | pass | fully-imported-common |
| V3 `nolog,pass` audit absence (`issue-2196`) | pass locally, empty audit log | pass locally, empty audit log | xfail because GitHub Actions observed a non-empty audit log |
| PR #3564 RAW argument collections | unsupported in current local v3 source | unsupported in current local v3 source | mapped-only/unsupported-local-source |

The active cases prove only the minimal YAML scenarios. V2 Perl harness
internals, v3 API-only cases, XML schema/DTD validation, malformed multipart,
NUL/binary transformation branches, streaming, HTTP/2, and optional-library
operators remain mapped until dedicated support is added.

## Real-World Connector Path

`real-world-connector-path` is the compatibility proof mode for Apache and
NGINX:

```text
HTTP client -> server process -> connector module -> libmodsecurity -> rule variables -> HTTP response
```

The direct v3 API smoke remains separate and is not connector proof. Connector
summary JSON records `connector_path`, `validation_mode`, `server_binary`,
`module`, `libmodsecurity`, and `verified_variables`. A variable appears there
only if at least one active passing case exercised it through the real server
runtime.

Current active passing cases verify `ARGS`, `ARGS_NAMES`, `REQUEST_COOKIES`,
`REQUEST_HEADERS`, `REQUEST_URI`, `REQUEST_BODY`, `FILES`, `XML`, `AUDIT_LOG`,
and `RESPONSE_HEADERS` through both Apache and NGINX in this workspace.
`RESPONSE_BODY` remains mapped/xfail until an active response-body
variable/blocking case passes on both connectors.

## RAW Argument Collections

ModSecurity PR #3564 introduces `ARGS_RAW`, `ARGS_GET_RAW`, `ARGS_POST_RAW`,
`ARGS_NAMES_RAW`, `ARGS_GET_NAMES_RAW`, and `ARGS_POST_NAMES_RAW`.

The current local `/root/conecter/ModSecurity_V3` checkout does not contain the
RAW collection implementation or its regression file, so this repository marks
RAW arguments as `mapped-only/unsupported-local-source`. They must not appear in
active PASS summaries until a configured v3 source includes the PR and both
Apache and NGINX pass real-world connector smokes for source-derived RAW cases.

`v3_action_nolog_pass_no_audit` is also classified as xfail/mapped for now:
local runs in this workspace produced HTTP 200 and empty audit logs, but the
current GitHub Actions run reported `expected audit log to be absent or empty`.
It is not counted as a stable common PASS until local Apache, local NGINX, and
GitHub Actions agree.
