# Capability Model

**Language:** English | [Deutsch](capability-model.de.md)

Capabilities describe what a YAML case exercises. They are evidence labels, not
automatic skips. A capability is counted as verified only when a real connector
smoke case passes through Apache or NGINX.

## Active Capability Names

| Capability | Meaning | Verified variable mapping |
| --- | --- | --- |
| `multipart` | Deterministic multipart/form-data request generation | none by itself |
| `files` | `FILES_*` multipart collections | `FILES` |
| `xml` | XML body processor and XML collection behavior | `XML` |
| `json` | JSON or raw JSON request-body behavior | `REQUEST_BODY` |
| `response-body` | Response-body access/pass-through behavior | not `RESPONSE_BODY` until blocking passes |
| `audit-log` | Stable audit-log fields are asserted | `AUDIT_LOG` |
| `audit-log-absent` | Expected audit-log absence; currently used only for non-promoted probes | none |
| `collections` | ModSecurity collection behavior | none by itself |
| `request-cookies` | Cookie value/name collections | `REQUEST_COOKIES` |
| `args-names` | Argument-name collection | `ARGS_NAMES` |
| `request-uri` | Raw request URI variable | `REQUEST_URI` |
| `response-headers` | Response header phase/filter behavior | `RESPONSE_HEADERS` |
| `request-headers` | Request header values or names | `REQUEST_HEADERS` |
| `request-body` | Request body access | `REQUEST_BODY` |
| `query-args` / `form-urlencoded` | Query or URL-encoded body args | `ARGS` |

`RESPONSE_BODY` is intentionally not emitted in `verified_variables` while
`response_body_basic_block` remains non-promoted/mapped-only.

## Validation Rules

YAML cases may express capabilities as a list or as a mapping of booleans.
Underscore aliases such as `request_body` normalize to dash names such as
`request-body`. Unknown capability names fail materialization.

Capabilities do not decide whether a case is active. Topic paths provide
category/scope; YAML status metadata provides active versus inventory behavior:

- Cases with missing `status` are treated as active.
- Cases with `status: imported`, `minimal`, `v2-imported`, or `v3-imported`
  remain default runtime candidates for compatibility.
- Cases with historical expected-failure metadata, `pending`, `future`,
  `connector-gap`, or `runtime-difference` classification are
  inventory/evidence cases unless force-all execution is requested.
- Connector-specific cases are active only for their matching connector.
