# Real-World Connector Validation

Status: implemented

`real-world-connector-path` means the smoke result came from this path:

```text
HTTP client
  -> real Apache or NGINX process
  -> real ModSecurity connector module
  -> libmodsecurity
  -> rule variables
  -> real HTTP response
```

This is different from the connector-free libmodsecurity API smoke under
`src/v3-api-smoke/`. The API smoke proves a public libmodsecurity C API path,
but it does not prove that a server connector populated the same variables,
buffered the same bodies, wrote the same audit artifacts, or ran the same hook
phase.

## Why This Exists

Direct API tests do not exercise server and connector behavior. The
real-world connector path catches issues such as:

- server-specific query argument normalization before `ARGS` reaches
  libmodsecurity;
- headers not being passed into `REQUEST_HEADERS` as expected;
- request bodies not being read early enough for phase:2 rules;
- raw JSON body content being unavailable to `REQUEST_BODY`;
- multipart uploads not populating `FILES`, `FILES_NAMES`,
  `FILES_COMBINED_SIZE`, or `MULTIPART_FILENAME`;
- audit-log artifacts being written differently by a connector runtime;
- response filter behavior differing from direct API expectations.

If the server starts and the module loads, but an expected variable does not
reach libmodsecurity and the YAML expectation fails, that is `fail`, not
`blocked`. `blocked` is reserved for missing sources, downloads, build tools,
module artifacts, libraries, or runtime prerequisites.

## Current Proof Cases

The active YAML cases are the only source of rules, requests, and expectations.
The connector harnesses materialize them and send real HTTP requests.

| Verified variable | Example active cases | Status |
| --- | --- | --- |
| `ARGS` | `phase2_args_block`, `collection_args_get_block`, V2 operator/transform cases | Apache and NGINX pass locally |
| `REQUEST_HEADERS` | `phase1_header_block` | Apache and NGINX pass locally |
| `REQUEST_BODY` | `request_body_json_block`, `request_body_raw_text_block`, `json_request_body_block` | Apache and NGINX pass locally |
| `FILES` | `multipart_files_value_block`, `multipart_files_names_block`, `multipart_files_combined_size`, `multipart_filename_block` | Apache and NGINX pass locally |
| `XML` | `xml_request_body_block` | Apache and NGINX pass locally |
| `AUDIT_LOG` | `audit_log_phase1_block` | Apache and NGINX pass locally |
| `RESPONSE_HEADERS` | `response_header_basic` | Apache and NGINX pass locally |

`RESPONSE_BODY` is deliberately not listed as verified. The active
`response_body_pass` case proves pass-through with response-body access enabled,
but response-body rule-variable blocking remains mapped/xfail until both
connectors return stable HTTP 403 for the same YAML case.

## Result Metadata

Each connector summary under `$BUILD_ROOT/results/` records:

```json
{
  "connector_path": "real-world",
  "validation_mode": "real-world-connector-path",
  "server": "apache",
  "server_binary": "...",
  "module": "...",
  "libmodsecurity": "...",
  "verified_variables": ["ARGS", "REQUEST_BODY"]
}
```

`verified_variables` is computed only from active cases whose result is
`pass`. Mapped-only, xfail, blocked, and failed cases do not add variables.

## Current Connector Status

Observed locally on 2026-05-15 with
`BUILD_ROOT=/src/ModSecurity-test-Framework-build`:

| Connector | Real server | Connector module | Result |
| --- | --- | --- | --- |
| Apache | source-built httpd 2.4.67 | `mod_security3.so` | `make smoke-apache` pass |
| NGINX | source-built NGINX 1.31.0 from `release-1.31.0` | `ngx_http_modsecurity_module.so` | `make smoke-nginx` pass |

Other environments must run the same smoke targets before claiming pass.

## Future Connectors

HAProxy, Envoy, Lighttpd, and Traefik need analogous proof before any runtime
claim is made:

- real server/proxy process;
- real integration module, plugin, filter, SPOE service, or middleware;
- libmodsecurity or documented equivalent integration path;
- active YAML cases sent as HTTP traffic;
- result summary with real server binary/module metadata and verified
  variables derived only from passing cases.
