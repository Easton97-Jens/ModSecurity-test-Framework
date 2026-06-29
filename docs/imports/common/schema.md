# Common Test Schema

**Language:** English | [Deutsch](schema.de.md)

Status: scaffolded

Portable common cases use the minimal mapping shape below:

```yaml
name: example

capabilities:
  query_args: true
  phase2: true
  intervention: true

rules: |
  SecRuleEngine On
  SecRule ARGS:test "@streq attack" "id:1,phase:2,deny,status:403"

request:
  method: GET
  path: "/?test=attack"
  headers:
    User-Agent: optional
  body: optional
  multipart:
    boundary: optional-boundary
    parts:
      - name: optional
        body: optional

response:
  body: optional origin response body

expect:
  status: 403
  intervention: deny
  rule_id: 1
  response_contains: optional pass-through text
  audit_log:
    required: false
  phase4_log:
    required: false
    contains:
      - optional stable substring
    not_contains:
      - optional stable substring
```

`request.body` and `request.multipart` are mutually exclusive. Multipart bodies
are materialized by the shared runner with deterministic CRLF line endings and
a generated `Content-Type: multipart/form-data; boundary=...` header.

`response.body` is optional. When omitted, the harness writes a small default
origin body under the per-case runtime docroot.

`capabilities` names the portable behavior needed by the case. Current minimal
capabilities include `query_args`, `request_headers`, `request_body`,
`form_urlencoded`, `multipart`, `json`, `response_headers`, `response_body`,
`phase1`, `phase2`, `phase3`, `phase4`, `intervention`, `pass_through`, and
`audit_log`.

`expect.intervention` is limited to `deny`, `pass`, or `none`. A pass-through
case should use `intervention: none`, `status: 200`, and usually
`response_contains` to prove the request reached the origin content.

Audit-log cases keep the audit directives in `rules` and use
`@@AUDIT_LOG@@` / `@@AUDIT_LOG_DIR@@` placeholders. The shared runner
materializes those placeholders to per-case paths under `BUILD_ROOT`.
Stable audit-log expectations live in `expect.audit_log`; values are checked as
substrings, so volatile IDs, timestamps, ports, and absolute generated paths
must not be required.

NGINX-only PR #377 evidence cases may use connector-specific fields:

```yaml
nginx:
  files:
    phase4-content-types.conf: |
      application/json
  location_directives: |
    modsecurity_phase4_log "@@NGINX_PHASE4_LOG@@";
    modsecurity_phase4_content_types_file "@@NGINX_FILE:phase4-content-types.conf@@";
```

`nginx.location_directives` is rendered into an included file inside the NGINX
`location /` block. `nginx.files` writes deterministic per-case config fixtures
under that case runtime config directory. Supported placeholders are
`@@NGINX_PHASE4_LOG@@` and `@@NGINX_FILE:<name>@@`. `expect.phase4_log` checks
stable substrings in the generated phase-4 log and is intended only for
connector-specific NGINX imported or former expected-failure cases.

Open work is tracked in `docs/roadmap/todo-inventory.md`:

- Define a machine-readable JSON schema after the YAML shape settles.
- Reject connector-specific fields in common schema validation.
