# NGINX-Specific Cases

**Language:** English | [Deutsch](README.de.md)

Cases in this directory are NGINX-only evidence probes. They are marked with
YAML metadata such as `portable: false`, `connector: nginx`, and `status`
instead of being separated into status directories.

The PR #377 phase-4 cases verify `modsecurity_phase4_mode` or content-type log
behavior and HTTP 200 pass-through preservation. They do not verify
response-body blocking and must not add `RESPONSE_BODY` to `verified_variables`.

`nginx_phase4_strict_connection_abort.yaml` remains former expected-failure because strict mode
may abort the connection after headers are sent, while the current runner
asserts stable HTTP status. This is not RESPONSE_BODY promotion.
