# Xfail NGINX-Specific Cases

Status: xfail

These source-derived cases are probeable with `SMOKE_CASES=<path> make
smoke-nginx`, but they stay outside normal discovery because the current smoke
schema or observed behavior does not support an honest active PASS.

`nginx_phase4_strict_connection_abort.yaml` is derived from ModSecurity-nginx
PR #377 strict-mode behavior. It expects a late connection abort after headers
are sent, while the current runner is based on stable HTTP status assertions.
It remains xfail and does not promote `RESPONSE_BODY`.
