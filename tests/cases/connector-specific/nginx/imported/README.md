# Imported NGINX-Specific Cases

Status: imported

The YAML files in this directory are derived from local
local `/root/conecter/ModSecurity-nginx/tests/` behavior from upstream
https://github.com/owasp-modsecurity/ModSecurity-nginx. They are marked
`portable: false` and `connector: nginx` until the same behavior is proven
against another connector and promoted to `tests/common/cases/imported/`.

The PR #377 phase-4 cases in this directory are NGINX-only evidence probes.
They verify `modsecurity_phase4_mode`/content-type log behavior and HTTP 200
pass-through preservation. They do not verify response-body blocking and must
not add `RESPONSE_BODY` to `verified_variables`.
