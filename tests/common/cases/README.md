# Common Cases

Status: scaffolded

Only portable engine/rule/behavior cases belong here.

Do not add cases that require a specific server/proxy runtime.

`minimal/phase2_args_block.yaml` is a portable rule/request/expectation model.
It becomes a connector pass only when a connector-specific harness executes it
and observes the expected result.

`imported/` contains source-derived portable cases from the local Apache and
NGINX connector test suites. Each imported YAML must include `origin`,
`category`, `capabilities`, `portable: true`, `status: imported`, and
`known_limitations`.

`v2-imported/` contains source-derived portable semantics cases from
`ModSecurity_V2/tests/`. These cases are compatibility checks only; no v2
connector architecture is imported.

`v3-imported/` contains source-derived portable regression cases from
`ModSecurity_V3/test/`. These cases use libmodsecurity v3 behavior as the
primary compatibility reference.

Supported request shapes are intentionally small: `GET`, `POST`, headers,
plain bodies, and deterministic multipart form bodies. Multipart parser edge
cases, streaming, HTTP/2, and connector-specific server configuration stay out
of common cases until both connector harnesses prove the behavior.

Response-body pass-through can live here when both connectors pass. Response
body blocking is mapped as xfail until Apache and NGINX both return stable HTTP
403 for the same YAML case.
