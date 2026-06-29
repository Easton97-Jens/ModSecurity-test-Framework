# PR #3564 RAW Argument Collection Evidence

**Language:** English | [Deutsch](raw-args-pr3564.de.md)

Status: mapped-only / unsupported-local-source

Public source: https://github.com/owasp-modsecurity/ModSecurity/pull/3564

PR #3564 adds RAW URL-encoded argument collections intended to expose argument
names and values before libmodsecurity URL decoding:

- `ARGS_RAW`
- `ARGS_GET_RAW`
- `ARGS_POST_RAW`
- `ARGS_NAMES_RAW`
- `ARGS_GET_NAMES_RAW`
- `ARGS_POST_NAMES_RAW`

## Local Source Check

The helper below performs a read-only search of the configured v3 source:

```sh
sh ci/check-raw-args-support.sh
```

Observed locally on 2026-05-15 against `<workspace>/ModSecurity_V3`:

```text
raw_args_support: unsupported-local-source missing: ARGS_RAW ARGS_GET_RAW ARGS_POST_RAW ARGS_NAMES_RAW ARGS_GET_NAMES_RAW ARGS_POST_NAMES_RAW
```

No RAW argument YAML case is active in this repository for the current local
source. That avoids claiming PR #3564 behavior before the implementation is
present and tested through both connectors.

## Promotion Criteria

RAW cases may move from mapped-only to active common only when all conditions
are true:

1. `MODSECURITY_V3_SOURCE_DIR` contains the PR #3564 RAW collection
   implementation and regression data.
2. The YAML cases are source-derived from that implementation or regression
   data.
3. Apache returns the expected HTTP status through the real connector path.
4. NGINX returns the expected HTTP status through the real connector path.

Until then, RAW argument support remains mapped-only and must not appear in
`verified_variables`.
