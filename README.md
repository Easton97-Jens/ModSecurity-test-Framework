# ModSecurity Test Framework

This repository is the shared test, runtime, coverage, and reporting framework
for ModSecurity connector projects. It owns the reusable YAML case corpus,
runner code, normalizers, runtime-matrix tooling, generated report logic, and
testing documentation.

It is not a connector implementation repository. Connector projects provide
connector source code, harness entrypoints, adapter metadata, and connector-local
runtime evidence.

## Runtime Matrix

The runtime matrix joins framework-owned YAML cases with connector-owned runtime
summary evidence. It records per-case Apache and NGINX outcomes as evidence
only; it never promotes XFAIL, pending, future, connector-gap, or RESPONSE_BODY
cases automatically.

Connector projects normally run:

```sh
CONNECTOR_ROOT=/path/to/ModSecurity-conector make runtime-matrix-all
```

`runtime-matrix-all` sets `FORCE_ALL_CASES=1` and attempts all applicable YAML
cases. Expected failures remain visible in generated reports.

## Test Variants

The framework supports two ModSecurity rule-loading variants:

- `no-crs`: load only the local rules materialized from each YAML case.
- `with-crs`: load OWASP Core Rule Set before the local YAML case rules.

Use these entrypoints with a connector repository:

```sh
CONNECTOR_ROOT=/path/to/ModSecurity-conector make test-no-crs
CONNECTOR_ROOT=/path/to/ModSecurity-conector make test-with-crs
CONNECTOR_ROOT=/path/to/ModSecurity-conector make test
```

`make test` runs both variants. `make test-with-crs` fetches and prepares CRS
automatically under `SOURCE_ROOT`/`BUILD_ROOT`; `make fetch-crs` can be used
explicitly when you want to prefetch it. The CRS version pin, repository URL,
and generated CRS paths are centralized in `ci/common.sh`; do not duplicate the
CRS version in Makefiles, workflows, or other scripts.

## YAML Case System

Cases live under `tests/cases/` and are organized by topic:

```text
request/{args,cookies,headers,uri}/
body/{json,xml,multipart,files}/
security/{sql,xss}/
response/{headers,body}/
audit-log/
transformations/
phases/
negative-pass-through/
connector-specific/{apache,nginx,envoy,haproxy,lighttpd,traefik}/
future-gap/
```

Case identity comes from the YAML `name` field, not the filesystem path. Path
taxonomy is used for discovery and reporting only.

## Runner Architecture

The shell harnesses call `tests/runners/case_cli.py`, which uses
`tests/runners/runner_core.py` to load YAML cases, materialize rules and
fixtures, and assert runtime responses. Normalizers live in `tests/normalizers/`.

Default discovery uses active/imported/minimal metadata classes. Force-all
discovery also includes XFAIL, pending, future, and gap cases where they are
applicable to the current connector. These classes are read from YAML metadata
and connector inventory, not from status directories.

## Coverage Reports

The generator writes framework-owned reports when `OUTPUT_ROOT` is this
repository, and connector-owned evidence reports when `OUTPUT_ROOT` is a
connector repository:

```sh
python3 ci/generate-case-matrix.py \
  --framework-root /path/to/ModSecurity-test-Framework \
  --connector-root /path/to/ModSecurity-conector \
  --output-root /path/to/ModSecurity-conector
```

Connector output goes to `reports/testing/` plus a root
`TEST-COVERAGE-SUMMARY.md`. Framework output goes to `docs/testing/` plus its
own root `TEST-COVERAGE-SUMMARY.md`.

## Evidence Semantics

- Generated coverage is reporting only.
- Full runtime evidence must come from local connector source-build smokes.
- `make smoke-all` is authoritative only if it was actually executed
  successfully.
- XFAIL, pending, future, connector-gap, and runtime-difference cases are
  evidence classes, not PASS promotions.
- `RESPONSE_BODY` remains non-verified/non-promoted unless explicitly proven by
  stable full-smoke runtime evidence in the connector project.

## Connector Integration

Use explicit paths:

```sh
FRAMEWORK_ROOT=/path/to/ModSecurity-test-Framework
CONNECTOR_ROOT=/path/to/ModSecurity-conector
```

Connector repositories may vendor this framework as a submodule, commonly under
`modules/ModSecurity-test-Framework`. There is no hidden absolute workspace
fallback. Connector-specific inventory stays in the connector repository at
`config/testing/import-status.json`; runtime evidence stays under
`reports/testing/`.
