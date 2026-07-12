# Framework CI tooling

**Language:** English | [Deutsch](README.de.md)

`ci/` contains Framework-owned validation, local runtime orchestration,
provisioning, reporting, and helper tooling. These files organize existing
contracts; they do not define connector lifecycle semantics, capability states,
schemas, or evidence-promotion policy.

## Structure

| Directory | Responsibility |
|---|---|
| `checks/catalog/` | Catalog, metadata, helper, CRS-pin, and MRTS-import contract checks. |
| `checks/evidence/` | Response-body, full-lifecycle, and transport-hardening evidence validation. |
| `checks/protocol/` | Managed protocol client and its evidence checker. |
| `checks/security/` | Payload/data-flow and normalizer safety checks. |
| `checks/documentation/` | Markdown link, bilingual variable/reference, workflow, and moved-path checks. |
| `runtime/` | Connector-smoke and runtime-matrix entrypoints. |
| `provisioning/` | Explicit source, CRS, MRTS, and local component preparation. |
| `reporting/` | Case matrices, work queues, summaries, and runtime-snapshot generators. |
| `tools/` | Developer bootstrap, diagnostics, dependency, and fast-check commands. |
| `lib/` | Shared shell/Python helpers; `common.sh` is passive configuration and `path.sh` discovers Framework paths. |

## Entry points and path rules

Direct shell entrypoints determine their own directory, derive `CI_ROOT`, and
source `ci/lib/path-bootstrap.sh`. The bootstrap discovers or validates
`FRAMEWORK_ROOT`; scripts therefore remain callable after being grouped into
these responsibility folders. Python tools use their file location only to
find the Framework root and shared `ci/lib/` imports.

`ci/lib/common.sh` defines defaults and helpers but must not fetch, install,
create directories, or run a check merely because it was sourced. Version pins,
source URLs, checksums, and component defaults live there rather than being
duplicated in workflows or individual scripts.

Set `FRAMEWORK_ROOT` to this checkout and `CONNECTOR_ROOT` to the connector
checkout only when a command crosses repository boundaries. Set `BUILD_ROOT`,
`SOURCE_ROOT`, `TMP_ROOT`, `LOG_ROOT`, and `EVIDENCE_ROOT` to writable runtime
paths outside Git for an isolated run. For example, `/var/tmp/modsecurity-framework/build`
is a temporary build path, not a required host location. See
[variables and placeholders](../docs/reference/variables.md) for formats,
defaults, scope, examples, and sensitive-value guidance.

## Relevant targets

- `make lint` runs shell/Python syntax, catalog/security/evidence contracts,
  documentation checks, and whitespace validation. It does not create runtime
  proof.
- `make check-no-crs-catalog` validates catalog structure only.
- `make check-documentation` runs Markdown link, variables/placeholders, and
  obsolete-path checks.
- `make quick-check` adds the short local Python/MRTS checks after `lint`.
- `make refresh-framework-reports` regenerates Framework-owned reports through
  `ci/reporting/`; do not edit generated Markdown by hand.

Runtime scripts may report `BLOCKED` when a connector-owned executable harness
or prerequisite is absent. A build/self-test starter result is not runtime
smoke evidence and does not imply an evidence promotion. The [glossary](../docs/reference/glossary.md)
defines these status and evidence terms.

## Adding or moving a CI file

Place a new file according to its one primary responsibility. Keep reusable,
imported helpers in `lib/`; keep a report writer in `reporting/`; do not create
a second copy of a helper merely to place it beside a caller. When moving a
tracked file, use `git mv`, then update Make targets, workflows, shell sources,
Python imports, tests, documentation, and generator provenance. Run `make lint`
and the affected focused test afterwards.

Do not put connector implementation code, generated reports, external source
trees, runtime logs, private keys, credentials, or ad-hoc local scripts in
`ci/`.
