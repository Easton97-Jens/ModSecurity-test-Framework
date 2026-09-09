# Change record

**Language:** English | [Deutsch](20260909-01-remediate-modsecurity-v3-multipart.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260909-01-remediate-modsecurity-v3-multipart |
| UTC date | 2026-09-09 |
| Framework base revision | 86451b45ae7bb7953baf9f81f2c2dad07395a808 |
| Issue or pull request | No reference existed when this pre-delivery record was created. The current user authorized a separate Framework Draft PR; its observed reference is recorded after creation. |

## Motivation and problem statement

The reusable Framework dependency and multipart regression boundary needed a
patched ModSecurity v3 provenance tuple and byte-exact controls for newline
representations. This is a Framework-only engine-validation change. It does
not claim connector loading, backend-byte delivery, client behavior, or a
Parent Gitlink update, and it excludes the private audit and raw payloads.

## Affected components and security boundaries

- `ci/lib/common.sh` owns the approved ModSecurity v3 tag/commit tuple.
- `src/v3-api-smoke/` and the multipart case catalog exercise the engine
  parser-to-`ARGS` boundary.
- `tests/runners/runner_core.py` materializes quoted scalar escapes for the
  reusable YAML case path.

The security invariant is that multipart field bytes preserved by the engine
must reach rule evaluation without silent loss or normalization. This record
does not infer a connector or backend result from the engine evidence.

## Acceptance criteria

- The approved dependency tuple is `v3.0.16` at
  `7ea9fefbe0ba409d8733b4d682c8c4c059cd028d`.
- Exact CRLF and LF controls cause an engine intervention; the `AB` control
  remains allowed for the newline rule and is denied by an exact `AB` rule.
- The reusable YAML catalog and runner preserve those byte distinctions.
- Focused Framework source, regression, provenance, documentation, link, and
  path checks pass without editing generated historical reports.
- Delivery remains a separate Framework Draft PR only; no Parent, MRTS,
  Gitlink, merge, release, or deployment action is included.

## Alternatives considered

Updating only the dependency provenance would not preserve a reproducible
boundary test for the affected representation class. Broad connector/runtime
claims would exceed Framework ownership. The selected approach updates the
approved tuple and adds narrowly scoped engine and reusable-catalog controls.

## Implementation decision

The common-version tuple now selects the approved v3.0.16 commit. The C API
smoke adds exact CRLF, LF, allow, and exact-representation controls. The YAML
cases and runner use compatible quoted-scalar decoding for byte sequences, and
the regression test loads the current multipart catalog. Documentation limits
the result to engine evidence.

## Changed files and tests

- Provenance: `ci/lib/common.sh`.
- Engine smoke: `src/v3-api-smoke/v3_api_smoke.c`.
- Reusable case materialization: `tests/runners/runner_core.py`.
- Multipart cases:
  `tests/cases/body/multipart/multipart_crlf_field_deny_v3_0_16.yaml`,
  `multipart_lf_field_deny_v3_0_16.yaml`, and
  `multipart_ab_field_allow_v3_0_16.yaml`.
- Regression: `tests/security_regression/test_multipart_newline_runtime_difference.py`.
- Documentation: `docs/architecture.md`, `docs/architecture.de.md`, this
  paired Change Record, and the paired change-record indexes.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk proxy env MODSECURITY_V3_DIR=<task-built-v3.0.16> BUILD_ROOT=<task-owned-build-root> make -C src/v3-api-smoke run` | `0` | Primary control, exact CRLF/LF denies, `AB` allow, and exact-`AB` deny passed against the task-built library. | `security-audit-20260909` |
| `rtk proxy env PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest tests.security_regression.test_multipart_newline_runtime_difference tests.security_regression.test_runner_core_output_containment tests.security_regression.test_modsecurity_v3_git_ref_provenance tests.security_regression.test_common_version_atomic_provenance` | `0` | 56 focused tests passed, including the current YAML catalog load. | `security-audit-20260909` |
| `rtk proxy make check-documentation` | `0` | Documentation links, bilingual variable documentation, repository paths, and Change Record contract passed. | `security-audit-20260909` |
| `rtk proxy python3 ci/tools/check-common-versions.py --validate-canonical` | `0` | Canonical common-version provenance passed. | `security-audit-20260909` |
| `rtk proxy git diff --check` | `0` | No whitespace error was reported. | `security-audit-20260909` |

## Security impact

The change upgrades the approved engine provenance and makes representation
controls explicit at the parser-to-rule boundary. It rechecks the original
newline class, an LF variant, and an exact representation control without using
a broad substring rule or weakening an existing test. The evidence establishes
engine behavior only; it is not connector, backend, or client evidence.

## Documentation and runtime evidence

`docs/architecture.md` and `docs/architecture.de.md` state the bounded
engine-only conclusion. The task-built C API smoke is controlled engine
evidence, not a Framework-hosted lifecycle or connector runtime result. No
production service was contacted.

## Checks not run

- Controlled connector/backend evidence for the exact task library and
  delivered bytes is unavailable in this environment.
- Generated Framework reports remain unchanged: regeneration in a staging copy
  would rewrite historical runtime classifications outside this task scope.
- Exact-head hosted checks, review, and SonarQube disposition do not yet exist
  at pre-delivery record creation.

## Limitations and residual risk

The runner's compatible quoted-scalar decoding has broader catalog reach than
the three new cases; the full current catalog load passed, but future
non-JSON-compatible scalar conventions require separate review. Engine proof
does not establish the behavior of any connector, backend, or external client.
The finding remains locally fixed with connector/backend validation pending and
is not promoted to `verified`.

## Final diff and review status

An independent scoped review found no concrete bypass and no weakened security
control in the Framework candidate. The paired record, final task-owned diff,
staged-file list, commit, remote/PR-head relationship, and hosted results
remain to be observed during the authorized Draft-PR lifecycle. No merge,
release, deployment, Parent Gitlink update, or MRTS change is authorized.
