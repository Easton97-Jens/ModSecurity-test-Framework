# Native preparation contracts

**Language:** English | [Deutsch](20261108-01-native-preparation-contracts.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261108-01-native-preparation-contracts |
| UTC date | 2026-11-08 |
| Framework base revision | bacb3065aec2434a3b7b9cbdaba02533e84c3fb9 |
| Issue or pull request | Framework #169 |

## Motivation and problem statement

The build-contract scaffold did not enforce repository dependency boundaries.
Migration-map regeneration also treated one later Framework fixture as an
original Product source and failed its historical Git-blob prerequisite.

## Affected components and security boundaries

Framework-owned architecture validation, delegated Connector lint and migration
provenance are affected. Product code remains separate from test infrastructure;
source provenance must not admit an arbitrary missing historical file.

## Acceptance criteria

Accept neutral Common inputs and legitimate test delegation. Reject the supported
host SDK, Product-to-test-infrastructure and reverse-gitlink violations, invalid
models and incomplete relevant inputs. Validate the one registered later fixture
against actual Git history while preserving strict legacy-blob validation,
source-map identity, root containment and the 100 standard cases.

## Alternatives considered

The existing scaffold was insufficient. The native desired-contract check uses
the versioned ownership rules without enabling a paid service feature. A generic
skip for missing historical sources was rejected in favor of one explicit,
validated introduction with unchanged generated row schema.

## Implementation decision

Use a mandatory version-1 architecture model and a real CLI with explicit roots
and failure statuses. Keep literal/static scope and its limitations explicit.
Keep thin test orchestration and bounded source readers valid. Register the
later fixture with exact logical/physical routes, introduction commit and blob;
verify ancestry and both Product baselines before classifying it separately.
Reject current symlinks, symlink ancestors and root escapes before record hashing.

## Changed files and tests

New architecture model/checker and `test_repository_architecture.py` accompany
the `connector_suite/connector.mk` lint target. `build-migration-map.py` and
`test_migration_source_provenance.py` cover the provenance correction. Native
inventory, definition archive, migration baseline and test map are refreshed
through their generators. The paired architecture documentation describes both
contracts. New regression methods require explicit on-demand invocation.

## Commands and results

Commands below use portable interpreter/root placeholders.

| Command or check | Exit code | Concise result |
| --- | --- | --- |
| `python -m unittest discover -s connector_suite/modsecurity_connector_tests -p test_repository_architecture.py -v` | 0 | 35 CLI regression methods passed |
| `python -m unittest discover -s connector_suite/modsecurity_connector_tests -p test_migration_source_provenance.py -v` | 0 | 9 real-Git provenance methods passed |
| `check-repository-architecture.py --connector-root "$CONNECTOR_ROOT" --framework-root "$FRAMEWORK_ROOT"` | 0 | Bounded source/build dependency check passed |
| `update-inventory-bindings.py --check` | 0 | Existing source bindings match; standard selection stays at 100 |
| `update-test-archive.py --check` | 0 | Retained definitions and source identities match |
| `build-migration-map.py --check` | 0 | Native migration outputs match current inputs |
| Ruff 0.17.3 lint of affected Python files; format check of new Python files | 0 | Focused checks passed; formatting preserved ASTs |

## Security impact

The checks detect supported dependency and provenance violations. Negative
controls retain failure for unknown missing sources, Git errors, mapping and
blob mismatches, historical Product presence and symlink/root-escape inputs.
No Product runtime security remediation is claimed.

## Documentation and runtime evidence

Updated `docs/architecture.md` and `docs/architecture.de.md`. This change has
static and isolated Git-fixture evidence; no host runtime evidence was collected.

## Checks not run

Host qualification and a full acceptance campaign were not run for this native
contract change. Hosted exact-head CI and normal delivery remain separate checks.

## Limitations and residual risk

The architecture check covers documented literal dependency forms, not every
language graph, computed load, shell/Make evaluation, binary dependency or object
lifetime. External SDK headers and arbitrary hosted repository aliases are not
resolved. A native PASS does not activate an inactive Sonar architecture sensor.

## Final diff and review status

The implementation and isolated negative controls were locally reviewed. Native
generated bindings are refreshed without manual digest edits. This record makes
no commit, publication, hosted-gate or merge claim. Sensitive operational details
and raw diagnostic logs are not included.
