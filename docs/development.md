# Development

**Language:** English | [Deutsch](development.de.md)

This guide is the maintained entry point for Framework contribution, CI layout,
and local validation. It intentionally separates reproducible repository work
from connector-owned builds and runtime evidence.

## Local setup

Use explicit, writable locations outside the Git worktree for source copies,
build products, logs, temporary files, and evidence. The central
[variables and placeholders](reference/variables.md) define the accepted
values and path boundaries.

```sh
make setup-dev
make quick-check
make lint
```

Fetching upstream dependencies and running host smokes are explicit operations.
They must not silently write into a checkout, replace an existing source tree,
or turn an unavailable dependency into a PASS.

## Repository layout

| Path | Responsibility |
|---|---|
| `ci/lib/` | Shared shell and Python helpers |
| `ci/provisioning/` | Explicit source, build, and runtime preparation |
| `ci/runtime/` | Runtime-smoke entrypoints |
| `ci/checks/` | Catalog, documentation, evidence, protocol, and security checks |
| `ci/reporting/` | Generators for bounded reports and snapshots |
| `tests/runners/` | YAML validation, materialization, selection, and assertions |
| `tests/normalizers/` | Bounded artifact normalization |
| `tests/cases/` | Framework-owned YAML case corpus |

Keep connector implementation code, host configuration, and connector-specific
runtime evidence in the connector repository. Framework helper code must not
grow a hidden workspace or parent-directory fallback.

## Documentation policy

The maintained manual documentation is the six canonical pairs in `docs/` plus
the variables and glossary references. English and German partners must retain
the same paths, commands, identifiers, defaults, tables, and safety boundary.

Generated reports are changed only through their generator. The root
`TEST-COVERAGE-SUMMARY.md` is a deliberate public/generated exception because
Framework and connector checks consume it. It is not a second manual status
document.

Use `make check-documentation` after a documentation change. It runs link,
variable/reference, and repository-path checks. Avoid local developer paths,
temporary absolute examples, redirect-only Markdown files, and copied report
snapshots.

## Validation and review

| Change area | Minimum validation |
|---|---|
| Markdown navigation or references | `make check-documentation` and `git diff --check` |
| Variables or placeholders | `make check-variable-documentation` |
| YAML catalog or runner behavior | `make check-no-crs-catalog` and focused tests |
| Generated reports | `make refresh-framework-reports` and `make check-test-matrix` |
| Runtime or evidence helpers | Relevant focused checks plus the connector-owned harness |

Run the smallest relevant check first, then the repository-level checks before
handoff. Do not weaken a test, rename a case or rule identifier, or edit a
generated artifact merely to satisfy a path move.

## Quality and maintenance

Formatting, shell syntax, Python compilation, documentation checks, security
data-flow checks, catalog validation, and evidence checks are aggregated by
`make lint`. Quality findings should be resolved in the owning code or
documentation instead of preserved as a parallel planning document.

Keep secrets, credentials, raw request bodies, raw response bodies, and
unreviewed runtime logs out of versioned files. Prefer bounded metadata and
the privacy rules in [testing and evidence](testing-and-evidence.md).

## Historical context

Former CI audits, SonarCloud remediation lists, roadmap snapshots, and TODO
inventories were consolidated into the active maintenance rules above. Git
history remains the place for completed planning detail.
