# Case Matrix

**Language:** English | [Deutsch](case-matrix.de.md)

This page is a stable index for the current generated matrix reports.
Historical inline tables were removed because they duplicated generated output
and could drift from live YAML/runtime evidence.

Use these generated reports for current coverage snapshots:

- `docs/testing/test-coverage-overview.md`
- `docs/testing/generated/case-matrix.generated.md`
- `docs/testing/generated/coverage-summary.generated.md`
- `docs/testing/generated/xfail-summary.generated.md`
- `docs/testing/generated/connector-gap-summary.generated.md`
- `docs/testing/generated/phase-coverage.generated.md`

Regenerate with:

```sh
make generate-test-matrix
```

Validate freshness in CI/local checks with:

```sh
make check-test-matrix
```

Generated reports are documentation artifacts only. Runtime evidence still comes
from connector smoke summaries and runtime matrix snapshots.
