# Fallmatrix

**Sprache:** [English](case-matrix.md) | Deutsch

Diese Seite ist ein stabiler Index für die aktuell generierten Matrixberichte.
Historische Inline-Tabellen wurden entfernt, da sie die generierte Ausgabe duplizierten
und könnte von Live-YAML/runtime-Nachweisen abweichen.

Verwenden Sie diese generierten Berichte für aktuelle Abdeckungs-Snapshots:

- `docs/testing/test-coverage-overview.md`
- `docs/testing/generated/case-matrix.generated.md`
- `docs/testing/generated/coverage-summary.generated.md`
- `docs/testing/generated/xfail-summary.generated.md`
- `docs/testing/generated/connector-gap-summary.generated.md`
- `docs/testing/generated/phase-coverage.generated.md`

Regenerieren mit:

```sh
make generate-test-matrix
```

Validieren Sie die Frische in CI/local-Prüfungen mit:

```sh
make check-test-matrix
```

Generierte Berichte sind lediglich Dokumentationsartefakte. Laufzeitbeweise kommen noch
aus Connector-Smoke-Zusammenfassungen und Laufzeitmatrix-Snapshots.
