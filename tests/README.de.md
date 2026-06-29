# Tests

**Sprache:** [English](README.md) | Deutsch

Status: eingerüstet

## Grenzen

`tests/cases/` enthält das Laufzeit-Fallkorpus YAML. Fälle werden organisiert von
Thema und Connector-spezifische Varianten finden Sie weiter unten
`tests/cases/connector-specific/<connector>/`.

`docs/imports/common/` enthält Referenzkarten und historische Importmetadaten für
tragbare Engine-, Regel- und Verhaltenstests.

Wenn ein Test von Hook-Reihenfolge, Pufferung, Streaming, Neuladen, lokalen Ports abhängt,
Serverkonfiguration, Modulladung oder server/proxy Protokollformat, es ist nicht portierbar
bis zum Nachweis des Gegenteils.

## Kategorien

- Motorkerntests
- Connector-spezifische Tests
- Audit-Log-Tests
- Anforderungskörpertests
- Antwortkörpertests
- streaming/buffering Tests
- fähigkeitsabhängige Tests

## Status

Es gibt einen minimalen gemeinsamen YAML Case Materializer und HTTP Status Assertion Runner
unter `tests/runners/`. Die PoCs Apache und NGINX nutzen es aktuell
Themenbezogene Fälle gemäß `tests/cases/`, einschließlich Sperrung, Weiterleitung,
Request-Body-, Response-Header- und Audit-Log-Fälle.

XFAIL, Pending, Future, Connector-Gap und Runtime-Difference sind YAML Metadaten
Klassen, keine Verzeichnisnamen. Fehlende YAML `status` werden als aktiv für behandelt
discovery/reporting ohne Fallinhalt neu zu schreiben.

Fälle, die OWASP Kernregelsatz erfordern, können `requires_crs: true` festlegen. Das sind sie
aus `MODSECURITY_TEST_VARIANT=no-crs` ausgeschlossen und darin enthalten
`MODSECURITY_TEST_VARIANT=with-crs`.

Fälle, die in beiden Varianten gültig sind, aber unterschiedliche Behauptungen benötigen, können beibehalten werden
die Basiswerte `expect` für `no-crs` und `expect.variants.with-crs` für a hinzufügen
minimale With-CRS-Überschreibung. Ändern Sie die Grunderwartung nicht, wenn nur die
Der With-CRS-Laufzeitkontext ist unterschiedlich.

Zusätzliche Fallwurzeln können durch Doppelpunkt getrennt zugeführt werden
`EXTRA_CASE_ROOTS`. Die optionale MRTS-Integration verwendet diesen Mechanismus nur für
`MODSECURITY_MRTS_VARIANT=with-mrts`; `no-mrts` behält vom Anrufer bereitgestellte Extras bei
Wurzeln, ohne generierte MRTS-Fälle anzuhängen.

Es gibt noch keine vollständige Connector-Regressionssuite.
