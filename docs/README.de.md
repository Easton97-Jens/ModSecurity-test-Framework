# Framework-Dokumentation

**Sprache:** [English](README.md) | Deutsch

Das Framework pflegt gepaarte manuelle Dokumentation. Zusammen mit den
Referenzen und generierten Ausgaben unten bildet sie die aktuelle
Dokumentationsmenge.

## Anleitungen

| Anleitung | Verwendung |
|---|---|
| [Architektur](architecture.de.md) | Grenzen, Lifecycle, Daten, Privacy und Cache-Modell |
| [Katalog und Fälle](catalog-and-cases.de.md) | YAML-Schema, Provenienz, Auswahl, Status und Normalisierung |
| [Testing und Evidence](testing-and-evidence.de.md) | Validierungsworkflow, No-CRS, Berichte, Promotion und Privacy |
| [Connector-Integration](connector-integration.de.md) | Adaptervertrag, Ownership und Quellattribution |
| [Entwicklung](development.de.md) | CI-Layout, Beitragsworkflow und Wartungsregeln |
| [Änderungsnachverfolgbarkeit](change-traceability.de.md) | Framework-eigene Change Records, sichere Evidenz und Review-Erwartungen |
| [Variablen und Platzhalter](reference/variables.de.md) | Eingaben, Defaults, Beispiele, Scopes und Sicherheitsnotizen |
| [Glossar](reference/glossary.de.md) | Framework-Vokabular und Statusbegriffe |

## Generierte Ausgaben

Aktuelle generierte Coverage- und Runtime-Berichte bleiben unter
[testing/](testing/test-coverage-overview.de.md). Sie werden nur über ihren
Reporting-Generator aktualisiert. Die Framework-Root-
[Coverage-Zusammenfassung](../TEST-COVERAGE-SUMMARY.de.md) ist die extern
verwendete generierte Ausnahme.

## Dokumentationschecks

```sh
make check-documentation
make check-test-matrix
```

Füge für ein verschobenes Thema keine reine Redirect-Markdown-Datei hinzu.
Aktualisiere Links, halte die englischen und deutschen kanonischen Dokumente
strukturell parallel und füge den erforderlichen Framework-eigenen Change
Record hinzu.
