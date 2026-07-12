# Framework-Dokumentation

**Sprache:** [English](README.md) | Deutsch

Dieses Verzeichnis enthält gepflegte Framework-Dokumentation zu Design, Tests,
Importen, Qualität und Referenzen. Generierte Berichte bleiben generiert: Sie
werden durch die Reporting-Werkzeuge unter [`testing/generated/`](testing/generated/)
geschrieben und dürfen nicht durch manuelles Ändern von Markdown verändert werden.

## Einstieg

- [Framework-Überblick](../README.de.md): Umfang, Runtime-Grenzen und Einstiegspunkte.
- [Variablen und Platzhalter](reference/variables.de.md): Pflicht-/optionale Eingaben,
  Standards, Formate, Beispiele und Sicherheitshinweise.
- [Glossar](reference/glossary.de.md): Framework-Begriffe und Statusvokabular.
- [Test-Guide](testing/README.de.md): Fallkorpus, Varianten und Evidence-Grenze.
- [Architektur](architecture.de.md), [Katalog-/Capability-Modell](capability-model.de.md)
  und [Statusmodell](status-model.de.md): Katalog- und Normalisierungsmodell.
- [No-CRS-Evidence-Vertrag](testing/no-crs-baseline.de.md): Auswahl, Validierung,
  Promotion- und Privacy-Grenzen.
- [Connector-Adapter-Interface](connector-adapter-interface.de.md) und
  [zukünftige Connectoren](future-connectors.de.md): Integrations- und Erweiterungsregeln.

## Struktur und Quellen der Wahrheit

| Bereich | Zweck und Quelle der Wahrheit |
|---|---|
| `testing/` | Nutzerorientierte Guides zu Tests, Evidence, Kompatibilität und lokalen Checks. YAML-Fälle und Runner-Code bleiben die ausführbare Quelle der Wahrheit. |
| `imports/` | Provenienz und Importanalyse für Upstream-Testmaterial. Historische Fakten bleiben ihrer Quelle zugeordnet. |
| `connectors/` | Connector-fokussierte Framework-Verträge und Untersuchungen. Connector-Quellcode und Runtime-Evidence bleiben im Connector-Repository. |
| `quality/` und `roadmap/` | Qualitätsarbeit und ausdrücklich nicht aktuelle Planungsaufzeichnungen. |
| `reference/` | Zweisprachige Referenz für Variablen/Platzhalter und Glossar. |
| `testing/generated/` | Generierte Coverage-/Runtime-Berichte; [`generated/`](generated/) erklärt die kanonischen Ausgabeorte. |

Neue gepflegte Dokumente als englisch/deutsches Paar im nächstgelegenen Bereich
einordnen, bei Nutzer-Einstiegspunkten vom Bereichsindex verlinken und technische
Namen, Standards, Pfade, IDs und Beispiele in beiden Sprachen gleich halten.
Einen anpassbaren Wert direkt beim Befehl erklären und bei wiederkehrenden Werten
auf die zentrale Referenz verlinken.

Keine generierten Berichte, Connector-Implementierungsnotizen, Runtime-Logs oder
ungeprüfte Upstream-Kopien hier ablegen. Für Quellenanalyse `docs/imports/` und
für Connector-eigene Artefakte das Connector-Repository verwenden.

## Relevante Checks

`make check-documentation` prüft Markdown-Links, zweisprachige Variablen-/Referenzabdeckung,
unsichere Ersetzungsmarker, lokale Entwicklerpfade und Referenzen auf verschobene
CI-Pfade. `make lint` enthält dieses Target. Für einen lokalen Testablauf siehe
[`make quick-check`](testing/fast-checks.de.md) und die [Test-README](../tests/README.de.md).
