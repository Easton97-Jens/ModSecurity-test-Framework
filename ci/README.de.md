# Framework-CI-Werkzeuge

**Sprache:** [English](README.md) | Deutsch

`ci/` enthält Framework-eigene Validierung, lokale Runtime-Orchestrierung,
Provisionierung, Reporting und Hilfswerkzeuge. Diese Dateien ordnen bestehende
Verträge; sie definieren keine Connector-Lifecycle-Semantik, Capability-Zustände,
Schemas oder Evidence-Promotion-Richtlinien.

## Struktur

| Verzeichnis | Verantwortung |
|---|---|
| `checks/catalog/` | Katalog-, Metadaten-, Helfer-, CRS-Pin- und MRTS-Import-Vertragschecks. |
| `checks/evidence/` | Validierung für Response-Body-, Full-Lifecycle- und Transport-Hardening-Evidence. |
| `checks/protocol/` | Verwalteter Protokoll-Client und sein Evidence-Checker. |
| `checks/security/` | Payload-/Datenfluss- und Normalizer-Sicherheitschecks. |
| `checks/documentation/` | Markdown-Link-, zweisprachige Variablen-/Referenz-, Workflow- und verschobene-Pfad-Checks. |
| `runtime/` | Einstiegspunkte für Connector-Smokes und Runtime-Matrix. |
| `provisioning/` | Explizite Vorbereitung von Quellen, CRS, MRTS und lokalen Komponenten. |
| `reporting/` | Generatoren für Fallmatrizen, Work Queues, Summaries und Runtime-Snapshots. |
| `tools/` | Entwickler-Bootstrap, Diagnose-, Abhängigkeits- und Fast-Check-Befehle. |
| `lib/` | Gemeinsame Shell-/Python-Helfer; `common.sh` ist passive Konfiguration und `path.sh` findet Framework-Pfade. |

## Einstiegspunkte und Pfadregeln

Direkte Shell-Einstiegspunkte ermitteln ihr eigenes Verzeichnis, leiten
`CI_ROOT` ab und sourcen `ci/lib/path-bootstrap.sh`. Das Bootstrap erkennt oder
validiert `FRAMEWORK_ROOT`; deshalb bleiben Skripte nach der Gruppierung in
diese Verantwortungsordner aufrufbar. Python-Werkzeuge verwenden ihren
Dateiort nur, um die Framework-Wurzel und gemeinsame `ci/lib/`-Imports zu finden.

`ci/lib/common.sh` definiert Standards und Helfer, darf aber nicht allein durch
das Sourcen Quellen abrufen, installieren, Verzeichnisse anlegen oder Checks
ausführen. Versionspins, Source-URLs, Prüfsummen und Komponentenstandards
stehen dort, statt in Workflows oder Einzelskripten dupliziert zu werden.

`FRAMEWORK_ROOT` auf diesen Checkout und `CONNECTOR_ROOT` auf den Connector-
Checkout setzen, wenn ein Befehl Repository-Grenzen überschreitet. Für einen
isolierten Lauf `BUILD_ROOT`, `SOURCE_ROOT`, `TMP_ROOT`, `LOG_ROOT` und
`EVIDENCE_ROOT` auf beschreibbare Runtime-Pfade außerhalb von Git setzen.
`/var/tmp/modsecurity-framework/build` ist zum Beispiel ein temporärer
Build-Pfad, kein verpflichtender Host-Speicherort. Formate, Standards,
Gültigkeit, Beispiele und Hinweise für sensible Werte stehen unter
[Variablen und Platzhalter](../docs/reference/variables.de.md).

## Relevante Targets

- `make lint` führt Shell-/Python-Syntax, Katalog-/Security-/Evidence-Verträge,
  Dokumentationschecks und Whitespace-Validierung aus. Es erzeugt keinen
  Runtime-Beweis.
- `make check-no-crs-catalog` validiert nur die Katalogstruktur.
- `make check-documentation` führt Markdown-Link-, Variablen-/Platzhalter- und
  veraltete-Pfad-Checks aus.
- `make quick-check` ergänzt die kurzen lokalen Python-/MRTS-Checks nach `lint`.
- `make refresh-framework-reports` generiert Framework-eigene Berichte über
  `ci/reporting/`; generiertes Markdown nicht manuell ändern.

Runtime-Skripte können `BLOCKED` melden, wenn ein Connector-eigenes
ausführbares Harness oder eine Voraussetzung fehlt. Ein Build-/Self-Test-
Starter-Ergebnis ist keine Runtime-Smoke-Evidence und bedeutet keine Evidence-
Promotion. Das [Glossar](../docs/reference/glossary.de.md) definiert diese
Status- und Evidence-Begriffe.

## CI-Datei hinzufügen oder verschieben

Eine neue Datei nach ihrer einen primären Verantwortung einordnen. Wiederverwendbare,
importierte Helfer in `lib/`, Report-Schreiber in `reporting/` ablegen; keinen
zweiten Helfer nur zur Platzierung neben einem Aufrufer erstellen. Beim
Verschieben einer versionierten Datei `git mv` verwenden und danach Make-Targets,
Workflows, Shell-Sources, Python-Imports, Tests, Dokumentation und Generator-
Provenienz aktualisieren. Anschließend `make lint` und den betroffenen fokussierten
Test ausführen.

Keinen Connector-Implementierungscode, keine generierten Berichte, externen
Source-Trees, Runtime-Logs, privaten Schlüssel, Zugangsdaten oder ad-hoc-
lokale Skripte in `ci/` ablegen.
