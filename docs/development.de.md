# Entwicklung

**Sprache:** [English](development.md) | Deutsch

Diese Anleitung ist der gepflegte Einstiegspunkt für Framework-Beiträge,
CI-Layout und lokale Validierung. Sie trennt absichtlich reproduzierbare
Repository-Arbeit von Connector-eigenen Builds und Runtime-Evidence.

## Lokales Setup

Verwende explizite, beschreibbare Orte außerhalb des Git-Worktrees für
Quellkopien, Build-Produkte, Logs, temporäre Dateien und Evidence. Die zentrale
[Variablen- und Platzhalterreferenz](reference/variables.de.md) definiert die
akzeptierten Werte und Pfadgrenzen.

```sh
make setup-dev
make quick-check
make lint
```

Das Abrufen von Upstream-Abhängigkeiten und das Ausführen von Host-Smokes sind
explizite Operationen. Sie dürfen nicht still in einen Checkout schreiben,
einen vorhandenen Quellbaum ersetzen oder eine nicht verfügbare Abhängigkeit in
einen PASS verwandeln.

## Repository-Layout

| Pfad | Verantwortung |
|---|---|
| `ci/lib/` | Gemeinsame Shell- und Python-Helfer |
| `ci/provisioning/` | Explizite Source-, Build- und Runtime-Vorbereitung |
| `ci/runtime/` | Runtime-Smoke-Einstiegspunkte |
| `ci/checks/` | Katalog-, Dokumentations-, Evidence-, Protokoll- und Sicherheitschecks |
| `ci/reporting/` | Generatoren für begrenzte Berichte und Snapshots |
| `tests/runners/` | YAML-Validierung, Materialisierung, Auswahl und Assertions |
| `tests/normalizers/` | Begrenzte Artefaktnormalisierung |
| `tests/cases/` | Framework-eigener YAML-Fallkorpus |

Bewahre Connector-Implementierungscode, Host-Konfiguration und
connector-spezifische Runtime-Evidence im Connector-Repository. Framework-Code
darf keinen versteckten Workspace- oder Parent-Directory-Fallback erhalten.

## Dokumentationspolicy

Die gepflegte manuelle Dokumentation besteht aus den kanonischen Paaren in
`docs/`, einschließlich der Änderungsnachverfolgbarkeit, sowie den Variablen-
und Glossarreferenzen. Englische und deutsche Partner müssen dieselben Pfade,
Befehle, Identifikatoren, Defaults, Tabellen und Sicherheitsgrenzen behalten.

Nicht triviale Framework-Änderungen benötigen außerdem den in der
[Änderungsnachverfolgbarkeit](change-traceability.de.md) beschriebenen
gepaarten Record. Der Record gehört in dieses Repository und darf keine
Framework-Fakten mit Connector-Findings oder Parent-Repository-Änderungen
vermischen.

Generierte Berichte werden nur über ihren Generator geändert. Die Root-Datei
`TEST-COVERAGE-SUMMARY.md` ist eine bewusste öffentliche/generierte Ausnahme,
weil Framework- und Connector-Checks sie verwenden. Sie ist kein zweites
manuelles Statusdokument.

Verwende `make check-documentation` nach einer Dokumentationsänderung. Es
führt Link-, Variablen-/Referenz- und Repository-Pfad-Checks aus. Vermeide
lokale Entwicklerpfade, temporäre absolute Beispiele, reine Redirect-Markdown-
Dateien und kopierte Berichtssnapshots.

## Validierung und Review

| Änderungsbereich | Mindestvalidierung |
|---|---|
| Markdown-Navigation oder Referenzen | `make check-documentation` und `git diff --check` |
| Zweisprachige Dokumentation, Records oder Vorlagen | `make check-bilingual-docs` und `make check-doc-links` |
| Variablen oder Platzhalter | `make check-variable-documentation` |
| YAML-Katalog oder Runner-Verhalten | `make check-no-crs-catalog` und fokussierte Tests |
| Generierte Berichte | `make refresh-framework-reports` und `make check-test-matrix` |
| Runtime- oder Evidence-Helfer | Relevante fokussierte Checks plus Connector-eigener Harness |

Führe zuerst den kleinsten relevanten Check und vor der Übergabe die
Repository-Checks aus. Schwäche keinen Test ab, benenne keine Fall- oder
Regelidentität um und ändere kein generiertes Artefakt nur wegen eines
Pfadumzugs.

## Qualität und Wartung

Formatierung, Shell-Syntax, Python-Kompilierung, Dokumentationschecks,
Security-Data-Flow-Checks, Katalogvalidierung und Evidence-Checks bündelt
`make lint`. Qualitätsbefunde sollen im besitzenden Code oder Dokument
behoben werden, statt als paralleles Planungsdokument erhalten zu bleiben.

Halte Secrets, Credentials, rohe Request-Bodies, rohe Response-Bodies und
ungeprüfte Runtime-Logs aus versionierten Dateien heraus. Bevorzuge begrenzte
Metadaten und die Privacy-Regeln in
[Testing und Evidence](testing-and-evidence.de.md).

## Historischer Kontext

Frühere CI-Audits, SonarCloud-Remediation-Listen, Roadmap-Snapshots und
TODO-Inventare wurden in die aktiven Wartungsregeln oben zusammengeführt. Git
bleibt der Ort für abgeschlossene Planungsdetails.
