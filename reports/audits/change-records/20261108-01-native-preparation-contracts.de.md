# Native Vorbereitungsverträge

**Sprache:** [English](20261108-01-native-preparation-contracts.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261108-01-native-preparation-contracts |
| UTC-Datum | 2026-11-08 |
| Framework-Basisrevision | bacb3065aec2434a3b7b9cbdaba02533e84c3fb9 |
| Issue oder Pull Request | Framework #169 |

## Motivation und Problemstellung

Das Build-Vertragsgerüst setzte keine Repository-Abhängigkeitsgrenzen durch.
Die Migrationsmap-Neuerzeugung behandelte außerdem eine spätere Framework-Fixture
als ursprüngliche Produktquelle und scheiterte an deren historischer
Git-Blob-Voraussetzung.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-eigene Architekturvalidierung, delegiertes Connector-Lint und
Migrationsherkunft sind betroffen. Produktcode bleibt von Testinfrastruktur
getrennt; die Quellherkunft darf keine beliebige fehlende historische Datei
zulassen.

## Akzeptanzkriterien

Neutrale Common-Eingaben und zulässige Testdelegation akzeptieren. Unterstützte
Host-SDK-, Produkt-zu-Testinfrastruktur- und Rückgitlink-Verstöße, ungültige
Modelle und unvollständige relevante Eingaben ablehnen. Die eine registrierte
spätere Fixture gegen echte Git-Historie validieren und dabei strikte
Legacy-Blob-Validierung, Source-Map-Identität, Root-Containment und die 100
Standardfälle bewahren.

## Untersuchte Alternativen

Das bestehende Gerüst war unzureichend. Die native Sollvertragsprüfung verwendet
die versionierten Zuständigkeitsregeln, ohne eine kostenpflichtige
Dienstfunktion zu aktivieren. Ein allgemeines Überspringen fehlender historischer
Quellen wurde zugunsten einer expliziten, validierten Erstaufnahme mit
unverändertem generiertem Zeilenschema verworfen.

## Implementierungsentscheidung

Ein verpflichtendes Architekturmodell der Version 1 und eine echte CLI mit
expliziten Wurzeln und Fehlerstatus verwenden. Literalen/statischen Umfang und
seine Grenzen offenlegen. Dünne Testorchestrierung und begrenzte Quellleser
zulassen. Die spätere Fixture mit exakten logischen/physischen Routen,
Erstaufnahmecommit und Blob registrieren; Abstammung und beide Produktbaselines
vor gesonderter Einordnung prüfen. Aktuelle Symlinks, symlinkende Vorfahren und
Root-Escapes vor dem Hashen von Records ablehnen.

Der Qualitätsnachtrag trennt Make-, Sprachlader-, Include- und Gitlink-Prüfungen
in benannte Hilfsfunktionen. Lexikalische Shell-Stufen bewahren die geordneten
Rückfälle; ASCII-Bezeichnerenden behalten ihren bisherigen Umfang durch lokale
Regex-Flags. Host-Header-Prüfungen bewahren exakte Datei- und Verzeichnisgrenzen.
Die wiederholte Migrationsdiagnose für doppelte Produktquellen verwendet jetzt
eine gemeinsame Konstante.

## Geänderte Dateien und Tests

Neues Architekturmodell/Checker und `test_repository_architecture.py` ergänzen
das Lint-Ziel in `connector_suite/connector.mk`. `build-migration-map.py` und
`test_migration_source_provenance.py` decken die Herkunftskorrektur ab. Natives
Inventar, Definitionsarchiv, Migrationsbaseline und Testmap werden über ihre
Generatoren aktualisiert. Die gepaarte Architekturdokumentation beschreibt beide
Verträge. Neue Regressionsmethoden benötigen explizite On-Demand-Ausführung.

## Befehle und Ergebnisse

Die folgenden Befehle verwenden portable Interpreter-/Root-Platzhalter.

| Befehl oder Prüfung | Exit-Code | Kurzes Ergebnis |
| --- | --- | --- |
| `python -m unittest discover -s connector_suite/modsecurity_connector_tests -p test_repository_architecture.py -v` | 0 | 38 Regressionsmethoden bestanden: 35 bestehende Methoden und 3 zusätzliche Grammatik-/Grenzkontrollen |
| `python -m unittest discover -s connector_suite/modsecurity_connector_tests -p test_migration_source_provenance.py -v` | 0 | 9 Herkunftsmethoden mit echtem Git bestanden |
| `check-repository-architecture.py --connector-root "$CONNECTOR_ROOT" --framework-root "$FRAMEWORK_ROOT"` | 0 | Begrenzte Quell-/Build-Abhängigkeitsprüfung bestanden |
| `update-inventory-bindings.py --check` | 0 | Bestehende Quellbindungen stimmen; Standardauswahl bleibt bei 100 |
| `update-test-archive.py --check` | 0 | Erhaltene Definitionen und Quellidentitäten stimmen |
| `build-migration-map.py --check` | 0 | Native Migrationsausgaben entsprechen aktuellen Eingaben |
| Ruff-0.17.3-Lint betroffener Python-Dateien; Formatcheck neuer Python-Dateien | 0 | Fokussierte Prüfungen bestanden; Formatierung bewahrte ASTs |

## Sicherheitsauswirkung

Die Prüfungen erkennen unterstützte Abhängigkeits- und Herkunftsverstöße.
Negativkontrollen bewahren Fehler für unbekannte fehlende Quellen, Git-Fehler,
Mapping-/Blob-Abweichungen, historische Produktpräsenz und Symlink-/Root-Escape-
Eingaben. Keine Security-Remediation der Produkt-Runtime wird behauptet.

## Dokumentation und Runtime-Evidenz

`docs/architecture.md` und `docs/architecture.de.md` aktualisiert. Die Änderung
besitzt statische und isolierte Git-Fixture-Evidenz; Host-Runtime-Evidenz wurde
nicht erfasst.

## Nicht ausgeführte Prüfungen

Host-Qualifikation und eine Gesamtabnahmekampagne wurden für diese native
Vertragsänderung nicht ausgeführt. Gehostete CI am exakten Head und reguläre
Auslieferung bleiben gesonderte Prüfungen.

## Einschränkungen und Restrisiko

Die Architekturprüfung deckt dokumentierte literale Abhängigkeitsformen ab,
nicht jeden Sprachgraphen, berechneten Ladevorgang, Shell-/Make-Auswertung,
Binärabhängigkeiten oder Objektlebenszeiten. Externe SDK-Header und beliebige
gehostete Repository-Aliase werden nicht aufgelöst. Ein natives PASS aktiviert
keinen inaktiven Sonar-Architektursensor.

## Finaler Diff- und Review-Status

Implementierung und isolierte Negativkontrollen wurden lokal geprüft. Native
generierte Bindungen sind ohne manuelle Digeständerungen aktualisiert. Dieser
Record behauptet keinen Commit, keine Veröffentlichung, kein gehostetes Gate
und keinen Merge. Sensible Betriebsdetails und rohe Diagnoselogs sind nicht
enthalten.
