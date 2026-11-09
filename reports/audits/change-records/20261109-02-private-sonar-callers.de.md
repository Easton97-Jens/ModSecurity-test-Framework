# Unveränderliche private Sonar-Aufrufer

**Sprache:** Deutsch | [English](20261109-02-private-sonar-callers.md)

## Identität

| Field | Value |
| --- | --- |
| Change ID | 20261109-02-private-sonar-callers |
| UTC | 2026-11-09 |

## Motivation und Problemstellung

Gehostete Scans mit vollem Umfang zeigen Parser-Auslassungen ohne ausreichende Ursachenfakten. Die geprüfte private Diagnoseaktion muss aus einem vorher veröffentlichten unveränderlichen Quellcommit laufen. Der bestehende Aktionsquellprüfer schickt außerdem ihre Node-Metadaten fälschlich durch einen reinen Composite-Renderer.

## Betroffene Komponenten und Sicherheitsgrenzen

Das Framework verantwortet seinen Scanner-Aufrufer, die eigene native Datenrolle, das generierte Lock, Quellprüfer und Regressionstests. Parent verantwortet seinen getrennten Scanner-Aufrufer und nicht ausführende Projektionslogik. Die geschützte Parent-Closure aus fünf Quellen importiert keinen ausführbaren Framework-Code. MRTS bleibt unverändert.

## Akzeptanzkriterien

Die veröffentlichte Aktion wird auf `15588933f5f5456bb07f5eef12d7ce236e651c5c` festgesetzt. Upstream-Scanneridentität/-version, Signaturprüfung, voller Analyseumfang, Framework-cfd5-Fixture, Parent-Standards/-Projekte/-Gate-Semantik und alle 23 Integrationsprojektionen bleiben erhalten. Alle Composite-Quellen werden weiterhin geprüft; ungeprüfte Node-/Docker-Aktionen und Metadatenaliase werden abgelehnt.

## Untersuchte Alternativen

Lokale Token-Ausführung am PR-Head, breite Ausnahmen für denselben Eigentümer, erfundene Release-Tags, öffentliches rohes DEBUG, Umfangsreduktion und ausführbare Imports im geschützten Parent-Publisher werden verworfen.

## Implementierungsentscheidung

Die eigene Quellrolle bleibt von releaseverwalteten Aktionsrepositories getrennt. Zwei vollständige geprüfte Scanner-Mappings erlauben die gestufte Migration: ursprüngliche offizielle Aktion oder exakter geprüfter Remote-Wrapper mit denselben Eingaben. Die Quellauflösung bewahrt nur die festgesetzte Parent-Scannerrolle. Der Parent-Publisher prüft ihren exakten Datenblock lokal und bewahrt ihren SHA während der Projektion der Integrationsrevision. Node-Metadaten und Hauptimplementierung müssen den unabhängig geprüften Hashes entsprechen; alle anderen Aktionen erhalten weiterhin die tatsächliche Composite-Prüfung mit actionlint/ShellCheck. Parent-Zusammenfassungen bewahren Analyseergebnisse und verwenden begrenzte Identitätsfakten des Wrappers statt Report-URLs auszugeben.

Der getrennte Parent-Security-Tools-Updater erfasst den verwalteten offiziellen Upstream erst nach Prüfung des vollständigen festgesetzten Aufrufers. Checkout- und Tool-Updates bewahren dessen exakte Bytes. Änderungen am aktuell festgelegten Sonar-Upstream werden bewusst vor jedem Schreibzugriff abgelehnt und benötigen eine getrennt geprüfte Vertragsänderung; zentrales SonarSource-Lock und Resolver-Verwaltung bleiben erhalten.

## Geänderte Dateien und Tests

Scanner-Workflows, native Framework-Daten/Lock-Produzent, Vertragsmodul für vollständige Aufrufe, Workflow-/Quellprüfer, Parent-Projektion/-Fixtures und gezielte Regressionen. Die festgesetzte Aktionsimplementierung und ihre 17 Offline-Tests bleiben unverändert. Der Standardfallbestand bleibt unverändert.

## Befehle und Ergebnisse

Native kanonische Generierung und Aktualitätsprüfung endeten mit 0. Gezielte Prüfungen bestanden mit 4 Aufrufer-, 25 Quell-/Node-Zulassungs-, 14 kanonischen Pin-, 20 Sonar-Grenz- und 9 Workflow-Sicherheitstests. Die tatsächlich installierten und den nativen Pins entsprechenden Versionen actionlint v1.7.12 und ShellCheck v0.11.0 prüften alle 20 Composite-Quellen; die exakt geprüfte Node-Quelle wurde getrennt erfasst. Native Workflow-, Change-Record-, Link- und Zweisprachigkeitsprüfungen bestanden. Echte unveränderliche Git-Objektfixtures korrigierten drei veraltete Projektionstests. Die vollständige Parent-Gruppe führte 59 Methoden aus: 42 bestanden, 17 lehnten die aktuell nicht übereinstimmenden Parent-/Framework-Integrationspins ab. Diese 17 benötigen den synchronisierten Zyklus mit committeten Zielständen und sind keine bestandenen Tests.

Die vollständige Updater-Gruppe bestand alle 56 Methoden einschließlich aller fünf neuen Rollen-/Atomaritätskontrollen und der echten Proposed-Tree-Integration. Der native Produzent der Wartungsansichten aktualisierte zehn bestehende Quellbindungs-Digests und das generierte Archiv; seine Aktualitätsprüfung bestand. Alle 100 Standardfälle und 80 Ausführungsselektoren bleiben unverändert. Das Archiv bewahrt jede bestehende Definition und ergänzt 16 tatsächliche Regressionsmethoden; die Zahl seiner On-Demand-Definitionen steigt von 8292 auf 8308. Native Extraktionsidentität und erhaltene native Definitionen bleiben unverändert. Parent-eigenes Python 3.14.4 bestand unabhängig die tatsächliche Workflow-/Upstream-Erfassung und Ablehnung festgesetzter Änderungen ohne ausführbare Framework-Imports. Eine bestehende HTTPError-Testfixture meldete eine ResourceWarning; sie wurde nicht unterdrückt.

## Sicherheitsauswirkung

Token-Zugriff bleibt auf eine unveränderliche Remote-Aktion begrenzt. Falsche Pins, Metadatenhashes, Implementierungen, Eigentümerprofile, Scannereingaben, Aliase, Symlink-Quellen und zusätzliche Rollenvorkommen werden geschlossen abgelehnt. Hooks, Berechtigungen, Compilerwarnungen, Tests, Analyseprofile und Gates werden weder deaktiviert noch geschwächt. Rohe Scannerausgabe bleibt unter dem getrennt geprüften Aktionsvertrag privat.

## Dokumentation und Runtime-Evidenz

Dieses Berichtspaar beschreibt Vorbereitung und Offline-Validierung. Gehostete Diagnosen und Qualitätsprüfungen des aktuellen Heads bleiben unabhängige Evidenz; Connector-Laufzeit oder Deployment werden nicht behauptet.

## Nicht ausgeführte Prüfungen

Synchronisierte Parent-/Framework-Prüfungen mit committeten Zielständen, gehostete private Diagnosen und Qualitäts-/Readback des exakten Heads stehen aus. Lokale Syntax-/Lint-Evidenz ersetzt spätere gehostete Prüfungen nicht.

## Einschränkungen und Restrisiko

Die privaten Diagnosefakten können weiterhin unbekannte Ursachen melden. Ein bestandenes Gate belegt keine Parser-Vollständigkeit; ähnliche Parent-/Framework-Zähler beweisen keine gemeinsamen Ursachen. Beide Repositories benötigen getrennte Veröffentlichung und Integrationsprüfung.

## Finaler Diff- und Review-Status

Gezielte Offline-Validierung und unabhängige Quellprüfung sind abgeschlossen. Veröffentlichung, Integrationsprüfungen mit committeten Zielständen und gehostete Diagnoseverifikation stehen aus. Geschlossene Analyzer-Lücken werden nicht behauptet.
