# Framework-Migration auf Ubuntu-26.04-Runner

**Sprache:** Deutsch | [English](20261026-03-framework-ubuntu26.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change ID | 20261026-03-framework-ubuntu26 |
| UTC date | 2026-10-26 |
| Framework base revision | 312a298 |
| Issue or pull request | [PR #138](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/138) |

## Motivation und Problemstellung

Der Nutzer verlangt Version 26 für jede aktive Ubuntu-Version. Das gleitende ubuntu-latest wählt noch ein älteres Image; die Python-Installierbarkeitsprüfung muss zum tatsächlichen Runner passen.

## Betroffene Komponenten und Sicherheitsgrenzen

Alle aktiven Framework-GitHub-Actions-Jobs, strikte Runner-Profile, der gemeinsame Python-Manifestselektor und relevante Offline-Regressionen. Parent-Gitlink unverändert; MRTS bleibt schreibgeschützt. Kein Upgrade des Host-Betriebssystems.

## Akzeptanzkriterien

Jeder aktive Framework-Job wählt ausdrücklich ubuntu-26.04. Exakte Python-Metadatenprüfungen verlangen Linux-26.04-/x64-Artefakte. Strikte Sicherheitsprofile und aussagekräftige Negativmutationen bestehen ohne Änderungen an Rechten, Gates oder Abhängigkeiten.

## Untersuchte Alternativen

ubuntu-latest erfüllt die verlangte Version nicht. Nur Workflows umzustellen ließe den Installierbarkeitsselektor inkonsistent. Historische Evidence und unabhängige Sicherheits-Fixtures sollen nicht umgeschrieben werden.

## Implementierungsentscheidung

Alle 31 Jobs in 18 Workflows auf ubuntu-26.04 pinnen und die vorhandene x64-Architektur beibehalten. Exakte geprüfte Profile einschließlich eines ausschließlich durch den Runner geänderten Publisher-Gesamtdigests aktualisieren. Der offizielle setup-python-Manifestdatensatz muss das 26.04-Tupel und den passenden Dateinamen enthalten. Für das kanonische Python 3.14.8 und den Kandidaten 3.14.10 existieren passende offizielle stabile Builds; Python-Pins bleiben daher unverändert.

## Geänderte Dateien und Tests

Workflows, zwei Sicherheitsprüfer, Python-Manifesthelfer, relevante Updater-/Sicherheits-Fixtures und gepaarte aktuelle Workflow-Dokumentation. Neue Offline-Prüfungen erfassen jeden aktiven Workflow-Runner und lehnen ein Artefakt für das vorherige Ubuntu 24.04 ab.

## Befehle und Ergebnisse

106 gezielte Updater-, Workflow-, Sicherheits- und Sonar-Vertragsmethoden bestanden; die abschließende Bereitschaftssuite bestand nach der exakten actionlint-Label-Regression mit 12 Methoden. Kanonische Common-/Workflow-Pins und GitHub-Actions-Pin-/Rechteprüfungen bestanden. Actionlint mit ShellCheck, Offline-Zizmor (null Befunde), Dokumentation und abschließende Diff-Prüfungen bestanden. Ruff-Lint bestand für alle sechs geänderten Python-Dateien; Formatprüfungen bestanden für fünf. Beim Workflow-Prüfer wurde ein bereits vorhandener Formatfehler reproduziert; seine Änderung bleibt auf eine Runner-Zeile begrenzt. Die actionlint-Konfiguration ergänzt nur das exakte offizielle Label und blendet keine Fehler aus.

## Sicherheitsauswirkung

Rechtezuordnungen, Publisher-Programme, Action-Pins, Tokenbehandlung und Gates bleiben unverändert. Der Digest des MRTS-Updater-Publishers wurde erst neu berechnet, nachdem das alleinige Zurücksetzen seines Runner-Felds den zuvor geprüften Digest reproduzierte.

## Dokumentation und Runtime-Evidenz

Die gepaarte Workflow-Sicherheitsdokumentation beschreibt jetzt 26.04. Historische Change Records, Laufprotokolle, versionsgebundene Snapshots und allgemeine nicht ausgeführte Workflow-Fixtures behalten ihre ursprünglichen Plattformen. Außerhalb der schreibgeschützten MRTS-Grenze wurde kein aktiver Ubuntu-Containerverweis gefunden.

## Nicht ausgeführte Prüfungen

Hosted-Jobs, Kandidateninstallation, Updater-Veröffentlichung, Connector-Laufzeit, E2E- und I12-Kampagnen wurden durch diesen Worker nicht ausgeführt.

## Einschränkungen und Restrisiko

Offline-Prüfungen und offizielle Artefaktverfügbarkeit beweisen keine Hosted-Ausführung. Ubuntu-Image-Werkzeuge können abweichen; nach Auslieferung bleibt frische Hosted-Evidence erforderlich.

## Finaler Diff- und Review-Status

Für Koordinatorprüfung und reguläre PR-Fortsetzung vorbereitet. Keine Git- oder Provider-Schreibzugriffe durch diesen Worker.
