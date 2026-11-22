# Change Record 20261122-02-manual-common-header-fuzz

**Sprache:** [English](20261122-02-manual-common-header-fuzz.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261122-02-manual-common-header-fuzz |
| UTC-Datum | 2026-11-22 |
| Framework-Basisrevision | `b4d619127a3fbd2a4074998e874c592d693413b9` |
| Issue oder Pull Request | Für den Draft-PR zum manuellen Fuzzing vorbereitet. |

## Motivation und Problemstellung

Den vorhandenen Fuzz-Test für gemeinsame HTTP-Header für Maintainer in GitHub Actions verfügbar machen.

## Betroffene Komponenten und Sicherheitsgrenzen

Das Framework besitzt den Test. Der festgelegte Connector-Checkout liefert die gemeinsamen C-Quellen.

## Akzeptanzkriterien

Der Workflow startet über `workflow_dispatch`, führt das vorhandene begrenzte Make-Target auf einem GitHub-gehosteten Runner aus und meldet einen Testfehler als Jobfehler.

## Untersuchte Alternativen

Ein Pull-Request-Trigger würde die feste Testauswahl um zufallsgesteuerte Ausführungen erweitern. Der manuelle Start folgt dem vorhandenen Abrufmodell.

## Implementierungsentscheidung

Die ausgewählte Framework-Revision liefert den Test. Der separat ausgecheckte Connector-Stand ist auf `d21e34eb42b7e12793f670e318954798293bb897` festgelegt. Der Workflow prüft den ausgecheckten Commit und ruft das Connector-Makefile mit dem ausgewählten Framework auf.

Vor dem Make-Aufruf richtet der Job den geprüften Interpreter aus `.python-version` des Frameworks ein.

Auf dem Standardbranch steht **Actions → Common HTTP header fuzzing → Run workflow** zur Verfügung.

## Geänderte Dateien und Tests

- `.github/workflows/fuzz-common.yml`
- `ci/tools/check-common-versions.py` registriert den Workflow für zentral generierte Action-Pins.
- Dieses englische und deutsche Change-Record-Paar.

## Befehle und Ergebnisse

Das im Repository festgelegte `actionlint` mit der Repository-Konfiguration und `bash -n` lieferten jeweils Exitcode `0`. Der unveränderte Shell-Schritt des Workflows lieferte bei der lokalen Ausführung mit Clang 19.1.7 Exitcode `0`.

Die CI meldete die fehlende Registrierung für zentral generierte Action-Pins und verlangte die kanonische Python-Einrichtung vor Make. Nach diesen Änderungen bestanden die Prüfung der kanonischen Pins, die Prüfung des Pin-Synchronisierers, die Workflow-Einzelprüfung, der vollständige Framework-CI-Sicherheitsvertrag und der Python-Versionsvertrag mit Python 3.15.2.

Mit verfügbarem Clang und einem beschreibbaren absoluten Pfad außerhalb der Worktrees für `BUILD_ROOT` lautet der lokale Aufruf:

```sh
rtk make -C "$CONNECTOR_ROOT" FRAMEWORK_ROOT="$TEST_ROOT" ON_DEMAND_TESTS=1 BUILD_ROOT="$BUILD_ROOT" check-common-http-header-fuzz
```

## Sicherheitsauswirkung

Der Job hat ein Zeitlimit von fünf Minuten, verwendet Leserechte und speichert beim Checkout keine Zugangsdaten. Build, temporäre Compilerdateien und vollständige Fuzz-Ausgabe bleiben in einem laufbezogenen temporären Verzeichnis. Der Job veröffentlicht nur den Teststatus.

## Dokumentation und Runtime-Evidenz

Der vorhandene Fuzz-Test im selben Prozess wurde lokal abgeschlossen. Der Test startet keinen Connector-Dienst.

## Nicht ausgeführte Prüfungen

Ein manueller Lauf auf GitHub steht aus, bis der Workflow auf dem Standardbranch verfügbar ist. Bei der lokalen Prüfung war LeakSanitizer wegen der eingeschränkten Prozessinspektion in der Sandbox deaktiviert.

## Einschränkungen und Restrisiko

Die Prüfung deckt die gemeinsamen HTTP-Header-Helfer am festgelegten Connector-Commit ab. Das Update dieses Commits erfordert eine Kompatibilitätsprüfung mit der neueren Connector-Revision. Der begrenzte Lauf prüft 15 Sekunden lang generierte Eingaben. Die festen Regressionstests decken die kontinuierliche Prüfung ab.

## Finaler Diff- und Review-Status

Der Diff ergänzt den manuellen Workflow, registriert seine generierten Action-Pins und enthält das Change-Record-Paar. Das aktuelle Pull-Request-Testinventar gilt weiter.
