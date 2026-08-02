# Change Record — Behebung der Framework-Test-SonarQube-Cloud-S9073-Befunde

**Sprache:** [English](20260802-01-remediate-tests-sonar-s9073.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260802-01-remediate-tests-sonar-s9073` |
| UTC-Datum | 2026-08-02 |
| Framework-Basisrevision | `5cb371949ceafec6685cf716ba50a75d0f448bd1` |
| Issue oder Pull Request | SonarQube-Cloud-Framework-`tests/`-Baseline; Framework-PR ausstehend |

## Motivation und Problemstellung

Die aktuelle Framework-`master`-Analyse meldet sieben offene
`python:S9073`-Maintainability-Befunde in `tests/`. Jeder Befund kennzeichnet
eine zusammengesetzte Assertion, die sowohl die Existenz einer Import-
Spezifikation als auch ihres Loaders prüft.

## Betroffene Komponenten und Sicherheitsgrenzen

Die geänderten Pfade sind ausschließlich Framework-Testmodule. Connector-
Verhalten, Runtime-Evidenz, Netzwerk-, Dateisystem-, Subprozess-, Secret- und
MRTS-Grenzen werden nicht geändert.

## Akzeptanzkriterien

- Teile alle sieben aktuellen `tests/`-S9073-Composite-Assertions auf.
- Erhalte Assertions-Bedingungen und Testverhalten.
- Bestehe fokussierte Framework-Validierung, Lint-/Dokumentationsprüfungen und
  die SonarQube-Cloud-Analyse des aktuellen PR-Heads ohne Suppressions oder
  Quality-Gate-Änderungen.

## Untersuchte Alternativen

Das Beibehalten der zusammengesetzten Assertions oder eine S9073-Suppression
würde aktuelle Maintainability-Befunde offen lassen. Ein breiterer Test-
Refactor ist nicht erforderlich: getrennte Assertions liefern die verlangte
diagnostische Klarheit, ohne den Vertrag des importierten Moduls zu ändern.

## Implementierungsentscheidung

Jede Voraussetzung für Import-Spezifikation und Loader wird getrennt
assertiert. Vor `module_from_spec` oder `exec_module` bleiben dieselben
booleschen Bedingungen erforderlich, daher bleiben beobachtbares Erfolgs- und
Fehlerverhalten erhalten.

## Geänderte Dateien und Tests

- `tests/security_regression/test_no_crs_catalog_maintainability_wave.py`
- `tests/no_crs/test_transport_hardening_evidence.py`
- `tests/protocol_client/test_check_protocol_evidence.py`
- `tests/protocol_client/test_protocol_client.py`
- `tests/no_crs/test_no_crs_baseline.py`
- dieses Change-Record-Paar

Kein neues Testszenario ist erforderlich, weil die bestehenden Tests genau die
Importpfade ausführen, deren gleichwertige Voraussetzungen getrennt wurden.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Fokussierter Unittest-Aufruf für fünf Module | 0 | 5 Tests in 0,069 s bestanden; jedes geänderte Modul wurde importiert und ausgeführt | Externe Task-Evidenz `framework-tests-sonar-20260802` |
| `make lint` mit externen Build- und temporären Wurzeln | 0 | Shell-/Python-Checks, Verträge, Security-Regressionstests, Dokumentation und Whitespace-Prüfung bestanden | Externe Task-Evidenz `framework-tests-sonar-20260802` |

## Sicherheitsauswirkung

Es wird keine Security-Remediation durchgeführt. Die Änderung verändert
keine Sicherheitsgrenze und schwächt keine Sicherheitskontrolle.

## Dokumentation und Runtime-Evidenz

Dieses Change-Record-Paar ist die einzige Reader-facing-Dokumentationsänderung.
Es wird keine Connector-Runtime- oder Lifecycle-Evidenz erhoben, weil dies eine
Framework-Test-Maintainability-Behebung ist.

## Nicht ausgeführte Prüfungen

Die gehostete SonarQube-Cloud-Analyse kann erst nach Erstellung eines Pull
Requests laufen. Sie bleibt für den exakten veröffentlichten PR-Head
erforderlich; es wurden weder lokale Suppressions noch Quality-Gate-Änderungen
oder Scanner-Ausschlüsse eingeführt.

## Einschränkungen und Restrisiko

Der lokale Fix kann gleichwertige Python-Testvoraussetzungen beweisen, nicht
jedoch selbst das gehostete SonarQube-Cloud-Ergebnis; die Analyse des aktuellen
PR-Heads bleibt erforderlich.

## Finaler Diff- und Review-Status

Lokaler Scoped-Diff-, Whitespace- sowie Test-/Lint-Review sind abgeschlossen.
Der finale gehostete PR-Head-Review bleibt bis zur Veröffentlichung ausstehend.
