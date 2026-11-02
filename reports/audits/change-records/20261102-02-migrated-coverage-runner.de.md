# Change Record

**Sprache:** [English](20261102-02-migrated-coverage-runner.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261102-02-migrated-coverage-runner |
| UTC-Datum | 2026-11-02 |
| Framework-Basisrevision | `91145b7ba721bdec4e89af754cf40bf496fd2a08`; mit uncommitteten Task-Änderungen gemessen |
| Issue oder Pull Request | Task-Abgleich; bei Erstellung noch kein PR angelegt |

## Motivation und Problemstellung

Nach der Migration der Test-Ownership rief der Coverage-Runner entfernte
Parent-Pfade auf und erwartete Same-Package-Go-Tests im Produktbaum.
Evidence-Security-Fixtures patchten alte Modulaliase und ersetzten das
Python-Argument `-P` statt des Skriptpfads. Diese Fehler behinderten Messung
und Validierung, ohne einen Produktfehler nachzuweisen.

## Betroffene Komponenten und Sicherheitsgrenzen

Das Framework besitzt Runner, Test-Overlays, Fallzulassung und Sicherheits-Fixtures.
Parent besitzt Produktquellen und seinen Coverage-Bericht. Framework-Ausführungsdaten
dürfen nicht als Parent-Python-Coverage umbenannt werden. Exakte Testquellenzulassung,
private externe Artefakte und Evidence-Lesezugriffe ohne Symlink-Folgen bleiben Pflicht.

## Akzeptanzkriterien

Migrierte Helfer über die Source-Map auflösen; bestehende Go-Testquellen über das
vorhandene geprüfte Overlay zulassen; exakte Selektoren und alle Pakete des
Default-Builds im Coverage-Nenner erhalten; nur echte Parent-Python-Dateien
berichten; das explizite `offline-unit`-Assessment ohne implizite zusätzliche
Spezialisten-/Native-Kataloge auswählen. Sicheren Python-Aufruf und Schutz der
Evidence-Eingaben erhalten. Default-Auswahl von 100 Fällen unverändert erhalten.

## Untersuchte Alternativen

Tests zurück nach Parent zu kopieren würde Ownership verletzen. Breite Discovery
würde den Assessment-Umfang ändern. Framework-Dateien als Parent-Quellen zu zählen
würde Coverage falsch darstellen. Die gewählten Änderungen erhalten bestehende
Zulassungen und trennen Messumfang von fehlgeschlagenen oder nicht ausgeführten Stufen.

## Implementierungsentscheidung

Scope-Checker, Active-Test-Launcher und Common-Helper-Checker durch `source_path`
auflösen. Das bestehende On-Demand-Go-Overlay für `sonar-coverage` erzeugen und
Listing sowie Messung dasselbe exakte Overlay übergeben; Ablehnung fehlender
Selektoren, `-mod=readonly`, `-count=1` und `-coverpkg=./...` erhalten.

Branch-fähige Python-Daten mit Child-Ausführungsnachweis sammeln, Framework-Baum
von Parent-XML ausschließen und gemeldete Dateien gegen den physischen Parent-Baum
prüfen. Fremde Framework-Dateien bei der Suche nach dem zugelassenen Nachweis
ignorieren. Explizit `offline-unit` zulassen und zeitkritische Ausführungen in
ihrem getrennten ungemessenen Teil belassen. Kanonische Evidence-Modulnamen
patchen und beim Ersetzen des erzeugten Postprocess-Skriptpfads `-P` erhalten.

## Geänderte Dateien und Tests

- `connector_suite/modsecurity_connector_ci/checks/analysis/run-sonar-coverage.py`
- `connector_suite/modsecurity_connector_tests/test_sonar_coverage.py`
- `connector_suite/modsecurity_connector_tests/test_evidence_input_security.py`
- `connector_suite/modsecurity_connector_tests/test_nginx_root_broker.py` und seine inerte historische Caller-Fixture.
- Geprüfte Source-Map-/Inventory-Metadaten für die Fixture und explizite On-Demand-Inkompatibilitätsregression.
- Dieses englisch/deutsche Change-Record-Paar.

Regressionen prüfen Parent-/Framework-Zuordnung, exakte Go-Overlay-Nutzung in
beiden Befehlen, Offline-Zulassung, fremde Witness-Quellen und bestehende
Evidence-Pfadsicherheit. Inventory-Bindings und generierte Archive werden im
gemeinsamen Task synchronisiert; keine Spezialistenauswahl ergänzt den Default 100.
Der getrennte Metadatenabgleich von `.codex/inheritance-manifest.toml` aktualisiert
nach Inhaltsprüfung drei geerbte Digests; er ändert diese Runtime-Verträge nicht.

## Befehle und Ergebnisse

Task-Evidenzroot relativ zum genehmigten externen Speicherroot: `runs/master-reconcile-20261102/coverage`.
`run_measure.py` dokumentiert Interpreter, Quellroots, Umgebungsergänzungen und
Befehlsaufbau exakt; es ruft den folgenden Runner-Befehl je Sprache mit dem
Task-Coverage-Interpreter auf. Shell-Einstiegspunkte verwenden RTK.
`publish_focused.py` erhält die ausgewählten Branch-Rohdaten und veröffentlicht
sie über die bestehende Berichtsfunktion.

| Befehl oder dokumentiertes Verfahren | Exit-Code | Kurzes Ergebnis | Evidenz |
| --- | --- | --- | --- |
| `run-sonar-coverage.py --language go --on-demand --output-root <coverage>/after --temp-root "$TMP_ROOT"` über `run_measure.py go` | 0 | Vier ausgewählte Go-Gruppen mit tatsächlich zugelassenen Tests gemessen | `go.log`, `after/go/manifest.json` |
| Derselbe Launcher und Optionen mit `--language native` | 0 | Native-Helper-Messung und echte Branch-Beobachtungen | `native.log`, `after/native/manifest.json` |
| Derselbe Launcher und Optionen mit `--language python` | 1 | Benannte Stufe: 116 Tests bestanden; vollständige Offline-Stufe nach 56 bestandenen Ausführungen bei Ausführung 57 fehlgeschlagen; Timing-Teil nicht erreicht | `python.log`, `summary.json` |
| `publish_focused.py`, Aufruf von `publish_python_report` mit erhaltenen Daten der benannten Stufe | 0 | Ausgewählte Parent-Python-XML publiziert; fehlgeschlagenes Offline-Assessment ausgeschlossen | `focused/python/selected-scope.json`, `focused/python/python.xml` |

Der fokussierte Coverage-/Evidence-Security-Regressionslauf bestand 42 Tests.
Der Koordinator beobachtete `Ran 42 tests in 9.933s` / `OK`, Exit 0
(Tool-Session 20942), mit diesem Befehl (konfigurierte Roots und Interpreter als portable Variablen;
expandierter Aufruf in der Task-Übergabe erhalten):

```sh
rtk bypass env ON_DEMAND_TESTS=1 CONNECTOR_ROOT="$CONNECTOR_ROOT" CONNECTOR_REVISION=430d3194fa04ca4aafcdaef6aeb256d21dc18f0c TEST_ROOT="$TEST_ROOT" FRAMEWORK_ROOT="$TEST_ROOT" PYTHONPATH="$TEST_ROOT:$TEST_ROOT/connector_suite" TMPDIR="$TMP_ROOT" "$PYTHON" -m unittest -v modsecurity_connector_tests.test_sonar_coverage modsecurity_connector_tests.test_evidence_input_security
```

Die 116 benannten gemessenen Tests sind eine getrennte beobachtete Stufe und
kein Nachweis eines vollständig bestandenen Python-Runners.

Beobachtete Messwerte: Go-Statement-Coverage Envoy 1104/3971, Traefik native
586/959, composite 383/563 und observer 300/752. Native-Union: 2869/4290 Zeilen
und 1903/3977 Branches. Ausgewähltes Parent-Python: 59/6552 Zeilen und 16/2240
Branches über 33 Dateien. Native-Union verwendet Source-/Zeilen-/gcov-Branch-Identität;
generierte Harnesses und Framework-Testhelfer sind ausgeschlossen. Go berichtet
Statements, keine Branch-Coverage. `summary.json` und `provenance.json` binden
Messungen an Framework-Quellhashes und externe Parent-Basis
`430d3194fa04ca4aafcdaef6aeb256d21dc18f0c`; dies sind keine Messungen des final gemergten Paars.

Die fokussierte historische Caller-Reparatur verwendet exakte Bytes aus Parent-Commit
`f5523da040bd6325b369269ada074be6ba069c4f`, Pfad
`.github/workflows/run-protected-nginx-root-broker.yml`: Fixture-SHA-256
`d34b01b67d9f88552353186a3c78605b6d99d827541479207efe174bc994b341`.
Das ausgewählte unveränderliche Broker-/Framework-Paar
`8ae707d72f1a8acb25d239e55e28a73cbc7522b1` und
`99a7985c1be92a2297b1b59208f64df6768f2cbf` bleibt erhalten. Der ursprüngliche
Berechtigungstest scheiterte vor der Reparatur in drei Teilfällen und besteht
mit unveränderten Berechtigungsassertionen gegen die gültige Inline-Eingabe.
Alle 22 Caller-Grenztests bestehen, einschließlich der expliziten Ablehnung
des aktuellen delegierten Callers. Das vollständige Broker-Modul meldet 45/46
bestandene Tests: Die unveränderte Assertion für den aktuellen Broker-Workflow
scheitert weiter, weil sein delegierter Wrapper kein `runs-on` besitzt.
Evidenz: `broker-fixture-validation.json` und `broker-final.log` unter dem
Coverage-Taskroot. Diese reine Testreparatur stellt die geschützte Runtime-Zulassung
nicht wieder her. Der neue Inkompatibilitätsfall ist explizit On-Demand;
die 100 Standardfälle bleiben unverändert.

## Sicherheitsauswirkung

Keine Behebung einer Produktschwachstelle wird behauptet. Bestehende
Evidence-Input-Schutzprüfungen und Python-Safe-Path-Aufruf bleiben erhalten;
kanonische Fixture-Namen stellen Prüfungen gegen die tatsächliche Implementierung
wieder her. Keine Sicherheits-, Workflow- oder Zulassungsprüfung wird für einen Pass deaktiviert.

## Dokumentation und Runtime-Evidenz

Dieses Paar dokumentiert Framework-Verhalten und ausgewählte Messnachweise.
Keine frische Connector-Host-Lifecycle-Qualifikation oder H2/H3-Kampagne ausgeführt.
Die bestehende Sonar-Coverage-Ausnahme bleibt erhalten; lokale Messung ist weder
Analyzer-Import noch Sonar-Quality-Gate-Ergebnis. Kein neues Prozentziel eingeführt.

## Nicht ausgeführte Prüfungen

Das vollständige Python-Assessment endete nicht erfolgreich. Ausführung
`offline.nginx-broker-parser.caller-top-level-permissions-remain-exactly-deny-default`
wurde wegen eines unerwarteten Fixture-Key-Sets vor der erwarteten Diagnose für
Deny-Default-Berechtigungen abgewiesen. Die oben beschriebene fokussierte
historische Fixture-Reparatur korrigiert diese Testeingabe bei unveränderter
Berechtigungsinvariante; der folgende Timing-Teil ist ungemessen. Die ursprüngliche
Fehlermeldung des vollständigen Laufs bleibt erhalten; das breite Assessment wurde am aktuellen Head
nicht erneut ausgeführt. Zusätzlich ergab die getrennte Quellenanalyse des
Koordinators eine Inkompatibilität zwischen aktuellem dünnem Parent-Wrapper
und unveränderlichem historischem Broker bei der echten Runtime-Zulassung.
Dieser Runtime-Blocker ist kein behobener Fixture-Fehler und bleibt offen. Ausgewählte Python-Publikation
darf nicht als vollständiger Runner-PASS gelten. Nachweise für finales integriertes
Commitpaar und Remote-CI bleiben getrennte Prüfungen des Delivery-Koordinators.

Lokale Sonar-Secrets-Prüfung aufgrund ausdrücklicher Benutzeranweisung nicht ausgeführt.

## Einschränkungen und Restrisiko

Die Messung erfasst nur ausgewählte Produktpfade und Tests. Framework-Quellen
waren bei Messung dirty; exakte Quellhashes sind erhalten. Weitere Quell- oder
Inventory-Änderungen erfordern erneute Anwendbarkeitsprüfung. Keine Sonar-Ausnahme
entfernt, keine CI-Pflichtprüfung abgeschwächt und keine Connector-Promotion abgeleitet.

## Finaler Diff- und Review-Status

Runner-/Fixture-Diffs, Quellprovenienz und Sprachpaar wurden geprüft.
Keine Credential-Werte, sensiblen Rohbodies oder Umgebungs-Dumps aufgezeichnet.
Dieser Dokumentationstask führt keinen Commit, Push oder Merge aus. Native
Framework-Dokumentations- und Whitespace-Prüfungen stehen in der Task-Übergabe.
