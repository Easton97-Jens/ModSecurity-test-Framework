# Kanonische Action-Pins in Maintenance-Vertragstests

**Sprache:** [English](20261102-04-maintenance-action-pin-contracts.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261102-04-maintenance-action-pin-contracts |
| UTC-Datum | 2026-11-02 |
| Framework-Basisrevision | 92bd63630e0593e51b7a248bcfe1dd37fcefc518 |
| Issue oder Pull Request | Folgeänderung zu Actions-Run 41453911536, Job 125307348645; bei Dokumentationsübergabe noch kein neuer PR zugewiesen |

## Motivation und Problemstellung

Der Maintenance-Kandidat wandte alle 43 kanonischen Updates erfolgreich an;
anschließend scheiterten zwei seiner 64 Testmethoden, weil vier Assertions noch
alte Action-Commit-Literale enthielten. Die vorherige Maintenance-Reparatur war
an dieser Basis bereits gemergt. Diese Folgeänderung korrigiert den Testvertrag
für legitime, geprüfte Aktualisierungen kanonischer Pins.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-CI-Vertragstests validieren Identitäten und unveränderliche Commits von
`actions/upload-artifact`, `actions/download-artifact`, `actions/checkout` und
`actions/setup-python`. Diese Änderung verändert keine kanonischen Pins,
Workflows, Abhängigkeitsversionen, Berechtigungen, Artefaktbindungen oder
Runtime-Verhalten. Parent-Quellcode und dessen Framework-Gitlink bleiben
unverändert; MRTS bleibt unverändert und wurde für den Replay nicht initialisiert.

## Akzeptanzkriterien

Kanonische alte und aktualisierte Commits bestehen ohne Anpassung erwarteter
SHA-Literale. Veränderliche, fehlerhafte, fremde oder nichtkanonische Referenzen
scheitern. Eine gleichzeitige fremde Repository-Identität in kanonischen Daten
und Workflow muss scheitern. Portable Workflow-Prüfungen wählen genau einen
erwarteten benannten Schritt in `portable-contract`. Der exakte ursprüngliche
Update-Plan wird offline angewandt, die beiden ursprünglichen Fehler werden vor
dem Fix reproduziert und alle vier ursprünglichen Kandidaten-Testmodule bestehen
danach. Generierte Ansichten bleiben über ihren nativen Generator synchron.

## Untersuchte Alternativen

Die vier Literale durch heutige Commits zu ersetzen würde den Fehler beim
nächsten Update wiederholen. Jede 40-stellige SHA zu akzeptieren würde die
kanonische Gleichheit aufgeben. Erwartetes Repository und Commit aus derselben
veränderlichen Quelle zu lesen würde einem fremden Repository die Prüfung
erlauben. Der gewählte Helper behält feste Repository-Identitäten bei und liest
den kanonischen Commit unabhängig davon.

## Implementierungsentscheidung

`assert_canonical_action_pin` verwendet den vorhandenen, nicht ausführenden
Reader `load_canonical_ci_pins`, prüft das feste erwartete Repository, verlangt
einen kleingeschriebenen 40-Hex-Commit und vergleicht den vollständigen
`uses`-Wert mit `repository@commit`. YAML-Parsing bindet checkout/setup-python
an ihre exakt benannten Schritte im vorgesehenen Job. Bestehende
Sicherheits-Assertions, Berechtigungen, aufrufergebundene Artefaktnamen, Pfade
und nachgelagerte Kontrollen bleiben erhalten.

## Geänderte Dateien und Tests

- `tests/ci_security/workflow_contract_test_support.py`: gemeinsame Assertion für kanonische Pins.
- `tests/ci_security/test_unified_common_maintenance_workflow.py`: upload/download-Assertions und drei Regressionsmethoden mit 19 Unterfällen: zwei legitime Commits, neun ungültige Workflow-Referenzen und acht ungültige kanonische Tupel einschließlich gleichzeitiger fremder Quell-/Workflow-Identität.
- `tests/ci_security/test_five_connector_with_crs_no_mrts_contract.py`: YAML-basierte checkout/setup-python-Assertions mit Prüfung eindeutiger benannter Schritte.
- `connector_suite/reports/testing/test-selection-archive.generated.json`: native Aktualisierung des generierten Archivs: zwei betroffene Testquell-Hashes, drei neue On-demand-Test-IDs und Anzahl 8034 → 8037; source/evidence/native/extraction/case-Flags bleiben unverändert. `active-cases.json` ist byteidentisch.
- Dieses englisch/deutsche Change-Record-Paar.

## Befehle und Ergebnisse

Die Befehle liefen über RTK im Framework-Task-Worktree beziehungsweise, wie
angegeben, in dessen isoliertem Replay-Kandidaten. Portable Variablen bezeichnen
den vorhandenen Framework-Interpreter Python 3.15.2 (`FRAMEWORK_PYTHON`), das
vorhandene Ruff-0.17.3-Binary (`RUFF`), den Framework-Checkout (`FRAMEWORK_ROOT`)
sowie externe temporäre Task- und Bytecode-Cache-Verzeichnisse (`EXTERNAL_TMP`,
`EXTERNAL_CACHE`). Es wurde kein Werkzeug installiert. Hostspezifische Pfade
bleiben ausschließlich in der lokalen Task-Evidenz.

Fokussierter Befehl (fünf Methoden einschließlich der 19 Regressionsunterfälle):

```sh
rtk bypass env ON_DEMAND_TESTS=1 FRAMEWORK_ROOT="$FRAMEWORK_ROOT" TEST_ROOT="$FRAMEWORK_ROOT" PYTHONPATH="$FRAMEWORK_ROOT:$FRAMEWORK_ROOT/connector_suite" PYTHONPYCACHEPREFIX="$EXTERNAL_CACHE" TMPDIR="$EXTERNAL_TMP" "$FRAMEWORK_PYTHON" -m unittest tests.ci_security.test_unified_common_maintenance_workflow.CanonicalActionPinAssertionTests tests.ci_security.test_unified_common_maintenance_workflow.UnifiedCommonMaintenanceWorkflowTests.test_caller_bound_plan_artifact_is_uploaded_once_and_consumed_by_downstream_jobs tests.ci_security.test_five_connector_with_crs_no_mrts_contract.FiveConnectorWorkflowSecurityContractTest.test_workflow_is_a_read_only_portable_contract_gate -v
```

Exakte ursprüngliche Auswahl aus vier Modulen, ausgeführt im Replay-Kandidaten
mit dessen externen temporären/Cache-Pfaden und konfigurierten Kandidaten-Importwurzeln:

```sh
rtk bypass "$FRAMEWORK_PYTHON" -m unittest -v tests.ci_security.test_unified_common_maintenance_workflow tests.security_regression.test_common_version_descriptor_series tests.security_regression.test_runtime_component_lock tests.ci_security.test_five_connector_with_crs_no_mrts_contract
```

| Befehl oder dokumentiertes Verfahren | Exit-Code | Kurzes Ergebnis | Evidenzreferenz |
| --- | --- | --- | --- |
| Fokussierter Befehl oben | 0 | Fünf Methoden bestanden in 0.516s | Lokale Task-Evidenz |
| `rtk bypass "$RUFF" check tests/ci_security` | 0 | CI-Sicherheitstestverzeichnis bestand Lint | Lokale Task-Evidenz |
| `rtk bypass "$RUFF" format --check tests/ci_security` | 0 | 28 Dateien bereits formatiert | Lokale Task-Evidenz |
| `rtk bypass env ON_DEMAND_TESTS=1 PYTHONPYCACHEPREFIX="$EXTERNAL_CACHE" TMPDIR="$EXTERNAL_TMP" "$FRAMEWORK_PYTHON" ci/tools/sync-maintenance-test-views.py --write --root "$FRAMEWORK_ROOT"` | 0 | Natives generiertes Archiv aktualisiert | Lokale Task-Evidenz |
| Derselbe native Generatorbefehl mit `--check` statt `--write` | 0 | Generierte Ansichten synchron | Lokale Task-Evidenz |
| `rtk bypass env PYTHONPATH="$FRAMEWORK_ROOT" PYTHONPYCACHEPREFIX="$EXTERNAL_CACHE" TMPDIR="$EXTERNAL_TMP" "$FRAMEWORK_PYTHON" ci/checks/security/check-ci-security-contract.py` | 0 | CI-Sicherheitsvertrag bestanden | Lokale Task-Evidenz |
| `rtk bypass env FRAMEWORK_ROOT="$FRAMEWORK_ROOT" PYTHONPATH="$FRAMEWORK_ROOT" PYTHONPYCACHEPREFIX="$EXTERNAL_CACHE" TMPDIR="$EXTERNAL_TMP" make PYTHON="$FRAMEWORK_PYTHON" check-canonical-common-pins check-canonical-python-pins check-canonical-workflow-pins` | 0 | Alle drei kanonischen Prüfungen bestanden | Lokale Task-Evidenz |
| `rtk bypass env FRAMEWORK_ROOT="$FRAMEWORK_ROOT" PYTHONPATH="$FRAMEWORK_ROOT" PYTHONPYCACHEPREFIX="$EXTERNAL_CACHE" TMPDIR="$EXTERNAL_TMP" make PYTHON="$FRAMEWORK_PYTHON" check-documentation` | 0 | Links bestanden; zweisprachige Variablen: 372 Paare; Pfade: 2187, alte Pfade: 0; Change Records bestanden | Lokale Task-Evidenz |
| `rtk bypass git diff --check` | 0 | Whitespace-Prüfung bestanden | Lokale Task-Evidenz |
| Offline natives `apply_safe_updates` mit unveränderlicher Basis und Originalplan; Netzwerk-Sockets im anwendenden Interpreter blockiert | 0 | 43 Updates über 24 erlaubte Pfade angewandt; native generierte Ansichten abgeglichen | Replay zu Run 41453911536 |
| Ursprüngliche zwei fehlschlagende Methoden vor Testdatei-Overlay | 1 | Beide Fehler durch veraltete Pins reproduziert | Replay zu Run 41453911536 |
| Auswahl aus vier Modulen nach Overlay und Cachekorrektur, Befehl oben | 0 | 67 Methoden bestanden in 44.098s; drei neue Methoden erklären den Anstieg von 64 | Replay zu Run 41453911536 |

Der Replay verwendete die Original-Artefakt-SHA-256
`1660dda9911d20b979ace329a49608cb91b3473250438d6f0088b03ef97b665d`
und die interne Plan-SHA-256
`e82bd610298c4cb22d7c1d2f18930cfbdd6f705cc5f9bf96e40788705da74448`.
Nur die drei Test-/Helper-Dateien wurden über den angewandten Kandidaten gelegt;
Vorher-/Quell-/Nachher-Hashes je Datei wurden aufbewahrt. Plan und angewandte
Updates wurden nicht bearbeitet.

Ein erster vollständiger Replay behielt 66 bestandene Tests und einen Fehler
beim unveränderten FIFO-Start bei. Geerbtes `PYTHONDONTWRITEBYTECODE` hatte die
Cachevorbereitung verhindert (null tatsächliche Bytecode-Dateien). Das Entfernen
dieser Variable für den Vorbereitungsprozess erzeugte 209 externe Bytecode-Dateien.
Der unveränderte FIFO-Test bestand anschließend in 1.145s, gefolgt vom oben
genannten erfolgreichen vollständigen Lauf mit 67 Methoden. Die ursprünglichen
Fehler bleiben als Evidenz erhalten; kein Timeout, keine Assertion und kein
FIFO-Quellcode wurden zum Erreichen des Erfolgs geändert.

## Sicherheitsauswirkung

Dies repariert die Aktualität der Maintenance-Tests unter Erhalt der
Supply-Chain-Kontrollen; es wird keine neu behobene ausnutzbare Schwachstelle
behauptet. Negative Abdeckung verwirft veränderliche Tags,
kurze/nichthexadezimale/großgeschriebene/abweichende Commits, fremde/verschachtelte
Repositories, nachgestellte Zeilenumbrüche, fehlende Werte und ungültige
kanonische Identitäten. Der gleichzeitige fremde Quell-/Workflow-Fall verhindert,
dass passende nicht vertrauenswürdige Identitäten einander validieren. Bestehende
Artefakt- und Workflow-Sicherheitsbindungen bleiben unverändert.

## Dokumentation und Runtime-Evidenz

Nur dieses leserorientierte Change-Record-Paar wird ergänzt. Native generierte
Ausgabe wurde über ihren Generator aktualisiert. Die Evidenz umfasst statische
Verträge und lokale Offline-Subprozesse. Kein live veröffentlichender Workflow
wurde ausgelöst; kein Connector-Host-, I12-, Runtime-Matrix- oder gehosteter
Veröffentlichungserfolg wird behauptet.

## Nicht ausgeführte Prüfungen

Gehostete PR-Prüfungen und anwendbare Quality Gates einschließlich Sonar
benötigen separate Delivery-Evidenz; hier wird kein Remote-Ergebnis behauptet.
Connector-Builds/Runtime-Matrizen liegen außerhalb dieser reinen Testkorrektur;
live Veröffentlichung wurde bewusst nicht ausgeführt.

## Einschränkungen und Restrisiko

Der Offline-Replay belegt weder Upstream-Verfügbarkeit noch Timing gehosteter
Runner oder Veröffentlichungserfolg. Das FIFO-Ergebnis hing von der belegten
lokalen Cachekorrektur ab; aufbewahrte ursprüngliche Fehler machen diese
Umgebungsbedingung sichtbar. Die Prüfung kanonischer Pins bleibt eine separate
Voraussetzung. Keine Validierung oder Sicherheitskontrolle wurde gelockert.

## Finaler Diff- und Review-Status

Ein unabhängiges Read-only-Review der drei Codedateien ergab keine Findings.
Der Diff des generierten Archivs wurde gegen sein Quellinventar geprüft; nur
die erwarteten Hashes, neuen IDs und die Anzahl änderten sich. Finales
Code-/Archiv-/Dokumentationsreview und `git diff --check` bestanden.
Keine Secrets, sensiblen Rohlogs, Zugangsdaten oder vollständigen
Umgebungswerte sind enthalten.
Dieses Record behauptet keinen neuen Commit, Push, PR, Merge oder
gehosteten Erfolg.
