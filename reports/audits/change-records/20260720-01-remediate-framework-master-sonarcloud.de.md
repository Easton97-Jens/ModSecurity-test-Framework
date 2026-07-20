# 20260720-01-remediate-framework-master-sonarcloud — Behebung der Framework-master-SonarCloud-Befunde

**Language:** Deutsch | [English](20260720-01-remediate-framework-master-sonarcloud.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260720-01-remediate-framework-master-sonarcloud |
| UTC-Datum | 2026-07-20 |
| Framework-Basisrevision | efdbcbd98afeed0f39f8912ce1140aaa5742f507 |
| Issue oder Pull Request | Frisches SonarCloud-master-Inventar; normale Task-Branch-Delivery und Pull Request stehen noch aus |

## Motivation und Problemstellung

Ein frisches GitHub-master-/SonarCloud-Readback ergab 32 offene Zeilen an der
exakten Basisrevision: 15 Framework-eigene und 17 MRTS-Pfad-Zeilen. Das
aktuelle Quality Gate des Default-Branches ist ERROR, weil new_security_rating
5 gegen Grenzwert 1 beträgt. Die Aufgabe behebt nur reproduzierbare
Framework-eigene Punkte und dokumentiert die MRTS-Punkte anhand aufbewahrter
externer Scanner-Metadaten ohne Quellinspektion.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-Änderungen bleiben auf Action-Pin-Checker, No-CRS-Katalog-Checker,
Documentation-Variable-Checker, Apache-Provisioning-Helper, zwei Katalog-
Shell-Checker und fokussierte Regressionstests begrenzt. Relevante Grenzen
sind GitHub-Actions-Action-Pinning, Checksum-Verifikation, No-CRS-Fixture-/
Pfad-/Evidence-Containment, payload-sichere Transport-Evidence und
statisches Documentation-Parsing.

Die 17 gemeldeten MRTS-Zeilen sind ausschließlich dokumentierte Metadaten.
MRTS-Quellinhalt, generierte Artefakte, Git-Zustand und Gitlink liegen nicht im
Framework-Task-Scope und wurden nicht editiert.

## Akzeptanzkriterien

- SHA-gebundene Evidenz für aktuelles master-Inventar und Quality Gate bewahren.
- Alle 15 Framework-Zeilen klassifizieren und jeden reproduzierbaren
  Maintainability-Punkt mit fokussierter Regressionsevidenz beheben.
- Bestehende Fail-closed-/Containment-Kontrollen bei Scanner-Security-Zeilen
  bewahren; keinen unbelegten Patch oder eine False-Positive-Disposition erfinden.
- Alle 17 MRTS-Zeilen in äquivalenten englischen, deutschen und JSON-Finding-
  Datensätzen ausschließlich mit externen Metadaten dokumentieren.
- Kein Quality Gate, Profil, Regel, Exclusion, Accepted Issue, NOSONAR, Parent-
  Repository, Gitlink oder MRTS-Quellinhalt ändern.
- Erst nach lokaler Validierung nur über normalen Task-Branch und nicht
  gemergten PR liefern; vor Abschluss exakte Head-Remote-CI-/SonarCloud-
  Evidenz erhalten.

## Untersuchte Alternativen

Änderungen an SonarCloud-Quality-Gate, Accepted Issues, Exclusions oder NOSONAR
wurden verworfen, weil sie das Inventar verbergen statt es zu beheben. Breite
Refactorings wurden verworfen, weil die Pfade Security- und Testverträge
definieren. MRTS-Modifikation oder -Inspektion wurde wegen der externen
Read-only-Grenze verworfen. Der gewählte Ansatz verwendet eng begrenzte Helper,
expliziten Kontrollfluss, fokussierte Regressionen und eine reine
Metadaten-Übergabe.

## Implementierungsentscheidung

Der Action-Pin-Scanner extrahiert nun kleine Parser-Helper und behält seine
Full-SHA- und Unsupported-YAML-Schutzmechanismen. Der No-CRS-Katalogcode
extrahiert Validation-/Expectation-Helper ohne Änderung der Validierungsreihen-
folge oder des geschlossenen Transportvokabulars; ein ungenutzter Parameter
wird entfernt und ein Equality-Check explizit gemacht. Die Apache-Checksum-
Pipeline verwendet einen einzigen POSIX-Helper. Die zwei Shell-Case-Statements
machen ihren Fall-through explizit. Der Documentation-Regex verwendet eine
ASCII-scoped Word-Class, die seiner früheren ASCII-Grenze äquivalent ist und
weiter Unicode-Whitespace akzeptiert.

Fünf Framework-Scanner-Security-Zeilen erhielten eine Source-to-Sink-/
Control-Analyse statt spekulativer Codeänderungen: bestehende deterministische
Output-Roots, Containment-, Symlink-, Deny-list- und Fail-closed-Validierungen
werden bewahrt und durch vorhandene fokussierte Tests ausgeübt.

## Geänderte Dateien und Tests

Geänderte Framework-Dateien:

- ci/checks/security/check-workflow-action-pins.py
- ci/checks/catalog/no_crs_baseline.py
- ci/checks/documentation/check-variable-documentation.py
- ci/provisioning/prepare-apache-build.sh
- ci/checks/catalog/check-open-runtime-provisioning-contract.sh
- ci/checks/catalog/check-crs-version-pinning.sh
- tests/security_regression/test_workflow_action_pins.py
- tests/security_regression/test_variable_documentation_assignment_regex.py
- reports/audits/change-records/20260720-01-remediate-framework-master-sonarcloud.md
- reports/audits/change-records/20260720-01-remediate-framework-master-sonarcloud.de.md

Die hinzugefügten Tests schützen eine Action-Pin-Flow-Mapping mit GitHub-
Expression und den korrigierten Closing-Flow-Delimiter-Scan sowie ASCII-/Nicht-
ASCII-Grenz- und Unicode-Whitespace-Assignment-Verhalten. Bestehende No-CRS-,
Transport-, Runner-Containment-, Runtime-Snapshot-, Checksum- und CRS-Pinning-
Tests liefern negative und legitime Kontrollen.

## Befehle und Ergebnisse

Die folgenden replay-sicheren Befehlsvorlagen sind in den englischen und
deutschen Datensätzen identisch. Die Shell-Variable task_run_root ist auf ein
konfiguriertes task-eigenes externes Run-Verzeichnis und framework_python auf
den ausgewählten bestehenden Framework-Interpreter zu setzen. Vollständig
aufgelöste beobachtete Befehlsliterale werden außerhalb versionierter
Dokumentation in evidence/validation-command-manifest.md aufbewahrt, damit kein
lokaler Entwicklerpfad eingebettet wird.

<pre>
C01 rtk env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$task_run_root/tmp/final-workflow" TEST_TMPDIR="$task_run_root/tmp/final-workflow" PYTHONPYCACHEPREFIX="$task_run_root/build/final-workflow/pycache" make PYTHON="$framework_python" BUILD_ROOT="$task_run_root/build/final-workflow" test-workflow-action-pins
C02 rtk env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$task_run_root/tmp/final-variable" TEST_TMPDIR="$task_run_root/tmp/final-variable" PYTHONPYCACHEPREFIX="$task_run_root/build/final-variable/pycache" "$framework_python" tests/security_regression/test_variable_documentation_assignment_regex.py -v
C03 rtk env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$task_run_root/tmp/final-no-crs" TEST_TMPDIR="$task_run_root/tmp/final-no-crs" PYTHONPYCACHEPREFIX="$task_run_root/build/final-no-crs/pycache" "$framework_python" tests/no_crs/test_no_crs_baseline.py -v
C04 rtk env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$task_run_root/tmp/final-catalog" TEST_TMPDIR="$task_run_root/tmp/final-catalog" PYTHONPYCACHEPREFIX="$task_run_root/build/final-catalog/pycache" "$framework_python" ci/checks/catalog/no_crs_baseline.py catalog-check
C05 rtk env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$task_run_root/tmp/final-transport" TEST_TMPDIR="$task_run_root/tmp/final-transport" PYTHONPYCACHEPREFIX="$task_run_root/build/final-transport/pycache" "$framework_python" tests/no_crs/test_transport_hardening_evidence.py -v
C06 rtk env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$task_run_root/tmp/final-runner" TEST_TMPDIR="$task_run_root/tmp/final-runner" PYTHONPYCACHEPREFIX="$task_run_root/build/final-runner/pycache" "$framework_python" tests/security_regression/test_runner_core_output_containment.py -v
C07 rtk env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$task_run_root/tmp/final-snapshot" TEST_TMPDIR="$task_run_root/tmp/final-snapshot" PYTHONPYCACHEPREFIX="$task_run_root/build/final-snapshot/pycache" "$framework_python" tests/security_regression/test_runtime_snapshot_sonar.py -v
C08 rtk env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$task_run_root/tmp/final-pcre2" TEST_TMPDIR="$task_run_root/tmp/final-pcre2" PYTHONPYCACHEPREFIX="$task_run_root/build/final-pcre2/pycache" "$framework_python" tests/security_regression/test_pcre2_archive_digest.py -v
C09 rtk env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$task_run_root/tmp/final-crs" TEST_TMPDIR="$task_run_root/tmp/final-crs" PYTHONPYCACHEPREFIX="$task_run_root/build/final-crs/pycache" "$framework_python" tests/security_regression/test_crs_version_pinning_paths.py -v
C10a rtk sh -n ci/provisioning/prepare-apache-build.sh
C10b rtk sh -n ci/checks/catalog/check-open-runtime-provisioning-contract.sh
C10c rtk sh -n ci/checks/catalog/check-crs-version-pinning.sh
C11 rtk env TMPDIR="$task_run_root/tmp/final-open-runtime" sh ci/checks/catalog/check-open-runtime-provisioning-contract.sh
C12 rtk env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX="$task_run_root/build/final-pycompile/pycache" "$framework_python" -m py_compile ci/checks/catalog/no_crs_baseline.py ci/checks/security/check-workflow-action-pins.py ci/checks/documentation/check-variable-documentation.py
C13 rtk env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$task_run_root/tmp/final-lint" TEST_TMPDIR="$task_run_root/tmp/final-lint" PYTHONPYCACHEPREFIX="$task_run_root/build/final-lint/pycache" BUILD_ROOT="$task_run_root/build/final-lint" TMP_ROOT="$task_run_root/tmp/final-lint" STATE_HOME="$task_run_root/state/final-lint" make PYTHON="$framework_python" lint
C14 rtk env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$task_run_root/tmp/final-lint" TEST_TMPDIR="$task_run_root/tmp/final-lint" PYTHONPYCACHEPREFIX="$task_run_root/build/final-lint/pycache" BUILD_ROOT="$task_run_root/build/final-lint" TMP_ROOT="$task_run_root/tmp/final-lint" STATE_HOME="$task_run_root/state/final-lint" make PYTHON="$framework_python" lint
</pre>

| Befehls-ID | Exit-Code | Prägnantes Ergebnis | Run-ID oder genehmigter Evidence-Pfad |
| --- | --- | --- | --- |
| C01 | 0 | 23 Tests nach Parser-Extraktion und Closing-Delimiter-Regression bestanden | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |
| C02 | 0 | 3 Tests bestanden | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |
| C03 | 0 | 74 Tests bestanden; erwartete Negative-Control-Diagnostik wurde ausgegeben | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |
| C04 | 0 | no-crs-catalog PASS, 166 Cases | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |
| C05 | 0 | 13 Tests bestanden | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |
| C06 | 0 | 3 Containment-Tests bestanden | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |
| C07 | 0 | 3 Runtime-Snapshot-Control-Tests bestanden | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |
| C08 | 0 | 3 Checksum-/Negative-Path-Tests bestanden | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |
| C09 | 0 | 3 Tests bestanden | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |
| C10a-C10c | 0 | POSIX-Shell-Syntax für alle drei geänderten Skripte bestanden | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |
| C11 | 0 | open_runtime_provisioning_contract PASS | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |
| C12 | 0 | Syntax-Kompilierung bestanden | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |
| C13 | 2 | erster nativer Lint stoppte nur wegen lokaler Entwicklerpfade in neuen versionierten Datensätzen; kein Source-Fehler | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |
| C14 | 0 | vollständiger nativer Lint bestand nach der Documentation-Path-Korrektur | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |

## Sicherheitsauswirkung

Keine Analyse-Kontrolle wurde abgeschwächt. Der Action-Pin-Checker verlangt
weiterhin 40-Zeichen-Commit-SHA-Pins für externe Actions, auch in YAML-Flow-
Mappings. Der Checksum-Vergleich bleibt vor Extraction fail-closed. Das
No-CRS-Refactoring bewahrt Fixture-Containment, Real-host-/No-synthetic-pass-
Anforderungen, geschlossene Transport-Metadaten, No-body-/No-authorization-
Logging-Regeln und Protocol-client-Evidence-Regeln.

Die lokale Source-to-Sink-Prüfung validierte keinen ausnutzbaren Pfad für die
fünf Framework-Security-Scanner-Zeilen. Bestehende Runner-Containment-Tests
weisen Writes außerhalb einer Trusted Root und traversal-förmige Runtime-
Filenames ab; Snapshot- und No-CRS-Kontrollen bewahren deterministische Roots,
Symlink-Ablehnung und payload-sichere Evidence. Dies ist keine Remote-
SonarCloud-Closure-Behauptung.

## Dokumentation und Runtime-Evidenz

Das task-lokale Finding-System enthält äquivalente englische, deutsche und
JSON-Datensätze FND-FRAMEWORK-0001, FND-MRTS-0001 und FND-CROSS-0001. Der
MRTS-Datensatz enthält das vollständige reine Metadateninventar:

| Key | Regel | Gemeldeter Ort |
| --- | --- | --- |
| AZ84XDED2YUGB8FZMhlf | python:S3776 | tools/MRTS/mrts/generate-rules.py:122 |
| AZ84XDED2YUGB8FZMhlg | python:S7504 | tools/MRTS/mrts/generate-rules.py:139 |
| AZ84XDED2YUGB8FZMhlh | python:S108 | tools/MRTS/mrts/generate-rules.py:167 |
| AZ84XDED2YUGB8FZMhli | python:S3776 | tools/MRTS/mrts/generate-rules.py:182 |
| AZ84XDED2YUGB8FZMhlj | python:S3776 | tools/MRTS/mrts/generate-rules.py:208 |
| AZ84XDED2YUGB8FZMhlk | python:S8519 | tools/MRTS/mrts/generate-rules.py:336 |
| AZ84XDED2YUGB8FZMhll | python:S8519 | tools/MRTS/mrts/generate-rules.py:343 |
| AZ84XDED2YUGB8FZMhlm | pythonsecurity:S8707 | tools/MRTS/mrts/generate-rules.py:428 |
| AZ84XDED2YUGB8FZMhln | pythonsecurity:S8707 | tools/MRTS/mrts/generate-rules.py:444 |
| AZ84XDDw2YUGB8FZMhle | pythonsecurity:S8707 | tools/MRTS/mrts/mrts.py:13 |
| AZ84XDDw2YUGB8FZMhlb | pythonsecurity:S8707 | tools/MRTS/mrts/mrts.py:14 |
| AZ84XDDw2YUGB8FZMhlY | pythonsecurity:S8705 | tools/MRTS/mrts/mrts.py:30 |
| AZ84XDDw2YUGB8FZMhlc | pythonsecurity:S8707 | tools/MRTS/mrts/mrts.py:30 |
| AZ84XDDw2YUGB8FZMhlZ | pythonsecurity:S8705 | tools/MRTS/mrts/mrts.py:53 |
| AZ84XDDw2YUGB8FZMhld | pythonsecurity:S8707 | tools/MRTS/mrts/mrts.py:73 |
| AZ84XDDw2YUGB8FZMhla | pythonsecurity:S8707 | tools/MRTS/mrts/mrts.py:83 |
| AZ84XDED2YUGB8FZMhlX | python:S1940 | tools/MRTS/mrts/mrts.py:93 |

Die Quelle ist das aufbewahrte offizielle API-Artefakt
evidence/sonar-master/issues-page-1-full.json,
SHA-256 698b8fbdf7a99c31c451a693781e5f0ef95061412917cd2fa9afcbe17017dd4a.
Es wurde kein Host-Runtime-/Lifecycle-Run erhoben; die aufgelisteten lokalen
Checks sind statische/fokussierte Validierung, keine Connector-Runtime-Evidenz.

## Nicht ausgeführte Prüfungen

Eine vollständige unbeschränkte Repository-Suite wurde nicht ausgeführt, weil
die aktive Aufgabe Befehle vermeiden muss, die MRTS traversieren oder
inspizieren könnten. Eine lokale SonarCloud-Analyse ist kein akzeptierter
Ersatz für eine aktuelle GitHub-/PR-Analyse. Remote GitHub CI, Quality Gate des
aktuellen Heads, Issue-Readback des aktuellen Heads, normaler Push und
Draft-PR-Erstellung stehen in der aktuellen Revision dieses Records noch aus.
C14 ist das erfolgreiche vollständige native Lint-Ergebnis; es ist lokale
Verifikation, keine Remote-Evidenz.

Ein erster PCRE2-Testversuch und ein Make-Aufruf nutzten nicht existierende
task-lokale Temp-Unterverzeichnisse; der erste schlug fehl, bevor der Test seine
Fixture anlegen konnte, und der zweite fiel auf /tmp zurück. Das sind
Infrastruktur-Setup-Fehler, keine Source-Fehler; die Verzeichnisse wurden
angelegt und beide betroffenen Checks mit task-lokalen Pfaden erfolgreich
wiederholt.

## Einschränkungen und Restrisiko

Die 17 MRTS-Zeilen bleiben durch externe Verantwortlichkeit blockiert und
können master unabhängig weiter rot halten. Ein Dokumentationsdelegate führte
einen überbreiten rg --files-Versuch aus, der den Parent der Task-Worktrees
enthielt. Sein gefilterter Output enthielt keinen literalen MRTS-Pfad oder
MRTS-Quellinhalt und er machte keine Edits, aber Enumeration könnte vor dem
Filter erfolgt sein. Der Delegate wurde sofort gestoppt und der Vorfall ist
FND-CROSS-0001. Damit ist das strikte No-prohibited-action-Completion-Kriterium
dieser Aufgabe irreversibel verfehlt.

## Finaler Diff- und Review-Status

Der uncommittete Framework-Diff bestand die Whitespace-Prüfung und das
vollständige native make lint. Ein unabhängiger sicherheitsfokussierter Review
fand keine validierte funktionale Regression, Abschwächung einer Security-
Kontrolle, Kompatibilitätsunterbrechung oder versehentlichen Scope-Creep.
Normaler Task-Branch-Commit/-Push, PR-Erstellung und exakte Head-Remote-
Verifikation stehen noch aus. Kein Merge ist autorisiert.
