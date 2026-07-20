# 20260720-02-harden-nginx-https-redirects — HTTPS-only NGINX-Download-Redirects

**Sprache:** [English](20260720-02-harden-nginx-https-redirects.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260720-02-harden-nginx-https-redirects |
| UTC-Datum | 2026-07-20 |
| Framework-Basisrevision | 784977615acfc55567e37b863309abc4a38ac877 |
| Issue oder Pull Request | SonarCloud AZ9_o2_jSLr5VHr-smcj (shell:S6506) plus fünf ältere Framework-Write-Path-Zeilen; Draft PR #37 ist ungemergt und kein Merge ist autorisiert. |

## Motivation und Problemstellung

Die aktuelle SonarCloud-Analyse des Default-Branches meldete eine
Redirect-folgende GitHub-Latest-Release-Abfrage ohne expliziten HTTPS-
Protokollvertrag. Die Downloadpfade für Release-Asset und HTTP/3-TLS-Quelle
verwendeten dasselbe Curl-Muster. Eine Provisionierungsanfrage darf keinem
Redirect zu HTTP oder einem anderen Protokoll folgen.

## Betroffene Komponenten und Sicherheitsgrenzen

Die Framework-only-Transportgrenze umfasst:

- ci/provisioning/prepare-nginx-build.sh
- tests/security_regression/test_nginx_archive_digest.py
- Makefile
- ci/checks/catalog/no_crs_baseline.py
- ci/reporting/update-runtime-snapshot.py
- tests/runners/runner_core.py
- tests/runners/case_cli.py

Die Änderung beschränkt Redirect-Protokolle und erhält die unabhängige
gepinnte SHA-256-Prüfung vor der Archivextraktion. Parent, Connector, Gitlink
und MRTS-Inhalt werden nicht verändert.

## Akzeptanzkriterien

- Jeder Redirect-folgende NGINX-Curl-Aufruf erlaubt für initiale und
  Redirect-Protokolle explizit nur HTTPS.
- Das lokale Harness des echten Scripts verwirft die alte Aufrufform und
  akzeptiert deterministische HTTPS-Kontrollen für GitHub-API und
  Release-Archiv.
- Der HTTP/3-TLS-Download erhält denselben Source-Vertrag.
- Direkte Tests decken bestehende Output-Containment-Kontrollen für /tmp,
  Snapshots, Runner und Case-Informationen ab.
- Jede der fünf älteren Framework-Zeilen erhält eine Source-Level-Behebung,
  welche die bestehenden Zurückweisungs- und Output-Root-Invarianten erhält.
- Es gibt keine Änderung an SonarCloud-Regel, Profil, Gate, Exclusion,
  Accepted-Issue oder NOSONAR.

## Untersuchte Alternativen

Das Entfernen des Redirect-Folgens aus der Latest-Release-Abfrage würde
bestehendes Cache- und Endpoint-Verhalten ändern. Eine Beschränkung nur des
gemeldeten Metadatenaufrufs ließe zwei gleichartige Provisionierungspfade
offen. Eine HTTPS-only-Protokollbeschränkung erhält erwartete
GitHub/CDN-HTTPS-Redirects und setzt die gemeldete Transportinvariante direkt
durch.

Eine Änderung der Analyzer-Konfiguration oder das Akzeptieren eines Issues
wurde verworfen, weil dies die Transportgrenze nicht durchsetzen würde.

## Implementierungsentscheidung

Jeder Redirect-folgende Curl-Aufruf enthält jetzt:

~~~text
--proto =https --proto-redir =https
~~~

Der Latest-Release-Command-Record entspricht dem ausgeführten Befehl. Das
Regression-Harness erfasst beide Optionswerte und schlägt fehl, wenn einer
fehlt. Seine dynamische Kontrolle deckt Latest-Metadaten und ausgewähltes
Release-Asset ab; seine Source-Vertragskontrolle verlangt dasselbe Paar bei
allen drei aktuellen Curl-Aufrufen einschließlich des HTTP/3-TLS-Archivs.

Das benannte Make-Target test-nginx-archive-digest wurde zu lint hinzugefügt,
damit dieser Transportvertrag projektnativ bleibt.

Die No-CRS-Kontrolle vergleicht ihre verbotenen Roots jetzt als feste
`Path`-Werte, einschließlich der aus festen Komponenten zusammengesetzten
Shared-Temporary-Root. Das Snapshot-Schreiben berechnet den kanonischen festen
Dateinamen unmittelbar vor der Senke neu und verwendet den atomaren
No-Follow-Output-Writer des Frameworks. Rules- und Case-Information-Outputs
verwenden denselben Writer erst nach erneuter Prüfung ihres aufgelösten Ziels
unter der erforderlichen Output-Root des Aufrufers. Die Implementierung
akzeptiert kein Analyzer-Finding, unterdrückt keine Regel und lockert keine
Path-Prüfung.

## Geänderte Dateien und Tests

- ci/provisioning/prepare-nginx-build.sh
- Makefile
- tests/security_regression/test_nginx_archive_digest.py
- ci/checks/catalog/no_crs_baseline.py
- ci/reporting/update-runtime-snapshot.py
- tests/runners/runner_core.py
- tests/runners/case_cli.py
- tests/no_crs/test_no_crs_baseline.py
- tests/security_regression/test_runtime_snapshot_sonar.py
- tests/security_regression/test_runner_core_output_containment.py
- dieses englische/deutsche Change-Record-Paar

Die NGINX-Regression schlug vor dem Patch fehl, weil Fake-Curl beide
HTTPS-Optionswerte verlangte; nach dem Patch bestand sie. Die nachfolgende
Containment-Kontrolle erhält die Zurückweisung von /tmp und nicht passenden
Snapshot-Zielen, schreibt nur zum neu berechneten festen Snapshot-Dateinamen,
verwirft Runner- und Case-Information-Ziele, die außerhalb ihrer erlaubten
Root aufgelöst werden (einschließlich externer Links), und erhält legitime
verschachtelte Schreibvorgänge.

## Befehle und Ergebnisse

Alle Tests verwendeten eine vorhandene Framework-virtuelle Umgebung sowie
task-eigene externe Build- und temporäre Roots. task_run_root bezeichnet unten
diese konfigurierte externe Root, nicht einen Repository-Pfad.

~~~text
C01 rtk run 'PYTHONNOUSERSITE=1 PYTHONPYCACHEPREFIX="$task_run_root/build/pycache" TMPDIR="$task_run_root/tmp" "$framework_python" -m unittest discover -s tests/security_regression -p test_nginx_archive_digest.py -v'
C02 rtk run 'PYTHONNOUSERSITE=1 PYTHON="$framework_python" BUILD_ROOT="$task_run_root/build" TMP_ROOT="$task_run_root/tmp" LOG_ROOT="$task_run_root/logs" make test-nginx-archive-digest'
C03 rtk run 'sh -n ci/provisioning/prepare-nginx-build.sh'
C04 rtk run 'curl --proto =https --proto-redir =https --version'
C05 rtk run 'PYTHONNOUSERSITE=1 PYTHONPYCACHEPREFIX="$task_run_root/build/no-crs/pycache" TMPDIR="$task_run_root/tmp/no-crs" "$framework_python" tests/no_crs/test_no_crs_baseline.py -v'
C06 rtk run 'PYTHONNOUSERSITE=1 PYTHONPYCACHEPREFIX="$task_run_root/build/runtime-snapshot/pycache" TMPDIR="$task_run_root/tmp/runtime-snapshot" "$framework_python" tests/security_regression/test_runtime_snapshot_sonar.py -v'
C07 rtk run 'PYTHONNOUSERSITE=1 PYTHONPYCACHEPREFIX="$task_run_root/build/runner-containment/pycache" TMPDIR="$task_run_root/tmp/runner-containment" "$framework_python" tests/security_regression/test_runner_core_output_containment.py -v'
C08 rtk curl 'https://sonarcloud.io/api/issues/search?organization=easton97-jens&componentKeys=Easton97-Jens_ModSecurity-test-Framework&branch=master&resolved=false&ps=100&p=1'
C09 rtk curl 'https://sonarcloud.io/api/qualitygates/project_status?projectKey=Easton97-Jens_ModSecurity-test-Framework&branch=master'
C10 rtk run 'PYTHONNOUSERSITE=1 PYTHON="$framework_python" PYTHONPYCACHEPREFIX="$task_run_root/build/lint/pycache" TMPDIR="$task_run_root/tmp/lint" BUILD_ROOT="$task_run_root/build/lint" TMP_ROOT="$task_run_root/tmp/lint" LOG_ROOT="$task_run_root/logs/lint" FRAMEWORK_ROOT="$task_worktree" CONNECTOR_ROOT="$task_worktree" OUTPUT_ROOT="$task_worktree" CI_ROOT="$task_worktree/ci" make lint'
C11 rtk run 'PYTHONNOUSERSITE=1 PYTHONPYCACHEPREFIX="$task_run_root/build/legacy-write-focused/pycache" TMPDIR="$task_run_root/tmp/legacy-write-focused" "$framework_python" -m unittest tests.no_crs.test_no_crs_baseline.NoCrsBaselineTest.test_run_directory_rejects_shared_tmp_root tests.security_regression.test_runtime_snapshot_sonar tests.security_regression.test_runner_core_output_containment -v'
C12 rtk run 'PYTHONNOUSERSITE=1 PYTHONPYCACHEPREFIX="$task_run_root/build/legacy-write-remediation/pycache" TMPDIR="$task_run_root/tmp/legacy-write-remediation" "$framework_python" -m py_compile ci/checks/catalog/no_crs_baseline.py ci/reporting/update-runtime-snapshot.py tests/runners/runner_core.py tests/runners/case_cli.py'
C13 rtk run 'PYTHONNOUSERSITE=1 PYTHON="$framework_python" PYTHONPYCACHEPREFIX="$task_run_root/build/lint-legacy-write/pycache" TMPDIR="$task_run_root/tmp/lint-legacy-write" BUILD_ROOT="$task_run_root/build/lint-legacy-write" TMP_ROOT="$task_run_root/tmp/lint-legacy-write" LOG_ROOT="$task_run_root/logs/lint-legacy-write" FRAMEWORK_ROOT="$task_worktree" CONNECTOR_ROOT="$task_worktree" OUTPUT_ROOT="$task_worktree" CI_ROOT="$task_worktree/ci" make lint'
C14 rtk run 'PYTHONNOUSERSITE=1 PYTHON="$framework_python" PYTHONPYCACHEPREFIX="$task_run_root/build/doc-final/pycache" TMPDIR="$task_run_root/tmp/doc-final" BUILD_ROOT="$task_run_root/build/doc-final" TMP_ROOT="$task_run_root/tmp/doc-final" LOG_ROOT="$task_run_root/logs/doc-final" FRAMEWORK_ROOT="$task_worktree" CONNECTOR_ROOT="$task_worktree" OUTPUT_ROOT="$task_worktree" CI_ROOT="$task_worktree/ci" make test-change-record-contract'
C15 rtk run 'PYTHONNOUSERSITE=1 PYTHON="$framework_python" PYTHONPYCACHEPREFIX="$task_run_root/build/doc-final/pycache" TMPDIR="$task_run_root/tmp/doc-final" BUILD_ROOT="$task_run_root/build/doc-final" TMP_ROOT="$task_run_root/tmp/doc-final" LOG_ROOT="$task_run_root/logs/doc-final" FRAMEWORK_ROOT="$task_worktree" CONNECTOR_ROOT="$task_worktree" OUTPUT_ROOT="$task_worktree" CI_ROOT="$task_worktree/ci" make check-documentation'
C16 rtk run 'PYTHONNOUSERSITE=1 PYTHON="$framework_python" PYTHONPYCACHEPREFIX="$task_run_root/build/lint-final/pycache" TMPDIR="$task_run_root/tmp/lint-final" BUILD_ROOT="$task_run_root/build/lint-final" TMP_ROOT="$task_run_root/tmp/lint-final" LOG_ROOT="$task_run_root/logs/lint-final" FRAMEWORK_ROOT="$task_worktree" CONNECTOR_ROOT="$task_worktree" OUTPUT_ROOT="$task_worktree" CI_ROOT="$task_worktree/ci" make lint'
~~~

| Befehls-ID | Exit-Code | Kurzes Ergebnis | Run-ID |
| --- | --- | --- | --- |
| C01 | 1 vor dem Patch; 0 nach dem Patch | Die alte Transportform schlug nur wegen fehlender Optionswerte fehl; danach bestanden 11 fokussierte Archivtests. | 20260720T161432Z-master-post36-sonar-remediation-0ff399e8 |
| C02 | 0 | Das native Make-Target führte 12 Archiv-/Redirect-Kontrollen erfolgreich aus. | 20260720T161432Z-master-post36-sonar-remediation-0ff399e8 |
| C03 | 0 | POSIX-Shell-Syntax bestanden. | 20260720T161432Z-master-post36-sonar-remediation-0ff399e8 |
| C04 | 0 | Das installierte Curl 8.18.0 akzeptierte beide Protokolloptionen. | 20260720T161432Z-master-post36-sonar-remediation-0ff399e8 |
| C05 | 0 | 75 No-CRS-Tests bestanden, einschließlich direkter /tmp-Zurückweisung. | 20260720T161432Z-master-post36-sonar-remediation-0ff399e8 |
| C06 | 0 | Fokussierte Snapshot-Containment-Kontrollen bestanden. | 20260720T161432Z-master-post36-sonar-remediation-0ff399e8 |
| C07 | 0 | Fokussierte Runner- und Case-Information-Containment-Kontrollen bestanden. | 20260720T161432Z-master-post36-sonar-remediation-0ff399e8 |
| C08 | 0 | Current master meldet 23 offene Zeilen: sechs Framework- und 17 reine MRTS-Metadatenzeilen. | 20260720T161432Z-master-post36-sonar-remediation-0ff399e8 |
| C09 | 0 | Das aktuelle Master-Quality-Gate ist ausschließlich wegen new_security_rating=5 bei Schwelle 1 ERROR. | 20260720T161432Z-master-post36-sonar-remediation-0ff399e8 |
| C10 | 0 | Ersatz-Full-Lint bestand mit jeder Framework-/Connector-/Output-Root explizit am isolierten Task-Worktree; auch das abschließende `git diff --check` bestand. | 20260720T161432Z-master-post36-sonar-remediation-0ff399e8 |
| C11 | 0 | 14 fokussierte Kontrollen bestanden: direkte Shared-Temporary-Root-Zurückweisung, fünf Snapshot-Kontrollen einschließlich Escape-Link-Zurückweisung und acht Runner-/Case-Containment-Kontrollen einschließlich legitimer verschachtelter Writes und externer-Link-Target-Zurückweisung. | 20260720T161432Z-master-post36-sonar-remediation-0ff399e8 |
| C12 | 0 | Python-Kompilierung bestand für alle vier remediierten Implementierungsmodule. | 20260720T161432Z-master-post36-sonar-remediation-0ff399e8 |
| C13 | 0 | Post-Remediation-Full-Lint bestand mit explizit isolierten Framework-, Connector-, Output-, Build-, Temporary- und Log-Roots; das abschließende `git diff --check` bestand. | 20260720T161432Z-master-post36-sonar-remediation-0ff399e8 |
| C14 | 0 | Der finale Change-Record-Vertrag bestand alle vier Tests mit explizit isolierten Projekt- und Storage-Roots. | 20260720T161432Z-master-post36-sonar-remediation-0ff399e8 |
| C15 | 0 | Die finalen Dokumentationschecks bestanden Links, Variablen, Repository-Pfade und Change-Record-Validierung mit explizit isolierten Projekt- und Storage-Roots. | 20260720T161432Z-master-post36-sonar-remediation-0ff399e8 |
| C16 | 0 | Der finale Full-Lint bestand nach der Escaping-Snapshot-Link-Regression und den finalen Dokumentationsedits mit jeder Projekt- und Storage-Root explizit isoliert; `git diff --check` bestand. | 20260720T161432Z-master-post36-sonar-remediation-0ff399e8 |

## Sicherheitsauswirkung

Die Behebung verhindert, dass eine HTTPS-basierte NGINX-Provisionierungsanfrage
einem Redirect zu HTTP oder einem Nicht-HTTPS-Protokoll folgt. Die ursprünglichen
Metadaten- und Release-Asset-Pfade bestanden nach dem Patch die legitime
HTTPS-Kontrolle; der HTTP/3-TLS-Aufruf wird durch denselben Vertrag abgedeckt.

Dies ist eine Protokoll-Downgrade-Kontrolle. Sie beansprucht keine
Redirect-Host-Allowlist oder allgemeine SSRF-Behebung. Die bestehende
Pinned-Digest-Verifikation schützt das ausgewählte Archiv weiterhin vor der
Extraktion.

Die frische SonarCloud-Abfrage behielt fünf ältere
Framework-Sicherheitssignale:

| Key | Regel | Gemeldete Senke | Aktuelle Source-/Kontroll-Disposition |
| --- | --- | --- | --- |
| AZ9cRqtu1JCbMyYXCAue | python:S5443 | ci/checks/catalog/no_crs_baseline.py:1746 | /tmp, öffentliche Parents, Symlink-Komponenten und Source-Checkouts bleiben verworfen; feste `Path`-Komponenten machen die Domain der verbotenen Roots explizit. |
| AZ7Wh-x6WJ9AQTOMyhFJ | pythonsecurity:S8707 | ci/reporting/update-runtime-snapshot.py:72 | Der Writer berechnet den kanonischen festen Snapshot-Pfad unmittelbar vor der Senke neu. |
| AZ5Q3NAAoI4Cm-ZmWjGX | pythonsecurity:S2083 | ci/reporting/update-runtime-snapshot.py:72 | Der feste Snapshot-Dateiname wird atomar durch den No-Follow-Output-Writer des Frameworks ersetzt. |
| AZ55dzzC6nhd5cS8C48e | pythonsecurity:S2083 | tests/runners/runner_core.py:636 | Ein aufgelöstes Ziel wird unter der erforderlichen Root erneut geprüft und dann ohne Link-Folge atomar geschrieben. |
| AZ6jf1K_DIaptS4_Hf5n | pythonsecurity:S2083 | tests/runners/case_cli.py:424 | case-info übergibt nur ein unter der erforderlichen Root enthaltenes Ziel an denselben atomaren Writer. |

Offizielle Flows der letzten vier Zeilen zeigen tainted Inhalt, der eine
Write-API erreicht, nicht eine nachgewiesene Umgehung von
Path-Containment-Kontrollen. Die fokussierten Source-Level-Behebungen warten
auf eine neue Exact-PR-Head-Analyse; es wurde keine False-Positive-,
Unterdrückungs- oder Accepted-Issue-Aktion ausgeführt.

## Dokumentation und Runtime-Evidenz

Dieses englische/deutsche Paar dokumentiert den Framework-only-Patch. Lokale
Finding-Records halten das Framework-Inventar, die 17 externen
MRTS-Metadatenzeilen und den separaten Evidence-Gap-Kandidaten fest. Es wurde
kein Connector-Runtime-, Netzwerkdownload- oder MRTS-Quelltest erhoben.

Die MRTS-Zeilen sind ausschließlich aus offiziellen Metadaten dokumentiert:

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
| AZ84XDED2YUGB8FZMhla | pythonsecurity:S8707 | tools/MRTS/mrts/mrts.py:83 |
| AZ84XDED2YUGB8FZMhlX | python:S1940 | tools/MRTS/mrts/mrts.py:93 |

## Nicht ausgeführte Prüfungen

Es wurden keine Connector-Runtime-Matrix, kein externer Archivdownload, keine
MRTS-Quellinspektion, kein MRTS-Test, keine Default-Branch-Integration und kein
Merge ausgeführt. Ein früherer Lint-Versuch erbte Parent-Root-Variablen und
wurde bewusst unterbrochen; er ist als `FND-CROSS-0002` festgehalten und gilt
nicht als bestandene Validierung. C10 ist das Ersatzresultat mit expliziten
isolierten Roots. Eine neue Exact-Head-SonarCloud-Analyse steht nach normaler
Task-Branch-Auslieferung aus; die aktuelle Master-Analyse kann diese nicht
integrierte Änderung nicht bewerten.

## Einschränkungen und Restrisiko

Der aktuelle Master bleibt rot, bis die ungemergten Framework-Änderungen
integriert und analysiert sind; die 17 extern verantworteten MRTS-
Metadatenzeilen bleiben reine Dokumentation. Eine Current-Head-PR-Analyse ist
noch erforderlich, um die fünf Source-Behebungen zu verifizieren, und eine
Post-Delivery-Master-Verifikation braucht separate Integrationsautorisierung;
dieser Task hat keine Merge-Berechtigung. Der
festgehaltene unterbrochene Lint-Boundary-Incident kann nicht rückwirkend
entfernt werden, obwohl sein Ersatz mit expliziten Roots bestand; der
übergreifende Task kann daher keine vollständig saubere
Cross-Repository-Boundary-Historie beanspruchen.

## Finaler Diff- und Review-Status

Fokussierte Post-Remediation-Tests, Python-Kompilierung, der isolierte Full-
Lint und `git diff --check` bestanden. Aus stehen finaler Scoped-/Security-
Review, normaler Follow-up-Commit und Push zum bestehenden Draft-PR sowie
Exact-Head-Remote-Readback. Es ist keine Parent-, Gitlink-, MRTS-Quell- oder
Analyzer-Konfigurationsänderung enthalten.
