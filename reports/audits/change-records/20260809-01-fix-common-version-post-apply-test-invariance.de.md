# Change Record: Invarianz der Common-Version-Post-Apply-Test-Fixture beheben

**Sprache:** [English](20260809-01-fix-common-version-post-apply-test-invariance.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260809-01-fix-common-version-post-apply-test-invariance |
| UTC-Datum | 2026-08-09 |
| Framework-Basisrevision | c71e15db7b7517b237add9fa09b3493e7bc93627 |
| Issue oder Pull Request | Framework-Draft-PR [#70](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/70) auf dem task-eigenen Branch `fix/common-version-post-apply-test-invariance`. Dieser Record dokumentiert einen nutzerautorisierten Folge-Refactor; er autorisiert niemals einen Merge. |

## Motivation und Problemstellung

Der Common-Version-Publisher-Lauf #17 bestand Resolver- und
Candidate-Validation-Jobs, wendete HAProxy 3.2.21 auf 3.2.22 mit dem
genehmigten Digest fachlich korrekt an und schlug danach im Publish-Job-Schritt
„Independently revalidate and apply the candidate“ beim erneuten Ausführen der
Regressionstests fehl. Mehrere Fixtures lasen veränderliche kanonische Pins aus
ci/lib/common.sh und kodierten 3.2.22 als zwingend neues Ziel fest. Der
Validator startet mit einem nicht angewendeten Kandidaten, während der Publisher
den bereits mutierten Kandidaten erneut validiert; korrekt idempotentes
plan_update() liefert daher None. Dadurch wurde ein gültiger Kandidat zu einem
falschen Post-Apply-Fehler.

Die Folgeanalyse von SonarQube Cloud für den PR bestand das Quality Gate ohne
neue Issues oder Hotspots, meldete jedoch 20 neue Duplikatzeilen (1,876...%).
Die zwei exakten Duplikatblöcke lagen im Common-Version-Provenance-Test,
während das benannte Workflow-Tool-Updater/Test-Paar außerdem die kanonische
Kandidatenserialisierung und die Konstruktion offizieller Release-URLs
wiederholte. Der Nutzer autorisierte einen kleinen verhaltenserhaltenden
Refactor aller drei task-eigenen Dateien anstelle einer Metrikunterdrückung,
eines Ausschlusses oder einer bloßen Änderung des Nenners.

## Betroffene Komponenten und Sicherheitsgrenzen

Dies ist ein Framework-Test-Fixture/Test-Hilfs- und CI-Updater-Refactor unter
tests/security_regression/, tests/ci_security/ und ci/tools/. Er ändert weder
ci/lib/common.sh, noch Workflows, Veröffentlichungsrechte,
Connector-Laufzeitverhalten, Parent, MRTS oder einen Gitlink. Die
Sicherheitsgrenze des CI-Updaters bleibt die aus dem geprüften Lock abgeleitete
GitHub-Identität, kanonische Kandidatenbytes und fail-closed RUNNER_TEMP-
Dateikontrollen.

## Akzeptanzkriterien

- Eine frische Fixture wendet ein genehmigtes automatisches Update an und
  validiert es erneut.
- Ein bereits angewendetes Tupel ist ein semantischer No-op.
- Das HAProxy-Tupel aus Lauf #17 und ein synthetisches zukünftiges Tupel
  erhalten beide die fokussierte Publisher-Suite.
- Manuelle Provenance-Zeilen bleiben nach dem automatischen Fixture-Update
  byte-genau erhalten.
- Keine Produktversions-Pins oder Workflow-Verhalten ändern sich.
- Die tatsächlichen SonarQube-Cloud-Duplikatblöcke werden durch eine private
  Test-Setup-Hilfe ersetzt; es wird keine Analyseunterdrückung, kein Ausschluss
  und keine Metrikauffüllung verwendet.
- Kanonische Kandidatenbytes sowie offizielle Release-/Asset-URLs haben jeweils
  eine Konstruktionsquelle und erhalten ihre Digest-, Base64-, Lock- und
  Dateiausgabeverträge.

## Untersuchte Alternativen

Das Beibehalten kanonischer Pin-Fixtures erhält die falsche Kopplung. Das
Aufweichen der Post-Apply-Assertions würde einen echten Updater-Regressionfehler
verbergen. Das Ändern des Publishers, Updaters, Workflows oder genehmigter
Produkt-Pins überschreitet die Framework-Testgrenze. Der gewählte Ansatz
verwendet temporäre Fixtures mit synthetischen genehmigten Tupeln.

Eine SonarQube-Unterdrückung, ein Ausschluss oder nicht duplizierter, aber
unzusammenhängender Code würde die beobachtete Duplikation verdecken oder nur
verdünnen. Die Zusammenführung der Action- und Tool-Kandidatenpfade könnte ihre
unterschiedlichen Provenance-Kontrollen aufweichen. Die gewählten Hilfen
zentralisieren nur exakte gemeinsame Darstellungen und erhalten getrennte
Action-/Tool- sowie Sink-Time-Validierungspfade.

## Implementierungsentscheidung

Eine ausschließlich testbezogene Hilfe ersetzt strukturell genau eine
unterstützte common.sh-Zuweisung und lehnt fehlende oder mehrdeutige Zuweisungen
ab. Provenance-Tests bauen temporäre Framework-Wurzeln mit synthetischen
genehmigten Tupeln, während echte Produktionsskripte als zu testender Code
erhalten bleiben. Die Common-Version-Suite ergänzt Post-Apply-Idempotenz- und
wegwerfbare Child-Suite-Prüfungen für das dokumentierte Tupel aus Lauf #17 und
ein zukünftiges synthetisches Tupel. Archivtests verwenden paketqualifizierte
Test-Hilfsimporte, sodass vollständig qualifizierte unittest-Ausführung nicht
von durch Aufrufer gesetztem PYTHONPATH abhängt.

Der Folge-Refactor verwendet reine `release_url`-/`release_asset_url`-Hilfen
und eine kanonische UTF-8-Kandidatenbyte-Hilfe im Updater; Base64, SHA-256 und
die exklusive `0600`-Kandidatendatei nutzen damit dieselben Bytes. Die
zugehörigen Tests verwenden den bestehenden Kandidaten-Builder für beide
Gruppen und prüfen diese Byteverträge. Der Common-Version-Test besitzt das
wiederholte Safe/Manual-Setup nun in einer temporären Kontext-Hilfe, während
jeder Verbraucher seine getrennten Provenance-, Idempotenz- und
Quellbestandserhaltungs-Assertions behält.

## Geänderte Dateien und Tests

- tests/security_regression/common_version_fixture_support.py fügt den
  testbezogenen Single-Assignment-Fixture-Writer hinzu.
- test_common_versions_sonar_provenance.py isoliert HAProxy-Fixtures und fügt
  Post-Apply-/No-op-Invarianzabdeckung hinzu.
- test_nginx_release_provenance.py, test_crs_git_ref_provenance.py,
  test_modsecurity_v3_git_ref_provenance.py, test_apr_util_provenance.py,
  test_pcre2_archive_digest.py und test_nginx_archive_digest.py verwenden
  synthetische genehmigte Tupel oder strukturelle Ersetzung.
- Dieser gepaarte Change Record und seine Indizes dokumentieren den
  ausschließlich Framework-bezogenen Umfang.
- ci/tools/update-workflow-tools.py zentralisiert vertrauenswürdige
  Release-/Asset-URL- und kanonische Kandidatenbyte-Konstruktion, ohne die
  Updater-Autorität zu ändern.
- tests/ci_security/test_update_workflow_tools.py zentralisiert
  Kandidatengerüste und ergänzt Tests für exakte Bytes, Base64, Digest und
  Kandidatendateien.
- test_common_versions_sonar_provenance.py ersetzt die zwei SonarQube-Cloud-
  Duplikatblöcke durch eine private Safe/Manual-Application-Kontext-Hilfe.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| rtk proxy env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.security_regression.test_common_versions_sonar_provenance tests.security_regression.test_nginx_release_provenance tests.security_regression.test_crs_git_ref_provenance tests.security_regression.test_modsecurity_v3_git_ref_provenance tests.security_regression.test_apr_util_provenance -v | 0 | 65 fokussierte Publisher- und Provenance-Tests bestanden auf dem formatierten Endstand, einschließlich der Post-Apply-Fälle aus Lauf #17 und mit synthetischer Zukunftsversion. | Task-eigenes externes Framework-Worktree |
| rtk proxy env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.security_regression.test_pcre2_archive_digest tests.security_regression.test_nginx_archive_digest -v | 0 | 22 Archiv-/Release-Provenance-Tests bestanden. | Task-eigenes externes Framework-Worktree |
| rtk proxy python3 -m py_compile tests/security_regression/*.py | 0 | Alle acht bearbeiteten Testmodule kompilierten. | Task-eigenes externes Framework-Worktree |
| rtk proxy ruff check and ruff format --check for the eight changed modules | 0 | Ruff-Lint und -Formatierung akzeptierten den finalen Umfang geänderter Dateien. | SHA-256-gesperrtes tasklokales Tool-Verzeichnis |
| rtk proxy make test-ci-security-contract test-workflow-action-pins test-workflow-security-contract check-github-actions-workflows | 0 | CI-Security-, Action-Pin-, Workflow-Security- sowie Workflow-Pin-/Permission-Verträge bestanden. | Task-eigenes externes Framework-Worktree |
| rtk proxy make check-documentation test-change-record-contract check-bilingual-docs check-doc-links | 0 | EN/DE-Dokumentation, Links und Change-Record-Verträge bestanden. | Task-eigenes externes Framework-Worktree |
| rtk proxy make lint | 0 | Die finale native Lint-Matrix bestand nach dem Folge-Refactor, einschließlich Shell-Syntax-, Provenance-, CI-Security-, Workflow-, Dokumentations- und Whitespace-Prüfungen. | Task-eigenes externes Framework-Worktree |
| rtk proxy actionlint; rtk proxy zizmor --offline; rtk proxy shellcheck -x ci/lib/common.sh | 0 | Actionlint, zizmor mit repositorykonfigurierten Suppressions und relevanter Common-Helper-ShellCheck bestanden. | SHA-256-gesperrtes tasklokales Tool-Verzeichnis |
| rtk proxy git diff --check | 0 | Keine Whitespace-Fehler im Framework-Source-Diff. | Task-eigenes externes Framework-Worktree |
| rtk proxy python3 finalize_scan_contract.py --scan-dir security-scan-final-20260809T064127Z --source-root Framework-worktree | 0 | Der vollständige finale zwölfpfadige diff-bezogene Security-Scan wurde mit null berichtspflichtigen Findings versiegelt. | Task-eigenes externes Security-Scan-Evidenzverzeichnis |
| rtk proxy env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.ci_security.test_update_workflow_tools -v | 0 | 26 Updater-Regressionstests bestanden nach dem kanonischen URL-/Byte-Refactor. | Task-eigenes externes Framework-Worktree |
| rtk proxy env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.security_regression.test_common_versions_sonar_provenance.CommonVersionProvenanceTests.test_safe_partial_update_preserves_all_manual_provenance_lines_and_revalidates tests.security_regression.test_common_versions_sonar_provenance.CommonVersionProvenanceTests.test_common_version_regressions_are_invariant_after_candidate_application -v | 0 | Beide Verbraucher des extrahierten Safe/Manual-Setups bestanden. | Task-eigenes externes Framework-Worktree |
| rtk proxy env COMMON_VERSION_POST_APPLY_META_CHILD=1 PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.security_regression.test_common_versions_sonar_provenance -v | 0 | 29 Common-Version-Tests bestanden; der rekursive Publisher-State-Test wurde durch seine dokumentierte Child-Guard absichtlich übersprungen. | Task-eigenes externes Framework-Worktree |
| rtk proxy env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.security_regression.test_common_versions_sonar_provenance.CommonVersionProvenanceTests.test_publisher_focused_suite_accepts_real_and_synthetic_applied_tuples -v | 0 | Der isolierte rekursive Publisher-State-Test bestand in 447.165s für das Run-#17- und das synthetische Zukunftstupel. | Task-eigenes externes Framework-Worktree |
| rtk proxy python3 -m py_compile ci/tools/update-workflow-tools.py tests/ci_security/test_update_workflow_tools.py tests/security_regression/test_common_versions_sonar_provenance.py | 0 | Alle Python-Dateien des Folge-Refactors kompilierten. | Task-eigenes externes Validierungs-Root |

## Sicherheitsauswirkung

Es wurde keine Security-Remediation durchgeführt; diese Änderung stärkt die
Invarianz der Test-Fixtures. Sie erhält die fail-closed Provenance-, Prüfsummen-,
Immutable-Git-, Post-Write-Revalidierungs- und Rollback-Kontrollen, die die
Tests ausüben. Die vollständige diff-bezogene Sicherheitsprüfung fand kein
berichtspflichtiges patch-verankertes Problem.

Die fokussierten Security-Reviews des Folge-Refactors fanden keine Regression:
URL-Hilfen werden weiter durch aus dem Lock abgeleitete Identitäten gespeist,
und der gemeinsame Common-Version-Kontext erhält HAProxy-only-, Manual-
Provenance-, temporäre Containment-, Revalidierungs-, Idempotenz- und
Quellbestandserhaltungs-Verträge.

## Dokumentation und Runtime-Evidenz

Dieses englisch/deutsche Change-Record-Paar und seine Indizes sind
aktualisiert. Lauf 31292884310 ist gehostete Fehler-Evidenz: Der Kandidat war
gültig, aber die Post-Apply-Fixture-Kopplung ließ den Publisher-Testschritt
fehlschlagen. Für den bisherigen PR-#70-Head bestand SonarQube Cloud mit null
neuen Issues und null Security Hotspots, meldete aber 20 neue duplizierte
Zeilen. Der
aktuelle Follow-up-Head benötigt vor Merge eine neue Exact-Head-Sonar-Analyse.
Es wurde keine Connector- oder Produkt-Laufzeit-Evidenz erhoben.

## Nicht ausgeführte Prüfungen

Die finale native Make-/Dokumentations-/Lint-Matrix bestand für den
Folge-Refactor. Pyright ist lokal blockiert, weil sein hash-gesperrtes Paket
nicht verfügbares node benötigt; es wurde kein globales Tool installiert. Ein
vollständiger Worktree-ShellCheck-Lauf hat bestehende Findings außerhalb dieses
testbezogenen Umfangs, daher bleiben die fokussierten Kontrollen relevant.
Gehostete Exact-Head-Prüfungen, Sonar-Analyse und Review-Status bleiben für den
neuen PR-Head erforderlich.

## Einschränkungen und Restrisiko

Die Hilfe ist vertrauenswürdiger ausschließlich testbezogener Code und schreibt
an aktuellen Aufrufstellen nur temporäre Fixtures. Eine Überführung in einen
Produkt-Eingabepfad würde Validierung von Ersatzwerten und eine
Containment-Prüfung benötigen. Gehostete Validierung bleibt erforderlich, bevor
ein Draft-Pull-Request als verifiziert gilt.

## Finaler Diff- und Review-Status

Der Framework-PR existiert, aber der nutzerautorisierte Entdoppelungs-Follow-up
ist noch lokal. Der finale Source-Umfang enthält die ursprüngliche
Post-Apply-Fixture-Reparatur, drei fokussierte Refactor-Dateien und diesen
gepaarten Record; es gibt keine Parent-, MRTS-, Gitlink-, Workflow- oder
Produkt-Pin-Änderung. Die finale native Lint-Matrix und der fokussierte
Security-Review bestanden. Commit, Push, aktuelle gehostete Prüfungen,
Sonar-Nachweis und die autorisierte Squash-Integration stehen noch aus.
