# Change Record: Invarianz der Common-Version-Post-Apply-Test-Fixture beheben

**Sprache:** [English](20260809-01-fix-common-version-post-apply-test-invariance.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260809-01-fix-common-version-post-apply-test-invariance |
| UTC-Datum | 2026-08-09 |
| Framework-Basisrevision | c71e15db7b7517b237add9fa09b3493e7bc93627 |
| Issue oder Pull Request | Zum Zeitpunkt der Record-Erstellung existiert kein Pull Request. Ein Framework-Draft-Pull-Request ist nach den finalen lokalen Prüfungen durch den Nutzer autorisiert; dieser Record autorisiert niemals einen Merge. |

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

## Betroffene Komponenten und Sicherheitsgrenzen

Dies ist eine Framework-Test-Fixture- und Test-Hilfsänderung unter
tests/security_regression/. Sie ändert weder ci/lib/common.sh, noch den
Updater, Workflows, Veröffentlichungsrechte, Connector-Laufzeitverhalten,
Parent, MRTS oder einen Gitlink.

## Akzeptanzkriterien

- Eine frische Fixture wendet ein genehmigtes automatisches Update an und
  validiert es erneut.
- Ein bereits angewendetes Tupel ist ein semantischer No-op.
- Das HAProxy-Tupel aus Lauf #17 und ein synthetisches zukünftiges Tupel
  erhalten beide die fokussierte Publisher-Suite.
- Manuelle Provenance-Zeilen bleiben nach dem automatischen Fixture-Update
  byte-genau erhalten.
- Keine Produktversions-Pins oder Workflow-Verhalten ändern sich.

## Untersuchte Alternativen

Das Beibehalten kanonischer Pin-Fixtures erhält die falsche Kopplung. Das
Aufweichen der Post-Apply-Assertions würde einen echten Updater-Regressionfehler
verbergen. Das Ändern des Publishers, Updaters, Workflows oder genehmigter
Produkt-Pins überschreitet die Framework-Testgrenze. Der gewählte Ansatz
verwendet temporäre Fixtures mit synthetischen genehmigten Tupeln.

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

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| rtk proxy env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.security_regression.test_common_versions_sonar_provenance tests.security_regression.test_nginx_release_provenance tests.security_regression.test_crs_git_ref_provenance tests.security_regression.test_modsecurity_v3_git_ref_provenance tests.security_regression.test_apr_util_provenance -v | 0 | 65 fokussierte Publisher- und Provenance-Tests bestanden auf dem formatierten Endstand, einschließlich der Post-Apply-Fälle aus Lauf #17 und mit synthetischer Zukunftsversion. | Task-eigenes externes Framework-Worktree |
| rtk proxy env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.security_regression.test_pcre2_archive_digest tests.security_regression.test_nginx_archive_digest -v | 0 | 22 Archiv-/Release-Provenance-Tests bestanden. | Task-eigenes externes Framework-Worktree |
| rtk proxy python3 -m py_compile tests/security_regression/*.py | 0 | Alle acht bearbeiteten Testmodule kompilierten. | Task-eigenes externes Framework-Worktree |
| rtk proxy ruff check and ruff format --check for the eight changed modules | 0 | Ruff-Lint und -Formatierung akzeptierten den finalen Umfang geänderter Dateien. | SHA-256-gesperrtes tasklokales Tool-Verzeichnis |
| rtk proxy make test-ci-security-contract test-workflow-action-pins test-workflow-security-contract check-github-actions-workflows | 0 | CI-Security-, Action-Pin-, Workflow-Security- sowie Workflow-Pin-/Permission-Verträge bestanden. | Task-eigenes externes Framework-Worktree |
| rtk proxy make check-documentation test-change-record-contract check-bilingual-docs check-doc-links | 0 | EN/DE-Dokumentation, Links und Change-Record-Verträge bestanden. | Task-eigenes externes Framework-Worktree |
| rtk proxy make lint | 0 | Die vollständige native Lint-Matrix bestand, einschließlich Shell-Syntax-, Provenance-, CI-Security-, Workflow-, Dokumentations- und Whitespace-Prüfungen. | Task-eigenes externes Framework-Worktree |
| rtk proxy actionlint; rtk proxy zizmor --offline; rtk proxy shellcheck -x ci/lib/common.sh | 0 | Actionlint, zizmor mit repositorykonfigurierten Suppressions und relevanter Common-Helper-ShellCheck bestanden. | SHA-256-gesperrtes tasklokales Tool-Verzeichnis |
| rtk proxy git diff --check | 0 | Keine Whitespace-Fehler im Framework-Source-Diff. | Task-eigenes externes Framework-Worktree |
| rtk proxy python3 finalize_scan_contract.py --scan-dir security-scan-final-20260809T064127Z --source-root Framework-worktree | 0 | Der vollständige finale zwölfpfadige diff-bezogene Security-Scan wurde mit null berichtspflichtigen Findings versiegelt. | Task-eigenes externes Security-Scan-Evidenzverzeichnis |

## Sicherheitsauswirkung

Es wurde keine Security-Remediation durchgeführt; diese Änderung stärkt die
Invarianz der Test-Fixtures. Sie erhält die fail-closed Provenance-, Prüfsummen-,
Immutable-Git-, Post-Write-Revalidierungs- und Rollback-Kontrollen, die die
Tests ausüben. Die vollständige diff-bezogene Sicherheitsprüfung fand kein
berichtspflichtiges patch-verankertes Problem.

## Dokumentation und Runtime-Evidenz

Dieses englisch/deutsche Change-Record-Paar und seine Indizes werden
aktualisiert. Lauf 31292884310 ist gehostete Fehler-Evidenz: Der Kandidat war
gültig, aber die Post-Apply-Fixture-Kopplung ließ den Publisher-Testschritt
fehlschlagen. Es wurde keine Connector- oder Produkt-Laufzeit-Evidenz erhoben,
und in diesem Record-Stadium existiert kein gehostetes Exact-Head-Ergebnis.

## Nicht ausgeführte Prüfungen

Die native Make-/Dokumentations-/Lint-Matrix ist abgeschlossen. Pyright ist
lokal blockiert, weil sein hash-gesperrtes Paket nicht verfügbares node benötigt;
es wurde kein globales Tool installiert. Ein vollständiger Worktree-ShellCheck-
Lauf hat bestehende Findings außerhalb dieses testbezogenen Umfangs, daher ist
die fokussierte Produktions-Common-Hilfe die relevante Kontrollprüfung.
Gehostete Exact-Head-Prüfungen, Sonar-Analyse und Review-Status existieren erst,
wenn der nutzerautorisierte Draft-Pull-Request geöffnet ist.

## Einschränkungen und Restrisiko

Die Hilfe ist vertrauenswürdiger ausschließlich testbezogener Code und schreibt
an aktuellen Aufrufstellen nur temporäre Fixtures. Eine Überführung in einen
Produkt-Eingabepfad würde Validierung von Ersatzwerten und eine
Containment-Prüfung benötigen. Gehostete Validierung bleibt erforderlich, bevor
ein Draft-Pull-Request als verifiziert gilt.

## Finaler Diff- und Review-Status

Zum Zeitpunkt der Record-Erstellung ist die Framework-Arbeit lokal und nicht
committet. Der Source-Umfang ist Testcode und dieser Change Record; Whitespace-
Review, fokussiertes Ruff, zwei fokussierte Regression-Suiten und eine
versiegelte vollständige Security-Diff-Prüfung sind oben erfasst. Es gab noch
keine Parent-, MRTS-, Gitlink-, Workflow-, Produkt-Pin-, Push-, Pull-Request-
oder Merge-Aktion.
