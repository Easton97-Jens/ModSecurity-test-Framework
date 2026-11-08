# Folgekorrektur für Sonar-Parser und Ausnahmetest

**Sprache:** Deutsch | [English](20261108-03-sonar-parser-exception-followup.md)

## Identität

| Field | Value |
| --- | --- |
| Change-ID | 20261108-03-sonar-parser-exception-followup |
| UTC | 2026-11-08 |

Framework-Basis: `2fefbf6e91bbd910c7447f80fe84c54d3f295f49`.
Umfang: lokale Quellvorbereitung für [Draft-PR #169](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/169).

## Motivation und Problemstellung

Die gehostete Analyse der Basisrevision meldete zwei OPEN-Befunde. Ihr bestandenes Gate belegte keine vollständige Parserabdeckung: Die Common-Shellwarnung rückte zu einem zweiten oktalen Ausdruck vor. Diese Quellfolgekorrekturen betreffen die Darstellung der Rechteprüfung und die Isolierung des erwarteten Ausnahmeaufrufs.

## Betroffene Komponenten und Sicherheitsgrenzen

`ci/lib/common.sh`, `connector_suite/modsecurity_connector_tests/test_ci_security_workflows.py` und `tests/ci_security/test_five_connector_with_crs_no_mrts_contract.py` gehören dem Framework, ebenso native Inventar-/Archiv-Postimages und dieses Dokumentenpaar. Die Vertrauensprüfungen für Host-Git und neue private Verzeichnisse erhalten ihre Eigentümer-, Dateityp- und Rechtegrenzen. Parent-Orchestrierung, Auslieferung und Gitlink-Aktualisierungen bleiben separat; keine MRTS-Produkt- oder Testquelle wird geändert.

## Akzeptanzkriterien

Die genauen Rechteentscheidungen der Masken 022 und 077 sowie Status 77 für verworfene Eingaben erhalten. Gültige Workflow-Expansion außerhalb der Ausnahmeprüfung ausführen und manipulierten SHA verwerfen. Vor Befund- oder Parserabschluss sind Regressionsergebnisse des aktuellen Quellstands und ein frischer gehosteter Readback erforderlich.

## Untersuchte Alternativen

Rechteprüfungen zu entfernen, akzeptierte Modi zu erweitern, Regeln zu unterdrücken, den Analyseumfang zu verringern oder das Gate abzuschwächen würde den Vertrag entwerten. Mehrere potenziell scheiternde Aufrufe in den erwarteten Ausnahmeblock zu verschieben würde die Negativkontrolle schwächen.

## Implementierungsentscheidung

Validierte Oktalziffermuster ersetzen beide Rechtemasken, mit expliziten No-op-Defaultzweigen. Die Maske 022 verwirft Schreibbits der Gruppen-/Anderenziffern; 077 verwirft jeglichen Gruppen-/Anderenzugriff. Mutationseingaben werden vor der Assertion berechnet. Im erwarteten `WorkflowSourceError`-Block bleibt allein `expand_workflow_source`, nach einer getrennten gültigen Expansion.


Der erste native Quick-Check mit Python 3.15.2 scheiterte in zwei Methoden, die dieselbe Writerless-FIFO-Kontrolle ausführen. Der gemessene Spawn-/Importstart dauerte 2,49–2,62 Sekunden und überschritt die vor dem Bootstrap gestartete Zwei-Sekunden-Bereitschaftsuhr. Der Reader selbst verwarf das FIFO nichtblockierend. Eine strikte erste Meldung `bootstrap-ready` trennt jetzt den auf zehn Sekunden begrenzten Start von unveränderten zwei Sekunden Bereitschaft, einer Sekunde Ergebnis und einer Sekunde Join. Read-only-/Nonblocking-Flags, Ablehnung nicht regulärer Dateien, natürlicher Child-Exit null für PASS und Cleanup bleiben vorgeschrieben. Fehlender, falscher oder gescheiterter Bootstrap ist FAIL.

## Geänderte Dateien und Tests

Die geprüften Quell-SHA256 lauten `404d38eed61418f8d5c096ed4539c9a80c35af2cf84eccd7ee4a057235a43779` für Common und `f6230a3f205c4f33f3900461bec50751d467c866f4dd3ca60a8ad7dc3f62e66c` für den Workflow-Test. Der FIFO-Testquell-SHA256 lautet `0bdeeedbfaa6a7f5a6aad47eb4b2d73fa4c2618855774e5e77a6358bb9eb104e`. Spätere Änderungen erfordern erneute Bindung und Prüfung.

## Befehle und Ergebnisse

Unabhängige RTK-Prüfungen bestanden 18.760 Erwartungen: zwei Masken × Dash/Bash × 4.680 gültige und zehn ungültige Modi gegen eine Python-Bitmaskenreferenz. Acht native Prüfausführungen erfassten tatsächliche Quellsyntax und die exakten Host-Git-/Privatverzeichnisfunktionen, einschließlich Ablehnung vorhandener Verzeichnisse, regulärer Dateien und Symlinks.

Die Framework-eigene Python-Umgebung bestand `modsecurity_connector_tests.test_ci_security_workflows.CiSecurityWorkflowTest.test_all_remote_actions_are_immutable_sha_pins` einschließlich gültiger und manipulierter SHA-Kontrollen. Die AST-Prüfung bestätigte eine Anweisung und einen Aufruf im relevanten Ausnahmeblock. Die gesamte Workflow-Klasse bestand in der isolierten Framework-Umgebung mit Python 3.15.2: 48 Methoden und 222 Subtest-Ausführungen in 14 Methoden, ohne Failures, Errors oder Skips. Parent-Arbeitsprojektionen wurden vom nativen Publisher für die tatsächlich veröffentlichte Framework-Basis erzeugt. Frühere Aufrufe mit veralteter Revisionsvariable beziehungsweise älteren Projektionen bleiben als ungültige Kontextdiagnosen erhalten; dadurch werden weder Tests geändert noch ein endgültiges eingechecktes Paar zertifiziert.

Der native CRS-Vertragsblock mit 29 Methoden bestand unter Python 3.15.2. Drei echte Kaltstartkontrollen bestanden mit natürlichem Child-Exit null; alle sechs Fehlerkontrollen verwarfen blockierendes Read-only, Read-write, falschen/fehlenden Bootstrap, Bootstrap-Ausnahme und Bootstrap-Timeout mit Bereinigung der Kinder/FIFOs. Der frühere vollständige Quick-Check-Fehler und die korrigierte Nonzero-Exit-Erwartung des privaten Harness bleiben dokumentiert; der später bestandene fokussierte Lauf überschreibt sie nicht.

Der native Inventarerzeuger änderte genau zwei vorhandene Quellbindungs-Hashes. Der Archiverzeuger änderte nur seinen Inventarhash und zwei Quellhashes. Alle weiteren Felder und Identitäten bleiben gleich: 80 Selektoren, 100 Standardfälle, 8.245 On-demand-Definitionen und 69 erhaltene native Funktionen. Erzeugung und anschließende Prüfungen endeten mit null.

## Sicherheitsauswirkung

Ungültige Modi, nicht vertrauenswürdige Eigentümer und unsichere bestehende Pfade bleiben abgewiesen. Es entstehen keine Zugangsdatenänderung, Scannerausnahme, Quellausnahme, Gate-Änderung oder Zusammenführung.

## Dokumentation und Runtime-Evidenz

Private Reviewartefakte liegen unter `$RUN_ROOT/followup-review/`; Belege unter `$EVIDENCE_ROOT/followup-review/`: `validation.json`, `workflow-control.log`, `report.de.md` und `secrets-selection-incident.json`. Beim aufgelösten Auswahlvorfall mit fehlender Datei erfolgte zwischen Fehler und erfolgreicher Wiederherstellung kein Inhaltszugriff. Weitere quellgebundene Belege sind `$EVIDENCE_ROOT/followup-source/full48-python3152.json`, `native-generator-exact-diff.json` und `$EVIDENCE_ROOT/quick-check/fifo-bootstrap-closure/fifo-bootstrap-local-closeout.json`. Kein Dienst und keine Runtime-Abnahmekampagne wurden gestartet.

## Nicht ausgeführte Prüfungen

Die frische gehostete Analyse dieser Folgekorrektur ist **NOT_RUN**. Die endgültige Prüfung des veröffentlichten Paars und ein neuer vollständiger nativer Quick-Check bleiben koordinierte Auslieferungsprüfungen. Vollständige Abnahmekampagne und endgültige Prüfung des veröffentlichten Paars bleiben außerhalb dieser lokalen Ergebnisse.

## Einschränkungen und Restrisiko

Native Äquivalenz belegt keinen gehosteten Parser- oder Befundabschluss. FIFO-/JSON-Analyselücken und weitere unabhängig berichtete Analyzergrenzen bleiben bis zur gesonderten Prüfung offen. Ein bestandenes Basis-Gate zertifiziert diese geänderten Quellen nicht.

## Finaler Diff- und Review-Status

Der unabhängige lokale semantische Review bestand für die gebundenen Quellen. Dieser Datensatz beschreibt geprüfte lokale Vorbereitung und erklärt keine Gesamtbereitschaft. Der Koordinator verantwortet Abschlussprüfungen, native Metadatenerzeugung, EN/DE-Integration, reguläre Git-Auslieferung und gehosteten Readback am exakten Head. Bestehende Datensätze bleiben historisch.
