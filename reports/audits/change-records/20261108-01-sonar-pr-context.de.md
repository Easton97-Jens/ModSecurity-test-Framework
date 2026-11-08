# Sonar-Vertrag für den Pull-Request-Kontext

**Sprache:** [English](20261108-01-sonar-pr-context.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261108-01-sonar-pr-context |
| UTC-Datum | 2026-11-08 |
| Framework-Basisrevision | `d14937ce8fe7a534bb755cffa6597e62eadbb126` |
| Issue oder Pull Request | [Framework-Draft-PR #169](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/169) |

## Motivation und Problemstellung

Der Framework-Workflow-Vertrag verlangte für Parent-C++20-/C++23-Scans die
Branch-Überschreibung `master`, auch bei Pull Requests. Dadurch lieferten diese
Analysen nicht die vorgesehenen Pull-Request-Kontexte. Parent besitzt die
Workflow-Korrektur; Framework besitzt deren Prüfvertrag.

## Betroffene Komponenten und Sicherheitsgrenzen

Der Validator in `connector_suite/modsecurity_connector_tests/test_ci_security_workflows.py`,
seine On-Demand-Registrierung in `connector_suite/config/testing/active-cases.json`
und dieser englische/deutsche Record ändern sich. Exakte Projektschlüssel,
Standards, Advisory-Verhalten, Quellumfang, Scanner-Secret-Beschränkungen und
Quality Gates bleiben abgedeckt. MRTS bleibt schreibgeschützt behandelt.

## Akzeptanzkriterien

Der korrigierte Workflow besteht den Vertrag. Ein erneut eingefügtes
Matrix-Feld `branch_args` scheitert bei jeder der drei Varianten. Direkte
Scanner-Überschreibungen von `branch.name`, `branch.target`, `pullrequest.key`,
`pullrequest.branch` und `pullrequest.base` scheitern. Jede Negativmutation
muss ihre Eingabe tatsächlich ändern.

## Untersuchte Alternativen

Die bisherige `master`-Überschreibung würde den falschen Analysekontext erhalten.
Explizite Pull-Request-Argumente würden die GitHub-Ereigniserkennung duplizieren
und einen weiteren Weg für widersprüchliche Identitäten schaffen.

## Implementierungsentscheidung

`branch_args` entfällt in der exakt erwarteten Matrix. Direkte Scanner-Branch-
oder Pull-Request-Eigenschaften werden abgelehnt. Der vorhandene Scanner wählt
den Kontext aus dem tatsächlichen GitHub-Ereignis. Die bestehenden Tests für
vollen Quellumfang und Advisory-Verhalten bleiben erhalten.
Der neue Offline-Mutationstest liest das zugelassene Parent-YAML direkt, weil
er Scanner-/Matrix-Felder prüft und keine fremden Composite-Actions expandieren
muss. Offline-Prozess- und Netzwerksperren bleiben unverändert.

## Geänderte Dateien und Tests

Der Validator erhält eine Routing-Prüfung. Ein Regressionstest deckt den
korrigierten Workflow und acht Negativmutationen ab. Das Record-Paar beschreibt
den Framework-Vertrag und die externe Parent-Abhängigkeit.
Die neue On-Demand-Ausführung heißt
`offline.sonar-merged-contract.sonar-standard-matrix-rejects-context-overrides`,
mit acht erwarteten Subtests und expliziten Fällen. Die 80 Standardselektoren
und 100 Standardfälle bleiben unverändert. Native Binding-/Archivgeneratoren
führt der koordinierende Auftrag nach der Registrierung aus.

## Befehle und Ergebnisse

Explizite Secrets-Prüfungen vor dem Lesen und nach Änderungen bestanden.
Fokussierte Testergebnisse und exakt gewählte Roots stehen im externen
Auftragsbericht. Ein erster Aufruf ohne `CONNECTOR_REVISION` und ein zweiter
ohne `TEST_ROOT` scheiterten beim Import; sie zählen nicht als ausgeführte Tests.
Mit beiden expliziten Bindungen führte die Legacy-Klasse 48 Tests aus, mit
26 Fehlschlägen und zwei Fehlern in bestehenden breiteren Workflow-Verträgen.
Die sechs fokussierten Sonar-Methoden bestanden (1,612 Sekunden), einschließlich
der acht neuen Negativmutationen. Eine Baseline im Speicher mit ursprünglichem
Framework-Modul und ursprünglichem Parent-Sonar-Workflow führte 47 Tests mit
denselben 26 Fehlschlägen und zwei Fehlern aus. Jeder betroffene Methodenkörper
ist unverändert. Eine separate Methode für nicht vertrauenswürdige PRs wiederholt
ihren bestehenden Fehler beim Digest des nativen Workflows. Logs liegen unter
`$RUN_ROOT/contract-fix/`. `RUN_ROOT` bezeichnet den externen Auftragslauf
`20261108-sonar-free-zero`, der im privaten Ausführungsbericht festgehalten ist.
Die bereits qualifizierte Framework-Python-
3.15.2-Umgebung wird unter dem bestehenden Kompatibilitäts-/Lock-Vertrag genutzt.

Mit expliziten Parent-/Framework-Roots und Revisionen, `TEST_ROOT`, Profil und
vorhandenem privatem Ausgabe-Root wird das native `run-active-tests.py --on-demand
--execution offline.sonar-merged-contract.sonar-standard-matrix-rejects-context-overrides
--strict-skips --output-root <external-output-root>` durch RTK ausgeführt. Der
finale native Lauf endete mit Exit 0: eine Methode, acht beobachtete Subtests,
keine Skips und keine erwarteten Fehler. Der Beleg heißt
`contract-fix/native-context-direct.stdout` unter `RUN_ROOT`.
Frühere Fehler bleiben erhalten: fehlendes Ausgabeverzeichnis und anschließend
ein Git-Aufruf der Composite-Expansion nach Aktivierung der Offline-Sperre.
Das direkte YAML-Lesen entfernt diese sachfremde Expansion aus dem neuen Test;
Sperren und Provenienzprüfung werden nicht gelockert.

## Sicherheitsauswirkung

Die Änderung korrigiert die Prüfung der Analyseidentität; sie behebt keine
Runtime-Sicherheitslücke. Scanner-Ausnahmen, Quellausschlüsse, Gate-Änderungen
oder Änderungen an Zugangsdaten werden nicht eingeführt.

## Dokumentation und Runtime-Evidenz

Dieser Record hat einen englischen/deutschen Partner. Die fokussierte
Vertragsänderung erfasst keine Host-Runtime-Evidenz. Neue gehostete Analysen
müssen PR-Kontexte und Gate-Ergebnisse am gelieferten Head separat nachweisen.

## Nicht ausgeführte Prüfungen

Die vollständige Abnahmekampagne bleibt **NOT_RUN**. Vollständige Regression
des Commit-Paars, generierte Inventar-/Archivprüfungen und gehostete CI gehören
zum koordinierenden Auftrag und werden durch diesen Record nicht bestätigt.

## Einschränkungen und Restrisiko

Ein lokaler Vertrags-PASS beweist weder einen erzeugten SonarCloud-PR-Kontext
noch eine gespeicherte Issue-Entscheidung. Bestehende Master-Branch-Befunde
bleiben bis zur unabhängigen Klärung von den korrigierten PR-Kontexten getrennt.

## Finaler Diff- und Review-Status

Die Änderungen gehen zur begrenzten Diff-Prüfung, nativen Dokumentations- und
Generatorprüfung und regulären Auslieferung im bestehenden Draft-PR an den
koordinierenden Auftrag. Dieser Record erklärt den Gesamtauftrag nicht für
abgeschlossen.
