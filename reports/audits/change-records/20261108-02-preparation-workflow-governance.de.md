# Workflow- und Governance-Verträge der Vorbereitung

**Sprache:** Deutsch | [English](20261108-02-preparation-workflow-governance.md)

## Identität

| Field | Value |
| --- | --- |
| Change-ID | 20261108-02-preparation-workflow-governance |
| UTC | 2026-11-08 |
Framework-Basis: `c34343c65311b78d3de87059a4a20bcfe8e9919d`.
Umfang: PRECOMMIT-Vorbereitung am Arbeitsquellstand für [Draft-PR #169](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/169).

## Motivation und Problemstellung

Der frühere vollständige Workflow-Vertragslauf meldete in 48 Tests 26 Fehlerdatensätze aus 23 eindeutigen fehlgeschlagenen Methoden sowie zwei Error-Methoden. Vier fehlgeschlagene Modul-Subtests erklären die wiederholten Datensätze. Die Basis mit 47 Methoden zeigte dieselben Failures/Errors; der Untrusted-PR-Fehler überschneidet beide Läufe. Beim Import abgebrochene Aufrufe zählen separat. Die Befunde erforderten eine Diagnose anhand aktueller Verträge statt einer Baseline-Ausnahme. Das separate alte Governance-Audit mit 84 Datensätzen ist nicht dieser Testblock.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-Änderungen betreffen `connector_suite/modsecurity_connector_tests/test_ci_security_workflows.py`, `ci/lib/common.sh` und `.codex/inheritance-manifest.toml`, dazu native Inventar-/Archiv-Postimages und dieses Dokumentenpaar. Workflow-Orchestrierung, Publisher-Modusguard und Governance-Updater gehören dem Parent und sind externe Abhängigkeiten. MRTS-Governance-PR #7 und dessen geprüfte Revision sind externe Abhängigkeiten, keine Framework-Auslieferungsfakten. Dieses Dokument erhöht den Framework-MRTS-Gitlink nicht.

## Akzeptanzkriterien

Alle ursprünglichen 48 Methoden ohne Failures, Errors oder Skips ausführen; aussagekräftige Mutationsablehnung und die ausgewählten 100 Standardfälle erhalten. Den Shell-Rechteersatz gegen die ursprüngliche Maske und native Shells prüfen. Nur geprüfte Vererbungsdigests durch den nativen Erzeuger aktualisieren. Vor Auslieferungsabschluss sind Prüfungen der veröffentlichten Kette und gehostete Prüfungen erforderlich.

## Untersuchte Alternativen

Tests zu entfernen, historische Fehler zu überspringen, bedingungslose Akzeptanz zu prüfen, Offline-Guards zu lockern, Workflow-Rechte zu erweitern, Scannerwarnungen zu unterdrücken oder die Standardfallgrenze zu erhöhen würde den Vertrag entwerten. Alte Parent-Testarchivpfade sind nach der Framework-Eigentumsmigration überholt.

## Implementierungsentscheidung

Die Tests binden an aktuelle unveränderliche Framework-Bootstraps und native Dispatch-Verträge, feste Produkt-Allowlisten, explizite Fixture-Eigentümer und native Inventarselektoren. Expandierte Sonar- und Publisher-Verträge werden vor Aktualisierung ihrer geschlossenen Digests geprüft. Die ursprünglichen 20 nativen Sonar-Mutationen und acht Kontextmutationen bleiben erhalten; sechs zusätzliche Pin-Mutationen verwerfen fehlende, falsche und wörtliche Platzhalter-Pins vor der Normalisierung. Alle zusätzlichen Diagnosevarianten gehören zu bestehenden On-demand-Methoden.

Die tatsächliche Broker-Kette lautet Parent-Wrapper → fest gepinnter historischer Framework-Wrapper → fester Parent-Broker bei `8ae707d72f1a8acb25d239e55e28a73cbc7522b1`. Die aktuelle Expansion prüft exakt Rechte, Remote/Pfad/Revision, sechs erforderliche String-Eingaben und deren Weitergabe; der unveränderliche Endvertrag behält seine tiefen Vertrauensprüfungen. Die explizite Vollmoduldiagnose benötigt dieses lokale Gitobjekt und scheitert andernfalls ohne Fetch oder Skip. Reguläre CI verwendet die kompakte native Supply-chain-Gruppe.

Die Shell-Änderung ersetzt äquivalente oktale Schreibbit-Arithmetik durch eine genaue Moduszeichenprüfung und erhält das Fehlerverhalten. Die geerbten Architektur-, Befehlsausführungs- und Sonar-Policyhashes wurden einzeln geprüft und durch den nativen Parent-Erzeuger mit koordiniertem exklusivem Eigentum, optimistischen Prüfungen und atomarem Ersetzen aktualisiert; dies garantiert keinen Kernel-Compare-and-swap.

## Geänderte Dateien und Tests

Die Workflow-Testquelle hat SHA256 `2c2d21681353a350088858aad9ed0e989159968e0c325dbcd09b6b8587c50bab`. Ihre 48 Methodenidentitäten bleiben erhalten. Der expandierte geschlossene Sonar-Digest lautet `8346bcb3261d71210ff28687c15bd1e9b69e848ec0316dec966878f524fc56ff`; der unabhängig geprüfte Publisher-Digest lautet `ca21fd86d12ba5bd7fc489073a3e26fdfdcab702e24ba4c4ea918c49a575e38f`.

Der Shell-Postimage-SHA256 lautet `850f9d9bc198391a2a74be17a22f79dd96ef3305c9199a1b8ba85413d3bda2ab`. Der Vererbungsmanifest-SHA256 lautet `2703f1015c20cb89eecb8b75e492947a353836e3baa78d8d9d0d2472d11d1fd1` (Architektur `a62b475a…`, Befehlsausführung `1b30804d…`, Sonar `3ec379f7…`). Native Metadatenprüfungen unterscheiden explizite Worktree-Diagnosen von der endgültigen kanonischen verschachtelten Validierung.

## Befehle und Ergebnisse

Über RTK lief der qualifizierte Interpreter `$FRAMEWORK_VENV/bin/python` mit `-m unittest -v modsecurity_connector_tests.test_ci_security_workflows.CiSecurityWorkflowTest`, expliziten Parent-/Framework-Wurzeln und Revisionen, `TEST_ROOT`, reinem Framework-`PYTHONPATH`, `PYTHONSAFEPATH=1`, `PYTHONNOUSERSITE=1`, deaktiviertem Bytecode und privater externer temporärer Ausgabe. Die gesamte Klasse bestand zweimal; der instrumentierte Lauf erfasste 48 Methoden, 222 Subtest-Ausführungen in 14 Methoden sowie null Failures/Errors/Skips. Subtests und Wiederholungen erzeugen keine neuen eindeutigen Fälle.

Das Inventar wählt weiterhin 80 Ausführungsselektoren und 100 Fälle. Nur eine Methode dieser Klasse ist standardmäßig ausgewählt; ihr AST stimmt mit dem Basiscommit überein. Keine Methode wurde hinzugefügt, entfernt oder übersprungen. Die 222 beobachteten Subtests sind explizite Diagnoseausführungen und keine Ergänzungen der Standardauswahl.

Native dash/bash-Syntax, die echte Host-Git-Grenze und je Shell 4.690 gültige/ungültige Modusfälle bestanden; 14 bestehende fokussierte Regressionsmethoden bestanden. Der native Parent-Metadatenerzeuger bestand 22 Tests; Parent-Katalog und explizite Parent-/Framework-/MRTS-Worktree-Diagnose bestanden. Dies sind qualifizierte lokale Ergebnisse, keine Ergebnisse der endgültigen Kette oder gehosteter Analysen.

Der native Inventarerzeuger aktualisierte genau zwei bestehende Quelldigests; sämtliche Nicht-Bindungsfelder sowie Selektor-, Fall- und Exception-Identitäten bleiben unverändert. Der native Archiverzeuger erhielt alle Python-/Go-Definitionsidentitäten. Anschließend endeten `update-inventory-bindings.py --check`, `update-test-archive.py --check`, `check-doc-links.py`, `check-variable-documentation.py`, `check-repository-path-references.py` und `check-change-records.py` jeweils mit 0. Zwei frühere übergroße aggregierte Secrets-Versuche scheiterten am 30.000-ms-Timeout; dieselbe vollständige Eingabevereinigung wurde in 32 PATH-Batches mit unveränderten Ganzdateien wiederhergestellt: alle Exit 0, insgesamt 2.430 eindeutige Dateien ohne Auslassung. Während der beobachteten globalen Pause wurden keine Quellen weiter gelesen oder geändert; native Prüfungen liefen erst nach ausdrücklicher Freigabe.

## Sicherheitsauswirkung

Ein tatsächlicher externer Parent-Publisher-Fehler erlaubte das Umschalten des Ausführungsbits regulärer Dateien. Sein eng begrenzter Guard für gleichbleibende Modi wurde korrigiert und mit den bestehenden Raw-Modus-/Status-Negativkontrollen geprüft. Framework-Tests erhalten diese Grenze. Es entstehen keine Scannerausnahme, Quellausnahme, Zugangsdatenänderung, Gate-Abschwächung, Zusammenführung oder Erweiterung der Root-Grenze.

## Dokumentation und Runtime-Evidenz

Englischer und deutscher Datensatz beschreiben denselben Umfang. Private Laufartefakte liegen unter `$RUN_ROOT/workflow-tests/`. Evidenz liegt unter `$EVIDENCE_ROOT/`: `workflow-tests/full-class-result.json`, `workflow-tests/final-default100-scope.json`, `workflow-tests/publisher-mode-repro.json`, `warnings/semantic-remediation/applied-validation.json`, `warnings/semantic-remediation/focused-regression.json`, `inheritance/native-metadata-applied.json` und `inheritance/native-inheritance-checks.json`. Diese externen Dateien sind keine portablen Repository-Dokumentationslinks. Ein korrigierter Secrets-Protokollvorfall ist separat erfasst; der verfrühte Lesezugriff wird nicht als regelkonform dargestellt. Kein neuer Dienst und keine Runtime-Abnahmekampagne wurden gestartet.

## Nicht ausgeführte Prüfungen

Die vollständige Abnahmekampagne bleibt **NOT_RUN**. Frische gehostete Analyse dieser Quellen, gehostete FIFO-/JSON-Reproduktionen, endgültige veröffentlichte Paarregression und kanonische verschachtelte Vererbungsprüfung `--all` bleiben koordinierte Auslieferungsprüfungen. Vorhandene gehostete Ergebnisse zertifizieren diesen PRECOMMIT-Stand nicht. Lokales Python 3.14.4 belegt nicht die erforderliche gehostete MRTS-Python-3.14.6-Prüfung.

## Einschränkungen und Restrisiko

Native Shell-/JSON-Gültigkeit beweist keine vollständige Analyzer-Abdeckung. FIFO-Parserwarnung, ausgelassene übergroße JSON-Datei und interne Veröffentlichungsdiagnosen benötigen eine unabhängig qualifizierte gehostete Bewertung. Lokale Tests beweisen weder Befundübergang noch gehostetes Quality Gate oder endgültige Gitlink-Kette. Die Governance-Klassifikation mit 84 Datensätzen bleibt separat und wurde hier nicht als frisches Audit wiederholt.

## Finaler Diff- und Review-Status

Der Koordinator verantwortet abschließenden Diff-Review, native Dokumentations-/Inventarbelege, reguläre Commits/Pushes und Aktualisierungen der bestehenden Draft-PRs. Unabhängiger semantischer Review bestätigte die Publisher-Grenze vor Änderung ihres geschlossenen Digests; die Abschlussvalidierung ist extern dokumentiert. Dieser Datensatz beschreibt lokale Vorbereitung und erklärt weder Gesamtabnahme noch Bereitschaft des ausgelieferten Heads.
