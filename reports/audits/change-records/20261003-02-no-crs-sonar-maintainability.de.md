# Change Record: No-CRS-Sonar-Wartbarkeit

**Sprache:** [English](20261003-02-no-crs-sonar-maintainability.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20261003-02-no-crs-sonar-maintainability` |
| UTC-Datum | `2026-10-03` |
| Framework-Basisrevision | `b9b9534b7e0b15edad31393699ebd0617748148d` |
| Issue oder Pull Request | Framework-PR #135; externer Parent-PR #396 bleibt Draft |

## Motivation und Problemstellung

Die aktuelle Sonar-Analyse von Framework-PR #135 bestand das Quality Gate,
behielt aber 28 offene Wartbarkeitshinweise: vier `python:S3776`, siebzehn
`python:S9073`, drei `python:S1192`, zwei `python:S5713`, einen
`python:S8714` und einen `python:S5778`. Dies ist nicht die unabhängige
historische Parent-PR #135. Ein bestandenes Gate bedeutet nicht Issue-Freiheit.

## Betroffene Komponenten und Sicherheitsgrenzen

`ci/checks/catalog/no_crs_baseline.py` und die dreizehn betroffenen
`tests/no_crs`-Module gehören dem Framework. Selection, Evidence-Matching,
Statusvorrang, Descriptor-gestützte Artefaktautorität und Receipt-Validierung
müssen unverändert bleiben. MRTS bleibt unverändert. Ein späteres Parent-
Gitlink-Update ist eine separat autorisierte Parent-Operation, keine
Framework-Sourceänderung.

## Akzeptanzkriterien

Echte Codeursachen ohne Suppressionen, Exclusions, Regeländerungen,
synthetische Runtime-Evidence oder verkleinerte Required-Auswahl entfernen.
Geordnete Fehlermeldungen, exakte Run-/Case-/Rule-/Phase-Identitäten, echte
aufbewahrte Bytes und Grenzen, geschlossene Config-Templates, No-Follow-
Admission, Cleanup und explizite Wiederverwendung erhalten. Fokus- und native
Framework-Gates sowie frisches Remote-Readback des exakten Heads verlangen.

## Untersuchte Alternativen

Validator-Abschwächung oder geänderte Sonar-Einstellungen würden die Ursachen
nicht beheben. Eine neue generische Validierungsabstraktion würde den Vertrag
unnötig erweitern. Kleine Helper-Extraktionen, Dateinamenkonstanten im vorhandenen
Stil und eng begrenzte Test-Assertion-/Exception-Hygiene nutzen.

## Implementierungsentscheidung

Zuerst die unveränderten Blattnamen `nginx.conf`, `stdout.log` und
`stderr.log` in Konstanten zentralisieren. Separate Folgecommits behandeln
Testdiagnostik, redundante Exception-Unterklassen und die vier komplexen
Funktionen. Katalog, Schema, Runner-Case, Capability, öffentlicher Vertrag und
Runtime-Verhalten werden nicht absichtlich geändert.

## Geänderte Dateien und Tests

Die genannte Produktdatei, die dreizehn durch Sonar identifizierten Testmodule,
dieses Record-Paar und der gepaarte Archivindex. Tests behalten geordnete
Spec-/Loader-Prüfungen; der Exception-Test bereitet Collaborators vor der einen
werfenden Invocation vor; der positive FIFO-Test behält sein Timeout und
scheitert bei einer unerwarteten Exception unmittelbar.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| RTK-gewrappter owning Interpreter: unveränderte No-CRS-Baseline-Discovery | 0 | 166 Tests, keine Skips, vor Änderungen | Externes Coordinator-Baseline-Log |
| RTK-gewrappter owning Interpreter: Code-Muster-Regression | 1 / 0 | Baseline 0/19, korrigierte Tests 19/19 | Externe Test-Hygiene-Kontrollen |
| RTK-gewrappter owning Interpreter: dreizehn betroffene Testmodule | 0 | 65 Tests bestehen | Externes Test-Hygiene-Fokuslog |
| RTK-gewrappter owning Interpreter: Config-Artefakt-/Receipt-/Size-Fokus | 0 | 25 Tests nach Konstantenextraktion bestehen | Externe Produkt-Owner-Validierung |
| RTK-gewrappter owning Interpreter: Baseline-/Current-Charakterisierung | 0 | 1.218 Vergleiche vor Komplexitätsextraktion stimmen überein | Externer Produkt-Parity-Harness |
| `rtk proxy git diff --check` | 0 | Whitespace geprüft | Framework-Task-Worktree |

Dies sind Source-/Unit-Prüfungen, keine Connector-Promotion oder Runtime-
Zertifizierung. Integrierte und Postcommit-Native-Gates sowie neue Remote-
Analyse sind an diesem ersten getrennten Ursachencheckpoint noch ausstehend
und werden erst nach Ausführung dokumentiert.

## Sicherheitsauswirkung

Keine Sicherheitskontrolle wird gelockert und keine Runtime-Evidence erzeugt.
Die Wartbarkeitsarbeit erhält den vorhandenen Autoritäts-/Validierungsvertrag,
statt ihn zu reparieren oder zu erweitern. Descriptor-Lebensdauer, exaktes
Diagnose-Matching und selected-required Missing-Evidence bleiben verbindlich.

## Dokumentation und Runtime-Evidenz

Dieses EN/DE-Record-Paar und der Index dokumentieren den exakten Umfang.
Kein Connector-Lifecycle oder Full Exact-Head E2E wird in diesem Arbeitsschritt
gestartet. Alte Evidence wird nicht als neue Exact-Head-Evidence umetikettiert.

## Nicht ausgeführte Prüfungen

Full E2E ist ausdrücklich verboten. Remote-Prüfungen neuer Commits und finale
integrierte native Gates dürfen vor echter Ausführung nicht behauptet werden.

## Einschränkungen und Restrisiko

Parity-Fixtures beweisen keine echte Hostausführung. Finale Sonar-Akzeptanz
benötigt den neu veröffentlichten exakten Framework-Head statt Baseline-Gate.
Framework-Delivery und Parent-Integration bleiben getrennt; keines ist ein Merge.

## Finaler Diff- und Review-Status

Der erste Dateinamenkonstanten-Schritt ist nach Einsetzen der unveränderten
Konstantenwerte für das gesamte Modul AST-äquivalent, mit Fokusprüfungen und
Diff-Review. Weitere Schritte benötigen unabhängiges Review und finale
integrierte Validierung. Secrets, generierte Runtime-Ergebnisse, MRTS-Änderungen
und Suppression-Konfiguration gehören nicht in diesen Change.
