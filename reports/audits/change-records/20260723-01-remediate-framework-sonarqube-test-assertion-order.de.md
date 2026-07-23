# Behebung der Framework-SonarQube-Test-Argumentreihenfolge

**Sprache:** [English](20260723-01-remediate-framework-sonarqube-test-assertion-order.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260723-01-remediate-framework-sonarqube-test-assertion-order` |
| UTC-Datum | 2026-07-23 |
| Framework-Basisrevision | `935cf14c676a24672be5c336e92cd13457cc35c8` |
| Issue oder Pull Request | Framework-Draft-PR wird aus `agent/framework-sonarqube-test-issues-507` erstellt |

## Motivation und Problemstellung

Die aktuelle Framework-`master`-Analyse in SonarQube Cloud
`dda3ea04-2721-4ee6-a9c1-74bd2925f139` meldet 507 Framework-eigene
`python:S3415`-Testdiagnostiken in 29 Dateien. Jede meldet eine umgekehrte
`unittest`-Diagnosekonvention: erwarteter Wert zuerst und tatsächlicher Wert
danach. Die Gleichheitsrelation selbst ist symmetrisch, aber die
Tatsächlich-zuerst-Reihenfolge liefert die beabsichtigte Fehlerdiagnose und
erfüllt die konfigurierte Static-Analysis-Regel.

Dies ist eine Framework-eigene Testwartungsänderung. Sie ändert keinen
Connector, kein Server-/Proxy-Runtime-Verhalten, kein Katalogresultat, keine
Regel, kein Quality Gate und nicht das getrennte MRTS-only-Sonar-Security-
Finding.

## Betroffene Komponenten und Sicherheitsgrenzen

- `tests/no_crs/` — 220 Test-Assertions für begrenzte Evidenz-, Lifecycle-
  und Transport-Controls.
- `tests/protocol_client/` — 23 Test-Assertions für payload-freie
  Protocol-Evidenz- und Artifact-Containment-Controls.
- `tests/security_regression/` — 262 Test-Assertions für CI-, Provenance-,
  Path-, Archive-, Runtime-Evidenz- und Workflow-Contract-Controls.
- `tests/makefile_contract/` — 2 Makefile-Contract-Assertions.

Kein produktiver Security-Control wird geändert. Der Test-Source übt
sicherheitsrelevante Grenzen aus; daher bewahrt die Änderung jede Relation,
Message, Fixture und Ausdrucksauswertungsreihenfolge. Zwei berechnete
Erwartungslisten werden unmittelbar vor ihrer Tatsächlich-zuerst-Assertion in
lokale `expected_*`-Werte ausgewertet, wodurch die ursprüngliche
Auswertungsreihenfolge erhalten bleibt.

## Akzeptanzkriterien

1. Jede der 507 Live-S3415-Stellen verwendet `actual, expected`, ohne Relation,
   Message, Fixture oder Testfluss zu verändern.
2. Die zwei nichttrivialen Erwartungsausdrücke bewahren ihre bisherige
   Auswertungsreihenfolge.
3. Es wird weder `NOSONAR`, Exclusion, False-Positive-Status, Rule-/Gate-
   Änderung, Testabschwächung, Parent-Edit noch MRTS-Edit eingeführt.
4. Die relevanten Framework-Testsuiten, Source-Quality-Checks,
   Dokumentations-Checks und das finale Diff-Review bestehen.
5. Ein normaler Framework-Draft-PR wird erstellt; ein Master-Merge ist nicht
   Teil dieses Records.

## Untersuchte Alternativen

- **Sonar-Issues unterdrücken oder akzeptieren:** verworfen, weil dies einen
  konsistenten Diagnosequalitätsfehler verdecken und die gewünschte
  Remediation-Evidenz abschwächen würde.
- **Alle ersten zwei Argumente blind tauschen:** verworfen, weil ein
  Erwartungsausdruck beobachtbares Auswertungsverhalten haben kann.
- **Assertion-Helper oder Testlogik refaktorieren:** verworfen, weil diese
  Aufgabe eine schmale, source-erhaltende Remediation mit klarer
  Sonar-Nachvollziehbarkeit benötigt.

## Implementierungsentscheidung

Jede Live-Stelle wurde gegen die Sonar-API und den Python-AST abgebildet. 505
Aufrufe tauschen ausschließlich ihre ersten zwei Positionsargumente. Für die
zwei berechneten Erwartungslisten in
`test_no_crs_finalize_argument_safety.py` wird der frühere Erwartungsausdruck
vor der Assertion gebunden und als zweites Argument verwendet. Ein
Whole-AST-Äquivalenzcheck gegen die Basisrevision bestätigt, dass in den 29
Dateien keine andere Python-Semantikänderung existiert.

## Geänderte Dateien und Tests

Die 29 geänderten Dateien entsprechen exakt der Live-Sonar-Inventur: 4
No-CRS-/Makefile-, 2 Protocol-Client- und 23 Security-Regression-Tests. Neue
Testfälle sind nicht erforderlich, weil die Remediation bestehende Assertions
korrigiert; vorhandene positive und negative Security-Control-Fixtures bleiben
die Regression-Abdeckung.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | ---: | --- | --- |
| SonarQube-Cloud-S3415-Seiten 1 und 2 | 0 | 507 offene `python:S3415`-Master-Stellen (500 + 7) | `20260723T092456Z-framework-sonarqube-test-issues-507-10387697` |
| Whole-AST-Remediation-Verifier | 0 | 29 Dateien; 505 direkte Swaps und 2 auswertungsreihenfolge-erhaltende Fälle; keine weitere AST-Änderung | sealed Security-Scan-Artefakt `artifacts/02_discovery/verify_s3415_whole_ast.py` |
| `make test-no-crs-contract` | 0 | 97 Tests bestanden | externe Build-Roots des Task-Runs |
| `make test-protocol-client` | 0 | 24 Tests bestanden | externe Build-Roots des Task-Runs |
| `python -m unittest discover -s tests/security_regression -v` | 0 | 254 Tests bestanden | externe Build-Roots des Task-Runs |
| `make test-makefile-contract` | 0 | 3 Tests bestanden; Make warnte, dass sein noch nicht vorhandenes geliefertes `TMPDIR` auf `/tmp` zurückfiel, ohne verbleibenden Testoutput | externe Build-Roots des Task-Runs |
| Diff-scoped Codex-Security-Review | 0 | 29/29 Full-File-Receipts, null reportable Findings | sealed `report.md` im aktuellen Task-Run |
| `make lint` | 0 | Nativer Framework-Lint bestanden, einschließlich Shell-/Python-Checks, fokussierter Contracts, Katalog-Checks, Dokumentations-Checks und `git diff --check` | externe Build-Roots des Task-Runs |
| `make check-change-records` | 0 | Englischer/deutscher Change-Record-Contract bestanden | externe Build-Roots des Task-Runs |
| `make check-documentation` | 0 | Links, Variablendokumentation, Repository-Pfade und bilinguale Paare bestanden | externe Build-Roots des Task-Runs |
| Finales `git diff --check` | 0 | Keine Whitespace-Fehler im vollständigen Framework-Task-Diff | externe Build-Roots des Task-Runs |

## Sicherheitsauswirkung

Es wird keine Security-Remediation durchgeführt. Der abgeschlossene
diff-scoped Security-Review fand keinen reportable Finding: Der gesamte
Python-AST unterscheidet sich nur durch die genehmigten
Tatsächlich-/Erwartet-Transformationen und die zwei
reihenfolgeerhaltenden Bindungen. Die ursprünglichen Path-, Parser-,
Provenance-, Workflow- und Artifact-Containment-Controls wurden über ihre
bestehenden Framework-Suiten erneut ausgeführt; ihre Negativ-Controls bestehen
weiterhin. Diese Änderung behebt weder `FND-SONAR-0002` noch behauptet sie ein
grünes Master-Quality-Gate.

## Dokumentation und Runtime-Evidenz

Dieses englisch/deutsche Change-Record-Paar dokumentiert die
Testwartungsentscheidung. Es hat sich kein generierter Report und kein
User-facing-Verhalten geändert. Es wurde keine Connector-Runtime- oder
Lifecycle-Evidenz gesammelt: Die ausgeführten Checks sind ausschließlich
statische/Contract-Test-Evidenz.

## Nicht ausgeführte Prüfungen

- Vollständige Connector-Smokes, Runtime-Matrizen und MRTS-generierende Targets
  wurden nicht ausgeführt: Sie liegen außerhalb dieses Framework-only-
  Assertion-Order-Scopes und können Runtime-/MRTS-Grenzen überschreiten.
- Lokale Ruff-/Pyright-Parität wurde nicht hergestellt, weil die zugelassene
  CI-Tool-Umgebung lokal nicht provisioniert ist; gehostete Checks bleiben für
  den eingereichten PR-Head erforderlich.
- Eine frische SonarQube-Cloud-PR-Analyse ist noch nicht verfügbar, weil dieser
  Record der Erstellung des Draft PR vorausgeht.

## Einschränkungen und Restrisiko

Die lokale Test-Evidenz ersetzt weder Hosted-Exact-Head-CI noch die
SonarQube-Cloud-Analyse. Die S3415-Korrektur muss im gepushten Draft PR
erscheinen, bevor Sonar bestätigen kann, dass kein ursprüngliches Issue
verbleibt. Die aktuelle Master-Security-C-Bedingung entsteht aus getrennten
read-only-MRTS-Pfaden und bleibt außerhalb des Scopes.

## Finaler Diff- und Review-Status

Der Task hat vor der Delivery scoped Whitespace-, Suppression-, Secret- und
Whole-AST-Reviews abgeschlossen. Der Parent-Checkout, sein Framework-Gitlink,
der kanonische Framework-Checkout und MRTS sind keine Delivery-Ziele. Beim
Erstellen dieses Records ist der Framework-Task-Branch uncommitted; Commit-,
Push- und Draft-PR-Details werden erst nach Beobachtung ihrer exakten Heads
dokumentiert.
