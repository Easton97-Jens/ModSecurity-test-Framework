# Change Record: CodeQL-Release-Testdaten isolieren

**Sprache:** [English](20260929-01-fix-codeql-test-fixtures.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260929-01-fix-codeql-test-fixtures |
| UTC-Datum | 2026-09-29 |
| Framework-Basisrevision | 6df30cc261b6033c1498f9d035fe4e7771c14a4a |
| Issue oder Pull Request | [PR #122](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/122) |

## Motivation und Problemstellung

PR #122 aktualisiert den produktiven CodeQL-Action-Pin auf v4.38.1. Vier
Resolver-Tests verwenden feste Release-Listen rund um v4.38.0, lesen ihre
Ausgangswerte aber aus dem veränderlichen produktiven Lock. Drei dieser
Tests erreichen deshalb die Prüfung auf veraltete Releases statt ihres
eigentlich vorgesehenen Validierungszweigs.

## Betroffene Komponenten und Sicherheitsgrenzen

Die Änderung beschränkt sich auf `tests/ci_security/test_update_workflow_tools.py`
und diesen gepaarten Record. Produktive Resolver, Workflows, Dependency-Pins,
Berechtigungen, Publisher-Allowlist und Connector-Verhalten bleiben unverändert.

## Akzeptanzkriterien

Die vier Tests mit synthetischen Release-Listen verwenden zusammenpassende,
testeigene Ausgangswerte. Der Fixture-Helper verändert das geladene Lock
nicht und bleibt unabhängig von simulierten produktiven Versionen v4.38.1,
v4.99.0 und v5.0.0. Eine gegenüber der Fixture veraltete Release-Liste wird
weiterhin vor der Release-Bestätigung abgelehnt. Erfolgreiche vollständige
Tests und PR-Checks müssen noch durch CI nachgewiesen werden.

## Untersuchte Alternativen

Ein Downgrade des produktiven Pins oder eine Abschwächung der Prüfung auf
veraltete Releases würde den Testfehler verdecken. Wiederholtes Erhöhen
fest codierter Release-Versionen würde nach späteren Wartungsupdates erneut
scheitern. Eine kopierte Fixture übernimmt bestehende produktive Policy-Felder,
ohne veränderlichen Testzustand gemeinsam zu verwenden.

## Implementierungsentscheidung

`codeql_release_fixture` kopiert den geladenen CodeQL-Eintrag und setzt
Version, Commit und Release-URL gemeinsam über den vorhandenen Helper
`changed_action`. Nur die vier Tests mit synthetischen Release-Listen
verwenden diese Fixture. Alle bestehenden Assertions und produktiven
Schutzprüfungen bleiben erhalten.

## Geänderte Dateien und Tests

`tests/ci_security/test_update_workflow_tools.py` ergänzt die Fixture und
zwei Regressionstests: `test_codeql_release_fixture_is_independent_and_does_not_mutate_lock`
und `test_codeql_resolver_still_rejects_a_stale_release_page`. Vier bestehende
Tests beziehen ihre Ausgangswerte nun aus der Fixture. Dieser Record und
sein englischer Partner dokumentieren denselben Umfang und dieselben
Validierungsgrenzen.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Python `compile` und `ast.parse` für die drei ergänzten Methoden | 0 | Syntax akzeptiert; zwei neue Regressionstests erkannt; kein Testsuite-Lauf | Nicht anwendbar |
| `git apply --numstat` für den vorbereiteten Fix-Patch | 0 | Testdatei-Patch mit 62 Ergänzungen und 8 Löschungen; keine Aussage zur Anwendbarkeit | Nicht anwendbar |
| `git ls-remote` für den PR-Branch | 128 | Lokales Netzwerk konnte github.com nicht auflösen; Repository-Lesen und Veröffentlichung erfolgen über den GitHub-Connector | Nicht anwendbar |

## Sicherheitsauswirkung

Es wurde keine Security-Remediation durchgeführt. Prüfungen auf veraltete
Listen, gleiche Major-Version, unveränderliche Releases, Drafts und
Tag-Konsistenz werden nicht abgeschwächt. Der neue negative Regressionstest
deckt die Ablehnung vor der Bestätigung ab; seine Ausführung wird durch
die Syntaxprüfung nicht behauptet.

## Dokumentation und Runtime-Evidenz

Der englische und deutsche Change Record werden gemeinsam ergänzt. Keine
generierten Reports, Runtime-Evidenz, Host-Builds oder Connector-Lifecycle-
Ergebnisse werden geändert oder als nachgewiesen dargestellt.

## Nicht ausgeführte Prüfungen

`make test-ci-security-contract`, `make lint`, `make check-change-records`,
`make check-documentation`, `make check-bilingual-docs`, `make check-doc-links`
und `git diff --check` für einen vollständigen Worktree wurden lokal nicht
ausgeführt, da nach dem GitHub-DNS-Fehler kein vollständiger Checkout verfügbar
war. CI-Ergebnisse müssen für den neuen PR-Head gelesen werden und dürfen
nicht aus dem vorbereiteten Patch abgeleitet werden.

## Einschränkungen und Restrisiko

Dieser Commit setzt nur den vorbereiteten CodeQL-Testfix um. Die automatische
AWS-LC-Wartung bleibt eine separate, nicht implementierte Aufgabe. Der PR
bleibt ein Draft; Merge und Auto-Merge sind nicht freigegeben. Bestehende
Scope-Prüfungen des automatischen Publishers bleiben erhalten und können
die Wiederverwendung eines manuell erweiterten Wartungsbranches ablehnen;
es wird keine Umgehung eingeführt.

## Finaler Diff- und Review-Status

Der vorgesehene Delta besteht aus dem vorbereiteten Testdatei-Patch und diesem
gepaarten Record. Die Veröffentlichung muss die PR-Historie erhalten und
einen nicht erzwungenen Fast-Forward verwenden. Ein vollständiger lokaler
staged oder unstaged Diff liegt nicht vor. Die ergänzten Methoden wurden
auf Whitespace und Secrets durchgesehen; Zugangsdaten und rohe Runtime-Daten
sind nicht enthalten. GitHub-Commit-Diff und erneutes Lesen des PR-Heads dienen
als Veröffentlichungsprüfungen; vollständiger CI-Erfolg wird in diesem Record
nicht behauptet.
