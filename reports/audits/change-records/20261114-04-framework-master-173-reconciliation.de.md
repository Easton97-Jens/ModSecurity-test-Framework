# Change Record: Framework-master-Abgleich mit #173

**Sprache:** [English](20261114-04-framework-master-173-reconciliation.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20261114-04-framework-master-173-reconciliation` |
| UTC-Datum | 2026-11-14 |
| Framework-Basisrevision | `b0b507a58d3c763ee39b631e79282b694703d13c` |
| Integrierte Upstream-Revision | `939d1718b7548a36ff7a550080ed8b811aad8a98` (#173) |
| Issue oder Pull Request | Framework #169 |

## Motivation und Problemstellung

Während der Vorbereitung von #169 lief master weiter. Die neuen Prüfungen
logischer Common-Quellidentitäten überlappten die Diagnosekorrektur für getrennte
Arbeitsbäume; beide Branches änderten das generierte Testarchiv. Die PR-API
behielt eine ältere Basis-SHA; der direkte master-Ref belegte die tatsächliche
Integrationsquelle.

## Betroffene Komponenten und Sicherheitsgrenzen

Der Abgleich gehört zu Framework-Prüfern, Diagnosetests und generiertem Katalog.
Parent-Implementierungen und MRTS-Pin bleiben unverändert. Logische
Common-Zuordnung, vollständiger Quellscan und die ausschließlich für Runtime
geltende ModSecurity-Include-Ausnahme bleiben durchgesetzt.

## Akzeptanzkriterien

Die tatsächlichen Testdefinitionen und Reihenfolge beider Branches erhalten;
100 aktive Fälle und 80 Selektoren behalten; beide echten Git-Layouts und
unveränderte Negativkontrollen prüfen; die übernommenen Verträge gegen eine
exakte kompatible Quell-Fixture testen; Fehler des älteren externen
Verbrauchers als eigene Nachweise erhalten.

## Untersuchte Alternativen

Nur ein generiertes Archiv zu übernehmen würde legitime Definitionen verlieren.
Ausschließlich physische Labels widersprächen der neuen logischen Common-
Zuordnung. Der native Producer kombiniert stattdessen die tatsächlichen
Quelldefinitionen.

## Implementierungsentscheidung

Der aufgelöste Common-Prüfer ist byteidentisch mit Upstream #173. Eine gemeinsame
Assertion der zwei echten Layouttests erwartet jetzt die logische Identität
`common/{directory}/{name}{suffix}`. Alle vier Ablehnungen migrierter Helfer
je Layout, Common-Ablehnung außerhalb Runtime und Runtime-Zulassung bleiben
unverändert. Allein die Rücknahme dieser Assertion reproduziert die gesamte
Testdatei der Basis.

## Geänderte Dateien und Tests

Der reguläre Merge erhält Upstreams Apache-/HAProxy-Adoptionsprüfer, vier
Testowner und Record-Paar. Dieser Abgleich ändert die Layout-Diagnoseassertion
und erzeugt das Archiv aus aktuellen Quellen neu. Alle 8437 Basisdefinitionen
und alle 8211 Einträge in Upstreams archivierter Ansicht bleiben in relativer
Reihenfolge erhalten; gegenüber der Basis kommen genau 13 tatsächliche Methoden
hinzu. Ergebnis: 8450 Definitionen ohne Umbenennung oder Löschung. Die Bytes des
aktiven Inventars bleiben unverändert.

## Befehle und Ergebnisse

Die Einstiegspunkte verwenden das vorhandene Framework-Python 3.15.2 und
ausdrückliche Wurzeln; exakte Argumente und qualifizierte Logs bleiben privat.

| Einstiegspunkt / Verfahren | Exit | Ergebnis | Laufreferenz |
| --- | --- | --- | --- |
| Reguläres `git merge --no-commit --no-ff` der Upstream-Revision | 1 | Zwei Konflikte, durch geprüfte Quellidentität und native Erzeugung aufgelöst | master-173-Abgleich, 2026-11-14 |
| `rtk bypass python -B -P -m unittest -v modsecurity_connector_tests.test_repository_architecture.RepositoryArchitectureTests` | 0 | 38 Methoden bestanden | Derselbe Lauf |
| `rtk bypass python -B -P -m unittest -v modsecurity_connector_tests.test_repository_architecture.CommonSecurityContractLayoutTests` | 0 | Beide echten Git-Layouts samt Negativkontrollen bestanden | Derselbe Lauf |
| `rtk bypass python -B -P -m unittest -v modsecurity_connector_tests.test_migration_source_provenance` | 0 | 9 Methoden bestanden | Derselbe Lauf |
| Vier ausgewählte Adoptions-/Eventmodule gegen externen Parent `5bab6e9d` | 1/0/1/1 | Apache-Suite bricht vor Tests ab; Event11 besteht; HAProxy24 scheitert an fehlenden Produktverträgen | Ursprüngliche Verbrauchsdiagnose |
| `rtk bypass python -B -P -m unittest -v modsecurity_connector_tests.test_apache_common_adoption` | 0 | 27 an gebundener kompatibler Fixture bestanden | Passende Quell-Fixture |
| `rtk bypass python -B -P -m unittest -v modsecurity_connector_tests.test_event_runtime_security_contract` | 0 | 11 an gebundener kompatibler Fixture bestanden | Passende Quell-Fixture |
| `rtk bypass python -B -P -m unittest -v modsecurity_connector_tests.test_haproxy_adoption_rule_id` | 0 | 12 an gebundener kompatibler Fixture bestanden | Passende Quell-Fixture |
| `rtk bypass python -B -P -m unittest -v modsecurity_connector_tests.test_haproxy_common_adoption` | 0 | 12 an gebundener kompatibler Fixture bestanden | Passende Quell-Fixture |
| Natives `ci/tools/sync-maintenance-test-views.py --write`, danach qualifizierte Postimages und `--check` | 0/0 | 8450 Definitionen; 100 Fälle / 80 Selektoren unverändert | Nativer Ansichtsproducer |

## Sicherheitsauswirkung

Scanumfang, verbotene Token-/Funktions-/Include-Muster und die logische Ausnahme
`common/runtime` bleiben erhalten. Die unabhängige Quellprüfung bestätigt den
exakten Upstream-Prüfer und die Testinversion eines Literals. Keine Validierung,
Quellzulassung, CI-Anforderung oder Quality Gate wurde gelockert.

## Dokumentation und Runtime-Evidenz

Dieses Record-Paar beschreibt Quell- und Fixture-Nachweise. Die kompatible
Read-only-Fixture ist externer Parent #448 an
`b1017969f766209eb9401820a4aca01d71180636`, Baum
`16ae9d0cea7e231f5322f3ff7ca6ebc25ddac085`. Dort bestehen alle 62 Methoden;
138 ausgewählte Quellhashes bleiben fest. Dies qualifiziert Parent #445 nicht:
dessen ursprünglicher HEAD/Index und die frühere fehlgeschlagene Diagnose
bleiben unverändert. Keine SDK-Builds, Hostausführung oder Gesamtabnahme erfolgte.

## Nicht ausgeführte Prüfungen

Lokales Ruff/Pyright wurde nicht erneut ausgeführt; keine Toolinstallation
gehört zur Änderung. Gehostete Checks und Sonar an den resultierenden Task-/
master-Commits werden über bestehende Workflows geprüft und mit tatsächlichen
SHAs dokumentiert. Dieser Record behauptet kein zukünftiges Analyseergebnis.

## Einschränkungen und Restrisiko

Die kompatible Quell-Fixture belegt diese Framework-Prüfungen, nicht
Implementierung oder Laufzeit des älteren Verbrauchers. Parent-Integration,
endgültige Runtime-Nachweise und Promotion des tatsächlichen MRTS-main-Pins
bleiben eigenständig zugeordnete Arbeit.

## Finaler Diff- und Review-Status

Quellüberlappung und erhaltene Diagnosekontrollen bestanden die unabhängige
Prüfung. Native Erhaltungsprüfungen bewahren die Definitionen beider
Quellbranches. Der Koordinator verantwortet finale gestagte Whitespace-/
Dokumentationsprüfungen und veröffentlicht tatsächliche Commit-, CI- und
Merge-Ergebnisse getrennt; nichts davon wird aus Fixtures abgeleitet.
