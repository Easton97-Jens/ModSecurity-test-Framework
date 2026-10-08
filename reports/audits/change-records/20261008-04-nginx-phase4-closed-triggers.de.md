# Änderungsnachweis

**Sprache:** Deutsch | [English](20261008-04-nginx-phase4-closed-triggers.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261008-04-nginx-phase4-closed-triggers |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | `11e1d20990d4ecbbcf18641782b04f0bb6369c69` |

## Motivation und Problemstellung

Acht ausgewählte Required-Phase-4-Records besitzen keine angesetzte native Operation. Deklarative Future-Fixtures beweisen weder getrennte Verarbeitung noch EOS, Engine-Limit-Ergebnisse oder begrenzte native Metadaten.

## Betroffene Komponenten und Sicherheitsgrenzen

Geschlossener Framework-Eingabehelfer, NGINX-Fixtures und fokussierte Unittests. Tatsächliche Parent-Host-Operationen und native Produktbeobachtungen bleiben getrennte Grenzen.

## Akzeptanzkriterien

Geschlossene Eingaben behalten alle acht Identitäten, begrenzte Antwort-Chunks, ausdrückliche Engine-Limits und deterministische Wiederverwendungsquellen. Unbekannte Identitäten scheitern. Eingabespezifikationen enthalten keinen beobachteten Status und keine erfundenen Events.

## Untersuchte Alternativen

Off-Evidence für safe wiederzuverwenden, beobachtete Ergebnisse aus Eingaben zuzuweisen oder beliebige native Events anzunehmen würde den exakten Vertrag nicht belegen. Geschlossene Eingaben und separate echte Beobachtungen erhalten diese Unterschiede.

## Implementierungsentscheidung

`tests/runners/nginx_phase4_contracts.py` liefert frische begrenzte Spezifikationen und acht eindeutige NGINX-Fixtures. Ein Marker verteilt sich auf 16- und 11-Byte-Chunks; keiner trifft einzeln. Limit-Operationen verwenden 64/65-Byte-Antworten und ausdrückliche `SecResponseBodyLimitAction`-Werte `ProcessPartial` oder `Reject`. Die bestehende Required-Identität `phase4_deny_after_commit_log_only_minimal` verwendet aufgrund der neuesten ausdrücklichen Benutzerentscheidung "minimal muss in safe rein" den bestehenden Modus `safe`. Kein Parser-Modus oder Alias `minimal` wird eingeführt; bestehendes Legacy-Verhalten von off bleibt erhalten. EOS verwendet nur die exakte Split-Operation wieder; begrenzte Metadaten nur die exakte Over-Limit-Operation.

## Geänderte Dateien und Tests

Neuer Helfer, `tests/runners/test_nginx_phase4_contracts.py`, acht Fixtures unter `tests/cases/connector-specific/nginx/` sowie dieses EN/DE-Paar. Gemeinsame Katalog-/Schema-/Normalizer-Integration gehört dem Koordinator.

## Befehle und Ergebnisse

RTK-gekapselte Framework-Python-Unittest-Discovery: Die anfängliche Regression wegen fehlendem Helfer scheiterte; die Implementierung führt neun Tests mit Exit 0 aus. Eine spätere MIME-Scope-Negativkontrolle scheiterte vor Entfernung von gleichgeladenem `SecResponseBodyMimeTypesClear`, das der Merge-Pfad der gepinnten Engine zusammen mit neu hinzugefügten Typen löscht. Eingaben behalten bestehende Defaults und ausdrückliches `text/plain`. YAML-Eingabefixtures sind parsebar. `make check-documentation` und Whitespace-Prüfungen bestehen. Vollständiger nativer Lint bleibt Integrationsarbeit.

## Sicherheitsauswirkung

Keine Selection-Verkleinerung, Validator-Abschwächung, Payload-Events, synthetischen nativen Beobachtungen oder MRTS-Schreibzugriffe. Die Engine besitzt weiterhin die Antwort-Inspektionspolitik; kein kumulatives Connector-Budget wird eingeführt.

## Dokumentation und Runtime-Evidenz

Eingabefixtures sind keine Evidence. Native Chunk-Zustellung, Rule-/EOS-Beobachtung, tatsächliche Engine-Inspektionslänge/-Aktion, Root/nobody, Client-Ergebnis, Cleanup und strenge kanonische Zuordnung bleiben erforderlich. Der externe Entwicklungsfokus `stream-c-r1` rief vor der abschließenden Safe-Migrationsentscheidung tatsächlich alle acht Identitäten mit bestehenden Baseline-Artefakten auf: Split/EOS lieferten HTTP 200 mit nativer Rule/EOS; Engine Reject und die damals gewählte Off-Operation nach Commit erzeugten Client-Exit 18 und native Failure-/Abort-Beobachtungen. Diese beiden Ergebnisse sind kein Vertrags-PASS; Off-Daten beweisen nicht die neu gewählte Safe-Operation. Ein frischer Safe-Aufruf bleibt Pflicht. Insbesondere bleibt die Reject-Fixture future, bis der echte native Operationsvertrag validiert wurde; sie erfindet keine erfolgreiche HTTP-Erwartung. Die Änderungen belegen weder finale Exact-Head-Coverage noch Protected-Abnahme.

## Nicht ausgeführte Prüfungen

Vollständiger Framework-Lint und finale integrierte Host-/CI-/Sonar-Validierung gehören dem Koordinator; Eingabetests ersetzen sie nicht.

## Einschränkungen und Restrisiko

Tatsächliche Engine-Inspektionslänge und natives Limit-Ergebnis sind durch Fixture-Größe oder an Append übergebene Bytes nicht belegt. Eigene native Beobachtung und strenge Zuordnung bleiben Pflicht.

## Finaler Diff- und Review-Status

Implementierung im exklusiven Worktree; keine Veröffentlichung oder Parent-Gitlink-Aktualisierung durch diesen Arbeitsstrang.
