# Änderungsnachweis

**Sprache:** [English](20261008-26-nginx-native-event-vocabulary.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change ID | 20261008-26-nginx-native-event-vocabulary |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | `7ea908b8c0404621f9f979317c6d3f40f6b22178` |

## Motivation und Problemstellung

Common gibt geschlossene allow/pass/error-Aktionen und konkrete Transaktionsfehlerklassen aus, die das Canonical-Vokabular bisher nicht abbildete.

## Betroffene Komponenten und Sicherheitsgrenzen

Canonical-Vokabularkonstanten, Event-/Case-Result-Schemas und Fokustests. Keine Änderung an Auswahl, Required-Scope, Runtime-Identität oder Source-Autorität.

## Akzeptanzkriterien

Tatsächliche dokumentierte Common-Skalarwerte akzeptieren; beliebige Aktionen, Phasen, Cleanup-Ursachen, verschachtelte Felder und Payloads weiterhin ablehnen.

## Untersuchte Alternativen

Tatsächliche native Felder zu entfernen oder beliebige Strings zu erlauben würde die Originalbeobachtung verdecken und die Prüfung schwächen.

## Implementierungsentscheidung

Nur ausdrückliche Enum-Mitglieder für Common-Aktionen, Engine-Aufrufphasen und Common-Cleanup-Fehlerklassen ergänzen. Logging-Cleanup ist keine Request-Header-Allow-Evidence.

## Geänderte Dateien und Tests

`ci/checks/catalog/no_crs_baseline.py`, `tests/schemas/no-crs-baseline/event.schema.json`, `case-result.schema.json`, `tests/no_crs/test_nginx_native_event_vocabulary.py` und dieses EN/DE-Paar.

## Befehle und Ergebnisse

Drei rote Kontrollen vor der Änderung beobachtet. 31 RTK-gekapselte Vokabular-, Transport-Hardening-, Selected-Status- und Case-Binding-Tests bestanden; externes Log `root-native-vocabulary-green.log`. Dokumentations- und Whitespace-Prüfungen sind vor dem Commit erforderlich.

## Sicherheitsauswirkung

Enum-Prüfung bleibt geschlossen; keine beliebigen Strings, Payload-Ausnahmen, synthetischen Events oder Cleanup-zu-Request-Aufwertung.

## Dokumentation und Runtime-Evidenz

Dieser Record dokumentiert nur Source-Vertragsprüfung. Kein frischer NGINX-Request oder Canonical-PASS nachgewiesen.

## Nicht ausgeführte Prüfungen

Vollständiger Lint, frischer integrierter E2E und geschützter Exact-Head-Workflow fehlen weiterhin; die native Canonical-Anbindung ist unvollständig.

## Einschränkungen und Restrisiko

Ein bekanntes Enum beweist weder Event-Identität noch Authentizität. Strikte sourcegebundene, erhaltene Evidence bleibt erforderlich.

## Finaler Diff- und Review-Status

Vier fokussierte Produkt-/Testdateien und Record-Paar; Required-Auswahl und Statusprioritäten unverändert.
