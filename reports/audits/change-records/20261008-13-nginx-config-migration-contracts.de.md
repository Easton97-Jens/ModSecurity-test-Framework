# NGINX-Konfigurationsmigrationsverträge

**Sprache:** Deutsch | [English](20261008-13-nginx-config-migration-contracts.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20261008-13-nginx-config-migration-contracts` |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | `11e1d20990d4ecbbcf18641782b04f0bb6369c69` |
| Issue oder Pull Request | Framework-PR #137 Folgearbeit; nicht veröffentlicht |

## Motivation und Problemstellung

Drei ausgewählten Required-Konfigurationscases fehlten explizite Hostoperationen.

## Betroffene Komponenten und Sicherheitsgrenzen

Der neue `ci/lib/nginx_migration_config_contracts.py` deklariert Verträge,
keine Beobachtungen. Strikte Artefakt-/Operations-Evidence bleibt erforderlich.

## Akzeptanzkriterien

Genau drei geschlossene Verträge, präzise Fehlergründe, unabhängige Kopien,
keine neue numerische Statusrange oder Engine-MIME-Dateiverarbeitungsbehauptung.

## Untersuchte Alternativen

Keine neue Common-Statusdirektive oder Wiederherstellung der entfernten API.
Der Benutzer wählte lexikalischen Parser-/Removed-API-Ablehnungsvertrag.

## Implementierungsentscheidung

`invalid_status` verwendet ungültige Engine-Aktion `status:not-a-number`.
`phase4_invalid_scope_file` und `phase4_wildcard_scope_rejected` lehnen die
entfernte `modsecurity_phase4_content_types_file`-API ab, nicht Dateiinhalte.
Der Koordinator integriert strikte Katalog-, Receipt- und Parent-Dispatch-Bindung.
Deklarationen allein sind keine kanonische Evidence.

## Geänderte Dateien und Tests

Helper, `tests/no_crs/test_nginx_migration_config_contracts.py` und dieses
englisch/deutsche Paar. Vier Tests schützen exakte Operationen und Mutationsisolation.

## Befehle und Ergebnisse

RTK-umhüllte Framework-Python-Unittest-Discovery: fehlender Helper RED Exit 1;
implementierter Helper GREEN Exit 0, vier Tests. Der native Dokumentationscheck
lehnte zunächst die Struktur ab; korrigierte Records werden vor Übergabe geprüft.

## Sicherheitsauswirkung

Keine Änderung an Validatoren, Required-Selection, Produktpolitik oder MRTS.
Beliebige Nonzero-Exits erfüllen den Vertrag nicht.

## Dokumentation und Runtime-Evidenz

Echte diagnostische NGINX-1.31.6-Configtests beobachteten Exit 1 für lexikalische
Statussyntax sowie zwei Removed-API-Ablehnungen mit exakten Diagnosen.
Konfigurationen, Fixture-Bytes, Captures und Artefaktdigests verbleiben im externen
Task `nginx-all-required-20261008T124555Z`. Unveränderte committete Artefakte,
kein neuer integrierter Exact-Head oder kanonischer PASS. Beide Records sind gleichwertig.

## Nicht ausgeführte Prüfungen

Integrierte Runtime, vollständiger Framework-Lint und Remote-CI/Sonar warten auf Integration.

## Einschränkungen und Restrisiko

Zentraler Katalog, Validator, Schema und Parent-Wiring gehören dem Koordinator.
Test-Erwartungen begründen keine neue Source-Politik.

## Finaler Diff- und Review-Status

Nur explizite Scheibendateien staged; kein Push, Merge oder Parent-Gitlink-Update
durch diesen Workstream. Integrierte finale Abnahme bleibt offen.
