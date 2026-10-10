# Change record

**Sprache:** Deutsch | [English](20261010-03-removed-phase4-body-limit-contract.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261010-03-removed-phase4-body-limit-contract |
| UTC-Datum | 2026-10-10 |
| Framework-Basis | 3a1932ef9060103d3a63b47d87c36006af954ee6 |
| PR | Framework137; Parent-Integration396 separat |

## Motivation und Problemstellung

Der Benutzer entfernt die reine Parent-Kompatibilitäts-API `modsecurity_phase4_body_limit` ausdrücklich repositoryweit und genehmigt die Migration des bestehenden Required-Records `invalid_size` zu einem echten Ablehnungstest der entfernten API.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-Konfigurationskatalog, geschlossene Validierungszuordnung, Tests, generierter Paketkatalog und zweisprachige Dokumentation. Parent-Produktänderungen und anschließender Gitlink-Update sind separat. MRTS bleibt read-only.

## Akzeptanzkriterien

Required-Identität und Auswahl behalten; den früher gültigen Wert 1048576 mit exakter Unknown-Directive-Diagnose und Prozess-Exit 1 ablehnen. Alte Größenparser-Fehler, unabhängige Diagnosen und Identitäts-/Artefakt-Abweichungen dürfen nicht bestehen. Die vier Engine-Response-Limit-Cases bleiben unverändert.

## Untersuchte Alternativen

Required-Record entfernen, beliebige Nonzero-Exits akzeptieren, HTTP/Events erfinden und Validatoren abschwächen wurden verworfen.

## Implementierungsentscheidung

Fehlerklasse `removed_directive`, Input `modsecurity_phase4_body_limit 1048576;` und Diagnose `unknown directive "modsecurity_phase4_body_limit"`. Die stabile Required-ID bleibt `invalid_size`; ihr Titel beschreibt ausdrücklich den neu freigegebenen Vertrag. Keine Schemaerweiterung nötig.

## Geänderte Dateien und Tests

`ci/checks/catalog/no_crs_baseline.py`, Quellkatalog, `tests/no_crs/test_configtest_size.py`, generierter Paketkatalog und `docs/testing-and-evidence.md` / deutsche Begleitdatei.

## Befehle und Ergebnisse

Mit RTK und Framework-Python: fokussierter Größenvertrags-Unittest RED (9 Tests, drei Fehler und ein Closed-Template-Error gegen den alten Descriptor); GREEN (9 Tests, Exit 0). Gesamte No-CRS-Suite:415 Tests, Exit0, keine SKIPs; öffentliche Contract-API:30 Tests, Exit0. Nativer Katalog166 im aktuellen Worktree, Aktualität des generierten Katalogs und Dokumentationschecks Exit0. Die Negativkontrollen hashen manipuliertes stderr vor der Validierung erneut, damit ein bloßer Digest-Mismatch keine fälschlich akzeptierte Diagnose verbirgt. Integrierte Clean-Head-Checks bleiben separate Koordinator-Evidence.

## Sicherheitsauswirkung

Echter Configtest-Exit, exakte Diagnose, Case-/Run-/Source-Identität sowie Originaldigests von Binary/Modul/Config/Logs bleiben erforderlich. Keine Required-Verkleinerung, Protokoll-Umetikettierung oder synthetische Runtime-Evidence.

## Dokumentation und Runtime-Evidenz

Unit-Fixtures sind kein Hostnachweis. Frischer Parent-Build und echter Configtest sind für das neue exakte Tupel erforderlich; alte Größenparser-Evidence erfüllt den migrierten Record nicht.

## Nicht ausgeführte Prüfungen

Frische Parent-Runtime, Full97, geschützter Workflow und Server-CI/Sonar sind separate Integrationsevidence und werden hier nicht behauptet.

## Einschränkungen und Restrisiko

Dies ist eine freigegebene inkompatible API-Entfernung. Lokale Framework-Python3.14.7 ist nicht exakte CI3.14.8.

## Finaler Diff- und Review-Status

Der Koordinator reviewt diese unabhängige Framework-Änderung und übernimmt Veröffentlichung sowie den separaten Parent-Gitlink-Update; keine Historienumschreibung.
