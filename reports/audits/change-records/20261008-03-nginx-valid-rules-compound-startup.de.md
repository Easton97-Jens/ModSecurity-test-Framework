# Change Record

**Sprache:** [English](20261008-03-nginx-valid-rules-compound-startup.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261008-03-nginx-valid-rules-compound-startup |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | `dc41bd22c335156cae02d9049098b92af65b7c57` |
| Issue oder Pull Request | Freigegebener Branch `fix/nginx-seven-contracts-20261008` und neuer Draft-Folge-PR; externer Parent-PR #396 bleibt Draft. |

## Motivation und Problemstellung

`valid_rules_file` verlangt erfolgreiches Konfigurationsladen und tatsächliche
Regelausführung. Erfolgreiches `nginx -t`, eine vorgegebene Regel-ID oder eine
unabhängige HTTP-Antwort allein belegen diesen zusammengesetzten Vertrag nicht.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-Katalog, Configtest-Receipt-Schema, Artefaktnormalisierung, öffentliche
Contract-API samt generiertem Katalog und No-CRS-Regressionstests. Parent besitzt
die tatsächlichen Host-Operationen. Common-Serialisierung und MRTS bleiben unverändert.

## Akzeptanzkriterien

Der geschlossene Startup-Deskriptor verlangt Konfigurations-Exit `0`, die genaue
akzeptierte Vorlage und Baseline-Regeln. Erhaltene native Evidence für Regel
`1100001` muss Run, Transaktion, Methode `GET`, URI `/no-crs/deny`, Phase und
Status entsprechen. Separate tatsächliche Client-Evidence verlangt HTTP `403`
und Client-Exit `0`. Root-Master/nobody-Worker-Identitäten und verifiziertes
Prozess-/Listener-Cleanup sind Pflicht. Fehlende oder erneut gehashte abweichende
Evidence darf nicht bestehen.

## Untersuchte Alternativen

Reine Configtest-Akzeptanz, Regel-IDs aus Fixture-Text und als beobachtete
Host-Aktion umetikettierte Events reichen nicht. Den bestehenden gebundenen
Receipt-Vertrag erweitern, statt Events zu synthetisieren oder Produktsemantik
zu ändern.

## Implementierungsentscheidung

Raw-Binary-, Modul-, Konfigurations-, Regel-, Configtest-Ausgabe-, native Event-,
Request-Ergebnis-, Rollen- und Cleanup-Artefakte mit strikten Digest- und
Identitätsprüfungen erhalten. Das native Common-Event ist `engine_decision` mit
`MSCONN_EVENT_ENGINE_DECISION`, angeforderter Deny-Aktion und HTTP `403`;
`actual_action` ist leer, `visible_http_status` ist `0` und `transport_result`
ist `not_observable`. Dieses Event allein belegt keine Host-Aktion. Der separat
gebundene echte HTTP-Request liefert diese Beobachtung, ohne das Event umzuschreiben.
Explizites `access_log off` verhindert historische Compile-Prefix-Ausgabepfade
in kopierten Konfigurationen. Öffentliche Startup-API-Unterstützung bleibt auf
den deklarierten NGINX-Vertrag begrenzt und kombiniert Konfigurations-, HTTP-,
Regel- und Lifecycle-Assertions. Bestehende Ablehnungs-Configtests bleiben Configtest-only.

## Geänderte Dateien und Tests

`ci/checks/catalog/no_crs_baseline.py`,
`tests/schemas/no-crs-baseline/configtest-receipt.schema.json`,
`tests/cases/no-crs-baseline/catalog.json`,
`tests/cases/no-crs-baseline/valid_rules_file.yaml`,
`tests/no_crs/test_valid_rules_file_receipt.py`,
`ci/tools/generate-framework-contract-catalog.py`,
`modsecurity_test_framework/contracts.py`,
`modsecurity_test_framework/data/framework-contract-catalog.json` und
`tests/contract_api/test_public_contract_api.py`; dieses EN/DE-Paar. Die
Katalogressource wird über ihren nativen Generator neu erzeugt.

## Befehle und Ergebnisse

Fokussierte Red-/Green-Logs liegen unter
`nginx-seven-contracts-20261008T080604Z` (externe Analysis-Run-ID).
`framework-valid-actual-event-kind-red.log` dokumentiert das Scheitern vor der
Korrektur; `framework-valid-actual-event-kind-green.log` dokumentiert 11 bestandene
Receipt-Tests. Der native Lauf `make test-contract-api` dokumentiert 24 bestandene
Tests und Exit `0` in `framework-startup-api-green.log`; die Katalogaktualitätsprüfung
endete ebenfalls mit `0`. Diese Prüfungen belegen Framework-Verträge, keine
Runtime-Coverage des aktuellen Heads.
`make check-documentation` endete nach den Dokumentationsänderungen mit `0`:
Link-, Bilingual-Variable-, Repository-Pfad- und Change-Record-Prüfungen bestanden.
`git diff --check` endete mit `0`. Alle Command-Payloads verwendeten den
vorgeschriebenen RTK-Proxy.

## Sicherheitsauswirkung

Pfad-, Symlink-, Ownership-, Artefakt-, Provenance-, Status- und Required-Prüfungen
werden nicht abgeschwächt. Zusätzliche Schema-Bedingungen und negative Bindungen
erhalten strikte Validierung. Weder Protected-Runtime-Zertifizierung noch
Produkt-Remediation wird behauptet.

## Dokumentation und Runtime-Evidenz

Dieses EN/DE-Paar dokumentiert Framework-Verhalten. Die externe Diagnose
`diagnostic-valid-r2` beobachtete echten Root-Master/nobody-Worker-HTTP `403`,
natives Regel-Event und Cleanup mit uncommittetem Arbeitsstand und historischen
Binary-/Modul-Artefakten. Dies ist ausschließlich Diagnose-Evidence, keine frische
committete Exact-Head-Coverage. Ein integrierter Standardlauf `full_lifecycle`
steht weiterhin aus.

## Nicht ausgeführte Prüfungen

Vollständiger Framework-Lint/Canonical-Regressionen und frische committete
Standard-Lifecycle-Ergebnisse sind noch nicht abgeglichen. Revisionsgebundene
Remote-CI/Sonar und geschützte Workflow-Evidence fehlen zum Erstellungszeitpunkt.

## Einschränkungen und Restrisiko

`PRODUCT DECISION REQUIRED — invalid_status` bleibt selected und required;
weder Statusbereich noch Directive werden erfunden. Andere Required-Coverage-Lücken
bleiben bestehen. Passende Hashes oder Gesamt-Exit `0` belegen keinen
Gesamt-Exact-Head-PASS.

## Finaler Diff- und Review-Status

Das Dokumentationspaar wurde auf äquivalente Fakten und technische Literale
geprüft; native Dokumentations- und Whitespace-Prüfungen bestanden. Übergabe im
Implementierungsstadium; finaler Source-Diff, vollständige Validierung,
frische Runtime und Delivery-Abgleich stehen aus. Keine Secrets, Raw-Bodies oder
ungeprüften Logs sind eingebettet. Merge und History-Rewrite sind nicht freigegeben.
