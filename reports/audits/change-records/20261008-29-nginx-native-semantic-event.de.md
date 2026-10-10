# Änderungsprotokoll

**Sprache:** Deutsch | [English](20261008-29-nginx-native-semantic-event.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change ID | 20261008-29-nginx-native-semantic-event |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | `fa0efc012a6a3b2e7b3f4d660956eab63a94bc67` |
| Issue oder Pull Request | Koordinatorfreigegebene begrenzte Semantik-Korrektur |

## Motivation und Problemstellung

Das erste erhaltene Phase4-Ereignis kann ein erlaubter Append sein, während eine spätere echte Intervention log-only ist. Eine Zusammenfassung aus der ersten Zeile verliert die tatsächliche Ursache. Diese Änderung behauptet keine native Ausführung.

## Betroffene Komponenten und Sicherheitsgrenzen

Nur eigener Faktenvertrag, fokussierte Tests und dieses Dokumentpaar. Strikter Reader, zentrale Akzeptanz, Katalog, Schemas, Parent, MRTS und Gitlinks bleiben unverändert.

## Akzeptanzkriterien

Ein unverändertes tatsächliches Ereignis samt originaler JSONL-Herkunft gemäß geschlossenem Operation/Phase/Rule-Vertrag zurückgeben. Fehlende Fakten, fremde Identität und widersprüchliche gleichartige Bedeutungen zurückweisen. Append-Allow oder LOGGING-Cleanup ersetzen keine frühere Entscheidung.

## Untersuchte Alternativen

Umgeschriebene Felder oder erwartungsbasierte native Evidenz würden Beobachtungen erfinden. Eine Zusammenfassung aus der ersten Zeile erhält die falsche Append-Interpretation. Beides wird nicht verwendet.

## Implementierungsentscheidung

Rückgabe von semantic_native_event, semantic_native_event_origin und semantic_native_event_origins. Ablehnung vor dem Connector liefert None/None/leere Herkunft. Technische Fälle wählen den echten Fehler; Ereignisgrenzen den tatsächlich gekürzten Rule-Match; Rule-basierte Phase4 die Intervention, Rule-lose Fertigstellung completion und Reject body_limit. Request-Deny wählt engine_decision. Phase1-Allow benötigt echtes request_headers_complete. Phase5 wählt tatsächlichen technischen Fehler oder LOGGING-Cleanup. Unter gleichwertigen Zeilen ist Source-first deterministisch; alle geeigneten Herkünfte werden offengelegt. Jedes zurückgegebene Feld stammt unverändert aus erhaltener nativer Evidenz.

## Geänderte Dateien und Tests

tests/runners/nginx_native_operation_contract.py und tests/no_crs/test_nginx_native_operation_contract.py samt Dokumentpaar. Kontrollierte Tests umfassen zwölf Strict-Reader-Phase4/MIME-Varianten, gekürzte Over-Variante, Pre-Connector-Abwesenheit, Pointer-/Finish-Fehler, Cleanup und negative TX-/Rule-/Phase-/Bedeutungskontrollen.

## Befehle und Ergebnisse

Test-first-Semantikprüfungen endeten vor Implementierung mit exit1 wegen fehlendem semantic_native_event. Danach bestanden50 Tests mit exit0 über `rtk proxy env TMPDIR=<external-task-runs> PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 python -m unittest tests.no_crs.test_nginx_native_operation_contract tests.no_crs.test_nginx_native_operation_projection tests.no_crs.test_nginx_native_operation_bundle -q` mit Framework-eigenem Interpreter. `rtk proxy make check-documentation PYTHON=<framework-python>` und `rtk proxy git diff --check` endeten beide mit exit0.

## Sicherheitsauswirkung

Strikte payloadfreie Evidenzauswahl. Keine Produktbehebung oder Akzeptanzumgehung; Originalbytes, Ereignis-Dictionaries und Receipt-Siegel werden nicht umgeschrieben.

## Dokumentation und Runtime-Evidenz

EN/DE-Paar. Reine kontrollierte Source-förmige Fixtures, keine Runtime-Evidenz oder kanonischer PASS.

## Nicht ausgeführte Prüfungen

Native Build-/Runtime-/vollständige E2E-Prüfungen und Remote-Scans waren nicht autorisiert. Keine Toolinstallation.

## Einschränkungen und Restrisiko

Root muss die Zusammenfassung mit expliziter Caller-Autorität und Offline-Revalidierung nutzen und versiegeln. Fehlende echte Producer-Felder bleiben Fehler; kein positiver Runtime-Nachweis aller42 Fälle.

## Finaler Diff- und Review-Status

Vier begrenzte Dateien; keine zentralen Änderungen. Separater normaler Commit nach fokussierter Validierung und Dokumentationsprüfung.
