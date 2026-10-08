# Change record

**Language:** Deutsch | [English](20261008-11-nginx-actual-phase-overrides.md)

## Identität

| Field | Value |
| --- | --- |
| Change ID | 20261008-11-nginx-actual-phase-overrides |
| UTC date | 2026-10-08 |
| Framework base revision | `9f74f9b742af1498bd642f83306f40549f163f63` |

## Motivation und Problemstellung

NGX-spezifische Registrierung der tatsächlichen Phase. Die Body-Pointer-Mapper-Prüfung und das weiche Engine-Budget vor dem Commit werden bei request_headers beobachtet, nicht in den generischen Phase2-/Phase4-Vertragssichten.

## Betroffene Komponenten und Sicherheitsgrenzen

Nur die zwei geschlossenen NGX-Descriptor-Overrides und das strikte Fallschema ändern sich. Generische Fallphasen, andere Connectoren, zentrale Normalisierung und native Producer bleiben unverändert.

## Akzeptanzkriterien

Genau zwei NGX-Overrides phase=1; die generischen Phasen bleiben 2 und 4. Falsche, fehlende oder nicht ganzzahlige Overrides scheitern an der Schemavalidierung.

## Untersuchte Alternativen

Die generischen Phase2/4 als native Beobachtung zu akzeptieren würde eine Phase erfinden. Das connectorlokale Override erhält den generischen Vertrag und zeigt die tatsächliche P1.

## Implementierungsentscheidung

Source access.c validiert den Common-Request-Mapper vor der Engine-Verarbeitung; Initialisierungsfehler gelangen mit REQUEST_HEADERS in request_result. Der synchrone Request-Headers-Aufruf liegt zwischen engine_call_begin/finish. Dies belegt die Beobachtungsgrenze im Quelltext, keinen Runtime-PASS.

Root-Integration bindet außerdem `clean_shutdown` durch ein geschlossenes natives `expected_status`-Override an das tatsächliche NGINX-Wire-HTTP200. Generischer erwarteter Status0 bleibt unverändert; tatsächlicher Prozess-Exit0 und abgeschlossenes Cleanup bleiben separat im strikten Original-Sequence-Beleg erforderlich. HTTP0 ersetzt niemals den echten Requeststatus.

| case_id | Generic phase | NGX phase |
| --- | --- | --- |
| body_size_nonzero_with_null_data | 2 | 1 |
| engine_timeout_before_commit | 4 | 1 |

## Geänderte Dateien und Tests

catalog.json, case-catalog.schema.json, test_nginx_native_invocation_catalog.py, paired record.

## Befehle und Ergebnisse

Der erste fokussierte Lauf scheiterte mit zwei fehlenden Phasen und einer Descriptor-Abweichung. Nach Katalog-/Schemaänderung bestanden 20 Registry-/Selection-Kontrollen. Externes Log: stream-c-phase-override-green.log.

Das fehlende Clean-Shutdown-Wire-Override erzeugte vor der ausdrücklichen Katalog-/Schemaregistrierung eine rote Projektionskontrolle. Frische integrierte Registry-/Projektionstests sind vor dem Folgecommit erforderlich.

## Sicherheitsauswirkung

Closed per-ID schema rejects generic-phase substitution, boolean/string/null phase values and removal. No Required IDs or capabilities are removed.

## Dokumentation und Runtime-Evidenz

Source review: ngx_http_modsecurity_access.c mapper guard and request-result P1 boundary; actual request-headers budget glue. Native execution remains independently required.

## Nicht ausgeführte Prüfungen

Kein nativer Build oder Runtime-Lauf. Root verantwortet das Normalizer-Overlay und die integrierte Evidenzprüfung.

## Einschränkungen und Restrisiko

The registry describes expected observation inputs; it does not itself produce or validate native observations.

## Finaler Diff- und Review-Status

Focused Framework catalog/schema/test slice only; no Root worktree edits, central normalizer changes, Parent Gitlinks or MRTS changes.
