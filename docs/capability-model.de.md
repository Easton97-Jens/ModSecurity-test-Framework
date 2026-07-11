# Fähigkeitsmodell

**Sprache:** [English](capability-model.md) | Deutsch

Fähigkeiten beschreiben, was ein YAML-Fall ausübt. Es handelt sich nicht um Nachweislabels
automatische Sprünge. Eine Fähigkeit gilt nur dann als verifiziert, wenn es sich um einen echten Connector handelt
Der Smoke-Fall läuft über Apache oder NGINX.

## Aktive Fähigkeitsnamen

| Fähigkeit | Bedeutung | Verifizierte Variablenzuordnung |
| --- | --- | --- |
| `multipart` | Deterministische multipart/form-data Anforderungsgenerierung | keines für sich |
| `files` | `FILES_*` mehrteilige Sammlungen | `FILES` |
| `xml` | XML Körperprozessor und XML Erfassungsverhalten | `XML` |
| `json` | JSON oder rohes JSON Anforderungskörperverhalten | `REQUEST_BODY` |
| `response-body` | Antworttext access/pass-through Verhalten | nicht `RESPONSE_BODY`, bis die Blockierung vorüber ist |
| `audit-log` | Stabile Audit-Log-Felder werden bestätigt | `AUDIT_LOG` |
| `audit-log-absent` | Erwartete Abwesenheit des Audit-Protokolls; Wird derzeit nur für nicht hochgestufte Sonden verwendet | keine |
| `collections` | Verhalten der ModSecurity-Sammlung | keines für sich |
| `request-cookies` | Cookie value/name Sammlungen | `REQUEST_COOKIES` |
| `args-names` | Sammlung von Argumentnamen | `ARGS_NAMES` |
| `request-uri` | Rohanforderung URI Variable | `REQUEST_URI` |
| `response-headers` | Antwortheader phase/filter Verhalten | `RESPONSE_HEADERS` |
| `request-headers` | Fordern Sie Header-Werte oder -Namen an | `REQUEST_HEADERS` |
| `request-body` | Körperzugriff anfordern | `REQUEST_BODY` |
| `query-args` / `form-urlencoded` | Abfrage- oder URL-codierte Textargumente | `ARGS` |

`RESPONSE_BODY` wird in `verified_variables` während absichtlich nicht ausgegeben
`response_body_basic_block` bleibt non-promoted/mapped-only.

## Full-Lifecycle-No-CRS-Vokabular

Das kanonische No-CRS-Manifest verwendet Capability-Schlüssel mit Unterstrich.
Die Full-Lifecycle-Ergänzungen sind `transport_metadata`,
`request_body_incremental_ingest`, `response_body_incremental_ingest`,
`phase4_end_of_stream_evaluation`, `content_type_scope`, `header_limits`,
`request_body_limits`, `response_body_limits`, `no_full_response_buffering`,
`first_byte_before_response_end`, `http1_content_length`, `http1_chunked`,
`keep_alive`, `parallel_requests`, `http2`, `client_abort`, `upstream_abort`
und `response_body_decompression`.

`response_body_incremental_ingest` ist von der Behauptung getrennt, dass eine
Phase-4-Regel für jeden Chunk ausgewertet wird. Ein Connector kann korrekt
`phase4_end_of_stream_evaluation` deklarieren, wenn er Chunks inkrementell
übergibt, die Engine die Regelauswertung aber erst am Streamende abschließt.
Die No-Buffer- und First-Byte-Capabilities benötigen synchronisierte
Real-Host-Evidence; die Existenz eines Fixtures, Konfiguration oder ein
Mapper-Selbsttest reicht nicht für `verified`.

## Validierungsregeln

YAML Fälle können Fähigkeiten als Liste oder als Zuordnung von booleschen Werten ausdrücken.
Unterstrich-Aliase wie `request_body` werden zu Bindestrichnamen wie z. B. normalisiert
`request-body`. Unbekannte Funktionsnamen können nicht materialisiert werden.

Fähigkeiten entscheiden nicht darüber, ob ein Fall aktiv ist. Themenpfade bieten
category/scope; YAML Statusmetadaten bieten aktives Verhalten im Vergleich zum Inventarverhalten:

- Fälle mit fehlenden `status` werden als aktiv behandelt.
- Fälle mit `status: imported`, `minimal`, `v2-imported` oder `v3-imported`
  bleiben aus Kompatibilitätsgründen Standard-Laufzeitkandidaten.
- Fälle mit historischen Metadaten zu erwarteten Fehlern, `pending`, `future`,
  `connector-gap` oder `runtime-difference` Klassifizierung sind
  inventory/evidence Fälle, es sei denn, es wird eine erzwungene Vollstreckung gefordert.
- Konnektorspezifische Fälle sind nur für den entsprechenden Konnektor aktiv.
