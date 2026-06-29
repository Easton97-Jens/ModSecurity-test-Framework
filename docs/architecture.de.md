# Architektur

**Sprache:** [English](architecture.md) | Deutsch

Status: eingerüstet

## Richtung

Neue Connector-Arbeit zielt auf libmodsecurity v3 ab. Der lokale v3-Checkout macht a verfügbar
Connector-neutrale Engine mit öffentlichen C- und C++-APIs unter
`headers/modsecurity/`.

Der vorgesehene Adapterfluss ist:

1. Der Connector-Hook empfängt den Anforderungsstatus server/proxy.
2. Der Connector-Adapter übersetzt den server/proxy-Status in eine neutrale Anforderungsansicht.
3. Der Connector-Adapter ruft die öffentlichen APIs von libmodsecurity v3 in der Phasenreihenfolge auf.
4. Der Connector-Adapter übersetzt Eingriffe zurück in das server/proxy-Verhalten.
5. Konnektorspezifische Tests beweisen das Hook-Timing und die Artefaktsammlung.

## Gemeinsame Grenze

`common/` enthält nur neutrale Datenformen. Es besitzt keine server/proxy
Objekte und enthält keine Connector-SDK-Header.

`connectors/<name>/` besitzt alle server/proxy Integrationen:

- Hook-Registrierung
- module/filter/plugin Baukleber
- Laufzeitkonfiguration
- server/proxy-specific Anforderungs- und Antwortübersetzung
- Connector-spezifische Tests

## v3-Transaktionsfluss

Die lokalen v3-Header und -Quellen stellen diese relevanten öffentlichen C-APIs bereit:

- `msc_init`, `msc_set_connector_info`, `msc_set_log_cb`, `msc_cleanup`
- `msc_create_rules_set`, `msc_rules_add`, `msc_rules_add_file`,
`msc_rules_add_remote`, `msc_rules_merge`, `msc_rules_cleanup`
- `msc_new_transaction`, `msc_new_transaction_with_id`
- `msc_process_connection`, `msc_process_uri`,
  `msc_add_n_request_header`, `msc_process_request_headers`,
  `msc_append_request_body`, `msc_process_request_body`,
  `msc_add_n_response_header`, `msc_process_response_headers`,
  `msc_append_response_body`, `msc_process_response_body`,
  `msc_update_status_code`, `msc_process_logging`
- `msc_intervention`, `msc_intervention_cleanup`,
  `msc_transaction_cleanup`

Der Konnektor darf nur Phasen aufrufen, die er tatsächlich unterstützen und fehlende dokumentieren kann
oder Teilphasen als Fähigkeitslücken.

## Statusbedingungen

- `implemented`: in diesem Gerüst vorhanden und lokal überprüft.
- `scaffolded`: Struktur oder Schnittstelle vorhanden, Verhalten ist nicht vollständig.
- `planned`: geplante spätere Arbeit mit bekannter Richtung.
- `unknown`: Fakten müssen noch durch Quellennachweis oder Dokumentation nachgewiesen werden.
- `blocked`: Die Arbeit kann nicht ohne eine externe Entscheidung, Quelle oder Prüfung fortgesetzt werden.
