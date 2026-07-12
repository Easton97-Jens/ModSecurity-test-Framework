# Importanalyse: ModSecurity v3 / libmodsecurity

**Sprache:** [English](import-analysis-modsecurity-v3.md) | Deutsch

Status: umgesetzt

Lokaler Bezug: `<workspace>/ModSecurity_V3`
Upstream-Quelle: https://github.com/owasp-modsecurity/ModSecurity
Beobachtete Referenz: `v3/master`, `v3.0.15`

## Rolle

Dies ist die primäre Architektur und API Referenz für neue Connector-Arbeiten.
Es stellt die Connector-neutrale libmodsecurity-Engine und öffentliche C/C++ APIs bereit.

## Build-System

Beobachtete Dateien:

- `configure.ac`
- `Makefile.am`
- `src/Makefile.am`
- `test/Makefile.am`
- `modsecurity.pc.in`

Der v3-Baum erstellt eine Bibliothek und testet Binärdateien über Autotools. Windows-Build
Dateien sind unter `build/win32/` vorhanden, aber dieses Gerüst verbraucht sie nicht.

## Connectorneutrale Komponenten

Wiederverwendbare Konzepte ab v3:

| Komponente | Quelle | Umfang | Kompatibilität | Notizen |
| --- | --- | --- | --- | --- |
| `ModSecurity` Lebenszyklus der Instanz | v3 | motorspezifisch | kompatibel | Öffentliches C API: `msc_init`, `msc_cleanup` |
| Regeln legen den Lebenszyklus fest | v3 | motorspezifisch | kompatibel | `msc_create_rules_set`, `msc_rules_add*`, `msc_rules_cleanup` |
| Transaktionslebenszyklus | v3 | motorspezifisch | kompatibel | `msc_new_transaction*`, Phasenaufrufe, Aufräumen |
| Interventionsmodell | v3 | motorspezifisch | kompatibel | `ModSecurityIntervention`, `msc_intervention` |
| Rückruf protokollieren | v3 | motorspezifisch | kompatibel | `msc_set_log_cb`; Die Rückrufnutzlast hängt von der Protokolleigenschaft ab |
| Regression JSON Fälle | v3 | motorspezifisch | teilweise kompatibel | Gute tragbare Kandidaten nach Fähigkeitsprüfung |

## Relevante öffentliche APIs

Zukünftige Connector-Adapter sollten um das öffentliche C API herum aufgebaut werden:

- Motor: `msc_init`, `msc_set_connector_info`, `msc_set_log_cb`, `msc_cleanup`
- Regeln: `msc_create_rules_set`, `msc_rules_add`, `msc_rules_add_file`,
  `msc_rules_add_remote`, `msc_rules_merge`, `msc_rules_cleanup`
- Transaktion: `msc_new_transaction`, `msc_new_transaction_with_id`,
  `msc_transaction_cleanup`
- Anforderungsphasen: `msc_process_connection`, `msc_process_uri`,
  `msc_add_n_request_header`, `msc_process_request_headers`,
  `msc_append_request_body`, `msc_process_request_body`
- Antwortphasen: `msc_add_n_response_header`,
  `msc_process_response_headers`, `msc_append_response_body`,
  `msc_process_response_body`
- Finalisierung: `msc_update_status_code`, `msc_process_logging`,
  `msc_intervention`, `msc_intervention_cleanup`

## Transaktionslebenszyklus

v3 trennt Verbindungshaken von Motorphasen. Dafür ist ein Connector zuständig
Rufen Sie die öffentlichen API in der Reihenfolge auf, die ihre Laufzeit unterstützen kann. Fehlende Phasen müssen
als Fähigkeitslücken dokumentiert und nicht versteckt werden.

## Protokollierung

v3 stellt einen Serverprotokollrückruf über `msc_set_log_cb` bereit. Audit/debug Protokoll
Das Verhalten hängt immer noch von rules/configuration und Engine-Interna ab. Dieses Repo
implementiert die Protokollsammlung noch nicht; Es definiert nur Normalisierergerüste und
Artefaktsammlungs-Hooks in der Runner-Schnittstelle.

## Tests

Beobachtete v3-Tests umfassen JSON Regressionsfälle unter
`test/test-cases/regression/` und C++-Runner unter `test/regression/`.
Diese JSON-Fälle sind die bevorzugte tragbare Engine-Testquelle, vorbehaltlich
Fähigkeitsüberprüfung.
