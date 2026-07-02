# Security-Data-Flow-Framework-Tests

Diese Tests definieren connector-neutrale Security- und Data-Flow-Cases im Framework. Sie implementieren keinen Connector-Code, keinen gemeinsamen Runtime-Code, keine Server-Adapter, keine Harness-Entrypoints, keine Adapter-Metadaten und keine Runtime-Evidence.

Ein Connector-Repository muss diese Cases ausführen und Runtime-Evidence im Connector-Repository ablegen. Ein Starter-PASS ist keine Runtime-Evidence, und kein Case in dieser Kategorie behauptet Production-Readiness, CRS-Abdeckung, ein Full-Matrix-Ergebnis oder RESPONSE_BODY-Verifikation. RESPONSE_BODY bleibt unverifiziert, bis stabile Connector-Runtime-Evidence existiert.

## Geprüfte Risiken

- Header-Manipulation: Header-Anzahl-Limits, zu große Werte und konfliktierende Content-Length-Header.
- Body-Limit- und DoS-Verhalten: deterministische Policy für Request-Body über Limit und Evidence für Response-Body-Truncation.
- Transaction-ID-Sicherheit: Ablehnung von Control Characters, CR/LF, nicht druckbaren Bytes und zu langen IDs, außer Truncation-Evidence ist explizit sichtbar.
- Phase-Order und Flow-Guards: übersprungene Phasen und doppelte mutierende Phasenverarbeitung müssen durch Connector-Evidence abgelehnt oder als idempotent/readonly markiert werden.
- Decision/Event-JSONL-Sicherheit: Logs dürfen keine Request- oder Response-Body-Payload-Felder enthalten und sollten Transaction-ID, Phase, Action/Decision, HTTP-Status sowie Redaction-/Truncation-Hinweise prüfen können, wenn Connectoren sie liefern.
- Hash-Chain-/Tamper-Evidence: sequence, previous_event_hash und event_hash können durch Framework-Normalizer validiert werden.
- Log-Sanitizing/Redaction: Control Characters und secret-/payload-artige Werte müssen sanitized oder redacted werden.

## Hash-Hinweis

Nicht-kryptografische oder reine CI-Hash-Chain-Evidence reicht nur für Smoke-Tamper-Detection. Echte Manipulationssicherheit benötigt connector-seitige HMACs oder Signaturen mit sicherem Key-Handling und append-only Storage.
