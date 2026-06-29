# Connector-Adapter-Schnittstelle

**Sprache:** [English](connector-adapter-interface.md) | Deutsch

Dieses Dokument ist der stabile Vertrag für zukünftige Connectorbäume. Das ist es nicht
ein Webserver-Implementierungsplan.

## Connector-neutrale Verantwortlichkeiten

Der Shared Runner besitzt YAML Laden, capability/status Validierung, Regel
Materialisierung, Anfrage body/header Generierung, erwartete HTTP Statusprüfungen,
Stabile Audit-Log-Prüfungen und zusammenfassende JSON-Generierung.

Connector-Code besitzt nur serverspezifische build/runtime-Mechaniken: Modul
Laden, Serverkonfiguration, Anforderungsversand, Protokollerfassung und Bereinigung.

## Erforderliche Haken

| Haken | Verantwortung |
| --- | --- |
| `prepare()` | Überprüfen Sie die Voraussetzungen und erstellen Sie generierte Verzeichnisse gemäß `BUILD_ROOT` |
| `start()` | Starten Sie den echten Serverprozess mit geladenem Connector-Modul |
| `stop()` | Stoppen Sie den Serverprozess, ohne veraltete Listener zu hinterlassen |
| `reload()` | Laden Sie die Konfiguration dort neu, wo der Connector sie unterstützt. Andernfalls wird das Dokument nicht unterstützt |
| `apply_rules()` | Installieren Sie generierte ModSecurity-Regeln für einen Fall |
| `materialize_case()` | Wandeln Sie gemeinsam genutzte YAML-Artefakte in Connector-spezifische Konfigurationsdateien um |
| `send_request()` | Senden Sie die echte HTTP-Anfrage aus dem YAML-Fall |
| `collect_logs()` | Kopieren oder referenzieren Sie Server-, Connector-, Audit- und Zugriffsprotokolle |
| `summarize_results()` | Schreiben Sie Connector-JSON/text-Ergebnisse mithilfe eines gemeinsamen Schemas |
| `cleanup()` | Laufzeitstatus unter `BUILD_ROOT` entfernen oder isolieren |

## Grenzregeln

- `common/` und `docs/imports/common/` bleiben konnektorneutral.
- `connectors/<name>/` enthält serverspezifische build/runtime-Logik.
- Generierte Konfigurationen, Protokolle, Downloads und Binärdateien bleiben unter `BUILD_ROOT`.
- Der direkte Erfolg von libmodsecurity API zählt nie als Connector-Erfolg.

Zukünftige HAProxy-, Envoy-, Lighttpd- und Traefik-Adapter müssen dasselbe beweisen
`real-world-connector-path` Semantik, bevor ein häufiger Fall als PASS gewertet wird.
