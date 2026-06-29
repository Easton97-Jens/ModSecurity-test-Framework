# Importanalyse: ModSecurity NGINX Connector

**Sprache:** [English](import-analysis-nginx.md) | Deutsch

Status: umgesetzt

Lokale Quelle: `<workspace>/ModSecurity-nginx`
Beobachtete Referenz: `master`, `v1.0.4-14-g9eb44fd`

## Rolle

Dieses Repository ist ein NGINX Connector für libmodsecurity v3. Es ist eine Quelle von
NGINX-spezifische module/filter Konzepte und Testzuordnung, keine Quelle zum Kopieren
blind.

## Build-System

Beobachtete Dateien:

- `config`
- `README.md`

Build folgt NGINX Modulkonventionen von Drittanbietern mit `--add-module` oder
`--add-dynamic-module` wie in der Quell-README-Datei dokumentiert.

## Testsystem

Beobachtete Tests:

- `tests/README.md`
- `tests/modsecurity-*.t`
- `tests/nginx-tests-cvt.pl`

Die Tests sind NGINX-spezifisch und hängen vom Nginx-Test-Harness und den `prove` ab.

## libmodsecurity v3 Verwendung

Beobachtete öffentliche C API-Aufrufe umfassen engine/ruleset Einrichtung, Transaktionserstellung,
request/response Phasenaufrufe, Protokollierung, Eingriffsbehandlung und Bereinigung.

## NGINX Haken

Beobachtete Konzepte:

- HTTP Zugriffsphasenhandler
- HTTP Protokollphasenhandler
- Header-Filter
- Körperfilter
- location/main Konfigurationserstellung und Zusammenführung
- dynamic/static Überlegungen zur Modulreihenfolge

Dies sind `connector-specific` und gehören nur unter `connectors/nginx/`.

## Wiederverwendungsklassifizierung

| Konzept | Quelle | Umfang | Kompatibilität | Entscheidung |
| --- | --- | --- | --- | --- |
| v3 C API Phasenfolge | v3 über Connector | motorspezifisch | kompatibel | Dokumentieren und anpassen |
| NGINX phase/filter Registrierung | Connector | Connector-spezifisch | kompatibel nur für NGINX | NGINX docs/TODO |
| Nginx-Tests-Fälle | Connector | Connector-spezifisch | teilweise | Zu `tests/nginx/` zuordnen |
| Quellcodedateien | Connector | Connector-spezifisch | unbekannt | Kein Import ohne license/proven Notwendigkeit |
