# Importanalyse: ModSecurity NGINX Connector

**Sprache:** [English](import-analysis-nginx.md) | Deutsch

Status: umgesetzt

Lokaler Bezug: `/root/conecter/ModSecurity-nginx`
Upstream-Quelle: https://github.com/owasp-modsecurity/ModSecurity-nginx
Beobachtete Referenz: `master`, `v1.0.4-14-g9eb44fd`

## Rolle

Dieses Repository ist ein NGINX Connector für libmodsecurity v3. Es ist jetzt ein
Kontrollierter Adapter-eigener Quellimport unter `connectors/nginx/`, mit Modul
`config` im Connector-Root und in Produktivquellen unter `connectors/nginx/src/`. Die
Der ehemalige `connectors/nginx/upstream/`-Baum wurde in der Phase 10 nach dauerhaft entfernt
Die Namensnennung wurde gemäß `licenses/nginx/`, `connectors/nginx/ORIGIN.md` beibehalten.
und `connectors/nginx/SOURCE_MAP.json`. Importierte und migrierte Dateien sind
NGINX-spezifisch gehalten.

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
| NGINX phase/filter Registrierung | Connector | Connector-spezifisch | kompatibel nur für NGINX | Verfolgt in `docs/roadmap/todo-inventory.md` |
| Nginx-Tests-Fälle | Connector | Connector-spezifisch | teilweise | Zu `tests/cases/connector-specific/nginx/` zuordnen |
| Quellcodedateien | Connector | Connector-spezifisch | kompatibel nur für NGINX | Auf Adapter-eigene `connectors/nginx/src/` migriert |

## Importentscheidung

Der Import wird bewusst von `common/` getrennt. NGINX Phasenhandler,
header/body Filter, Konfigurationszusammenführungslogik und NGINX Modul-Build-Metadaten
Bleiben Sie unter `connectors/nginx/`. Zukünftige gemeinsame Extraktionen erfordern einen gesonderten Nachweis
über reale Apache- und NGINX-Smoketests.

## Quellstatus der Phase 9

Das NGINX-Modul `config` befindet sich jetzt unter `connectors/nginx/config`; produktiv
Quelldateien leben unter `connectors/nginx/src/`. Die dem Adapter gehörende Quelle enthält ausgewählte
ModSecurity-nginx PR #377 Quelländerungen von
`3d72b004ff27a78ea19c6b945870e2cae62a97ac`; das ist kein `RESPONSE_BODY`
Hochstufung.
