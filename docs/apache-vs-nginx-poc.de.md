# Apache vs. NGINX PoC

**Sprache:** [English](apache-vs-nginx-poc.md) | Deutsch

Status: eingerüstet

## Geteiltes Verhalten

Beide Connector-PoCs verwenden die gleichen tragbaren Gehäuse:

```text
tests/cases/*.yaml
tests/cases/*.yaml
tests/cases/*.yaml
tests/cases/*.yaml
```

Geteilte Stücke:

- `tests/runners/case_cli.py materialize` schreibt Connector-Laufzeitregeldateien
  und Anforderungsvariablen aus dem YAML-Fall.
- `tests/runners/case_cli.py assert-status` vergleicht den beobachteten HTTP-Status
  mit `expect.status`.
- Der erwartete Nachweis ist der HTTP-Status, der derzeit in jeder YAML-Datei codiert ist
  HTTP `403` für alle minimalen Blockierungsfälle.

Der gemeinsame Fall ist ein rule/request/expectation-Modell. Es ist kein Nachweis für a
Connector, bis der Laufzeitkabelbaum dieses Connectors die erwarteten HTTP einhält
Status.

`make smoke-common` führt nur diese häufigen Fälle sowohl auf Apache als auch auf NGINX aus.
`make smoke-all` führt auch Connector-spezifische importierte Fälle bei ihrem Abgleich aus
Connector.

Der Proof-Modus für beide PoCs ist `real-world-connector-path`: ein echter HTTP Client
kommuniziert mit einem realen Serverprozess, der Server lädt das reale Connector-Modul, das
Das Modul ruft libmodsecurity auf und die beobachtete HTTP-Antwort muss mit der YAML-Antwort übereinstimmen.
Erwartung. Direkte libmodsecurity API Smoke-Ergebnisse sind separat und nicht
als Connector-Erfolg gezählt.

## Connectorspezifische Teile

Apache:

- Build-Integration verwendet APXS/Autotools aus dem lokalen `ModSecurity-apache`
Quellkopie.
- Die Laufzeit lädt `mod_security3.so` mit `LoadModule security3_module`.
- Die Konfiguration ermöglicht `modsecurity on` und verweist auf `modsecurity_rules_file`
  die materialisierte Regeldatei.
- Ein von einer lokalen Quelle erstellter Apache-httpd-Smoke hat den von YAML erwarteten HTTP beobachtet.
  Status für alle aktuell freigegebenen Minimalfälle.

NGINX:

- Die Build-Integration verwendet den dynamischen Modulpfad ModSecurity-nginx eines Drittanbieters
  mit `--with-compat --add-dynamic-module=...`.
- Die Laufzeit lädt `ngx_http_modsecurity_module.so` mit `load_module`.
- Die Konfiguration ermöglicht `modsecurity on` und verweist auf `modsecurity_rules_file`
  die materialisierte Regeldatei.
- Ein von einer lokalen Quelle erstellter NGINX-Smoke hat den von YAML erwarteten HTTP-Status beobachtet
  für alle aktuellen gemeinsamen Minimalfälle.
- NGINX-spezifische importierte Fälle derzeit unter `tests/cases/connector-specific/nginx/`
  Cover-Umleitung und TX-Scoring-Verhalten aus der lokalen NGINX-Suite. Sie bleiben
  Nur NGINX, bis die Apache-Äquivalenz explizit getestet wird.

## Unterschiede im Lebenszyklus

Apache und NGINX stellen unterschiedliche Hook-Modelle bereit. Der geteilte Runner absichtlich
modelliert keine Haken; es stellt nur die tragbaren Testdaten bereit.

Beobachtete NGINX lokale Quellenfakten:

- Die Zugriffsverwaltung wird in `NGX_HTTP_ACCESS_PHASE` registriert.
- Die Protokollierung wird in `NGX_HTTP_LOG_PHASE` registriert.
- Header- und Body-Filter werden separat installiert.
- Die Verarbeitung des Antworttexts hängt von der Filterreihenfolge NGINX ab.

Apache-Hook-Details bleiben Connector-spezifisch und werden in dokumentiert
`docs/import-analysis-apache.md` und `docs/apache-poc.md`.

## Unterschiede aufbauen

Der Apache-Source-Build-Modus lädt httpd, APR und APR-util unter herunter und erstellt sie
`BUILD_ROOT`. NGINX Der Source-Build-Modus lädt die offizielle GitHub-Version herunter
Archiv aus `nginx/nginx`, erstellt NGINX unter `BUILD_ROOT` und schreibt das
dynamisches Modul unter:

```text
$BUILD_ROOT/nginx-runtime/nginx/modules/ngx_http_modsecurity_module.so
```

Keiner von PoC schreibt an `/usr`, `/usr/local`, `/etc/apache2`, `/etc/nginx` oder
`<workspace>/*`.

## Aktueller lokaler Vergleich

Beobachtet am 15.05.2026 mit `BUILD_ROOT=/src/ModSecurity-test-Framework-build`:

| Geteilter Fall | Apache, httpd 2.4.67 | NGINX, Nginx 1.31.0 von `release-1.31.0` |
| --- | --- | --- |
| `audit_log_phase1_block.yaml` | HTTP 403 plus Prüffelder | HTTP 403 plus Prüffelder |
| `phase1_header_block.yaml` | HTTP 403 | HTTP 403 |
| `phase2_args_block.yaml` | HTTP 403 | HTTP 403 |
| `phase2_args_pass.yaml` | HTTP 200 plus Ursprungskörper | HTTP 200 plus Ursprungskörper |
| `request_body_json_block.yaml` | HTTP 403 | HTTP 403 |
| `request_body_urlencoded_block.yaml` | HTTP 403 | HTTP 403 |
| `response_header_basic.yaml` | HTTP 403 | HTTP 403 |

Dies beweist, dass diese gemeinsamen PoC-Fälle nur für diesen Arbeitsbereich gelten. Breiter
Für die Kompatibilität ist weiterhin eine Connector-spezifische Regressionsabdeckung erforderlich.

Importierte häufige Fälle fügen Phasenaktion, Sammlung und Anforderungstextabdeckung hinzu.
Ihre Quellpfade und Portabilitätsentscheidungen sind in dokumentiert
`docs/imports/common/shared-case-origin-map.md` und `docs/test-import-plan.md`.
Die lokalen `make smoke-all` laufen am 15.05.2026 nach dem V2/V3-Importdurchlauf
gemeldet, dass 30 Apache erfolgreich ist und 33 NGINX erfolgreich ist. Der Unterschied liegt in der 3
NGINX-spezifische importierte Fälle, die nicht auf Apache ausgeführt werden.

V2/V3-derived Häufige Fälle fügen Semantik- und Regressionsabdeckung hinzu, ohne zu kopieren
Upstream-Tests:

| Geteilte Gruppe | Apache | NGINX | Notizen |
| --- | --- | --- | --- |
| V2 operators/transformations | HTTP 403 | HTTP 403 | Abgeleitet von `ModSecurity_V2/tests/op` und `tests/tfn` |
| V3 mehrteilige FILES Variablen | HTTP 403 | HTTP 403 | Abgeleitet von den Fällen v3 `variable-FILES*` und `variable-MULTIPART_FILENAME` JSON |
| V3 XML Körperverarbeiter | HTTP 403 | HTTP 403 | Nur einfache Sammlungsprüfung XML; schema/DTD bleibt zugeordnet |
| V3 operator/action Grundlagen | HTTP 403 | HTTP 403 | Abgeleitet von `operator-rx.json`, `transformations.json` und `secruleengine.json` |

## Body- und Multipart-Import

Der Shared Runner materialisiert nun deterministische mehrteilige Körper und pro Fall
Antwortvorrichtungen unter jedem Connector-Laufzeitverzeichnis. Das aktive Gemeinsame
body/filter Ergänzungen sind:

| Geteilter Fall | Apache | NGINX | Notizen |
| --- | --- | --- | --- |
| `json_request_body_block.yaml` | HTTP 403 | HTTP 403 | Raw `REQUEST_BODY` Übereinstimmung; Geparste JSON-Sammlungen bleiben zugeordnet |
| `multipart_basic_block.yaml` | HTTP 403 | HTTP 403 | Einfacher mehrteiliger Textfeldabgleich über `ARGS:name` |
| `response_body_pass.yaml` | HTTP 200 | HTTP 200 | Nur Pass-Through für den Zugriff auf den Antworttext |

`response_body_basic_block` ist kein aktiver gemeinsamer PASS. NGINX hat das erkannt
Antwortkörperregel bei der lokalen Prüfung, aber die HTTP-Antwort war nicht stabil
403 und der Upstream-Test NGINX markiert den Blockfall TODO. Es bleibt dokumentiert
wie bisher expected-failure/mapped-only, bis beide Konnektoren die gleichen stabilen HTTP 403 zurückgeben.

## Zusammenfassende Metadaten

Zu den Apache- und NGINX-Zusammenfassungen unter `$BUILD_ROOT/results/` gehören:

- `connector_path: real-world`
- `validation_mode: real-world-connector-path`
- Binärpfad des Servers
- Pfad des Connector-Moduls
- Pfad der gemeinsam genutzten libmodsecurity-Bibliothek
- `verified_variables` werden nur aus dem Bestehen von YAML-Fällen abgeleitet

Die derzeit verifizierten realen Variablenfamilien sind `ARGS`,
`REQUEST_HEADERS`, `REQUEST_BODY`, `FILES`, `XML`, `AUDIT_LOG` und
`RESPONSE_HEADERS`. `RESPONSE_BODY` bleibt bis zu einem Antworttext ausgeschlossen
Regelvariable case übergibt beide Konnektoren.
