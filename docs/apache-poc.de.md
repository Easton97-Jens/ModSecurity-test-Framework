# Apache Connector PoC

**Sprache:** [English](apache-poc.md) | Deutsch

Status: eingerüstet

## Umgesetzt

- `ci/prepare-apache-build.sh` bereitet einen Connector-spezifischen Apache PoC-Build vor
  unter `BUILD_ROOT`.
- Der Helfer kann Apache httpd aus dem Quellcode unter `BUILD_ROOT` erstellen; systemweit
  `apxs` und `httpd` sind nicht erforderlich.
- `connectors/apache/harness/run_apache_smoke.sh` bereitet einen lokalen Apache vor
  Laufzeit unter `BUILD_ROOT` und sucht nach einem echten HTTP `403`.
- Die gemeinsam genutzten minimalen YAML-Fälle unter `tests/cases/` definieren die
  rule/request/expectation Modell, das von Apache und NGINX verwendet wird.
- `tests/runners/case_cli.py` liest jede YAML-Datei und materialisiert den Apache
  Regeln, Anfrage method/path, Header, Text, mehrteiliger Text, Antwortvorrichtung,
  und erwarteter HTTP Status für den Harness.

Hier implementiert bedeutet Build-Orchestrierung, Laufzeitnutzung und Dokumentation.
Dies bedeutet nicht, dass Apache das Modul in jedem Fall erfolgreich geladen hat
Umgebung.

Wenn der Smoke durchgeht, handelt es sich um eine `real-world-connector-path`-Validierung:

```text
HTTP client -> source-built httpd -> mod_security3.so -> libmodsecurity -> HTTP response
```

Der Connector-freie v3 API Smoke unter `src/v3-api-smoke/` ist separat und ist
wird nicht als Apache-Connector-Erfolg gezählt.

## Build-Flow

Standardwerte sind nur lokale Annehmlichkeiten:

```sh
MODSECURITY_V3_SOURCE_DIR=<workspace>/ModSecurity_V3
MODSECURITY_APACHE_SOURCE_DIR=<workspace>/ModSecurity-apache
BUILD_ROOT=/src/ModSecurity-test-Framework-build
LOG_DIR=$BUILD_ROOT/logs/apache
```

Alle Pfade können von der Umgebung überschrieben werden. Generierte Dateien müssen außerhalb bleiben
Git-Checkout und außerhalb `<workspace>/*`.

## Quellbasierter httpd-Modus

Der Apache PoC kann httpd ohne Paketinstallation erstellen:

```sh
REFRESH=1 \
BUILD_HTTPD_FROM_SOURCE=1 \
BUILD_ROOT=/src/ModSecurity-test-Framework-build \
sh ci/prepare-apache-build.sh
```

Standard-Quellversionen:

| Variabel | Standard |
| --- | --- |
| `HTTPD_VERSION` | `2.4.67` |
| `APR_VERSION` | `1.7.6` |
| `APR_UTIL_VERSION` | `1.6.3` |
| `PCRE2_VERSION` | `10.47` |

Standardmäßig generierte Pfade:

```text
$BUILD_ROOT/apache-build/downloads/
$BUILD_ROOT/apache-build/httpd-src/
$BUILD_ROOT/apache-build/httpd/
$BUILD_ROOT/apache-runtime/httpd/
$BUILD_ROOT/logs/apache/
```

Der Helfer lädt httpd, APR und APR-util von Apache-Distributions-URLs herunter.
überprüft ihre SHA256-Dateien, entpackt APR und APR-util in den httpd `srclib`
Baum und konfiguriert httpd mit:

```text
--prefix=$HTTPD_PREFIX
--with-included-apr
--with-pcre=$PCRE_CONFIG
--enable-so
--enable-mods-shared=most
--enable-mpms-shared=all
--with-mpm=event
```

Die PCRE-Behandlung ist explizit:

- `PCRE_CONFIG=/path/to/pcre2-config` oder `/path/to/pcre-config` gewinnt.
- `BUILD_PCRE2_FROM_SOURCE=1` baut PCRE2 unter auf
  `$BUILD_ROOT/apache-build/output/pcre2`.
- Wenn kein PCRE Konfigurationstool verfügbar ist und PCRE2 Source Build nicht aktiviert ist,
  Der Helfer beendet `77` mit `blocked`.

OpenSSL ist für diese reine HTTP-Smoke-Probe nicht aktiviert.

Der Helfer kopiert die schreibgeschützten Quellen nach:

```text
$BUILD_ROOT/apache-build/ModSecurity_V3
$BUILD_ROOT/apache-build/ModSecurity-apache
```

Es wird dann nur innerhalb dieser Kopien erstellt. Der Apache-Connector-Build verwendet die
beobachteter Upstream Autotools/APXS Pfad:

```sh
./autogen.sh
./configure --with-libmodsecurity=$BUILD_ROOT/apache-build/output/modsecurity
make
```

Das Staging-Verzeichnis libmodsecurity enthält kopierte Header und gemeinsam genutzte Bibliotheken
Artefakte aus der v3-Build-Kopie:

```text
$BUILD_ROOT/apache-build/output/modsecurity/include/
$BUILD_ROOT/apache-build/output/modsecurity/lib/
```

## Laufzeitrauch

Das Apache-Harness rendert `connectors/apache/harness/apache_smoke.conf` in a
Laufzeitverzeichnis pro Fall, zum Beispiel:

```text
$BUILD_ROOT/apache-runtime/phase2_args_block/conf/httpd.conf
```

Regeln, Anforderungsdetails und erwartete Status werden gelesen aus:

```text
tests/cases/*.yaml
tests/cases/*.yaml
tests/cases/connector-specific/apache/*.yaml
```

Der Standardlauf führt Folgendes aus:

```text
phase1_header_block
phase2_args_block
phase2_args_pass
audit_log_phase1_block
request_body_json_block
request_body_urlencoded_block
response_header_basic
json_request_body_block
multipart_basic_block
response_body_pass
```

Gehen Sie das formale Ziel durch:

```sh
BUILD_ROOT=/src/ModSecurity-test-Framework-build make smoke-apache
```

Der Harness codiert die Regel, den Anforderungspfad, die Anforderungsmethode, die Header usw. nicht fest.
Textkörper, Antwortvorrichtung oder erwarteter HTTP-Status. Bereitschaft nutzt
`/__modsec_smoke_ready` mit deaktivierter ModSecurity, also Phasen- und Antwortregeln
hat keinen Einfluss auf die Startprüfungen. Status `pass` ist nur gültig, wenn der gemeinsame Runner
prüft die beobachtete Apache-Antwort anhand jeder YAML-Erwartung. Ein Erfolg
Kompilieren allein ist kein Laufzeitdurchlauf.

Die generierten `$BUILD_ROOT/results/apache-summary.json`-Datensätze
`connector_path: real-world`, `validation_mode:
real-world-connector-path`, the httpd binary, `mod_security3.so`,
libmodsecurity und `verified_variables` werden nur aus übergebenen Fällen abgeleitet.

## Aktueller lokaler Status

In diesem Arbeitsbereich am 15.05.2026 beobachtet:

- `autoconf`, `automake`, `libtoolize`, `make`, `cc`, `c++`, `curl` und `perl`
  vorhanden sind.
- `apxs`, `apxs2`, `apache2`, `httpd`, `apachectl` und `apache2ctl` waren nicht vorhanden
  gefunden in `PATH`.
- `REFRESH=1 BUILD_HTTPD_FROM_SOURCE=1
  BUILD_ROOT=/src/ModSecurity-test-Framework-build sh ci/prepare-apache-build.sh`
  Apache httpd aus dem Quellcode erstellt, libmodsecurity v3 in einer beschreibbaren Kopie erstellt,
  und baute `mod_security3.so`.
- `BUILD_ROOT=/src/ModSecurity-test-Framework-build make smoke-apache` hat den Pass zurückgegeben
  für alle aktuellen gemeinsamen Minimalfälle und die aktiven gemeinsamen importierten Fälle,
  einschließlich rohem JSON-Textkörper, einfachem mehrteiligem Textfeld und Antworttext
  Durchgangsrauch.

Vom lokalen Pass generierte Artefakte:

```text
/src/ModSecurity-test-Framework-build/apache-build/ModSecurity_V3
/src/ModSecurity-test-Framework-build/apache-build/ModSecurity-apache
/src/ModSecurity-test-Framework-build/apache-build/output/apache/mod_security3.so
/src/ModSecurity-test-Framework-build/apache-build/output/modsecurity/
/src/ModSecurity-test-Framework-build/apache-runtime/httpd/bin/apxs
/src/ModSecurity-test-Framework-build/apache-runtime/httpd/bin/httpd
/src/ModSecurity-test-Framework-build/logs/apache/
/src/ModSecurity-test-Framework-build/logs/apache-runtime/<case>/status.txt
/src/ModSecurity-test-Framework-build/results/apache-summary.txt
/src/ModSecurity-test-Framework-build/results/apache-summary.json
```

Beobachtete Tool- und Versionsdetails:

```text
httpd_source_built=1
httpd_version=2.4.67
apxs=/src/ModSecurity-test-Framework-build/apache-runtime/httpd/bin/apxs
apache_httpd=/src/ModSecurity-test-Framework-build/apache-runtime/httpd/bin/httpd
apache_httpd_version=Apache/2.4.67
pcre_config=/usr/bin/pcre2-config
pcre_config_version=10.46
pcre2_source_built=0
apache_smoke_cases=audit_log_phase1_block, phase1_header_block, phase2_args_block, phase2_args_pass, request_body_json_block, request_body_urlencoded_block, response_header_basic, json_request_body_block, multipart_basic_block, response_body_pass
apache_smoke_status=all pass; blocking cases HTTP 403; pass-through case HTTP 200
apache_validation_mode=real-world-connector-path
apache_verified_variables=ARGS,REQUEST_HEADERS,REQUEST_BODY,FILES,XML,AUDIT_LOG,RESPONSE_HEADERS
```

## Statusbedeutungen

- `implemented`: Hilfsskripte, Harness-Vorlage, gemeinsamer Fall und Dokumente sind vorhanden.
- `blocked`: Erforderliche Quelle, APXS, Apache, Modul oder Bibliotheksvoraussetzung ist
  fehlt; Es wird keine Funktionalität beansprucht.
- `fail`: Voraussetzungen sind vorhanden, aber ein Build, Configtest, Startup oder HTTP
  Erwartung scheitert.
- `pass`: Apache gibt für jede Auswahl den von YAML erwarteten HTTP-Status zurück
  gemeinsamer Smoke-Fall.

## TODOs öffnen

- Überprüfen Sie die genauen Ladeanforderungen für Apache-Module in mehreren Distributionen.
- Führen Sie den von der Quelle erstellten httpd-Modus in CI aus, sobald die externen Quell-Checkouts abgeschlossen sind
  dort erhältlich.
- Wenn Apache Nicht-403 zurückgibt, prüfen Sie vorher `$BUILD_ROOT/logs/apache-runtime`
  Ändern des Harnesss oder der Regel.
- Fördern Sie nur nachgewiesenes Verhalten in konnektorspezifischen Regressionstests.

## Öffentliche Quellen

- Dokumentation zur Apache httpd-Installation:
  https://httpd.apache.org/docs/current/install.html.en
- Apache httpd-Archiv für angeheftete Veröffentlichungen:
  https://archive.apache.org/dist/httpd/
- Apache APR Downloadseite:
  https://apr.apache.org/download.cgi
- PCRE2 Build- und Release-Dokumentation:
  https://pcre2project.github.io/pcre2/guide/readme/
