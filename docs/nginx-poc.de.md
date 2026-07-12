# NGINX Connector PoC

**Sprache:** [English](nginx-poc.md) | Deutsch

Status: eingerüstet

## Umgesetzt

- `ci/provisioning/prepare-nginx-build.sh` bereitet einen Connector-spezifischen NGINX PoC-Build vor
  unter `BUILD_ROOT`.
- Der Helfer kopiert die schreibgeschützten Dateien libmodsecurity v3 und ModSecurity-nginx
  Quellen in `$BUILD_ROOT/nginx-build/` und erstellt nur innerhalb dieser Kopien.
- Die NGINX-Quelle wird von der offiziellen `nginx/nginx` GitHub-Version heruntergeladen
  Archivfluss.
- `connectors/nginx/harness/run_nginx_smoke.sh` bereitet eine lokale NGINX Laufzeit vor
  unter `BUILD_ROOT` und sucht nach einem echten HTTP `403`.
- Die gemeinsam genutzten minimalen YAML-Fälle unter `tests/cases/` sind die
  rule/request/expectation-Quelle, die sowohl von Apache- als auch von NGINX-Harnessesn verwendet wird.
- Die gemeinsam genutzten importierten YAML-Fälle fügen rohen JSON-Körper hinzu, einfach mehrteilig
  Textfeld- und Antworttext-Pass-Through-Abdeckung, ohne diese fest zu codieren
  Werte im Harness.

Hier implementiert bedeutet Build-Orchestrierung, Laufzeitnutzung, Shared-Case
Integration und Dokumentation. Das bedeutet nicht, dass jede Umgebung bauen oder erstellen kann
Führen Sie das Modul NGINX aus.

Wenn der Smoke durchgeht, handelt es sich um eine `real-world-connector-path`-Validierung:

```text
HTTP client -> source-built NGINX -> ngx_http_modsecurity_module.so -> libmodsecurity -> HTTP response
```

Der Connector-freie v3 API Smoke unter `src/v3-api-smoke/` ist separat und ist
Wird nicht als NGINX Connector-Erfolg gezählt.

## Build-Flow

Standardwerte sind nur lokale Annehmlichkeiten:

```sh
MODSECURITY_V3_SOURCE_DIR=<workspace>/ModSecurity_V3
MODSECURITY_NGINX_SOURCE_DIR=<workspace>/ModSecurity-nginx
BUILD_ROOT=/src/ModSecurity-test-Framework-build
LOG_DIR=$BUILD_ROOT/logs/nginx
```

Alle Pfade können von der Umgebung überschrieben werden. Generierte Dateien müssen außerhalb bleiben
Git-Checkout und außerhalb `<workspace>/*`.

Führen Sie den Build-Helfer aus mit:

```sh
REFRESH=1 \
BUILD_NGINX_FROM_SOURCE=1 \
BUILD_ROOT=/src/ModSecurity-test-Framework-build \
sh ci/provisioning/prepare-nginx-build.sh
```

Der Helfer erstellt libmodsecurity v3 in:

```text
$BUILD_ROOT/nginx-build/ModSecurity_V3
```

Es stellt libmodsecurity-Header und gemeinsam genutzte Bibliotheken bereit unter:

```text
$BUILD_ROOT/nginx-build/output/modsecurity/include/
$BUILD_ROOT/nginx-build/output/modsecurity/lib/
```

Der NGINX-Connector-Build verwendet das beobachtete dynamische ModSecurity-nginx-Modul
Pfad:

```text
MODSECURITY_INC=$BUILD_ROOT/nginx-build/output/modsecurity/include
MODSECURITY_LIB=$BUILD_ROOT/nginx-build/output/modsecurity/lib
auto/configure --with-compat --add-dynamic-module=$BUILD_ROOT/nginx-build/ModSecurity-nginx
```

Der Helfer verwendet `auto/configure`, wenn dieses Skript im GitHub vorhanden ist
Archiv oder `./configure`, wenn ein Archiv es bereitstellt.

## NGINX Quellmodus

Standardquellenmodus:

```sh
NGINX_SOURCE_MODE=github-release
NGINX_GITHUB_REPO=https://github.com/nginx/nginx
NGINX_RELEASE_TAG=latest
```

Bei `NGINX_RELEASE_TAG=latest` fragt der Helfer Folgendes ab:

```text
https://api.github.com/repos/nginx/nginx/releases/latest
```

und extrahiert `tag_name` mit `python3`. Das eigentliche Tag wird geschrieben in:

```text
$BUILD_ROOT/logs/nginx/artifacts.txt
```

Beobachtet während der Planung am 15.05.2026: GitHub meldete `release-1.31.0` als
neueste Version. Der Helfer codiert diesen Wert nicht fest.

Für eine angeheftete Veröffentlichung:

```sh
NGINX_RELEASE_TAG=release-1.31.0 sh ci/provisioning/prepare-nginx-build.sh
```

Das Archiv URL ist:

```text
https://github.com/nginx/nginx/archive/refs/tags/<TAG>.tar.gz
```

Der Helfer berechnet immer einen lokalen SHA256 und zeichnet ihn auf. Wenn `NGINX_SHA256` ist
festgelegt, überprüft der Helfer das Archiv anhand dieses Werts. Wenn `NGINX_SHA256` ist
Wenn der lokale Hash nicht gesetzt ist, dient er nur der Dokumentation und wird nicht als Upstream beansprucht
Überprüfung.

## Laufzeitrauch

Der NGINX-Harness macht `connectors/nginx/harness/nginx_smoke.conf` zu einem
Laufzeitverzeichnis pro Fall, zum Beispiel:

```text
$BUILD_ROOT/nginx-runtime/phase2_args_block/conf/nginx.conf
```

Regeln, Anforderungsdetails und erwartete Status werden gelesen aus:

```text
tests/cases/*.yaml
tests/cases/*.yaml
tests/cases/connector-specific/nginx/*.yaml
```

Der Harness codiert die Regel, den Anforderungspfad, die Anforderungsmethode, die Header usw. nicht fest.
Textkörper, Antwortvorrichtung oder erwarteter HTTP-Status. Bereitschaft nutzt
`/__modsec_smoke_ready` mit deaktivierter ModSecurity, also Phasen- und Antwortregeln
hat keinen Einfluss auf die Startprüfungen. Status `pass` ist nur gültig, wenn der gemeinsame Runner
prüft die beobachtete NGINX-Antwort anhand jeder YAML-Erwartung.

Die generierten `$BUILD_ROOT/results/nginx-summary.json`-Datensätze
`connector_path: real-world`, `validation_mode:
„real-world-connector-path“, der binäre, dynamische Modulpfad NGINX,
libmodsecurity und `verified_variables` werden nur aus übergebenen Fällen abgeleitet.

Führen Sie den Smoke nach einem erfolgreichen Build aus:

```sh
BUILD_ROOT=/src/ModSecurity-test-Framework-build \
make smoke-nginx
```

## Aktueller lokaler Status

In diesem Arbeitsbereich am 15.05.2026 beobachtet:

- `REFRESH=1 BUILD_NGINX_FROM_SOURCE=1
  BUILD_ROOT=/src/ModSecurity-test-Framework-build sh ci/provisioning/prepare-nginx-build.sh`
  libmodsecurity v3 in einer beschreibbaren Kopie erstellt, NGINX-Release behoben
  über GitHub, erstellte NGINX und produzierte das dynamische ModSecurity-Modul.
- `BUILD_ROOT=/src/ModSecurity-test-Framework-build make smoke-nginx` hat den Pass zurückgegeben
  für alle aktuellen gemeinsamen Minimalfälle und die aktiven gemeinsamen importierten Fälle,
  einschließlich rohem JSON-Textkörper, einfachem mehrteiligem Textfeld und Antworttext
  Durchgangsrauch.
- `BUILD_ROOT=/src/ModSecurity-test-Framework-build make smoke-apache` wurde ebenfalls zurückgegeben
  Pass für die gleichen gemeinsamen YAML Fälle.

Beobachtete NGINX Quellen- und Artefaktdetails:

```text
nginx_source_mode=github-release
nginx_release_tag_requested=latest
nginx_release_tag_resolved=release-1.31.0
nginx_archive_url=https://github.com/nginx/nginx/archive/refs/tags/release-1.31.0.tar.gz
nginx_archive_sha256_local=a450299c82f24aebae00203f09995d02b3d3611622bfe2461e62cc858f963122
nginx_archive_sha256_verified=0
nginx_version=nginx/1.31.0
nginx_binary=/src/ModSecurity-test-Framework-build/nginx-runtime/nginx/sbin/nginx
nginx_module=/src/ModSecurity-test-Framework-build/nginx-runtime/nginx/modules/ngx_http_modsecurity_module.so
nginx_smoke_cases=audit_log_phase1_block, phase1_header_block, phase2_args_block, phase2_args_pass, request_body_json_block, request_body_urlencoded_block, response_header_basic, json_request_body_block, multipart_basic_block, response_body_pass
nginx_smoke_status=all pass; blocking cases HTTP 403; pass-through case HTTP 200
nginx_validation_mode=real-world-connector-path
nginx_verified_variables=ARGS,REQUEST_HEADERS,REQUEST_BODY,FILES,XML,AUDIT_LOG,RESPONSE_HEADERS
```

Der obige SHA256-Wert ist der lokale Hash des heruntergeladenen GitHub-Archivs
diesen Arbeitsbereich. Es handelt sich nicht um eine Upstream-Prüfsumme, da `NGINX_SHA256` dies nicht war
eingestellt.

Eine Blockierung des Antworttextes wird nicht beansprucht. Der NGINX-Referenztest bescheinigt dies
Verhalten TODO und lokales Sondieren erkannten die Regel, erzeugten jedoch keine Stabilität
HTTP 403, der Kandidat bleibt also ehemaliger expected-failure/mapped-only.

## Statusbedeutungen

- `implemented`: Hilfsskripte, Harness-Vorlage, Integration gemeinsamer Fälle und
  Dokumente existieren.
- `blocked`: erforderliche Quelle, Download, Build-Abhängigkeit, Modul oder Bibliothek
  Voraussetzung fehlt; Es wird keine Funktionalität beansprucht.
- `fail`: Voraussetzungen sind vorhanden, aber ein Build, Configtest, Startup oder HTTP
  Erwartung scheitert.
- `pass`: NGINX gibt den von YAML erwarteten HTTP-Status für jede ausgewählte Freigabe zurück
  Smoke-Fall.

## TODOs öffnen

- Führen Sie zuvor den NGINX Build und Runtime Smoke in jeder Zielumgebung aus
  Ich beanspruche dort den Pass.
- Untersuchen Sie alle NGINX Kompatibilitätsfehler der neuesten Version als Connector
  Build-Problem, kein vermutetes Abhängigkeitsproblem.
- Befördern Sie nur nachgewiesenes NGINX-Verhalten in konnektorspezifische Regressionstests.

## Öffentliche Quellen

- Offizielles NGINX Open-Source-Repository: https://github.com/nginx/nginx
- GitHub neueste Version API:
  https://api.github.com/repos/nginx/nginx/releases/latest
- NGINX Dokumentation konfigurieren: https://nginx.org/en/docs/configure.html
- ModSecurity-nginx lokale Quelle: `<workspace>/ModSecurity-nginx`
