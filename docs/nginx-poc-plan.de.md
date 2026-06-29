# NGINX PoC-Plan

**Sprache:** [English](nginx-poc-plan.md) | Deutsch

Status: eingerüstet

Dieses Dokument dokumentiert die PoC-Richtung NGINX und die dafür verwendeten Quellfakten
Gerüst build/runtime Gurt.

## Fakten zur lokalen Quelle

- Quelle: `<workspace>/ModSecurity-nginx`
- Beobachteter Zweig: `master`
- Beobachtete Version: `v1.0.4-14-g9eb44fd`
- Die Build-Integration ist die Datei NGINX des Drittanbietermoduls `config`.
- Die `config`-Datei unterstützt explizite libmodsecurity-Pfade durch
  `MODSECURITY_INC` und `MODSECURITY_LIB`.

## Modell erstellen

Der beobachtete README dokumentiert den Aufbau aus einem NGINX Quellbaum mit:

```sh
./configure --add-module=/path/to/ModSecurity-nginx
```

oder dynamischer Modulmodus:

```sh
./configure --add-dynamic-module=/path/to/ModSecurity-nginx --with-compat
```

Der implementierte PoC-Helfer wählt den dynamischen Modulmodus und erstellt nur darunter
`BUILD_ROOT`.

Standardquellenmodus:

```sh
NGINX_SOURCE_MODE=github-release
NGINX_GITHUB_REPO=https://github.com/nginx/nginx
NGINX_RELEASE_TAG=latest
```

Wenn `NGINX_RELEASE_TAG=latest`, `ci/prepare-nginx-build.sh` den tatsächlichen Wert auflöst
Release über die GitHub-Releases API und zeichnet das resultierende Tag auf
`$BUILD_ROOT/logs/nginx/artifacts.txt`. Explizite Tags wie z
`release-1.31.0` werden ebenfalls unterstützt. Es ist kein Branch-Fallback zulässig.

## Lebenszyklus anfordern

Beobachtete lokale Quelle:

- `src/ngx_http_modsecurity_module.c` registriert den Zugriffshandler in
  `NGX_HTTP_ACCESS_PHASE`.
- Die gleiche Nachkonfiguration registriert einen Protokollhandler in `NGX_HTTP_LOG_PHASE`.
- Header- und Body-Filter werden durchgehend installiert
  `ngx_http_modsecurity_header_filter_init()` und
  `ngx_http_modsecurity_body_filter_init()`.
- `src/ngx_http_modsecurity_access.c` erstellt Anforderungskontext, Prozesse
  Verbindungsdaten, URI, Anforderungsheader und Anforderungstext über libmodsecurity
  v3-APIs.
- `src/ngx_http_modsecurity_header_filter.c` sendet Antwortheader und Aufrufe
  `msc_process_response_headers`.
- `src/ngx_http_modsecurity_body_filter.c` fügt Antworttextdaten und Aufrufe hinzu
  `msc_process_response_body` auf dem letzten Puffer.
- `src/ngx_http_modsecurity_log.c` ruft `msc_process_logging` auf.

## PoC-Ziel

Der NGINX PoC verwendet dieselben portablen Fälle wie Apache:

```text
tests/cases/*.yaml
```

Die Bestehenskriterien bleiben gleich: eine echte lokale HTTP-Antwort, die zu jedem YAML passt.
Fallerwartung. Die aktuellen Minimalfälle erwarten alle HTTP `403`.

## Gesperrte Artikel

- Neue Umgebungen werden bis zum schreibgeschützten v3 und ModSecurity-nginx blockiert
  Quell-Checkouts sind vorhanden oder werden über Umgebungsvariablen bereitgestellt.
- Die neueste GitHub-Versionsauflösung oder der explizite Tag-Download können blockiert werden
  network/API Fehler.
- NGINX `pass` wird blockiert, bis das dynamische Modul und die Laufzeit erstellt werden
  Harness beachtet HTTP `403`.
