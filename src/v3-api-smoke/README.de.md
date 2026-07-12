# libmodsecurity v3 API Smoke Probe

**Sprache:** [English](README.md) | Deutsch

Status: Portable Build-Harness implementiert. Lokaler Standardlauf beobachtet
`primary_args_phase2` wird nach dem Erstellen von libmodsecurity in `/src` übergeben.

In diesem Verzeichnis finden Sie eine Connector-lose C-Smoke-Probe für die Öffentlichkeit
libmodsecurity v3 C-API. Es enthält nicht Apache, NGINX, HAProxy, Envoy,
Lighttpd oder Traefik-Integration.

## Bauen

Standard-Build:

```sh
make -C src/v3-api-smoke
```

Ausführen:

```sh
make -C src/v3-api-smoke run
```

Optionale Überschreibungen:

```sh
make -C src/v3-api-smoke MODSECURITY_V3_DIR=/tmp/ModSecurity_V3_build
make -C src/v3-api-smoke BUILD_ROOT=/tmp/ModSecurity-test-Framework-build
```

Das Makefile prüft auf Folgendes:

- `$MODSECURITY_V3_DIR/headers/modsecurity/modsecurity.h`
- `$MODSECURITY_V3_DIR/src/.libs/libmodsecurity.so`

`build.sh`, `configure` oder `make` werden darin absichtlich nicht ausgeführt
`MODSECURITY_V3_DIR`.

`BUILD_ROOT` und `BUILD_DIR` sollten absolute Pfade außerhalb des Git-Checkouts sein.
Das Makefile blockiert relative `BUILD_DIR`-Werte, um repo-lokale Artefakte zu vermeiden.

Lokale Standardeinstellungen:

```sh
MODSECURITY_V3_SOURCE_DIR="<workspace>/ModSecurity_V3"
MODSECURITY_V3_DIR=/src/ModSecurity_V3_build
BUILD_ROOT=/src/ModSecurity-test-Framework-build
LOG_DIR=/src/ModSecurity-test-Framework-build/logs
```

Pfade im GitHub Actions-Stil:

```sh
MODSECURITY_V3_SOURCE_DIR=$GITHUB_WORKSPACE/ModSecurity_V3
MODSECURITY_V3_DIR=$RUNNER_TEMP/ModSecurity_V3_build
BUILD_ROOT=$RUNNER_TEMP/ModSecurity-test-Framework-build
LOG_DIR=$RUNNER_TEMP/ModSecurity-test-Framework-build/logs
```

Für Automatisierungen, die den blockierten Exit-Code `77` benötigen, verwenden Sie:

```sh
sh ci/provisioning/check-v3-api-smoke-prereqs.sh
sh ci/runtime/run-v3-api-smoke.sh
```

GNU Make meldet fehlgeschlagene Rezeptbefehle als Make-Fehler; es wird gedruckt
`Error 77` aus dem Rezept, aber die Wrapper-Skripte behalten den Exit-Code `77` bei.

## Ergebnisbedeutungen

- `implemented`: Diese Quelldatei und Makefile existieren.
- `blocked`: In der konfigurierten v3-Build-Kopie fehlen Header oder
`src/.libs/libmodsecurity.so`.
- `pass`: `primary_args_phase2` erzeugte Interventionsstatus `403`.
- `fallback pass`: `fallback_request_uri_phase1` erzeugte Status `403` danach
  der primäre ARGS-Test ist fehlgeschlagen; Dies ist nur ein minimaler API-Nachweis.
- `fail`: Das Probe wurde erstellt und ausgeführt, das erwartete primäre Ergebnis wurde jedoch nicht erzielt
  beobachtet.

Der Fallback darf nicht als ARGS Support dokumentiert werden.

Beobachteter lokaler Pass:

```text
primary_args_phase2: pass status=403 phase=request_body
fallback_request_uri_phase1: skipped primary_passed
```
