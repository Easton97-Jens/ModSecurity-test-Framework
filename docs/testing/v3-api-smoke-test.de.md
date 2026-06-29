# libmodsecurity v3 API Smoketest

**Sprache:** [English](v3-api-smoke-test.md) | Deutsch

Status: Portable Build-Harness implementiert. Eine lokale explizite Build-Root-Ausführung
beobachtet, dass `primary_args_phase2` nach dem Erstellen von libmodsecurity bestanden wurde.

Dieses Dokument beschreibt eine minimale Connector-lose Sonde für die Öffentlichkeit
libmodsecurity v3 C-API.

## Zweck

Das Probe prüft, ob dieses Repository ein kleines C-Programm kompilieren und ausführen kann
gegen einen konfigurierten libmodsecurity v3-Build und laden Sie eine einfache SecRule durch
die öffentliche C-API.

Dies ist kein Webserver-Connector-Test. Es verwendet nicht Apache, NGINX, HAProxy,
Envoy, Lighttpd oder Traefik.

Der kanonische Quell- und Build-Harness ist verfügbar unter:

```text
src/v3-api-smoke/
```

`docs/imports/common/v3-api-smoke.md` enthält nur einen Zeiger auf diese Quelle, also der Test
Der Baum dupliziert keine Implementierungslogik.

## Pfadmodell

Jeder relevante Pfad ist konfigurierbar. Die aktuellen Standardwerte stammen von
`modules/ModSecurity-test-Framework/ci/common.sh` und verwenden Sie einen portablen lokalen build/output Root plus `SOURCE_ROOT`:

```sh
BUILD_ROOT=$HOME/.local/state/ModSecurity-conector-build
SOURCE_ROOT=$BUILD_ROOT/sources
MODSECURITY_SOURCE_DIR=$SOURCE_ROOT/ModSecurity_V3
MODSECURITY_V3_SOURCE_DIR=$SOURCE_ROOT/ModSecurity_V3
MODSECURITY_V3_DIR=$BUILD_ROOT/ModSecurity_V3_build
LOG_DIR=$BUILD_ROOT/logs
```

Das Auschecken der lokalen v3-Quelle entspricht dem öffentlichen ModSecurity-Repository:

| Repository | Referenzrolle | Stromaufwärts | Beobachteter Commit | Beobachtet version/tag | Lizenz |
| --- | --- | --- | --- | --- | --- |
| ModSecurity v3 | Auschecken der konfigurierten Engine-Quelle | https://github.com/owasp-modsecurity/ModSecurity | `0fb4aff98b4980cf6426697d5605c424e3d5bb60` | `v3.0.15` | Apache-2.0 |

Bedeutung:

- `MODSECURITY_V3_SOURCE_DIR`: Auschecken der schreibgeschützten Quelle zum Kopieren.
- `MODSECURITY_V3_DIR`: beschreibbare Build-Kopie, die die erstellte v3-Bibliothek enthält.
- `BUILD_ROOT`: Beschreibbares Stammverzeichnis für Smoke-Objektdateien, Binärdateien und Protokolle.
- `LOG_DIR`: beschreibbares Verzeichnis für Hilfsprotokolle.

Kein Build-Schritt darf generierte Dateien in diesen oder einen anderen Repository-Checkout schreiben
andere Quell-Checkout.

Generierte Pfade (`MODSECURITY_V3_DIR`, `BUILD_ROOT`, `LOG_DIR` und
`BUILD_DIR`) sollte absolut sein und außerhalb des Git-Checkouts liegen. Der Helfer und
Runner blockiert häufige unsichere Fälle, anstatt repo-lokale Artefakte zu erstellen.

## Primäres Szenario

Name: `primary_args_phase2`

Regeln:

```apache
SecRuleEngine On
SecRule ARGS:test "@streq attack" "id:1001,phase:2,deny,status:403"
```

Simulierte Anfrage:

```text
GET /?test=attack HTTP/1.1
```

Erwartetes Ergebnis:

```text
primary_args_phase2: pass status=403
```

Wenn dieses Szenario keinen 403-Eingriff durch das reine C API erzeugt
muss das Ergebnis als primärer Fehler dokumentiert werden. Die Umsetzung
darf ohne bestätigte Quelle keine Erklärung ableiten.

## Fallback-Szenario

Name: `fallback_request_uri_phase1`

Regeln:

```apache
SecRuleEngine On
SecRule REQUEST_URI "@contains test=attack" "id:1002,phase:1,deny,status:403"
```

Der Fallback ist nur ein minimaler Nachweis dafür, dass die öffentlichen API Regeln laden können und
einen Eingriff für den simulierten URI erzeugen. `ARGS:test` werden nicht validiert.
Handhabung.

Wenn das Fallback erfolgreich ist, während das primäre Szenario fehlschlägt, wird das Skript beendet
ungleich Null. Dieses Ergebnis ist `fallback pass`, nicht `pass`, und das darf auch nicht der Fall sein
dokumentiert als `ARGS:test` Unterstützung. Der erwartete Marker ist:

```text
fallback passed, primary failed
```

## Öffentliche API Anrufe

Das Probe verwendet diese öffentlichen libmodsecurity v3 C API-Aufrufe:

- `msc_init`
- `msc_set_connector_info`
- `msc_create_rules_set`
- `msc_rules_add`
- `msc_new_transaction`
- `msc_process_connection`
- `msc_process_uri`
- `msc_process_request_headers`
- `msc_process_request_body`
- `msc_intervention`
- `msc_intervention_cleanup`
- `msc_transaction_cleanup`
- `msc_rules_cleanup`
- `msc_cleanup`

Die Aufrufreihenfolge folgt den v3-Beispielen und dem beobachteten Regressions-Harness-Muster
in der lokalen Referenz-Checkout, aber die Smoke-Probe läuft dagegen
`$MODSECURITY_V3_DIR`.

## Bauen und ausführen

Standardbefehl:

```sh
sh modules/ModSecurity-test-Framework/ci/run-v3-api-smoke.sh
```

Direkter Makefile-Befehl:

```sh
make -C src/v3-api-smoke run
```

Nur Voraussetzungsprüfung:

```sh
sh modules/ModSecurity-test-Framework/ci/check-v3-api-smoke-prereqs.sh
```

Optionale Überschreibungen:

```sh
MODSECURITY_V3_SOURCE_DIR=/path/to/ModSecurity_V3 \
MODSECURITY_V3_DIR=/tmp/ModSecurity_V3_build \
BUILD_ROOT=/tmp/ModSecurity-conector-build \
LOG_DIR=/tmp/ModSecurity-conector-build/logs \
sh modules/ModSecurity-test-Framework/ci/run-v3-api-smoke.sh
```

Das Skript und das Makefile prüfen Folgendes:

- `$MODSECURITY_V3_DIR/headers/modsecurity/modsecurity.h`
- `$MODSECURITY_V3_DIR/src/.libs/libmodsecurity.so`

Der Smoke Runner und Makefile erstellen absichtlich keine libmodsecurity. Benutzen
der manuelle Helfer, wenn eine beschreibbare Build-Kopie benötigt wird.

Für die Automatisierung bevorzugen Sie die Shell-Skripte `ci/`. Sie behalten den blockierten Exit-Code bei
`77`. Ein direkter GNU Make-Aufruf gibt `Error 77` für das blockierte Rezept aus, aber
GNU Make selbst beendet sich mit seinem eigenen Fehlercode.

## Erstellen der v3-Kopie

Standardmäßig konfigurierter Build:

```sh
sh modules/ModSecurity-test-Framework/ci/build-v3-under-src.sh
```

Beispiel für tragbares Linux:

```sh
MODSECURITY_V3_SOURCE_DIR=/work/ModSecurity_V3 \
MODSECURITY_V3_DIR=/tmp/ModSecurity_V3_build \
BUILD_ROOT=/tmp/ModSecurity-conector-build \
LOG_DIR=/tmp/ModSecurity-conector-build/logs \
sh modules/ModSecurity-test-Framework/ci/build-v3-under-src.sh
```

Beispiel im GitHub Actions-Stil:

```sh
MODSECURITY_V3_SOURCE_DIR=$GITHUB_WORKSPACE/ModSecurity_V3 \
MODSECURITY_V3_DIR=$RUNNER_TEMP/ModSecurity_V3_build \
BUILD_ROOT=$RUNNER_TEMP/ModSecurity-conector-build \
LOG_DIR=$RUNNER_TEMP/ModSecurity-conector-build/logs \
sh modules/ModSecurity-test-Framework/ci/build-v3-under-src.sh
```

Der Helfer kopiert `MODSECURITY_V3_SOURCE_DIR` in `MODSECURITY_V3_DIR` und wird dann ausgeführt
`git submodule update --init --recursive`, `./build.sh`, `./configure` und
`make` nur innerhalb der Kopie. Protokolle werden unter `LOG_DIR` geschrieben.

Erzeugte Artefakte:

- libmodsecurity-Build-Baum: `$MODSECURITY_V3_DIR`
- Hilfsprotokolle: `$LOG_DIR`
- Smoke-Objekt und Binärdatei: `$BUILD_ROOT/v3-api-smoke`
- optionaler Python-Cache während Prüfungen: `$BUILD_ROOT/pycache` oder ein expliziter
  `PYTHONPYCACHEPREFIX`

Wenn Abhängigkeiten fehlen, dokumentieren Sie den genauen fehlerhaften Befehl und den Protokollpfad
vom Helfer gemeldet und behalten den Status `blocked`.

## Beobachtetes lokales Ergebnis

Beobachteter lokaler Build-Befehl:

```sh
sh modules/ModSecurity-test-Framework/ci/build-v3-under-src.sh
```

Beobachtete generierte Artefakte mit Pfaden, die auf die konfigurierten verallgemeinert wurden
Variablen:

- Build-Kopie: `$MODSECURITY_V3_DIR`
- gebaute Bibliothek: `$MODSECURITY_V3_DIR/src/.libs/libmodsecurity.so`
- Hilfsprotokolle:
  - `$LOG_DIR/copy-source.log`
  - `$LOG_DIR/git-submodule-update.log`
  - `$LOG_DIR/build-sh.log`
  - `$LOG_DIR/configure.log`
  - `$LOG_DIR/make.log`
- Ausgabe des Smoke-Builds:
  - `$BUILD_ROOT/v3-api-smoke/v3_api_smoke.o`
  - `$BUILD_ROOT/v3-api-smoke/v3_api_smoke`

Beobachtet in diesem Arbeitsbereich über `sh modules/ModSecurity-test-Framework/ci/check-v3-api-smoke-prereqs.sh`:

```text
v3_api_smoke: MODSECURITY_V3_SOURCE_DIR=<configured ModSecurity source>
v3_api_smoke: MODSECURITY_V3_DIR=<configured build copy>
v3_api_smoke: BUILD_ROOT=<configured build root>
v3_api_smoke: LOG_DIR=<configured log dir>
v3_api_smoke: v3 branch=v3/master
v3_api_smoke: v3 version=v3.0.15
v3_api_smoke: header present: <configured build copy>/headers/modsecurity/modsecurity.h
v3_api_smoke: library present: <configured build copy>/src/.libs/libmodsecurity.so
```

Beobachtet in diesem Arbeitsbereich über `sh modules/ModSecurity-test-Framework/ci/run-v3-api-smoke.sh`:

```text
v3_api_smoke: MODSECURITY_V3_SOURCE_DIR=<configured ModSecurity source>
v3_api_smoke: MODSECURITY_V3_DIR=<configured build copy>
v3_api_smoke: BUILD_ROOT=<configured build root>
v3_api_smoke: LOG_DIR=<configured log dir>
v3_api_smoke: v3 branch=v3/master
v3_api_smoke: v3 version=v3.0.15
v3_api_smoke: header present: <configured build copy>/headers/modsecurity/modsecurity.h
v3_api_smoke: library present: <configured build copy>/src/.libs/libmodsecurity.so
primary_args_phase2: pass status=403 phase=request_body
fallback_request_uri_phase1: skipped primary_passed
```

Interpretation:

- `blocked`: Die konfigurierte v3-Build-Kopie fehlt, Abhängigkeiten fehlen,
  oder `$MODSECURITY_V3_DIR/src/.libs/libmodsecurity.so` existiert nicht.
- `implemented`: die Connector-lose Smoke-Probenquelle, Makefile, Runner und
Voraussetzungsprüfer sind in diesem Repository vorhanden.
- `pass`: Das primäre `ARGS:test`-Szenario hat den Status `403` erzeugt.
- `fallback pass`: Nur das Fallback-`REQUEST_URI`-Szenario hat den Status erzeugt
  `403`; Dies ist nur ein minimaler API-Nachweis.
- `fail`: Die Sonde wurde erstellt und ausgeführt, das primäre `ARGS:test`-Ergebnis jedoch nicht
  Status `403`.
- `unknown`: Das `primary_args_phase2` Laufzeitergebnis wurde nicht beobachtet
  wenn die konfigurierte v3-Bibliothek nicht erstellt wird.

Aktueller Beobachtungsstatus:

```text
pass
```

## Offene Arbeit

Verfolgt in `docs/roadmap/todo-inventory.md`:

- Sorgen Sie dafür, dass der Build-Kopie-Pfad `MODSECURITY_V3_DIR` außerhalb der Quelle reproduzierbar bleibt
  Checkouts.
- Wenn `primary_args_phase2` fehlschlägt und `fallback_request_uri_phase1` erfolgreich ist,
  Dokumentieren Sie die genaue Ausgabe, ohne `ARGS:test` Unterstützung in Anspruch zu nehmen.
- Wenn eine öffentliche C API-Aufrufsequenz angepasst werden muss, geben Sie den v3-Header an.
  Beispiel oder Regressionskabelquelle, bevor Sie die Sonde wechseln.
