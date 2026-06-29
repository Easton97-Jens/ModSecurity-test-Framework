# Laufzeit-Bootstrap (optional)

**Sprache:** [English](bootstrap.md) | Deutsch

Dieses Projekt kann optional echte Upstream-Smoke-Voraussetzungen von GitHub abrufen.
Die Apache- und NGINX-Connector-Quelle ist standardmäßig repo-lokal; externer Anschluss
Repositorys sind nicht Teil des Standard-Laufzeit-Bootstraps.

Gemeinsam genutzte Shell-Standardwerte für die Framework-Laufzeithelfer sind zentralisiert in
`$FRAMEWORK_ROOT/ci/common.sh`. Connector-lokale `ci/`-Skripte sind Connector-spezifische Prüfungen. Das Framework `common.sh`
ist passiv: Es definiert nur Variablen und Hilfsfunktionen, wenn es mit Quellen versehen wird
ruft, installiert, validiert oder erstellt keine Verzeichnisse.

Legen Sie `FRAMEWORK_ROOT` fest, wenn das Framework-Checkout nicht das Modul ist
`modules/ModSecurity-test-Framework`.

## Verwendete Repositories

- ModSecurity v3: `https://github.com/owasp-modsecurity/ModSecurity.git` (ref: `v3/master` standardmäßig)
- OWASP Kernregelsatz: zentral konfiguriert in `$FRAMEWORK_ROOT/ci/common.sh`
- Quelle des Apache-Connectors: `connectors/apache` in diesem Repository
- NGINX Connector-Quelle: `connectors/nginx` in diesem Repository
- Gemeinsame YAML-Fälle und runner/generator-Code:
  `$FRAMEWORK_ROOT/docs/imports/common`, `$FRAMEWORK_ROOT/tests/runners`,
  `$FRAMEWORK_ROOT/tests/normalizers` und `$FRAMEWORK_ROOT/ci`
- Die Serverquellen Apache/httpd, APR/APR-util, PCRE2 und NGINX sind getrennt
  Laufzeit-Build-Abhängigkeiten, die über `modules/ModSecurity-test-Framework/ci/common.sh` konfiguriert werden.

Zentrale Override-Variablen:

- `FRAMEWORK_ROOT`
- `CONNECTOR_ROOT`
- `BUILD_ROOT`
- `SOURCE_ROOT`
- `MODSECURITY_TEST_VARIANT`
- `CRS_REPO_URL`, `CRS_GIT_REF`, `CRS_SOURCE_DIR`, `CRS_RUNTIME_DIR`
- `MODSECURITY_RULE_PREAMBLE_FILE`
- `MODSECURITY_REPO_URL` / `MODSECURITY_GIT_REF`
- Kompatibilitätsaliase: `MODSECURITY_V3_GIT_URL`, `MODSECURITY_V3_GIT_REF`
- Quellaliase: `MODSECURITY_SOURCE_DIR`, `MODSECURITY_V3_SOURCE_DIR`,
  `MODSECURITY_V3_ROOT`
- Connector-Quellaliase: `MODSECURITY_APACHE_SOURCE_DIR`,
  `MODSECURITY_NGINX_SOURCE_DIR` (standardmäßig repo-local)
- optionaler externer Connector-Abruf: `ALLOW_EXTERNAL_CONNECTOR_REPOS=1` plus
  explizit `MODSECURITY_APACHE_REPO_URL` / `MODSECURITY_NGINX_REPO_URL` und
  explizite Quellziele gemäß `SOURCE_ROOT`
- Server-Quellvariablen: `HTTPD_VERSION`, `HTTPD_SOURCE_URL`, `APR_VERSION`,
  `APR_SOURCE_URL`, `APR_UTIL_VERSION`, `APR_UTIL_SOURCE_URL`,
  `PCRE2_VERSION`, `PCRE2_SOURCE_URL`, `NGINX_SOURCE_REPO_URL`,
  `NGINX_SOURCE_GIT_REF`, `NGINX_RELEASE_TAG`
- optionale Hinweise zur installierten Laufzeit: `APACHE_BIN`, `APACHECTL_BIN`, `APXS_BIN`,
  `NGINX_BIN`, `MODSECURITY_PKG_CONFIG`, `MODSECURITY_LIB_DIR`,
  `MODSECURITY_INCLUDE_DIR`

Beispiel:

```bash
BUILD_ROOT=$HOME/.local/state/ModSecurity-conector-build \
MODSECURITY_GIT_REF=v3/master \
make fetch-deps
```

## Befehle

- Rufen Sie die von Smoke-Abhängigkeiten verwendete ModSecurity-Kernquelle ab:
  - `make fetch-deps`
- Nur den ModSecurity-Kern explizit abrufen:
  - `make fetch-modsecurity-v3`
- Nur OWASP CRS explizit abrufen:
  - `make fetch-crs`
- Führen Sie beide Varianten zum Laden von ModSecurity-Regeln aus:
  - `make test`
- Nur lokale Fallregeln ausführen:
  - `make test-no-crs`
- Führen Sie CRS plus lokale Groß-/Kleinschreibungsregeln aus:
  - `make test-with-crs`

## Verhalten und Sicherheit

- Der Abruf erfolgt **nur explizit** (manueller Befehlsaufruf).
- Vorhandene Repositorys werden **nicht überschrieben**; Vorhandene Git-Klone werden wiederverwendet.
- Wenn `git` fehlt oder das Netzwerk blockiert ist, beendet der Befehl BLOCKED/non-zero mit leerer Ausgabe.
- Es werden keine gefälschten Laufzeitartefakte erstellt.
- Die konkrete CRS-Version ist nur in `ci/common.sh` angepinnt; Arbeitsabläufe und
  Makefiles verbrauchen diesen Wert, anstatt ihn neu zu definieren.

## Wege

Das Standard-Abrufstammverzeichnis befindet sich unter Build-Temp:

- `SOURCE_ROOT=$BUILD_ROOT/sources`

Sie können Zielpfade überschreiben mit:

- `MODSECURITY_SOURCE_DIR`
- `MODSECURITY_V3_SOURCE_DIR`

Diese Zielpfade müssen für Abrufe nach absolut und unter `SOURCE_ROOT` sein
Vermeiden Sie destruktives Verhalten. Connector-Quellpfade zeigen normalerweise auf
`connectors/apache` und `connectors/nginx` in diesem Repository und sind nicht
geholt.


## BUILD_ROOT Konsistenz

`make fetch-deps`, `make doctor` und `make smoke-all` sollen die gleichen `BUILD_ROOT` verwenden.
Abgerufene Quellen leben unter `BUILD_ROOT/sources`.
Der Standard-Build-Root ist ein portabler lokaler build/output-Speicherort, kein Versprechen
dass alte Build-Artefakte wiederverwendet werden. Wenn Sie `BUILD_ROOT` überschreiben, verwenden Sie die
Gleicher absoluter Pfad für alle Befehle im Flow.

Beispiel:

```bash
BUILD_ROOT=/tmp/modsec-build make fetch-deps
BUILD_ROOT=/tmp/modsec-build make doctor
BUILD_ROOT=/tmp/modsec-build make smoke-all
```

NGINX Worker-bezogene Laufzeitdateien werden unter `NGINX_HARNESS_WORK_ROOT` bereitgestellt.
von `make smoke-nginx`. In Root-Run-Umgebungen ist der Standard ein temporäres Verzeichnis
wie `/tmp/ModSecurity-conector-nginx-runtime-0`; Nicht-Root-Läufe bevorzugen
`RUNNER_TEMP` sofern verfügbar. Berechtigungsanpassungen bleiben innerhalb der generierten Werte
Harnessarbeitswurzel. Keine globale NGINX Installation, System-NGINX Konfigurationsänderung,
oder breiter chmod ist erforderlich.


## Schnelle und vollständige Ziele

- Schnelle Framework-Prüfungen: `make quick-check`
- Installierte Laufzeitsonde: `make smoke-installed` / `make installed-readiness`
- Vollständiger maßgeblicher Verbindungsrauch: `make smoke-all`

Verwenden Sie `REFRESH=1 make smoke-all`, um vorhandene generierte build/output zu ersetzen
Bäume durch den bewachten Aufräumweg.

`make smoke-installed` / `make installed-readiness` ist eine optionale Diagnose
Bereitschaft für bereits installierte Systemkomponenten. Fehlendes System Apache,
NGINX-, APXS- oder libmodsecurity-Pakete blockieren den Source-Build-Smoke nicht
Pfad; `make smoke-all` bleibt der maßgebliche lokale Laufzeitbeweis.


## Schnelle Orchestrierung

Verwenden Sie `make quick-all` für einen schnellen, ehrlichen framework/smoke-basis-Lauf.
Es löst nie selbst vollständige Quellwiederherstellungen aus.
Wenn die optionale Laufzeitdiagnose unvollständig ist, wird BLOCKED gemeldet, nicht PASS.


## Cloud/GitHub Leichter Pfad

GitHub/Codex CI führt absichtlich Lightweight Framework, Generator, Lint usw. aus
Nur Dokumentationsprüfungen. Es werden keine Laufzeitquellen abgerufen, kein Apache erstellt oder
NGINX, installierte Sonden ausführen oder Connector-Smokes ausführen. Vollständiger Laufzeitbeweis
bleibt lokal über `make smoke-all`, `make smoke-apache` und
`make smoke-nginx`.
