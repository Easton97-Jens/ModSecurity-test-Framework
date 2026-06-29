# ModSecurity Test Framework

**Sprache:** [English](README.md) | Deutsch

Dieses Repository ist das gemeinsame Test-, Runtime-, Coverage- und Reporting-Framework
für ModSecurity-Connector-Projekte. Es verwaltet den wiederverwendbaren YAML-Fallkorpus,
Runner-Code, Normalizer, Runtime-Matrix-Werkzeuge, die Logik für generierte Berichte und
die Testdokumentation.

Es ist kein Repository für eine Connector-Implementierung. Connector-Projekte stellen
Connector-Quellcode, Harness-Einstiegspunkte, Adaptermetadaten und Connector-lokale
Runtime-Nachweise bereit.

## Runtime Matrix

Die Runtime Matrix verbindet Framework-eigene YAML-Fälle mit Connector-eigenen
Runtime-Zusammenfassungen. Sie zeichnet Apache- und NGINX-Ergebnisse pro Fall nur als
Nachweis auf; XFAIL-, pending-, future-, connector-gap- oder RESPONSE_BODY-Fälle werden
nicht automatisch zu PASS hochgestuft.

Connector-Projekte führen normalerweise Folgendes aus:

```sh
CONNECTOR_ROOT=/path/to/ModSecurity-conector make runtime-matrix-all
```

`runtime-matrix-all` setzt `FORCE_ALL_CASES=1` und versucht alle anwendbaren
YAML-Fälle auszuführen. Erwartete Fehler bleiben in den generierten Berichten sichtbar.

## Testvarianten

Das Framework unterstützt zwei Varianten zum Laden von ModSecurity-Regeln:

- `no-crs`: lädt nur die lokalen Regeln, die aus dem jeweiligen YAML-Fall erzeugt werden.
- `with-crs`: lädt den OWASP Core Rule Set vor den lokalen YAML-Fallregeln.

Verwenden Sie diese Einstiegspunkte mit einem Connector-Repository:

```sh
CONNECTOR_ROOT=/path/to/ModSecurity-conector make test-no-crs
CONNECTOR_ROOT=/path/to/ModSecurity-conector make test-with-crs
CONNECTOR_ROOT=/path/to/ModSecurity-conector make test
```

`make test` führt beide Varianten aus. `make test-with-crs` ruft CRS automatisch ab und
bereitet es unter `SOURCE_ROOT`/`BUILD_ROOT` vor; `make fetch-crs` kann verwendet werden,
wenn CRS explizit vorab abgerufen werden soll. CRS-Version, Repository-URL und generierte
CRS-Pfade sind zentral in `ci/common.sh` definiert; duplizieren Sie die CRS-Version nicht
in Makefiles, Workflows oder anderen Skripten.

## MRTS-Integration

MRTS ist als Framework-eigene Quelle für Testgenerierung verfügbar. Es ist kein
Connector-Code und ist als erforderliches Framework-Submodul `tools/MRTS` enthalten.
Initialisieren Sie es mit:

```sh
git submodule update --init --recursive
```

Die MRTS-Ziele verwenden standardmäßig `tools/MRTS` und akzeptieren
`MRTS_ROOT=/path/to/MRTS` für einen separaten Checkout. Wenn das Submodul fehlt, beenden
MRTS-Ziele mit Status 77. Siehe `docs/testing/mrts.md` für Setup- und
Klassifizierungsdetails.

```sh
make mrts-generate
make test-no-mrts
make test-with-mrts
make test-with-mrts-feature-demo
make test-mrts-matrix
```

Die standardmäßige MRTS-Runtime-Vorbereitung liest Upstream-Konfigurationstests direkt aus
`$MRTS_ROOT/config_tests` und schreibt generierte Regeln, go-ftw-YAML, importierte
Framework-Fälle und `mrts.load` unter `$MRTS_BUILD_ROOT`. Feature-Demo-Konfigurationstests
werden aus `$MRTS_ROOT/feature_demo/config_tests` gelesen und bleiben optionale
Demo-Nachweise, sofern nicht `MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO=1` verwendet wird.
Goldene Referenzen unter `$MRTS_ROOT/generated` und
`$MRTS_ROOT/feature_demo/generated` dienen nur der Drift-Berichterstattung und werden nie
als Runtime-Eingaben verwendet.

## Runtime-Smoke-Einstiegspunkte

Das Framework besitzt Runtime-Smoke-Einstiegspunkte für Apache, NGINX, Envoy, HAProxy,
lighttpd und Traefik. Apache und NGINX haben derzeit ausführbare Connector-Harnesses.
Envoy, HAProxy, lighttpd und Traefik haben Framework-eigene Einstiegsskripte, melden aber
BLOCKED, bis das Connector-Repository ein echtes Server-/Proxy-Runtime-Harness
bereitstellt.

Verwenden Sie `make smoke-<connector>` aus dem Connector-Repository als
Runtime-Smoke-Einstieg. `make connector-starter-checks` ist nur für Build-/Self-Test-
Starter-Nachweise gedacht; Starter-PASS-Ergebnisse sind keine Runtime-Smoke-Nachweise und
verifizieren RESPONSE_BODY nicht.

Runtime-Smoke-Runner verwenden standardmäßig zustandslokale Source- und Build-Roots unter
`${XDG_STATE_HOME:-$HOME/.local/state}`. Aufrufer können weiterhin explizite Werte für
`SOURCE_ROOT`, `BUILD_ROOT`, `TMP_ROOT`, `LOG_ROOT` und `RESULTS_DIR` angeben, um lokale
Läufe zu isolieren.

HAProxy hat einen lokalen Vorbereitungshelfer unter `ci/prepare-haproxy-runtime.sh`. Er
verwendet nur HAProxy-Quell-URL, Version und Prüfsumme aus `ci/common.sh`, prüft die
offizielle Prüfsumme vor dem Entpacken, bestätigt, dass das Quell-Makefile
`TARGET=linux-glibc` unterstützt, und stellt nur eine lokale Runtime-Binärdatei unter
`BUILD_ROOT` bereit. Diese Binärdatei ist nur Voraussetzung-Nachweis; sie ist kein
HAProxy-Runtime-Smoke-Nachweis.

## YAML-Fallsystem

Fälle liegen unter `tests/cases/` und sind thematisch organisiert:

```text
request/{args,cookies,headers,uri}/
body/{json,xml,multipart,files}/
security/{sql,xss}/
response/{headers,body}/
audit-log/
transformations/
phases/
negative-pass-through/
connector-specific/{apache,nginx,envoy,haproxy,lighttpd,traefik}/
future-gap/
```

Die Fallidentität stammt aus dem YAML-Feld `name`, nicht aus dem Dateisystempfad. Die
Pfadtaxonomie dient nur der Erkennung und Berichterstattung.

## Runner-Architektur

Die Shell-Harnesses rufen `tests/runners/case_cli.py` auf. Dieses verwendet
`tests/runners/runner_core.py`, um YAML-Fälle zu laden, Regeln und Fixtures zu
materialisieren und Runtime-Antworten zu prüfen. Normalizer liegen in
`tests/normalizers/`.

Die Standarderkennung verwendet die Metadatenklassen active/imported/minimal.
Force-all-Erkennung bezieht zusätzlich XFAIL-, pending-, future- und gap-Fälle ein, wenn
sie für den aktuellen Connector anwendbar sind. Diese Klassen werden aus YAML-Metadaten
und Connector-Inventar gelesen, nicht aus Statusverzeichnissen.

Aufrufer können zusätzliche Fall-Roots mit der durch Doppelpunkte getrennten
Umgebungsvariable `EXTRA_CASE_ROOTS` angeben. Der MRTS-Helfer hängt seinen generierten
Framework-Fall-Root nur für `MODSECURITY_MRTS_VARIANT=with-mrts` an.

## Coverage-Berichte

Der Generator schreibt Framework-eigene Berichte, wenn `OUTPUT_ROOT` dieses Repository
ist, und Connector-eigene Nachweisberichte, wenn `OUTPUT_ROOT` ein Connector-Repository
ist:

```sh
python3 ci/generate-case-matrix.py \
  --framework-root /path/to/ModSecurity-test-Framework \
  --connector-root /path/to/ModSecurity-conector \
  --output-root /path/to/ModSecurity-conector
```

Connector-Ausgaben gehen nach `reports/testing/`. Die Root-Datei
`TEST-COVERAGE-SUMMARY.md` gehört immer dem Framework und liegt am Root von
`ModSecurity-test-Framework`, auch wenn Connector-Nachweise aus einem übergeordneten
Repository generiert werden.

## Nachweissemantik

- Generierte Coverage dient nur der Berichterstattung.
- Vollständige Runtime-Nachweise müssen aus lokalen Connector-Source-Build-Smokes
  stammen.
- `make smoke-all` ist nur dann maßgeblich, wenn es tatsächlich erfolgreich ausgeführt
  wurde.
- XFAIL-, pending-, future-, connector-gap- und runtime-difference-Fälle sind
  Nachweisklassen, keine PASS-Hochstufungen.
- `RESPONSE_BODY` bleibt non-verified/non-promoted, sofern es nicht ausdrücklich durch
  stabile Full-Smoke-Runtime-Nachweise im Connector-Projekt bewiesen wurde.

## Connector-Integration

Verwenden Sie explizite Pfade:

```sh
FRAMEWORK_ROOT=/path/to/ModSecurity-test-Framework
CONNECTOR_ROOT=/path/to/ModSecurity-conector
```

Connector-Repositorys können dieses Framework als Submodul einbinden, üblicherweise unter
`modules/ModSecurity-test-Framework`. Es gibt keinen versteckten absoluten
Workspace-Fallback. Connector-spezifisches Inventar bleibt im Connector-Repository unter
`config/testing/import-status.json`; Runtime-Nachweise bleiben unter `reports/testing/`.

## GitHub-Actions-Artefakte

Das Framework-Repository hat einen eigenen Workflow zur Artefaktbereinigung, wenn es als
eigenständiges GitHub-Repository ausgeführt wird. Dieser Workflow behält nur das neueste
Artefakt pro logischer Artefaktgruppe und wendet repositoryweit eine Obergrenze von 20
neuesten Artefakten an. Artefaktnamen mit Run-IDs, Attempts oder langen numerischen
Suffixen werden vor dem Bereinigen gruppiert.

Connector-Repositorys, die dieses Framework als Submodul einbinden, führen ihre eigenen
Root-Workflows separat aus; die Framework-Workflows laufen nur, wenn GitHub Actions für
das Framework-Repository selbst aktiviert ist. Uploads von Framework-Berichten, Patches,
Logs, Debugdaten und Coverage-Artefakten sind Best-Effort-Diagnosen mit eintägiger
Aufbewahrung.

## GitHub-Actions-Versionsupdates

Dependabot prüft GitHub Actions wöchentlich für dieses Framework-Repository. Wenn das
Framework als `modules/ModSecurity-test-Framework` eingebunden ist, kann das übergeordnete
Connector-Repository diese Workflow-Dateien ebenfalls scannen. Automatische Schreibzugriffe
auf das Submodul erfordern jedoch separate Berechtigungen wie `SUBMODULE_UPDATE_TOKEN` und
normalerweise einen separaten Framework-Pull-Request. SHA-gepinnte Actions werden nicht
automatisch aktualisiert, und lokale, Docker- oder dynamische `uses:`-Einträge werden ohne
Änderung gemeldet.
