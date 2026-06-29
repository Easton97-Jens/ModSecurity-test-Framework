# Schnelle Checks vs. Full Smoke

**Sprache:** [English](fast-checks.md) | Deutsch

## Zweck

Schnelle Prüfungen liefern schnelles Feedback für Codex/developer-Iterationen, ohne den Anspruch einer vollständigen Connector-Validierung vorzutäuschen.

Gemeinsame Standardwerte für Laufzeithilfsskripte sind vorhanden
`$FRAMEWORK_ROOT/ci/common.sh`; Connector-lokale `ci/`-Skripte führen Connector-spezifische Prüfungen durch. Der Framework-Pfad ist
konfigurierbar mit `FRAMEWORK_ROOT` und standardmäßig lokal im Modul
`modules/ModSecurity-test-Framework`.

## Ziele

- `make quick-all`
  - Lokal bevorzugtes Orchestrierungsziel für schnelle Überprüfungen
  - Kombiniert Lint, Doctor-Quick, Quick-Check, Smoke-Installed, Py_Compile und Diff-Check
  - gibt QUICK PASS / QUICK BLOCKED / QUICK FAIL zurück
- `make quick-check` / `make codex-check`
  - führt Lint-, Py_compile- und Diff-Prüfungen durch
  - führt **nicht** Apache/NGINX Full Smoke aus
- `make smoke-installed` / `make installed-readiness`
  - Prüft installierte Komponenten und das Vorhandensein von libmodsecurity
  - Fungiert derzeit als installierter Bereitschaftstest; gibt BLOCKED zurück, wenn die Ausführungsverkabelung für echten installierten Laufzeitrauch nicht verfügbar ist
- `make smoke-all`
  - Vollständiger Source-Build-Smoke-Pfad (maßgebend)
- `make runtime-matrix`
  - lokaler Source-Build Apache/NGINX Laufzeitinventur pro Fall für den standardmäßigen ausführbaren Fallsatz
- `make runtime-matrix-all`
  - lokaler Source-Build Apache/NGINX fallweises Laufzeitinventar mit `FORCE_ALL_CASES=1`
  - Versucht ggf. frühere erwartete Fehler, ausstehende, zukünftige, experimentelle und Connector-Gap-YAML-Fälle
  - Die aufgezeichneten PASS/FAIL-Daten dienen lediglich der Nachweisführung und fördern weder den YAML-Status noch die RESPONSE_BODY-Unterstützung

## Ehrlichkeitsregeln

- BLOCKED ist nicht PASS.
- Schnelle Überprüfungen ersetzen niemals den vollständigen Smoke zum Nachweis der Freisetzungskompatibilität.
- kein gefälschter grüner Status, wenn Voraussetzungen fehlen.

## Empfohlener Durchfluss

```bash
make setup-dev
make quick-all
# if QUICK BLOCKED due to runtime prerequisites:
make fetch-deps
make smoke-all
```


## Installierte Smokeerkennung

`make smoke-installed` / `make installed-readiness` ist eine **detection/readiness**-Prüfung für bereits installierte Systemkomponenten; Es ist kein Ersatz für `make smoke-all`.
Es handelt sich nur um eine optionale Diagnoseausgabe: Der von der Quelle erstellte Anschluss raucht nicht
erfordern Systeminstallationen von Apache, NGINX, APXS oder libmodsecurity.

Erkannte Binärnamen:

- Apache-Laufzeit: `apache2`, `httpd`, `apachectl`
- APXS: `apxs`, `apxs2`
- NGINX Laufzeit: `nginx`

Erkannte ModSecurity-Signale:

- `pkg-config` Paket: `modsecurity` oder `libmodsecurity`
- Gemeinsam genutzte Bibliotheken: `libmodsecurity.so` / `libmodsecurity.so.3`
- Kopfzeile: `modsecurity/modsecurity.h`

Optionale Umgebungsvariablen zum Überschreiben:

- `APACHE_BIN`
- `APACHECTL_BIN`
- `APXS_BIN`
- `NGINX_BIN`
- `MODSECURITY_PKG_CONFIG`
- `MODSECURITY_LIB_DIR`
- `MODSECURITY_INCLUDE_DIR`
- `CI_APACHE_BIN_CANDIDATES`
- `CI_APXS_BIN_CANDIDATES`
- `CI_NGINX_BIN_CANDIDATES`
- `CI_INSTALLED_LIB_SEARCH_DIRS`
- `CI_INSTALLED_INCLUDE_SEARCH_DIRS`

Bereitschaftssemantik:

- `READY`: Komponentensatz wurde erkannt.
- `PARTIAL`: Es ist nur ein Connector-Pfad erkennbar.
- `BLOCKED`: Erforderliche Teile fehlen.

Auch mit `READY` bleibt `smoke-installed` nicht autorisierend, bis eine Verkabelung zur installierten Laufzeitausführung vorhanden ist; `make smoke-all` bleibt maßgeblich.


## Cloud/GitHub Schnellpfad für Aktionen

Verwenden Sie `make cloud-quick-check` für GitHub/Codex CI Umgebungen, in denen Prüfungen erforderlich sind
Bleiben Sie leichtgewichtig und deterministisch.

- Required/pass-fail: `setup-dev`, `lint`, `refresh-framework-reports`,
  `check-test-matrix`, `quick-check`, Python-Kompilierung, `git diff --check`.
- Laufzeitsonden werden absichtlich ausgeschlossen: nein `quick-all`, nein
  `installed-readiness` und kein vollständiger Connectorrauch.
- Dies ersetzt **nicht** `make smoke-all`; Die vollständige Laufzeitvalidierung bleibt bestehen
  lokal und maßgeblich.

Workflow: `.github/workflows/quick-framework-check.yml` führt das Lightweight aus
framework/generator Pfad zu `push` und `pull_request`.

Für Versions- und Pfadänderungen bevorzugen Sie Umgebungsüberschreibungen, die durch verbraucht werden
`$FRAMEWORK_ROOT/ci/common.sh`, zum Beispiel `FRAMEWORK_ROOT`, `CONNECTOR_ROOT`,
`BUILD_ROOT`, `SOURCE_ROOT`,
`MODSECURITY_GIT_REF`, `MODSECURITY_SOURCE_DIR`, `MODSECURITY_V3_SOURCE_DIR`,
`APACHE_BIN`, `APACHECTL_BIN`, `APXS_BIN` und `NGINX_BIN`. Apache und NGINX
Die Connector-Quelle ist standardmäßig repo-lokal. Server-Quellversionen sind konfiguriert
mit `HTTPD_VERSION`, `PCRE2_VERSION`, `NGINX_SOURCE_REPO_URL` und
`NGINX_RELEASE_TAG`. `BUILD_ROOT` ist ein lokaler build/output Standort und kann sein
durch einen beliebigen expliziten absoluten Pfad ersetzt.
