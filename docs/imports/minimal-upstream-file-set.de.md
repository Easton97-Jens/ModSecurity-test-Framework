# Minimaler Upstream-Dateisatz

**Sprache:** [English](minimal-upstream-file-set.md) | Deutsch

Status: umgesetzt

Dieses Dokument definiert die aktuellen, dem Adapter gehörenden Apache- und NGINX-Quellsätze
Wird von den Monorepo-Smokekonstruktionen verwendet. Die Dateien bleiben konnektorspezifisch. Phase 9
migrierte die NGINX-Modulquelle in den Adapter-eigenen `connectors/nginx/src`;
Phase 10 entfernte den früheren NGINX `upstream/` Referenzbaum. Phase 11 migriert
Apache-Quelle und Autotools/APXS-Eingaben in `connectors/apache/src` haben das bewiesen
materialisierte den Apache-Build und entfernte den früheren Apache `upstream/`-Baum.
Phase 12 hat Apache-attribution/history/documentation-only-Dateien aus dem entfernt
Aktiver Quellbaum. Kein Apache-Hook, NGINX Filter, Body, Transaktion oder Common
Die Laufzeitlogik wurde konnektorübergreifend zusammengeführt.

## Apache-Connector

Adaptereigenes Build-Source-Stammverzeichnis: `connectors/apache/`

Erforderlich für die Build- und Modulerstellung:

- `autogen.sh`
- `configure.ac`
- `Makefile.am`
- `build/apxs-wrapper.in`
- `build/ax_prog_apache.m4`
- `build/find_apxs.m4`
- `build/find_libmodsec.m4`
- `src/mod_security3.c`
- `src/mod_security3.h`
- `src/msc_config.c`
- `src/msc_config.h`
- `src/msc_filters.c`
- `src/msc_filters.h`
- `src/msc_utils.c`
- `src/msc_utils.h`

Nur-Build-Vorlagen werden aufgrund von `configure.ac` oder dem Upstream-Test beibehalten
Das Layout verweist auf sie:

- `t/conf/extra.conf.in`
- `tests/run-regression-tests.pl.in`
- `tests/regression/misc/40-secRemoteRules.t.in`
- `tests/regression/misc/50-ipmatchfromfile-external.t.in`
- `tests/regression/misc/60-pmfromfile-external.t.in`
- `tests/regression/server_root/conf/httpd.conf.in`

Der Herkunftskontext wird außerhalb des funktionalen Quellbaums beibehalten:

- `connectors/apache/SOURCE_MAP.json`

Dauerhafte Attribution außerhalb des Quellbaums:

- `licenses/apache/LICENSE`
- `licenses/apache/AUTHORS`
- `licenses/apache/CHANGES`
- `connectors/apache/ORIGIN.md`

Materialisierte Build-Eingabe:

- Monorepo-Standard-Apache-Builds verwenden
  `$BUILD_ROOT/apache-build/connector-src`.
- Der Materializer kopiert adaptereigene Build-Dateien aus `connectors/apache/`
  gemäß `connectors/apache/SOURCE_MAP.json`, bewahrt das Generierte
  Autotools-Layout und schreibt `MATERIALIZED_SOURCE.md` plus
`materialized-source.json`.
- Es wird erwartet, dass das generierte Manifest die Apache-Quelle, Build-Dateien usw. auflistet
  Vorlagen als `adapter-owned`, ohne Apache `upstream-derived`-Einträge.

## NGINX Connector

Es gibt keinen verbleibenden NGINX `connectors/nginx/upstream/` Baum. Ersteres
Upstream-Referenzdateien wurden in Phase 10 entfernt, nachdem die dauerhafte Zuordnung erfolgte
bestätigt in:

- `licenses/nginx/LICENSE`
- `licenses/nginx/AUTHORS`
- `licenses/nginx/CHANGES`
- `licenses/nginx/ORIGIN.md`
- `connectors/nginx/ORIGIN.md`
- `connectors/nginx/SOURCE_MAP.json`

Adaptereigene NGINX-Modul-Build-Eingaben:

- `connectors/nginx/config`
- `connectors/nginx/src/ngx_http_modsecurity_access.c`
- `connectors/nginx/src/ngx_http_modsecurity_body_filter.c`
- `connectors/nginx/src/ngx_http_modsecurity_common.h`
- `connectors/nginx/src/ngx_http_modsecurity_header_filter.c`
- `connectors/nginx/src/ngx_http_modsecurity_log.c`
- `connectors/nginx/src/ngx_http_modsecurity_module.c`
- `connectors/nginx/src/ddebug.h`
- `connectors/nginx/SOURCE_MAP.json`

§PR #377 Herkunft:

- `connectors/nginx/src/ngx_http_modsecurity_body_filter.c`,
`connectors/nginx/src/ngx_http_modsecurity_common.h`, und
  `connectors/nginx/src/ngx_http_modsecurity_module.c` enthalten Quelländerungen
  von ModSecurity-nginx PR #377 commit
  `3d72b004ff27a78ea19c6b945870e2cae62a97ac`.
- Bei diesen Änderungen handelt es sich lediglich um Phase-4-Evidenz auf Quellenebene. `RESPONSE_BODY` bleibt bestehen
  ehemalige expected-failure/mapped-only und aus `verified_variables` ausgeschlossen.

Materialisierte Build-Eingabe:

- Monorepo-default NGINX Builds verwenden
  `$BUILD_ROOT/nginx-build/connector-src`.
- Der Materializer kopiert die Adapter-eigenen `connectors/nginx/config` und
  `connectors/nginx/src` Dateien gemäß `connectors/nginx/SOURCE_MAP.json`
  und schreibt `MATERIALIZED_SOURCE.md` plus `materialized-source.json`.
- Externe NGINX-Quell-Builds verwenden weiterhin eine bereinigte externe Quellkopie; wenn
  dem ausgewählten externen Quellbaum fehlt `src/ddebug.h`,
  `modules/ModSecurity-test-Framework/ci/provisioning/prepare-nginx-build.sh` überlagert den Repo-eigenen Header in den generierten
  Externe Build-Kopie.

## Zukünftige gemeinsame Extraktionskandidaten

Dies sind nur Kandidaten. Sie dürfen nicht bewegt werden, bis das Verhalten nachgewiesen ist
Der reale Connector raucht nach dem Herausziehen.

| Kategorie | Apache-Quellbereich | NGINX Quellbereich | Aktuelle Entscheidung |
| --- | --- | --- | --- |
| Debug-Kompatibilität | keine | Repo-eigene `connectors/nginx/src/ddebug.h` | Importierter Upstream-Debug-Helfer ersetzt |
| Regelsatz wird geladen | `src/msc_config.*` | `src/ngx_http_modsecurity_module.c` | Konnektorspezifisch bleiben |
| Transaktionslebenszyklus | `src/mod_security3.c`, `src/msc_filters.*` | access/header/body/log Quellen | Konnektorspezifisch bleiben |
| Umgang mit Interventionen | `src/mod_security3.c`, `src/msc_utils.*` | `src/ngx_http_modsecurity_module.c` | Konnektorspezifisch bleiben |
| Audit/logging | Apache-Protokoll hook/filter Code | `src/ngx_http_modsecurity_log.c` | Konnektorspezifisch bleiben |
| Metadatenzuordnung anfordern | Apache request/filter-Code | `src/ngx_http_modsecurity_access.c` | Konnektorspezifisch bleiben |
| Zuordnung von Antwortmetadaten | Apache-Ausgabefiltercode | NGINX header/body Filter | Konnektorspezifisch bleiben |
| Konfigurationsmodell | Apache per-dir/server Konfiguration | NGINX main/location Konfig | Konnektorspezifisch bleiben |
| Fehlerbehandlung | Apache-Dienstprogramm und Hook-Pfade | NGINX return/finalize Pfade | Konnektorspezifisch bleiben |

## Schnittregel

Entfernen Sie eine Datei nicht aus einem Adapter-eigenen Quellbaum, es sei denn, alle
Folgendes trifft zu:

- Es wird nicht durch Build-Metadaten oder Quell-Includes referenziert.
- Es ist nicht für Lizenz-, Namensnennungs- oder Quellenkontexte erforderlich.
- Es handelt sich nicht um einen dokumentierten zukünftigen Kandidaten für eine gemeinsame Extraktion.
- Eine Einwegsonde unter `$BUILD_ROOT` beweist, dass Apache, NGINX und
  Mischrauch geht auch ohne vorbei.

Die Phase-4-Überprüfung hat einen sicheren Ersatz gefunden: die NGINX Debug-Kompatibilität
Kopfzeile. In Phase 9 wurde die produktive NGINX-Quelle in Dateien im Besitz des Adapters migriert.
Phase 10 entfernte den verbleibenden NGINX Upstream-Referenzbaum, da kein Build vorhanden war
Der Input hing davon ab und eine dauerhafte Zuschreibung blieb an anderer Stelle verfügbar. Phase
11 hat die Apache-Produktivquelle migriert und Eingaben in Dateien im Besitz des Adapters erstellt.
bewies einen materialisierten Autotools/APXS-Build und entfernte den früheren Apache
vorgelagerter Baum. Phase 12 reduzierte den Quellbaum des Apache-Adapters auf
funktionale build/runtime-Eingaben plus Herkunftsmetadaten; Nur Namensnennung
Dateien wurden nach `licenses/apache/` verschoben.

## Phase-8-Shadow-Build-Quelle

Phase 8 entfernt keine zusätzlichen Upstream-Dateien. Es verändert das Monorepo
Standardmäßig NGINX Build-Eingabe von einer direkt bereinigten Upstream-Kopie zu
`$BUILD_ROOT/nginx-build/connector-src`. Dieser generierte Quellbaum enthält
Manifeste, die `adapter-owned`, `upstream-derived` und identifizieren
`generated-overlay` Dateien.

Phase 11 ersetzt die Apache-Phase-8-Vorbereitung: Apache erstellt jetzt direkt
aus `$BUILD_ROOT/apache-build/connector-src`.

## Phase 9 NGINX Quellmigration

In Phase 9 wurden das NGINX-Modul `config` und alle verbleibenden Modulquelldateien verschoben
von `connectors/nginx/upstream/` zu `connectors/nginx/src/`, dann entfernt
Upstream-Kopien, nachdem ein Materialized-Source-NGINX-Smoke passiert ist.

## Phase 10 NGINX Upstream-Entfernung

Phase 10 entfernt die verbleibenden `connectors/nginx/upstream/` nur mit Namensnennung
Baum. Monorepo-default NGINX-Builds werden jetzt aus einer Quelle im Besitz des Adapters erstellt
nur. Es wird erwartet, dass das generierte Manifest NGINX `config` und das Modul auflistet
Quellen als `adapter-owned`, ohne NGINX `upstream-derived` Einträge.

## Phase 11 Apache-Quellmigration

Phase 11 verschobene Apache-Quelle, Autotools/APXS Dateien, license/provenance Dateien,
und erforderliche `.in`-Vorlagen in `connectors/apache/src/`. Das Monorepo
Die Standard-Apache-Quelle wird jetzt materialisiert
`$BUILD_ROOT/apache-build/connector-src` und aus diesem generierten Baum erstellt.
Der ehemalige `connectors/apache/upstream/`-Baum wurde danach entfernt
`REFRESH=1 BUILD_ROOT=/src/ModSecurity-conector-apache-final-build make
„Smoke-Apache“ ist vergangen.

## Phase 12 Apache-Quellenbereinigung

Phase 12 entfernt `AUTHORS`, `CHANGES`, `LICENSE` und `README.md` aus
`connectors/apache/src/`. Der Autoconf-Quellanker wurde von `LICENSE` geändert
zu `src/mod_security3.c`, daher befinden sich Nur-Attribution-Dateien außerhalb des Builds
Quelle. Die Namensnennung bleibt in `licenses/apache/`, `connectors/apache/ORIGIN.md`,
und der Abschnitt `relocated_files` von `connectors/apache/SOURCE_MAP.json`.

## Phase 13 Layoutvereinfachung

Phase 13 hält das materialisierte Build-Layout stabil und vereinfacht gleichzeitig das
Repository-Layout:

- Apache-Autotools/APXS-Dateien befinden sich unter `connectors/apache/`.
- Apache-Produktiv-C-Dateien befinden sich direkt unter `connectors/apache/src/`.
- Von Apache beibehaltene Autotools-Vorlagen finden Sie unter `tests/cases/connector-specific/apache/` und
  materialisieren sich wieder zu `t/` und `tests/`.
- Apache-Metadaten und Herkunft finden Sie unter `connectors/apache/metadata.*` und
  `connectors/apache/SOURCE_MAP.json`, nicht in `src/`.
- NGINX `config` befindet sich unter `connectors/nginx/config` und wird im Root gespeichert
  `config`.
- NGINX `src/` enthält nur das produktive Modul headers/sources plus `ddebug.h`.
- NGINX Metadaten und Herkunft finden Sie unter `connectors/nginx/metadata.*` und
  `connectors/nginx/SOURCE_MAP.json`, nicht in `src/`.

## Ergebnis der Phase-5-Überprüfung

In Phase 5 wurde eine zweite mögliche Reduzierung geprüft und kein weiterer Upstream vorgenommen
Änderungen. Die restlichen kleinen Helfer sind keine eigenständigen debug/build Unterlegscheiben:

- Apache `id()` scheint nicht verwendet zu werden, aber wenn Sie es entfernen, wird das importierte bearbeitet
`msc_utils.c/.h` Paar für keinen funktionalen Ersatz.
- Apache `send_error_bucket()` besitzt das Antwortverhalten von Apache bucket/error.
- NGINX `ngx_str_to_char()` wird von der Konfigurationsanalyse und den Anforderungsmetadaten gemeinsam genutzt
  Kartierung.
- NGINX PCRE Poolhelfer sind Teil des rules/config Lebenszyklus.
- NGINX Response-Header-Resolver-Helfer und Protokollrückruf sind aktiv
  response/audit Pfade.

Diese Bereiche bleiben konnektorspezifisch, bis Repo-eigene Adapterimplementierungen vorgenommen werden
existieren und before/after Smoke aus der realen Welt beweisen Äquivalenz.
