# Upstream-Beschneidungsanalyse

**Sprache:** [English](upstream-pruning-analysis.md) | Deutsch

Status: umgesetzt

Dieses Dokument dokumentiert die Pruning-Überprüfung für den kontrollierten Apache und NGINX
Connector-Quellenimporte. Die Rezension ist bewusst konservativ: Dateien sind es
Nur entfernt, wenn sie einen funktionsfähigen Ersatz haben, werden sie nicht benötigt
Lizenz- oder Ursprungskontext und verfügen über eine erfolgreiche isolierte `$BUILD_ROOT`-Prüfung.
Phase 4 entfernte einen NGINX Debug-Helfer, nachdem eine Repo-eigene Build-Kopie hinzugefügt wurde
Überlagerung. In Phase 5 wurden die verbleibenden Quellhilfsprogramme überprüft und keine weiteren gefunden
sicherer Ersatzkandidat. Phase 9 verschoben NGINX `config` und Modulquelle
Dateien in Adapter-eigene `connectors/nginx/src/`. Phase 10 entfernte die
verbleibender NGINX `upstream/` Attribution-Only-Baum nach dauerhafter Attribution war
bestätigt in `licenses/nginx/`, `connectors/nginx/ORIGIN.md` und
`connectors/nginx/SOURCE_MAP.json`. Phase 11 hat die Apache-Quelle verschoben und
Autotools/APXS Eingaben in Adapter-eigene `connectors/apache/src/`, bewiesen a
materialisierte Build plus echten Apache-Smoke und entfernte den ehemaligen Apache
`upstream/` Referenzbaum.

Phase 8 fügt eine Schatten-Build-Source-Ebene hinzu. Der monorepo-default NGINX wird jetzt erstellt
verwendet `$BUILD_ROOT/nginx-build/connector-src`, ursprünglich generiert aus
verbleibende importierte Upstream-Quelle plus adaptereigene Overlays. Phase 8 selbst
war kein neues Schnittereignis.

Phase 10 ändert die Build-Kopie-Zusammensetzung erneut: die NGINX Modulquelle und
`config` gehören dem Adapter und NGINX leistet keinen Beitrag mehr
`upstream-derived` Dateien zum materialisierten Quellmanifest.

Phase 13 vereinfacht das Repository-Layout, ohne die Materialisierung zu ändern
Build-Layout: Apache-Build-Dateien werden nach `connectors/apache/`, Apache-C-Dateien verschoben
werden unter `connectors/apache/src/` abgeflacht, Apache-Vorlagen werden darunter verschoben
`tests/cases/connector-specific/apache/` und NGINX `config` werden zu `connectors/nginx/config` verschoben.

## Verwendete Nachweise

- Aktenbestand aus den ehemaligen `connectors/apache/upstream/`, ehem
  `connectors/nginx/upstream/` und aktuelle `connectors/apache/` und
  `connectors/nginx/`.
- Apache Autotools-Eingaben: `configure.ac`, `Makefile.am`, `build/*.m4` und
  `build/apxs-wrapper.in`.
- NGINX Modulmetadaten vor Phase 9:
  `connectors/nginx/upstream/config`.
- NGINX Adaptereigene Modulmetadaten nach Phase 9:
  `connectors/nginx/config`.
- Aktuelles Smokegeschirrverhalten in `modules/ModSecurity-test-Framework/ci/prepare-apache-build.sh` und
  `modules/ModSecurity-test-Framework/ci/prepare-nginx-build.sh`.
- Vorhandener realer Smoke-Pfad, der Connector-Quellbäume materialisiert
  gemäß `$BUILD_ROOT` vor dem Bau.

## Ergebnis

| Connector | Importierte Dateien vor der Reduzierung | Nach Phase 4 entfernt | Nach Phase 5 entfernt | Nach Phase 9 entfernt | Nach Phase 10 entfernt | Nach Phase 11 entfernt | Grund |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Apache | 25 | 0 | 0 | 0 | 0 | 25 | Quelle, Autotools-Eingaben, Vorlagen und Namensnennung wurden in den Adapter-eigenen `connectors/apache/src` verschoben; Die dauerhafte Namensnennung bleibt unter `licenses/apache/` |
| NGINX | 12 | 1 | 0 | 7 | 4 | 0 | `src/ddebug.h` wurde durch Repo-eigene `connectors/nginx/src/ddebug.h` ersetzt; NGINX `config` und sechs Modul-source/dependency-Dateien wurden in den Adapter-eigenen `connectors/nginx/src` verschoben; Endgültige Namensnennungsdateien wurden in die dauerhafte Datei `licenses/nginx/` verschoben. |

Die importierten Bäume wurden ausgemustert. Apache und NGINX bleiben nicht mehr lokal
`connectors/*/upstream/` Bäume; Die Quelle des produktiven Connectors gehört dem Adapter
und verfolgt von `connectors/apache/SOURCE_MAP.json` und
`connectors/nginx/SOURCE_MAP.json`.
In Phase 5 wurde aufgrund der Überprüfung absichtlich keine weitere Datei gelöscht
Kandidaten waren Produktions-request/response, Konfigurations-, Lebenszyklus- oder Prüfpfade.

## Apache-Dateiklassifizierung

Quelle: ehemalige `connectors/apache/upstream/`; aktuelles, dem Adapter gehörendes Quellstammverzeichnis:
`connectors/apache/` plus dauerhafte Quellenangabe in `licenses/apache/`.

| Datei | Klassifizierung | Nachweise | Entscheidung |
| --- | --- | --- | --- |
| `AUTHORS` | Nur Dokumentation | Für den kontrollierten Import ist eine Upstream-Zuordnung erforderlich | Aus dem Upstream-Baum in Phase 11 und aus `connectors/apache/src/` in Phase 12 entfernt; dauerhafte Kopie verbleibt bei `licenses/apache/AUTHORS` |
| `CHANGES` | Nur Dokumentation | Der Upstream-Änderungskontext wird mit der importierten Quelle beibehalten | Aus dem Upstream-Baum in Phase 11 und aus `connectors/apache/src/` in Phase 12 entfernt; dauerhafte Kopie verbleibt bei `licenses/apache/CHANGES` |
| `LICENSE` | Dokumentation-nur nach Phase 12 | Lizenztext wird zentral gespeichert; `configure.ac` verwendet jetzt `AC_CONFIG_SRCDIR([src/mod_security3.c])` | Aus dem Upstream-Baum in Phase 11 und aus `connectors/apache/src/` in Phase 12 entfernt; dauerhafte Kopie verbleibt bei `licenses/apache/LICENSE` |
| `README.md` | Nur Dokumentation | Upstream-Build-Kontext durch Repository-eigene Connector-Dokumentation ersetzt | Aus dem Upstream-Baum in Phase 11 und aus `connectors/apache/src/` in Phase 12 entfernt; Die aktuelle Übersicht finden Sie in `connectors/apache/README.md` und Dokumenten |
| `Makefile.am` | erforderlich | Automake-Eingabe für den Connector-Build | Verschoben nach `connectors/apache/Makefile.am` |
| `autogen.sh` | Nur Build | Bootstrapst Autotools-Dateien in der Build-Kopie | Verschoben nach `connectors/apache/autogen.sh` |
| `configure.ac` | erforderlich | Definiert Build-Prüfungen und generierte Vorlagen | Verschoben nach `connectors/apache/configure.ac` |
| `build/apxs-wrapper.in` | Nur Build | APXS Wrapper-Vorlage, die vom Autotools-Build verwendet wird | Verschoben nach `connectors/apache/build/apxs-wrapper.in` |
| `build/ax_prog_apache.m4` | Nur Build | Apache-Erkennungsmakro | Verschoben nach `connectors/apache/build/ax_prog_apache.m4` |
| `build/find_apxs.m4` | Nur Build | APXS Erkennungsmakro | Verschoben nach `connectors/apache/build/find_apxs.m4` |
| `build/find_libmodsec.m4` | Nur Build | libmodsecurity-Erkennungsmakro | Verschoben nach `connectors/apache/build/find_libmodsec.m4` |
| `src/mod_security3.c` | erforderlich | Einstiegspunkt des Apache-Moduls | Verschoben nach `connectors/apache/src/mod_security3.c` |
| `src/mod_security3.h` | erforderlich | Deklarationen des Apache-Moduls | Verschoben nach `connectors/apache/src/mod_security3.h` |
| `src/msc_config.c` | erforderlich | Apache directive/configuration Implementierung | Verschoben nach `connectors/apache/src/msc_config.c` |
| `src/msc_config.h` | erforderlich | Apache-Konfigurationsdeklarationen | Verschoben nach `connectors/apache/src/msc_config.h` |
| `src/msc_filters.c` | erforderlich | Apache input/output Filterimplementierung | Verschoben nach `connectors/apache/src/msc_filters.c` |
| `src/msc_filters.h` | erforderlich | Apache-Filterdeklarationen | Verschoben nach `connectors/apache/src/msc_filters.h` |
| `src/msc_utils.c` | erforderlich | Implementierung des Apache Connector-Dienstprogramms | Verschoben nach `connectors/apache/src/msc_utils.c` |
| `src/msc_utils.h` | erforderlich | Deklarationen des Apache-Connector-Dienstprogramms | Verschoben nach `connectors/apache/src/msc_utils.h` |
| `t/conf/extra.conf.in` | Nur Build | Behält das Layout der Upstream-Testvorlage `t/conf` bei; Referenzen generiert `modules.conf` | Verschoben nach `tests/cases/connector-specific/apache/t/conf/extra.conf.in` |
| `tests/run-regression-tests.pl.in` | Nur Build | Gelistet in `configure.ac` `AC_CONFIG_FILES` | Verschoben nach `tests/cases/connector-specific/apache/run-regression-tests.pl.in` |
| `tests/regression/misc/40-secRemoteRules.t.in` | Nur Build | Gelistet in `configure.ac` `AC_CONFIG_FILES` | Verschoben nach `tests/cases/connector-specific/apache/regression/misc/40-secRemoteRules.t.in` |
| `tests/regression/misc/50-ipmatchfromfile-external.t.in` | Nur Build | Gelistet in `configure.ac` `AC_CONFIG_FILES` | Verschoben nach `tests/cases/connector-specific/apache/regression/misc/50-ipmatchfromfile-external.t.in` |
| `tests/regression/misc/60-pmfromfile-external.t.in` | Nur Build | Gelistet in `configure.ac` `AC_CONFIG_FILES` | Verschoben nach `tests/cases/connector-specific/apache/regression/misc/60-pmfromfile-external.t.in` |
| `tests/regression/server_root/conf/httpd.conf.in` | Nur Build | Gelistet in `configure.ac` `AC_CONFIG_FILES` | Verschoben nach `tests/cases/connector-specific/apache/regression/server_root/conf/httpd.conf.in` |

## NGINX Dateiklassifizierung

Quelle: ehemalige `connectors/nginx/upstream/`; aktuelles Quellverzeichnis:
`connectors/nginx/` plus dauerhafte Quellenangabe in `licenses/nginx/`.

| Datei | Klassifizierung | Nachweise | Entscheidung |
| --- | --- | --- | --- |
| `AUTHORS` | Nur Dokumentation | Für den kontrollierten Import ist eine Upstream-Zuordnung erforderlich | Aus `connectors/nginx/upstream/` entfernt; dauerhafte Kopie verbleibt bei `licenses/nginx/AUTHORS` |
| `CHANGES` | Nur Dokumentation | Der Upstream-Änderungskontext wird mit der importierten Quelle beibehalten | Aus `connectors/nginx/upstream/` entfernt; dauerhafte Kopie verbleibt bei `licenses/nginx/CHANGES` |
| `LICENSE` | erforderlich | Lizenztext für Apache-2.0-importierte Dateien | Aus `connectors/nginx/upstream/` entfernt; dauerhafte Kopie verbleibt bei `licenses/nginx/LICENSE` |
| `README.md` | Nur Dokumentation | Upstream-Build- und Nutzungskontext | Aus `connectors/nginx/upstream/` entfernt; Der Ursprungskontext bleibt in `connectors/nginx/ORIGIN.md` und Dokumenten |
| `config` | ersetzt | NGINX Modul-Build-Metadaten befinden sich jetzt unter `connectors/nginx/config` | Nach der Smokevalidierung der Phase 9 aus dem Upstream entfernt |
| `src/ngx_http_modsecurity_access.c` | ersetzt | Die Kopie im Besitz des Adapters befindet sich jetzt unter `connectors/nginx/src/ngx_http_modsecurity_access.c` | Nach der Smokevalidierung der Phase 9 aus dem Upstream entfernt |
| `src/ngx_http_modsecurity_body_filter.c` | ersetzt | Die Kopie im Besitz des Adapters enthält jetzt PR #377 Quelländerungen | Nach der Smokevalidierung der Phase 9 aus dem Upstream entfernt |
| `src/ngx_http_modsecurity_common.h` | ersetzt | Die Kopie im Besitz des Adapters enthält jetzt PR #377 Quelländerungen | Nach der Smokevalidierung der Phase 9 aus dem Upstream entfernt |
| `src/ngx_http_modsecurity_header_filter.c` | ersetzt | Die Kopie im Besitz des Adapters befindet sich jetzt unter `connectors/nginx/src/ngx_http_modsecurity_header_filter.c` | Nach der Smokevalidierung der Phase 9 aus dem Upstream entfernt |
| `src/ngx_http_modsecurity_log.c` | ersetzt | Die Kopie im Besitz des Adapters befindet sich jetzt unter `connectors/nginx/src/ngx_http_modsecurity_log.c` | Nach der Smokevalidierung der Phase 9 aus dem Upstream entfernt |
| `src/ngx_http_modsecurity_module.c` | ersetzt | Die Kopie im Besitz des Adapters enthält jetzt PR #377 Quelländerungen | Nach der Smokevalidierung der Phase 9 aus dem Upstream entfernt |

## Ersetzte Dateien

| Datei | Vorherige Klassifizierung | Ersatz | Nachweise | Entscheidung |
| --- | --- | --- | --- | --- |
| `connectors/nginx/upstream/src/ddebug.h` | Abhängigkeit aufbauen | `connectors/nginx/src/ddebug.h` wird bei Bedarf in den generierten Build-Baum kopiert | Der Header stellt nur Debug-Makros und Sanity-Check-No-Ops bereit; Es besitzt keine Hooks, Filter, Körper, Transaktionen oder den libmodsecurity-Lebenszyklus | Nach Smokevalidierung entfernt |

## Phase-4-Entfernungsentscheidung

Eine Datei wurde in Phase 4 entfernt. Zu diesem Zeitpunkt:

- Apache-`.in`-Vorlagen bleiben erhalten, da `configure.ac` auf sie verweist
  direkt über `AC_CONFIG_FILES`.
- NGINX Produktionsquelldateien wurden aufgrund `config` explizit beibehalten
  listete sie als Modulquellen oder Abhängigkeiten auf.
- NGINX `config` weiterhin aufgelistet `src/ddebug.h`, aber die generierte Build-Kopie
  erhielt einen Repo-eigenen Ersatz, wenn dieser im ausgewählten Quellbaum fehlte.
- Lizenz- und Namensnennungsdateien wurden zur Herkunft und Weiterverbreitung aufbewahrt
Klarheit.

Jede zukünftige Löschung muss in einer isolierten Kopie gemäß `$BUILD_ROOT` validiert werden.
dann folgen realer Apache, NGINX und kombinierte Smoke-Runs.

## Phase 5-Entscheidung zur Nichtentfernung

In Phase 5 wurde ein zweiter Ersatzkandidatensatz überprüft und es wurden keine neuen Entfernungen vorgenommen.

| Kandidat | Nachweise | Entscheidung |
| --- | --- | --- |
| Apache `id()`-Helfer | Keine Aufrufer außerhalb seines declaration/definition, aber durch das Entfernen würde `msc_utils.c/.h` bearbeitet, der auch `send_error_bucket()`-Deklarationen und den Apache-Dienstprogrammkontext besitzt | Zurückstellen als obsolete/reference-only, bis der Apache-Adaptercode im Besitz des Repo ist |
| Apache `send_error_bucket()` | Angerufen von `msc_filters.c`; Erstellt Apache-Buckets und steuert den Fehlerreaktionsfluss | Aufschieben |
| NGINX `ngx_str_to_char()` | Wird von Konfigurationsanweisungen, Standortzusammenführung und Anforderungsmetadatenzuordnung verwendet | Aufschieben |
| NGINX PCRE Poolhelfer | An NGINX Pool und rules/config Ladelebenszyklus gebunden | Aufschieben |
| NGINX Antwort-Header-Resolver-Helfer | Direkte Antwort header/filter Pfad | Aufschieben |
| NGINX Protokollrückruf | Audit/log Verhalten bleibt beweissensitiv | Aufschieben |

Kein Phase-5-Kandidat kann reduziert werden, ohne einen Adapter-eigenen Ersatz zu schaffen
Code in einem Produktions-Connector-Pfad. Das liegt absichtlich außerhalb des Rahmens
diese Rezension.

## Phase 8 Reduzierung des Bauaufwands

Der generierte NGINX Connector-Quellbaum reduziert die direkte Build-Abhängigkeit vom
ehemaliges `connectors/nginx/upstream/`-Verzeichnis. Zu diesem Zeitpunkt wurde das beibehalten
Der Upstream-Baum bleibt eine reference/provenance-Quelle, während der Wegwerfbaum vorhanden ist
`$BUILD_ROOT` Baum zeichnete die tatsächliche Build-Kopie-Zusammensetzung auf.

Apache erhält die gleiche Nur-Manifest-Vorbereitung. Sein produktiver Modulaufbau
Verwendet weiterhin die bereinigte Upstream-Kopie in Phase 8.

## Phase 9 NGINX Quellmigration

Phase 9 macht den generierten NGINX Build-Quelladapter standardmäßig zum Besitzer:

- `connectors/nginx/config` wird zu Root `config`;
- NGINX Modulquellen und `ngx_http_modsecurity_common.h` materialisieren sich unter
  `src/`;
- Upstream beibehalten `LICENSE`, `AUTHORS`, `CHANGES` und `README.md` bleiben erhalten
  `upstream-derived` im Manifest;
- `MATERIALIZED_SOURCE.md` und `materialized-source.json` sind
  `generated-overlay`;
- PR #377 Die Patch-Herkunft wird für den Body-Filter, den gemeinsamen Header und aufgezeichnet
  Modulquelleneinträge.

Dies ist eine Quellenreduzierung, keine semantische Hochstufung von
Phase-4-Reaktionskörperblockierung. `RESPONSE_BODY` bleibt ehemaliger expected-failure/mapped-only.

## Phase 10 Endgültige NGINX Upstream-Entfernung

Phase 10 entfernt den verbleibenden NGINX Upstream-Referenzbaum. Das materialisierte
Die NGINX-Quelle wird aus dem Adapter-eigenen `connectors/nginx/config` generiert.
`connectors/nginx/src/` und nur generierte Manifeste. Die Namensnennung bleibt erhalten
in `licenses/nginx/`, `connectors/nginx/ORIGIN.md` und
`connectors/nginx/SOURCE_MAP.json`.
