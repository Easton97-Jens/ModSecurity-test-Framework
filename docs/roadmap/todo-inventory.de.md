# TODO Inventar

**Sprache:** [English](todo-inventory.md) | Deutsch

Status: umgesetzt

Dieses Inventar verfolgt umsetzbare Arbeitsmarkierungen und eine mit dem Status gekennzeichnete Planung
Einträge. Es schließt absichtlich Laufzeitstatuszeichenfolgen wie Shell aus
`blocked()`-Funktionen, JSON-Zähler und gewöhnliches Ergebnisvokabular.

## Zusammenfassung

| Kategorie | Zählen | Notizen |
| --- | ---: | --- |
| Besitzt open/planned Artikel | 23 | Common-, Schema-, Normalizer-, Connector- und Future-Connector-Planung |
| Im Besitz früherer expected-failure/mapped-Nachweise | 4 | `RESPONSE_BODY`, `v3_action_nolog_pass_no_audit`, RAW-ARGS, Vorbehalt beim Pass-Through des Antworttexts |
| Eigene Gegenstände behoben | 1 | In Refactor-Phase 3 hinzugefügte allgemeine Metadaten-Helper-Implementierungen |
| Imported/upstream-derived Markierungen | 22 | Bleibt in der Apache- und NGINX-Quelle des Adapters unberührt; als „adaptereigene Quelle“ klassifiziert |
| Obsolete/resolved Markierungen gereinigt | 11 | Eigene `TODO:`-Überschriften wurden durch nachverfolgte Inventarreferenzen ersetzt |

## Inventar

| Datei | Linie | Markierung | Text | Kategorie | Status | Priorität | Eigentümerbereich | Aktion |
| --- | ---: | --- | --- | --- | --- | --- | --- | --- |
| `common/docs/design.md` | 58 | offene Arbeit | Definieren Sie Eigentumsregeln für Header- und Body-Puffer | Refaktor | geplant | P1 | häufig | Entwurf vor dem Verschieben der Adapterlogik in `common/` |
| `common/docs/design.md` | 59 | offene Arbeit | Entscheiden Sie, wo neutrale Statuswerte Teil zukünftiger Adapter-APIs werden | Refaktor | geplant | P2 | häufig | Erneuter Besuch beim ersten Adaptervorschlag API |
| `common/docs/design.md` | 60 | offene Arbeit | Fügen Sie Kompilierungstests hinzu, um zu beweisen, dass Header konnektorunabhängig bleiben | testen | geplant | P2 | häufig | Fügen Sie hinzu, wenn allgemeine Header zu Build-Eingaben werden |
| `common/src/README.md` | 19 | Phase 3 gelöst | Fügen Sie Implementierungsdateien nur hinzu, wenn ein konnektorneutraler Bedarf besteht | Refaktor | gelöst | P3 | häufig | Es gibt jetzt nur auf Metadaten beschränkte Common C-Helfer; Eine umfassendere Laufzeitextraktion bleibt zurückgestellt |
| `docs/imports/common/schema.md` | 67 | offene Arbeit | Definieren Sie ein maschinenlesbares JSON-Schema | testen | geplant | P1 | docs/imports/common | Fügen Sie ein Schema hinzu, nachdem sich die YAML-Form stabilisiert hat |
| `docs/imports/common/schema.md` | 68 | offene Arbeit | Konnektorspezifische Felder bei der allgemeinen Schemavalidierung ablehnen | testen | geplant | P1 | docs/imports/common | Mit maschinenlesbarem Schema hinzufügen |
| `modules/ModSecurity-test-Framework/tests/normalizers/README.md` | 18 | offene Arbeit | Normalisierung der Header-Reihenfolge | testen | geplant | P2 | Normalisierer | Fügen Sie einen artefaktspezifischen Parser hinzu |
| `modules/ModSecurity-test-Framework/tests/normalizers/README.md` | 19 | offene Arbeit | Analyse des Audit-Log-Abschnitts | Audit-Protokoll | geplant | P2 | Normalisierer | Fügen Sie einen stabilen abschnittsbewussten Parser hinzu |
| `modules/ModSecurity-test-Framework/tests/normalizers/README.md` | 20 | offene Arbeit | Connectorspezifische Protokollformate | Connector | aufgeschoben | P3 | Connectortests | Behalten Sie Connector-spezifische Normalisierer bei |
| `connectors/apache/TODO.md` | 1 | Planungsdatei | Apache-spezifische build/runtime/refactor-Elemente | Connector | geplant | P1 | Apache | Bewahren Sie eine mit diesem Inventar verknüpfte steckerlokale Checkliste auf |
| `connectors/nginx/TODO.md` | 1 | Planungsdatei | NGINX-spezifische build/runtime/refactor-Elemente | Connector | geplant | P1 | Nginx | Bewahren Sie eine mit diesem Inventar verknüpfte steckerlokale Checkliste auf |
| `connectors/haproxy/TODO.md` | 3 | `Status: unknown` | Integrationspfad ungeklärt | Zukunftsverbinder | geplant | P2 | haproxy | Entscheiden Sie sich nach gemeinsamer Stabilisierung |
| `connectors/envoy/TODO.md` | 3 | `Status: unknown` | Integrationspfad ungeklärt | Zukunftsverbinder | geplant | P2 | Gesandter | Entscheiden Sie sich nach gemeinsamer Stabilisierung |
| `connectors/lighttpd/TODO.md` | 3 | `Status: unknown` | Integrationspfad ungeklärt | Zukunftsverbinder | geplant | P2 | lighttpd | Entscheiden Sie sich nach gemeinsamer Stabilisierung |
| `connectors/traefik/TODO.md` | 3 | `Status: unknown` | Integrationspfad ungeklärt | Zukunftsverbinder | geplant | P2 | traefik | Entscheiden Sie sich nach gemeinsamer Stabilisierung |
| `connectors/apache/docs/architecture.md` | 16 | offene Arbeit | Genaue Hakenreihenfolge für einen neuen Adapter | Connector | geplant | P1 | Apache | Dokumentieren Sie, bevor Sie Änderungen am Apache-Adapter vornehmen |
| `connectors/apache/docs/build.md` | 56 | offene Arbeit | Mindestanforderungen Apache/APR/APR-util/PCRE | ci | geplant | P2 | Apache | Aufzeichnung aus einer reproduzierbaren Build-Matrix |
| `connectors/nginx/docs/architecture.md` | 17 | offene Arbeit | Genaue phase/filter Bestellung für dieses Repo | Connector | geplant | P1 | Nginx | Dokument vor gepflegten NGINX Adapteränderungen |
| `connectors/nginx/docs/build.md` | 44 | offene Arbeit | Unterstützte NGINX-Versionen und statischer Modulnachweis | ci | geplant | P2 | Nginx | Behalten Sie das dynamische Modul als aktiven PoC-Pfad bei |
| `connectors/*/docs/build.md` | 7 | offene Arbeit | Zukünftige Connector-Build-Dokumente | Zukunftsverbinder | geplant | P2 | Zukunftsverbinder | Nur füllen, wenn ein Verbindungspfad ausgewählt ist |
| `docs/testing/v3-api-smoke-test.md` | 281 | offene Arbeit | Halten Sie den v3-Build-Copy-Pfad reproduzierbar und dokumentieren Sie das Fallback-Verhalten | testen | geplant | P2 | v3-api-smoke | API Smoke vom Connectorschutz fernhalten |
| `docs/imports/import-analysis-modsecurity-v2.md` | 57 | offene Arbeit | Zuordnung pro Test von v2-Perl-Strukturen zu v3 YAML-Fällen | testen | geplant | P2 | Importe | Setzen Sie nur die von der Quelle abgeleitete Zuordnung fort |
| `docs/roadmap/roadmap.md` | 12 | RAW-ARGS | PR #3564-abhängige RAW Argumentsammlungsfälle | rohe Argumente | kartiert | P1 | docs/imports/common | Aktivierung erst nach lokaler Quellunterstützung plus Apache/NGINX PASS |
| `docs/evidence/raw-args-pr3564.md` | 8 | PR #3564 | RAW Argumentsammlungsbeweise | rohe Argumente | kartiert | P1 | Nachweise | Nur zugeordnet bleiben, bis die Unterstützung nachgewiesen ist |
| `docs/testing/response-body-blocking-investigation.md` | 1 | früherer erwarteter Misserfolg | Sonde zum Blockieren des Reaktionskörpers | Antwortkörper | früherer erwarteter Misserfolg | P1 | Anschlüsse | Nicht hochstufen, bis beide Konnektoren wieder stabil sind HTTP 403 |
| `tests/cases/response/body/response_body_basic_block.yaml` | 1 | ehemaliger Fall eines erwarteten Scheiterns | Gemeinsam genutzter Antwortkörper-Blockierungstest | Antwortkörper | früherer erwarteter Misserfolg | P1 | docs/imports/common | Nur explizite Prüfung; von der normalen Entdeckung ausgeschlossen |
| `tests/cases/audit-log/v3_action_nolog_pass_no_audit.yaml` | 1 | ehemaliger Fall eines erwarteten Scheiterns | `nolog,pass` Audit-Abwesenheit unterscheidet sich lokal von CI | Audit-Protokoll | früherer erwarteter Misserfolg | P2 | docs/imports/common | Bleib prüfbar, aber nicht aktiv, gemeinsam PASS |
| `connectors/apache/src/msc_filters.c` | 65 | Upstream-abgeleitete FIXME | Apache response/body Filter-Sicherheitshinweis | Antwortkörper | kartiert | P2 | Adaptereigene Quelle | Lassen Sie es unberührt; Verfolgen Sie während des Refactorings des Antwortfilters |
| `tests/cases/connector-specific/apache/run-regression-tests.pl.in` | 482 | Upstream-abgeleitete TODO | Verwenden Sie `select()`/`poll()` im Upstream-Harness | Aufräumen | aufgeschoben | P3 | Adaptereigene Quelle | Nicht von aktiven Smokeern verwendet |
| `tests/cases/connector-specific/apache/regression/server_root/conf/httpd.conf.in` | 3 | Upstream-abgeleitete TODO | Konfigurierbarkeit der Upstream-Regressionsvorlage | Aufräumen | aufgeschoben | P3 | Adaptereigene Quelle | Als Konfigurationsvorlage beibehalten |
| `connectors/nginx/src/ngx_http_modsecurity_module.c` | 245 | Upstream-abgeleitete FIXME | Genauigkeit des Antwortcodes des Prüfprotokolls | Audit-Protokoll | kartiert | P2 | Adaptereigene Quelle | Relevant für die Prüfung von Metadaten; Bearbeiten Sie nicht ohne eine spezielle NGINX Adapteränderung |
| `connectors/nginx/src/ngx_http_modsecurity_module.c` | 826 | Upstream-abgeleitete TODO | Protokollphasenparität mit Apache | Audit-Protokoll | kartiert | P2 | Adaptereigene Quelle | Verfolgen Sie die Helferextraktion vor der Protokollierung |
| `connectors/nginx/src/ngx_http_modsecurity_header_filter.c` | 423 | Upstream-abgeleitete XXX | `NOT_MODIFIED` Header-Filter-Verhalten | Antwortkörper | kartiert | P2 | Adaptereigene Quelle | Relevant für Antwortfilter-Nachweise |
| `connectors/nginx/src/ngx_http_modsecurity_header_filter.c` | 439 | Upstream-abgeleitete XXX | Bereits bearbeitete Anfragefrage | Antwortkörper | kartiert | P2 | Adaptereigene Quelle | Relevant für Antwortfilter-Nachweise |
| `connectors/nginx/src/ngx_http_modsecurity_header_filter.c` | 440 | Upstream-abgeleitete XXX | `ModSecurity off` Verhalten | Antwortkörper | kartiert | P2 | Adaptereigene Quelle | Relevant für Antwortfilter-Nachweise |
| `connectors/nginx/src/ngx_http_modsecurity_header_filter.c` | 445 | Upstream-abgeleitete FIXME | Überprüfen Sie den Status der bereits verarbeiteten Anfrage | Antwortkörper | kartiert | P2 | Adaptereigene Quelle | Relevant für Antwortfilter-Nachweise |
| `connectors/nginx/src/ngx_http_modsecurity_header_filter.c` | 454 | Upstream-abgeleitete FIXME | `SecResponseBody` Flag-Behandlung deaktiviert | Antwortkörper | kartiert | P2 | Adaptereigene Quelle | Relevant für PR #377 Nachweise |
| `connectors/nginx/src/ngx_http_modsecurity_body_filter.c` | 35 | Upstream-abgeleitete XXX | Verhalten mehrerer Körperfilter | Antwortkörper | kartiert | P2 | Adaptereigene Quelle | Relevant für Antwortfilter-Nachweise |
| `connectors/nginx/src/ngx_http_modsecurity_body_filter.c` | 168 | Upstream-abgeleitete XXX | Letzter Puffer / letzte Kettenbehandlung | Antwortkörper | kartiert | P2 | Adaptereigene Quelle | Relevant für PR #377 Nachweise |
| `connectors/nginx/src/ngx_http_modsecurity_body_filter.c` | 182 | Upstream-abgeleitete XXX | ModSecurity-Body-Transfer und Inhaltslängenanpassung | Antwortkörper | kartiert | P1 | Adaptereigene Quelle | Relevant für PR #377 Nachweise |
| `connectors/nginx/src/ngx_http_modsecurity_body_filter.c` | 206 | Upstream-abgeleitete XXX | Filterrückgabeverhalten | Antwortkörper | kartiert | P2 | Adaptereigene Quelle | Relevant für Antwortfilter-Nachweise |
| `connectors/nginx/src/ngx_http_modsecurity_access.c` | 80 | Upstream-abgeleitete FIXME | Auswahl des Adressmetadatentyps | Connector | kartiert | P3 | Adaptereigene Quelle | Kandidat für die Überprüfung der Metadatenzuordnung |
| `connectors/nginx/src/ngx_http_modsecurity_access.c` | 95 | Upstream-abgeleitete FIXME | Frühere NGINX Hook-Phase | Connector | kartiert | P2 | Adaptereigene Quelle | Kandidat für die Phasen-Timing-Überprüfung |
| `connectors/nginx/src/ngx_http_modsecurity_access.c` | 172 | Upstream-abgeleitete FIXME | Anfrage sicher abschließen | Connector | kartiert | P1 | Adaptereigene Quelle | Relevant vor der Interventionsextraktion |
| `connectors/nginx/src/ngx_http_modsecurity_access.c` | 291 | Upstream-abgeleitete FIXME | Leerer Upstream-Marker | Aufräumen | aufgeschoben | P3 | Adaptereigene Quelle | Bleiben Sie unberührt, bis die Bereinigung im Besitz des Adapters separat festgelegt wird |
| `connectors/nginx/src/ngx_http_modsecurity_access.c` | 338 | Upstream-abgeleitete TODO | `request_body_in_single_buf` Nutzen | Anfragetext | kartiert | P2 | Adaptereigene Quelle | Kandidat für die Überprüfung der Anforderungstextpufferung |
| `connectors/nginx/src/ngx_http_modsecurity_access.c` | 386 | Upstream-abgeleitete TODO | Streamen Sie Brocken, sobald sie eintreffen | Anfragetext | kartiert | P2 | Adaptereigene Quelle | Streaming bleibt außerhalb des aktiven Bereichs |
| `connectors/nginx/src/ngx_http_modsecurity_access.c` | 425 | Upstream-abgeleitete XXX | Kettenverarbeitung und Interventionszeitpunkt | Connector | kartiert | P2 | Adaptereigene Quelle | Kandidat für Interventionsprüfung |
| `connectors/nginx/src/ngx_http_modsecurity_access.c` | 445 | Upstream-abgeleitete XXX | Körper mutation/content-length Anpassung | Antwortkörper | kartiert | P1 | Adaptereigene Quelle | Relevant für Antwortfilter-Nachweise |

## Gereinigte Marker

Die folgenden Besitzmarkierungen wurden entfernt oder durch Inventarreferenzen ersetzt:

- `common/docs/design.md` alte `## TODO` Überschrift.
- `common/src/README.md` alte `TODO:` Überschrift.
- `docs/imports/common/schema.md` alte `TODO:` Überschrift.
- `modules/ModSecurity-test-Framework/tests/normalizers/README.md` alte `TODO:` Überschrift.
- Connector-lokale `TODO.md`-Titel verwenden jetzt „Planning“, während die Datei beibehalten wird
  Namen, die von Workflow-Strukturprüfungen erwartet werden.
- Connector-build/architecture-Dokumente verwenden jetzt die Formulierung „Offene Arbeit“ und verweisen hierher.
- Apache- und NGINX-PoC-Dokumente verwenden jetzt „Tracked Open Work“ und verweisen stattdessen hierher
  eigenständige TODO-Listen zu führen.
