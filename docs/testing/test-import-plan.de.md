# Testimportplan

**Sprache:** [English](test-import-plan.md) | Deutsch

Status: umgesetzt

Dieses Dokument dokumentiert die aktuelle Importrichtlinie für Connector-Tests. Historisch
Lokale Quellrepositorys waren während des Imports schreibgeschützte Referenzen. stromaufwärts
GitHub-Repositories bleiben die tragbaren Attributionsreferenzen für Rezensionen. Nein
Die Upstream-Apache- oder NGINX-Testdatei wird wörtlich in dieses Repository kopiert und
Die Quelle des Laufzeit-Connectors stammt nun standardmäßig aus diesem Repository.

## Inventar

Beobachteter lokaler Quellenbestand am 15.05.2026:

| Quelle | Referenzrolle | Stromaufwärts | Relevante Dateien analysiert | Notizen |
| --- | --- | --- | ---: | --- |
| ModSecurity-Apache-Tests | historisch import/reference | https://github.com/owasp-modsecurity/ModSecurity-apache | 29 | Apache-Regression `.t`, `.t.in` und Harness-Dateien |
| ModSecurity-nginx-Tests | historisch import/reference | https://github.com/owasp-modsecurity/ModSecurity-nginx | 17 | NGINX `.t`, README und Konverterdateien |
| ModSecurity v2-Tests | Referenz zur historischen Semantik | https://github.com/owasp-modsecurity/ModSecurity | 115 | v2-Operator-, Transformations- und Regressionsdateien, die nur als semantics/reference-Material verwendet werden |
| ModSecurity v3-Tests | konfigurierte Engine-Quellenreferenz | https://github.com/owasp-modsecurity/ModSecurity | 264 | v3 API/regression Dateien; 195 JSON Regressionsfälle unter `test/test-cases/regression/` |

Jede relevante Quelldatei wird abgebildet in:

- `docs/testing/imports/apache-regression-map.md`
- `docs/testing/imports/nginx-regression-map.md`
- `docs/imports/common/shared-case-origin-map.md`
- `docs/imports/common/v2-regression-map.md`
- `docs/imports/common/v3-regression-map.md`
- `docs/testing/v2-vs-v3-test-compatibility.md`

ModSecurity-nginx PR #377 Tests werden separat in inventarisiert
`docs/testing/pr377-test-import-map.md` weil sie aus einem Provisorium stammen
`$BUILD_ROOT` PR Checkout anstelle des schreibgeschützten lokalen NGINX Referenz-Repo.

## Regeln importieren

- Häufige Fälle sind nur zulässig, wenn die Regel, Bitte und Erwartung dies zulassen
  Connector-neutral und kann sowohl über Apache- als auch NGINX PoC-Harnesses laufen.
- Nur-Apache-Fälle gehören unter `tests/cases/connector-specific/apache/`.
- Nur NGINX-Fälle gehören unter `tests/cases/connector-specific/nginx/`.
- Fälle, die HTTP/2, Proxy-Topologie, mehrteiliges Parsing, Streaming erfordern,
Antworttextfilter, Konfigurationsvererbung, Debug-Protokolltext, Remote-Regeln oder
  Externe Datendateien bleiben zugeordnet, bis der Harness explizite Unterstützung erhält.
- Einfache mehrteilige Textfeldkörper werden unterstützt; Multipart-Parser-Fehler,
  Dateispeichersammlungen und Teil-Header-Randfälle bleiben zugeordnet.
- Der Pass-Through-Antworttext kann importiert werden, wenn beide Konnektoren den zurückgeben
  erwarteter HTTP Status. Das Blockieren des Antworttexts wird nicht als häufig gezählt PASS
  es sei denn, beide Konnektoren geben stabile HTTP 403 zurück.
- Importierte YAML müssen `origin`, `category`, `capabilities`, `portable`,
  `status` und `known_limitations`; Connector-spezifische YAML müssen enthalten
  `connector`.
- Aktive V2/V3-derived-Common-Cases müssen vorher sowohl Apache als auch NGINX übergeben
  sie werden als `fully-imported-common` gezählt.
- Nur-API-v3-Fälle bleiben dem konnektorfreien v3-API-Smokebereich zugeordnet, bis a
  dediziertes API Smoke-Ziel existiert; Sie sind nicht in den Connector eingefaltet
  `smoke-all`.

## Importierte häufige Fälle

Die folgenden aus der Quelle abgeleiteten häufigen Fälle wurden unten hinzugefügt
`tests/cases/`:

| Fall | Quellenbasis | Kategorie | Erwartetes Verhalten |
| --- | --- | --- | --- |
| `action_deny_phase1.yaml` | Störende Aktionen von Apache; NGINX Phasenaktionstests | Aktionen | HTTP 403 |
| `action_deny_phase2.yaml` | Störende Aktionen von Apache; NGINX Phasenaktionstests | Aktionen | HTTP 403 |
| `action_allow_phase1_pass.yaml` | Apache-Zulassen-vor-Verweigern-Aktionstest | Aktionen | HTTP 200 Ursprungskörper |
| `collection_args_names_block.yaml` | Apache `ARGS_NAMES` Zieltest | Sammlungen | HTTP 403 |
| `collection_args_get_block.yaml` | Apache `ARGS_GET` Zieltest; NGINX ARGS Tests | Sammlungen | HTTP 403 |
| `collection_args_combined_size_block.yaml` | Apache `ARGS_COMBINED_SIZE` Zieltest | Sammlungen | HTTP 403 |
| `request_body_args_post_names_block.yaml` | Apache `ARGS_POST_NAMES`; NGINX Anforderungskörpertests | Anfragetext | HTTP 403 |
| `request_body_raw_text_block.yaml` | NGINX raw `REQUEST_BODY`; Apache-Rohkörpermuster | Anfragetext | HTTP 403 |
| `json_request_body_block.yaml` | Apache JSON Parser-Abdeckung; NGINX Anforderungskörpertests | Körperprozessoren | HTTP 403 |
| `multipart_basic_block.yaml` | Apache normale mehrteilige Parser-Abdeckung; NGINX Anforderungskörpertests | mehrteilig | HTTP 403 |
| `response_body_pass.yaml` | Apache-Antwortanweisungen; NGINX Antworttext-Zugriffstests | Antwortkörper | HTTP 200 |
| `action_status_401_phase1_block.yaml` | NGINX `modsecurity.t` block401; Kompatibilität mit Apache-Disruptive-Action | Aktionen | HTTP 401 |
| `v2_operator_streq_block.yaml` | V2 `tests/op/streq.t` | Betreiber | HTTP 403 |
| `v2_operator_contains_block.yaml` | V2 `tests/op/contains.t` | Betreiber | HTTP 403 |
| `v2_operator_begins_with_block.yaml` | V2 `tests/op/beginsWith.t` mit Parameter `abcdef`, Eingabe `abcdefghi` | Betreiber | HTTP 403 |
| `v2_operator_ends_with_block.yaml` | V2 `tests/op/endsWith.t` mit Parameter `ghi`, Eingabe `abcdefghi` | Betreiber | HTTP 403 |
| `v2_operator_pm_block.yaml` | V2 `tests/op/pm.t` mit Parameter `abc`, Eingabe `abcdefghi` | Betreiber | HTTP 403 |
| `v2_operator_contains_word_block.yaml` | V2 `tests/op/containsWord.t` mit Parameter `abc`, Eingabe `abc def ghi` | Betreiber | HTTP 403 |
| `v2_transformation_lowercase_block.yaml` | V2 `tests/tfn/lowercase.t` | Transformationen | HTTP 403 |
| `v2_transformation_trim_block.yaml` | V2 `tests/tfn/trim.t` | Transformationen | HTTP 403 |
| `v2_transformation_url_decode_block.yaml` | V2 `tests/tfn/urlDecode.t` mit Eingabe `Test+Case`, Ausgabe `Test Case` | Transformationen | HTTP 403 |
| `v2_transformation_html_entity_decode_block.yaml` | V2 `tests/tfn/htmlEntityDecode.t` Fragment `&lt;&gt;` -> `<>` | Transformationen | HTTP 403 |
| `multipart_files_value_block.yaml` | V3 `variable-FILES.json` | multipart/files | HTTP 403 |
| `multipart_files_names_block.yaml` | V3 `variable-FILES_NAMES.json` | multipart/files | HTTP 403 |
| `multipart_files_combined_size.yaml` | V3 `variable-FILES_COMBINED_SIZE.json` | multipart/files | HTTP 403 |
| `multipart_filename_block.yaml` | V3 `variable-MULTIPART_FILENAME.json` | multipart/files | HTTP 403 |
| `xml_request_body_block.yaml` | V3 `variable-XML.json` | xml/body-processors | HTTP 403 |
| `v3_operator_rx_block.yaml` | V3 `operator-rx.json` | Betreiber | HTTP 403 |
| `v3_operator_pm_digit_block.yaml` | V3 `operator-pm.json` mit Regel `@pm 1 2 3`, Anfrage `param1=123` | Betreiber | HTTP 403 |
| `v3_request_cookies_block.yaml` | V3 `variable-REQUEST_COOKIES.json` mit `USER_TOKEN=Yes` | Sammlungen | HTTP 403 |
| `v3_request_cookies_names_block.yaml` | V3 `variable-REQUEST_COOKIES_NAMES.json` mit Cookie-Namen `USER_TOKEN` | Sammlungen | HTTP 403 |
| `v3_request_headers_names_block.yaml` | V3 `variable-REQUEST_HEADERS_NAMES.json`, angepasst an den stabilen benutzerdefinierten Headernamen | Sammlungen | HTTP 403 |
| `v3_args_names_get_block.yaml` | V3 `variable-ARGS_NAMES.json` mit GET Argumentname `key1` | Sammlungen | HTTP 403 |
| `v3_auditlog_serial_fields_block.yaml` | V3 `auditlog.json` und `issue-2000.json` stabile serielle Prüffelder | Audit-Protokoll | HTTP 403 plus Prüffelder |
| `v3_transformation_trim_block.yaml` | V3 `transformations.json` | Transformationen | HTTP 403 |
| `v3_secaction_block.yaml` | V3 `secruleengine.json` | Aktionen | HTTP 403 |

Diese Fälle werden als übertragbare Kandidaten importiert. Sie gelten nur in einem als nachgewiesen
Umgebung, in der beide Connector das erwartete HTTP-Verhalten beobachten.

Lokal beobachtet am 15.05.2026 mit einem expliziten externen `BUILD_ROOT`, gezielt
`make smoke-common` Läufe melden die V2/V3-derived aktiven Importe als `PASS` an
Apache und NGINX.
Die zweite Importwelle fügte 13 aktive PASS Fälle mit von der Quelle bestätigten Werten hinzu
für `urlDecode`, `htmlEntityDecode`, `pm` und `containsWord`; nichts davon
case verwendet erfundene Beispielwerte.

`v3_action_nolog_pass_no_audit.yaml` wurde aus der aktiven gemeinsamen Erkennung verschoben
nachdem GitHub Actions `expected audit log to be absent or empty` gemeldet hat.
Lokale Apache- und NGINX-Läufe beobachteten HTTP 200 mit leeren Audit-Logs, so der Fall
bleibt gemäß `tests/cases/` prüfbar, wird aber nicht als stabil gezählt
gemeinsamer PASS.

## Hinweise zum Import von Körper und Filtern

Der Response-Body-Block-Kandidat ist bewusst keine aktive gemeinsame Abdeckung.
`ModSecurity-nginx/tests/modsecurity-response-body.t` markiert den blockierenden Zweig
als TODO. ModSecurity-nginx PR #377
(https://github.com/owasp-modsecurity/ModSecurity-nginx/pull/377) Quelle
Änderungen werden jetzt auf die dem Adapter gehörende NGINX-Quelle angewendet, die Quellaufnahme jedoch schon
keine Response-Body-Promotion. Die dedizierte lokale Sonde in
`tests/cases/response/body/response_body_basic_block.yaml` führte drei Wiederholungen durch:
Apache und NGINX haben beide HTTP 200 anstelle von Stable HTTP 403 zurückgegeben. Die Quelle
Zeilen bleiben `former expected-failure`/`mapped-only`, während `response_body_pass.yaml` a bleibt
Nur Durchgangsrauch. Führen Sie diesen Pass-Through im spätesten 21.05.2026 NGINX aus
Der Fall hat HTTP 200 nach der Korrektur der Harness-Berechtigung zurückgegeben, ist dies aber immer noch nicht der Fall
RESPONSE_BODY Hochstufung.

`multipart_basic_block.yaml` deckt ein einfaches mehrteiliges Textfeld ab
durch `ARGS:name`. Von V3 abgeleitete FILES, FILES_NAMES, FILES_COMBINED_SIZE und
MULTIPART_FILENAME Smoke-Fälle sind jetzt aktiv und allgemein abgedeckt. Temporär hochladen
Pfade, fehlerhafte Multipart-Körper, Streaming und Teil-Header-Randfälle bleiben bestehen
zugeordnet, bis sie ohne konnektorspezifische Einrichtung nachgewiesen werden können.

`json_request_body_block.yaml` stimmt mit rohem `REQUEST_BODY`-Inhalt überein. Geparste JSON
Die Sammlungsextraktion aus Apache `rule/15-json.t` bleibt zugeordnet, da die
Der aktuelle gemeinsame Smoke-Pfad beweist keine `ARGS:foo`-Parität.

## Importierte Connector-spezifische Fälle

Die folgenden NGINX-spezifischen Fälle wurden unten hinzugefügt
`tests/cases/connector-specific/nginx/`:

| Fall | Quellenbasis | Kategorie | Erwartetes Verhalten | Warum jetzt Connector-spezifisch |
| --- | --- | --- | --- | --- |
| `nginx_redirect_phase1_302.yaml` | `tests/modsecurity.t` Redirect302 | Aktionen | HTTP 302 | Aus NGINX-Tests importiert und noch nicht gegen Apache getestet |
| `nginx_tx_scoring_absolute_block.yaml` | `tests/modsecurity-scoring.t` absolute Punktzahl | Aktionen | HTTP 403 | Aus NGINX-Tests importiert und noch nicht gegen Apache getestet |
| `nginx_tx_scoring_iterative_block.yaml` | `tests/modsecurity-scoring.t` iterativer Score | Aktionen | HTTP 403 | Aus NGINX-Tests importiert und noch nicht gegen Apache getestet |
| `nginx_phase4_minimal_log_only.yaml` | PR #377 `tests/modsecurity-phase4-modes.t` minimaler Zweig | response-body/phase4 | HTTP 200 Körper erhalten plus Phase4 `log_only`/`mode_minimal` Nachweise | Nur NGINX-Anweisungsverhalten; keine Werbeaktion zum Blockieren von Antworttexten |
| `nginx_phase4_safe_log_only.yaml` | PR #377 `tests/modsecurity-phase4-modes.t` sicherer Zweig | response-body/phase4 | HTTP 200 Körper erhalten plus Phase4 `log_only`/`mode_safe` Nachweise | Nur NGINX-Anweisungsverhalten; keine Werbeaktion zum Blockieren von Antworttexten |
| `nginx_phase4_content_type_out_of_scope.yaml` | PR #377 `tests/modsecurity-phase4-content-types.t` Zweig außerhalb des Gültigkeitsbereichs | response-body/phase4 | HTTP 200 Körper erhalten plus `content_type_not_in_scope` Phase4-Nachweis | Nur NGINX-Anweisungsverhalten; keine Werbeaktion zum Blockieren von Antworttexten |

In diesem Durchgang geprüfte Apache-spezifische Kandidaten erfordern meist Apache::Test
Kontext, httpd-Konfigurationsvererbung oder Apache-spezifisches Laufzeit-Setup, also sie
werden eher gemappt als portiert.

Lokal beobachtet am 15.05.2026 mit einem expliziten externen `BUILD_ROOT`,
`make smoke-all` meldete die ursprünglich NGINX-spezifischen importierten Fälle als `PASS`
auf NGINX. Ein vom Quellcode erstellter Lauf vom 20.05.2026 NGINX hat eine Harness-Berechtigung offengelegt
Blocker für die PR #377 erwartete 200 Phase-4-Sonden, aber die Wiederholung am 21.05.2026
Nachdem der Harness-Berechtigungs-Fix HTTP 200 für alle drei aktiven zurückgegeben hatte
Phase-4-Log-Only-Probes. Strict/invalid-config/large-response Antworttext
Zweige bleiben bei früheren erwarteten Fehlern oder nur zugeordneten Zweigen erhalten
`docs/testing/pr377-test-import-map.md`.

## Smokefernrohre

Die Smoke-Ziele verwenden explizite Bereiche:

```sh
make smoke-common  # common minimal + common imported cases on Apache and NGINX
make smoke-apache  # common cases + Apache-specific imported cases on Apache
make smoke-nginx   # common cases + NGINX-specific imported cases on NGINX
make smoke-all     # all applicable cases on the matching connector
```

`SMOKE_CASES` können weiterhin einzelne Fälle oder Pfade benennen. Der Python-Fall CLI jetzt
löst Namen innerhalb des ausgewählten Bereichs auf, validiert Portabilitätsmetadaten und
schreibt detaillierte Ergebniszusammenfassungen unter `$BUILD_ROOT/results/`.

## Zurückgestellte Kategorien

| Kategorie | Status | Grund |
| --- | --- | --- |
| mehrteilig | importiert | Einfache Textfeld- und V3-abgeleitete FILES/FILES_NAMES/FILES_COMBINED_SIZE/MULTIPART_FILENAME-Fälle sind aktive gemeinsame Abdeckung |
| http2 | blockiert | Aktuelle Harnesses sind HTTP/1.1 lokale Smokeer |
| Proxy | todo | Noch keine Unterstützung für die Upstream-Topologie |
| Streaming-Pufferung | todo | Noch keine Streaming-Behauptungen oder Chunk-Kontrolle |
| Antwortkörper | todo | Die Reihenfolge der Connector-Filter erfordert explizite Unterstützung |
| Blockierung des Antwortkörpers | nicht hochgestuft | NGINX Upstream-Markierungen blockieren das Verhalten TODO und die lokale Prüfung ergab keinen stabilen HTTP 403 |
| Antworttext-Durchleitung | Pass-Through-Nachweis im letzten NGINX-Lauf | `response_body_pass.yaml` gab HTTP 200 nach dem NGINX Harness-Berechtigungs-Fix zurück; Dies ist keine RESPONSE_BODY blockierende Überprüfung |
| mehrteiliges Basistextfeld | importiert | `multipart_basic_block.yaml` behandelt die einfache portable mehrteilige Analyse |
| mehrteilige Dateisammlungen | importiert | FILES, FILES_NAMES, FILES_COMBINED_SIZE und MULTIPART_FILENAME verfügen über eine aktive Smoke-Abdeckung; FILES_TMPNAMES bleibt zugeordnet |
| XML | importiert | Winziger XML-Körperprozessorfall ist aktive allgemeine Berichterstattung; schema/DTD/parser-error Fälle bleiben zugeordnet |
| Semantik der v2-Engine | importiert | Operator- und Transformationsfälle sind eine aktive gemeinsame Abdeckung, einschließlich „beginsWith“, „endsWith“, „pm“, „containsWord“, „urlDecode“ und „htmlEntityDecode“. |
| v3-Regression JSON | importiert | Multipart/XML/operator/action/cookie/header-name/ARGS_NAMES/audit Fälle sind aktive gemeinsame Deckung; `issue-2196` nolog/pass behält den früheren Verlauf der erwarteten Fehler aufgrund von local/CI Prüfabweichungen bei |
| externe Dateioperatoren | todo | Benötigt die Materialisierung der Fixture-Datei |
| Debug-Protokolle | kartiert | Der Text ist flüchtig und konnektorspezifisch |

## Inkrementelle Negative/Pass-through Ergänzungen (19.05.2026)

Von der Quelle abgeleitete portable negative/pass-through-Fälle hinzugefügt, ohne die Connector-Laufzeitsemantik zu ändern:

- `tests/cases/negative-pass-through/v3_request_cookies_names_pass_no_match.yaml` (Quelle: `ModSecurity_V3` `variable-REQUEST_COOKIES_NAMES.json`)
- `tests/cases/negative-pass-through/v3_args_names_get_pass_no_match.yaml` (Quelle: `ModSecurity_V3` `variable-ARGS_NAMES.json`)
- `tests/cases/negative-pass-through/v2_transformation_url_decode_pass_no_match.yaml` (Quelle: `ModSecurity_V2` `tests/tfn/urlDecode.t`)
- `tests/cases/negative-pass-through/v3_request_cookies_pass_no_match.yaml` (Quelle: `ModSecurity_V3` `variable-REQUEST_COOKIES.json`)
- `tests/cases/negative-pass-through/v3_request_headers_names_pass_no_match.yaml` (Quelle: `ModSecurity_V3` `variable-REQUEST_HEADERS_NAMES.json`)

Diese Fälle sind absichtlich durchgereicht (`expect.status: 200`) und dienen als
Negativzweigbeweis für REQUEST_COOKIES/REQUEST_COOKIES_NAMES,
REQUEST_HEADERS_NAMES, ARGS_NAMES und REQUEST_URI+t:urlDecode-Abdeckung. Apache
und NGINX hat sie in den letzten von der Quelle erstellten Läufen nach dem NGINX-Harness übergeben
Berechtigungskorrektur. Es handelt sich hierbei nicht um aktuelle lokale Laufzeit-Pass-Through-Nachweise
Automatische Hochstufung für umfassendere ehemalige expected-failure/future-Randfälle.

## Kompatibilitätserweiterungswelle (19.05.2026, pending/former erwarteter Fehler)

10 aus der Quelle abgeleitete YAML Kompatibilitätskandidaten unter `tests/cases/` für bekannte Lücken und zukünftige Ziele hinzugefügt:

- header/cookie/ARGS benennen Laufzeitdifferenz- oder Connector-Gap-Probes
- Transformationskantensonden (`trim` Tab-Zweig, `urlDecode` ungültige Sequenz, `removeNulls`)
- parser/runtime Lückentests (ungültige JSON, fehlerhafte XML)
- Antwort-Header-Laufzeitlücken-Probe mit mehreren Werten

Diese werden absichtlich nicht zur aktiven verifizierten PASS-Abdeckung hochgestuft und bleiben bei der früheren expected-failure/pending-Laufzeitverifizierung.

## Operator/Transformation/Phase Erweiterung (19.05.2026)

16 zusätzliche aus der Quelle abgeleitete `former expected-failure` häufige Fälle hinzugefügt für:
- Operatoren: `@contains`, `@beginsWith`, `@endsWith`, `@streq`, `@rx` (hauptsächlich no-match/pass-through Ziele)
- Transformationen: `t:none`, `t:lowercase`, `t:trim`, `t:urlDecode`, `t:urlDecodeUni`, `t:compressWhitespace`
- Phasenhandhabung: Verhaltenssonden der Phasen 1 und 2
- edge/parser: Semikolon-Abfrage, fehlender Header, Plus-gegen-Leerzeichen-Dekodierung, leerer JSON-Körper

Diese Fälle werden absichtlich als pending/former-Kompatibilitätsziele mit erwartetem Fehler verfolgt und ohne vollständige Laufzeitbeweise nicht zu verifizierten PASS heraufgestuft.

## Audit/Normalization/Parser Erweiterung (19.05.2026)

12 zusätzliche aus der Quelle abgeleitete frühere Kompatibilitätsprüfungen für erwartete Fehler hinzugefügt für:
- Audit-Protokoll presence/normalization/multiline und übereinstimmende Variablenbeweise
- Duplikat collection/name Normalisierung (headers/cookies/args)
- Parser von Teilkörperkanten (JSON/XML)
- Transformationskettenverhalten (`lowercase+trim`, `urlDecode+compressWhitespace`)

Alle warten noch auf die Laufzeitüberprüfung und sind von der verifizierten PASS-Buchhaltung ausgeschlossen.

## Multipart/FILES/Unicode/Parser Erweiterung (19.05.2026)

16 Zusätzliche aus der Quelle abgeleitete ehemalige Kompatibilitätsprüfungen für erwartete Fehler hinzugefügt, die Folgendes abdecken:
- FILES/FILES_NAMES und mehrteiliges Kantenverhalten (Grenze, doppelte Felder, Dateinamennormalisierung)
- Unicode/encoding Normalisierung und Dekodierkettenverhalten
- komplexe JSON/XML Struktur und Parser-Edge-Probes
- harmlose XSS-ähnliche und SQLi-ähnliche normalization/transformation-Kompatibilitätsprüfungen

Alle werden als ausstehende Laufzeitüberprüfung verfolgt und nicht auf verifizierte PASS hochgestuft.

## Phase-3/Phase-4 Erweiterung (19.05.2026)

12 Von der Quelle abgeleitete ehemalige Tests zu erwarteten Fehlern hinzugefügt, die sich auf die ausgehende Verarbeitung konzentrieren:
- Phase-3-Antwort-Header normalization/duplicate/multi-value/missing Verhalten
- Phase-4-Reaktionskörper-Experimentalsonden (empty/unicode/chunk/compressed/html)
- Phase-4-Verhaltensprüfungen für ausgehende Überwachungsprotokolle (rule-id/message Erwartungen)

Dabei handelt es sich weiterhin um nicht verifizierte Kompatibilitätsprüfungen. RESPONSE_BODY wird absichtlich nicht zum verifizierten PASS befördert.

## Phase-3/4 Folgeerweiterung (19.05.2026)

10 Zusätzliche aus der Quelle abgeleitete frühere Tests auf erwartete Fehler wurden hinzugefügt für:
- Phase-3-Antwortheader presence/charset/location/set-cookie Verhalten
- Phase-4-Antwortkörper no-match/buffering/entity-decode Annahmen
- Phase-4-Outbound-Audit matched-var/escaped/multiline Annahmen

Dabei handelt es sich weiterhin nur um Kompatibilitätsprüfungen, die nicht auf den verifizierten PASS-Status heraufgestuft werden.

## Generierte Abdeckungsberichte

Das Repository stellt jetzt generierte matrix/coverage-Berichte bereit:

- Menschliche Einstiegsseite: `docs/testing/test-coverage-overview.md`
- Maschinell generierte Detailseiten unter `docs/testing/generated/*.generated.md`

Befehle:

```sh
make generate-test-matrix
make check-test-matrix
```

Zu den Datenquellen gehören Testfall-YAML-Dateien unter `tests/cases/`, `tests/cases/connector-specific/apache/`, `tests/cases/connector-specific/nginx/` sowie `config/testing/import-status.json`.

Wichtig: Generierte Berichte sind **nicht** laufzeitsicher. Die autorisierende Laufzeitüberprüfung bleibt `make smoke-all`.
