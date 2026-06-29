# Testimportplan

**Sprache:** [English](test-import-plan.md) | Deutsch

Status: umgesetzt

In diesem Dokument wird die aktuelle Importrichtlinie für lokale Connector-Tests aufgezeichnet. Die
Quellrepositorys unter `<workspace>/*` sind schreibgeschützte Referenzen. Nein
Die Upstream-Apache- oder NGINX-Testdatei wird wörtlich in dieses Repository kopiert.

## Inventar

Beobachteter lokaler Quellenbestand am 15.05.2026:

| Quelle | Relevante Dateien analysiert | Notizen |
| --- | ---: | --- |
| `<workspace>/ModSecurity-apache/tests/` | 29 | Apache-Regression `.t`, `.t.in` und Harness-Dateien |
| `<workspace>/ModSecurity-nginx/tests/` | 17 | NGINX `.t`, README und Konverterdateien |
| `<workspace>/ModSecurity_V2/tests/` | 115 | v2-Operator-, Transformations- und Regressionsdateien, die nur als semantics/reference-Material verwendet werden |
| `<workspace>/ModSecurity_V3/test/` | 264 | v3 API/regression Dateien; 195 JSON Regressionsfälle unter `test/test-cases/regression/` |

Jede relevante Quelldatei wird abgebildet in:

- `tests/apache/apache-regression-map.md`
- `tests/nginx/nginx-regression-map.md`
- `docs/imports/common/shared-case-origin-map.md`
- `docs/imports/common/v2-regression-map.md`
- `docs/imports/common/v3-regression-map.md`
- `docs/v2-vs-v3-test-compatibility.md`

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

Lokal beobachtet am 15.05.2026 mit
`BUILD_ROOT=/src/ModSecurity-test-Framework-build`, gezielt `make smoke-common`
Läufe meldeten die V2/V3-derived aktiven Importe als `PASS` auf Apache und NGINX.
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
als TODO. Die dedizierte lokale Sonde in
`tests/cases/response/body/response_body_basic_block.yaml` führte drei Wiederholungen durch:
Apache hat HTTP 200 ohne den erforderlichen Audit-Treffer zurückgegeben, während NGINX mit dem übereinstimmte
Phase 4 `RESPONSE_BODY` Regel und schrieb audit/error Nachweise, gab aber eine zurück
leere Client-Antwort (`000`) statt stabiler HTTP 403. Die Quellzeilen bleiben erhalten
`former expected-failure`/`mapped-only`, während `response_body_pass.yaml` ein Durchgang bleibt
nur rauchen.

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

In diesem Durchgang geprüfte Apache-spezifische Kandidaten erfordern meist Apache::Test
Kontext, httpd-Konfigurationsvererbung oder Apache-spezifisches Laufzeit-Setup, also sie
werden eher gemappt als portiert.

Lokal beobachtet am 15.05.2026 mit
`BUILD_ROOT=/src/ModSecurity-test-Framework-build`, `make smoke-all` haben alle gemeldet
drei NGINX-spezifische importierte Fälle als `PASS` auf NGINX.

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
| Blockierung des Antwortkörpers | früherer erwarteter Misserfolg | NGINX Upstream-Markierungen blockieren das Verhalten TODO und die lokale Prüfung ergab keinen stabilen HTTP 403 |
| Antworttext-Durchleitung | importiert | `response_body_pass.yaml` überprüft, ob eine Regression vorliegt, wenn der Zugriff auf den Antworttext aktiviert ist |
| mehrteiliges Basistextfeld | importiert | `multipart_basic_block.yaml` behandelt die einfache portable mehrteilige Analyse |
| mehrteilige Dateisammlungen | importiert | FILES, FILES_NAMES, FILES_COMBINED_SIZE und MULTIPART_FILENAME verfügen über eine aktive Smoke-Abdeckung; FILES_TMPNAMES bleibt zugeordnet |
| XML | importiert | Winziger XML-Körperprozessorfall ist aktive allgemeine Berichterstattung; schema/DTD/parser-error Fälle bleiben zugeordnet |
| Semantik der v2-Engine | importiert | Operator- und Transformationsfälle sind eine aktive gemeinsame Abdeckung, einschließlich „beginsWith“, „endsWith“, „pm“, „containsWord“, „urlDecode“ und „htmlEntityDecode“. |
| v3-Regression JSON | importiert | Multipart/XML/operator/action/cookie/header-name/ARGS_NAMES/audit Fälle sind aktive gemeinsame Deckung; `issue-2196` nolog/pass ist früherer erwarteter Fehler aufgrund local/CI Prüfabweichung |
| externe Dateioperatoren | todo | Benötigt die Materialisierung der Fixture-Datei |
| Debug-Protokolle | kartiert | Der Text ist flüchtig und konnektorspezifisch |

## PR #3564 RAW Argumentsammlungen

PR #3564 fügt sechs RAW URL-codierte Argumentsammlungen hinzu:

- `ARGS_RAW`
- `ARGS_GET_RAW`
- `ARGS_POST_RAW`
- `ARGS_NAMES_RAW`
- `ARGS_GET_NAMES_RAW`
- `ARGS_POST_NAMES_RAW`

Die aktuell konfigurierte lokale `ModSecurity_V3`-Quelle enthält diese nicht
Sammlungen, es handelt sich also nicht um aktive YAML Fälle. Der Importstatus ist
`mapped-only/unsupported-local-source`.

Zukünftige Hochstufung erfordert:

1. `MODSECURITY_V3_SOURCE_DIR` zeigt auf eine v3-Quelle, die RAW enthält
Sammlungsunterstützung.
2. Die YAML-Fälle werden nicht aus den RAW-Regressionsdaten dieser Quelle abgeleitet
   erfundene Beispiele.
3. Apache und NGINX geben beide das von YAML erwartete HTTP-Verhalten zurück
   `make smoke-all`.
