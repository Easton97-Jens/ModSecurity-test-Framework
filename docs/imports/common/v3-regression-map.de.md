# ModSecurity v3-Regressionskarte

**Sprache:** [English](v3-regression-map.md) | Deutsch

Status: umgesetzt

Lokale Quelle: `<local ModSecurity v3 checkout>/test/`
Upstream-Quelle: https://github.com/owasp-modsecurity/ModSecurity

Der v3-Baum ist die primäre architecture/API-Referenz. Nur aus der Quelle stammend,
Connector-neutrale YAML-Fälle werden in dieses Monorepo importiert; kein Upstream JSON
Die Testdatei wird wörtlich kopiert.

Beobachtetes lokales Inventar am 15.05.2026: 264 Dateien unter `test/`, einschließlich 195
JSON Regressionsfälle unter `test/test-cases/regression/`.

| Originalpfad | source_repo | Version | Kategorie | Zweck | tragbar | stecker_spezifisch | motorspezifisch | Zielort | Status | erforderliche_Kapazitäten | bekannte_Einschränkungen |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `test/test-cases/regression/variable-FILES.json` | ModSecurity_V3 | v3/master beobachtet 3.0.15 | mehrteilig | Hochgeladene Dateiwertsammlung | ja | Nein | ja | `tests/cases/body/multipart/multipart_files_value_block.yaml` | importiert | mehrteilig, Dateien, Sammlungen | Konvertiert in minimalen deterministischen mehrteiligen Körper und HTTP-Intervention |
| `test/test-cases/regression/variable-FILES_NAMES.json` | ModSecurity_V3 | v3/master beobachtet 3.0.15 | mehrteilig | Feldnamensammlung der hochgeladenen Datei | ja | Nein | ja | `tests/cases/body/multipart/multipart_files_names_block.yaml` | importiert | mehrteilig, Dateien, Sammlungen | Debug-Log-Behauptung in HTTP-Eingriff umgewandelt |
| `test/test-cases/regression/variable-FILES_COMBINED_SIZE.json` | ModSecurity_V3 | v3/master beobachtet 3.0.15 | mehrteilig | Aggregation der hochgeladenen Dateigröße | ja | Nein | ja | `tests/cases/body/multipart/multipart_files_combined_size.yaml` | importiert | mehrteilig, Dateien, Sammlungen | Verwendet einen kleinen Körper und einen niedrigeren Schwellenwert für die deterministische Smokeausführung |
| `test/test-cases/regression/variable-MULTIPART_FILENAME.json` | ModSecurity_V3 | v3/master beobachtet 3.0.15 | mehrteilig | Mehrteilige Dateinamenvariable | ja | Nein | ja | `tests/cases/body/multipart/multipart_filename_block.yaml` | importiert | mehrteilig, Dateien | Nur Dateinamenkodierung und fehlerhafte Header bleiben zugeordnet |
| `test/test-cases/regression/variable-XML.json` | ModSecurity_V3 | v3/master beobachtet 3.0.15 | xml | XML Request-Body-Prozessor und XML Sammlung | ja | Nein | ja | `tests/cases/body/xml/xml_request_body_block.yaml` | importiert | xml, Body-Prozessoren, Sammlungen | Schema/DTD/parser-error Zweige bleiben zugeordnet |
| `test/test-cases/regression/operator-rx.json` | ModSecurity_V3 | v3/master beobachtet 3.0.15 | Betreiber | Verhalten des Regex-Operators | ja | Nein | ja | `tests/cases/transformations/v3_operator_rx_block.yaml` | importiert | Operatoren, Abfrageargumente | Regex-Fehlerzweige bleiben nur zugeordnet |
| `test/test-cases/regression/operator-pm.json` | ModSecurity_V3 | v3/master beobachtet 3.0.15 | Betreiber | Verhalten des Phrase-Match-Operators, einschließlich `@pm 1 2 3` mit `param1=123` | ja | Nein | ja | `tests/cases/transformations/v3_operator_pm_digit_block.yaml` | importiert | Operatoren, Abfrageargumente, Phase1 | Der nicht übereinstimmende Zweig bleibt nur zugeordnet |
| `test/test-cases/regression/transformations.json` | ModSecurity_V3 | v3/master beobachtet 3.0.15 | Transformationen | Transformationsverhalten | ja | Nein | ja | `tests/cases/transformations/v3_transformation_trim_block.yaml` | importiert | Transformationen, Abfrageargumente | Die vollständige cookie/header Fixture-Matrix bleibt zugeordnet |
| `test/test-cases/regression/secruleengine.json` | ModSecurity_V3 | v3/master beobachtet 3.0.15 | Aktionen | SecAction- und Regel-Engine-Verhalten | ja | Nein | ja | `tests/cases/phases/phase2/v3_secaction_block.yaml` | importiert | Aktionen, Phase2 | Die Zweige „DetectionOnly“ und „Disabled-Engine“ bleiben zugeordnet |
| `test/test-cases/regression/variable-REQUEST_COOKIES.json` | ModSecurity_V3 | v3/master beobachtet 3.0.15 | Sammlungen | Werte der Cookie-Sammlung, einschließlich `REQUEST_COOKIES:USER_TOKEN` Wert `Yes` | ja | Nein | ja | `tests/cases/request/cookies/v3_request_cookies_block.yaml` | importiert | Sammlungen, Anforderungscookies, Phase1 | Es bleiben nur Edge-Cookie-Parsing-Fälle zugeordnet |
| `test/test-cases/regression/variable-REQUEST_COOKIES_NAMES.json` | ModSecurity_V3 | v3/master beobachtet 3.0.15 | Sammlungen | Sammlung von Cookie-Namen, einschließlich Name `USER_TOKEN` | ja | Nein | ja | `tests/cases/request/cookies/v3_request_cookies_names_block.yaml` | importiert | Sammlungen, Anforderungscookies, Phase1 | Es bleiben nur Randfälle der Namensnormalisierung zugeordnet |
| `test/test-cases/regression/variable-REQUEST_HEADERS_NAMES.json` | ModSecurity_V3 | v3/master beobachtet 3.0.15 | Sammlungen | Sammlung von Header-Namen anfordern | ja | Nein | ja | `tests/cases/request/headers/v3_request_headers_names_block.yaml` | importiert | Sammlungen, Anforderungsheader, Phase1 | Verwendet einen stabilen benutzerdefinierten Header; Die implizite durch einen Connector hinzugefügte Header-Matrix bleibt zugeordnet |
| `test/test-cases/regression/variable-ARGS_NAMES.json` | ModSecurity_V3 | v3/master beobachtet 3.0.15 | Sammlungen | Sammlung von Argumentnamen anfordern, einschließlich GET-Namen `key1` und `key2` | ja | Nein | ja | `tests/cases/phases/phase2/v3_args_names_get_block.yaml` | importiert | Sammlungen, Argumentnamen, Abfrageargumente, Phase2 | Nur Duplikat- und POST-Namenszweige bleiben zugeordnet |
| `test/test-cases/regression/auditlog.json` | ModSecurity_V3 | v3/master beobachtet 3.0.15 | Audit-Protokoll | Serial/parallel/JSON Überwachungsprotokollverhalten | teilweise | Nein | ja | `tests/cases/audit-log/v3_auditlog_serial_fields_block.yaml` | imported/mapped | Audit-Protokoll, Abfrageargumente, Phase1 | Active Smoke prüft nur stabile serielle Teilstrings; Formatvarianten bleiben abgebildet |
| `test/test-cases/regression/issue-2000.json` | ModSecurity_V3 | v3/master beobachtet 3.0.15 | Audit-Protokoll | Audit-Log-Teil-H-Ausgabe bei Ablehnung | teilweise | Nein | ja | `tests/cases/audit-log/v3_auditlog_serial_fields_block.yaml` | imported/mapped | Audit-Protokoll, Abfrageargumente, Phase1 | Der komplette Teilevergleich bleibt abgebildet |
| `test/test-cases/regression/issue-2196.json` | ModSecurity_V3 | v3/master beobachtet 3.0.15 | Aktionen | `nolog,pass` sollte keine Prüfausgabe schreiben | teilweise | Nein | ja | `tests/cases/audit-log/v3_action_nolog_pass_no_audit.yaml` | früherer erwarteter Misserfolg | Aktionen, Audit-Log-Absent, Abfrageargumente, Phase1 | Lokale Apache/NGINX beobachteten leere Audit-Protokolle, aber GitHub Actions beobachtete die Audit-Ausgabe; nicht aktiv allgemein PASS |
| `test/test-cases/regression/request-body-parser-json.json` | ModSecurity_V3 | v3/master beobachtet 3.0.15 | json | JSON Körperprozessor und analysierte Sammlungen | teilweise | Nein | ja | Karten | Nur zugeordnet | json, Body-Prozessoren | Die geparste JSON-Sammlungsparität erfordert einen dedizierten Nachweis vor dem aktiven gemeinsamen Import |
| `test/test-cases/regression/request-body-parser-xml*.json` | ModSecurity_V3 | v3/master beobachtet 3.0.15 | xml | XML Schema, DTD und Parserverhalten | teilweise | Nein | ja | Karten | Nur zugeordnet | xml, Vorrichtungen | Externe fixture/schema Materialisierung noch nicht Teil des aktiven Smokes |
| `test/test-cases/regression/debug_log.json` | ModSecurity_V3 | v3/master beobachtet 3.0.15 | Protokollierung | Verhalten des Debug-Protokolls | teilweise | teilweise | ja | Karten | Nur zugeordnet | Protokollierung | Der Text des Debug-Protokolls ist flüchtig und Connector-spezifisch |
| `test/test-cases/regression/operator-*.json` | ModSecurity_V3 | v3/master beobachtet 3.0.15 | Betreiber | Operatormatrix | teilweise | Nein | ja | zukünftige YAML Importe oder Karten | kartiert | Betreiber | Optionale Bibliotheks- und dateigestützte Operatoren benötigen die Fähigkeit gates/fixtures |
| `test/test-cases/regression/config-*.json` | ModSecurity_V3 | v3/master beobachtet 3.0.15 | Regelparser | Directive/config Verhalten | teilweise | Nein | ja | Karten | Nur zugeordnet | Regelparser | In einigen Fällen sind Dateien, Netzwerke oder Protokollierungsgeräte erforderlich |
| `test/test-cases/regression/issue-*.json` | ModSecurity_V3 | v3/master beobachtet 3.0.15 | Rückschritt | Spezifische Fehlerregressionen | unbekannt | unbekannt | unbekannt | Karten | todo | fallspezifisch | Erfordert eine Einzelfallprüfung vor dem Import |
| `test/test-cases/*.json` außerhalb `regression/` | ModSecurity_V3 | v3/master beobachtet 3.0.15 | API-Smoke | C/C++ Testkabelbaumdaten | teilweise | Nein | ja | `src/v3-api-smoke/` oder Karten | Nur zugeordnet | API-Smoke | Nur-API-Fälle sind noch nicht in den Connector `smoke-all` integriert |

## Aktive, von V3 abgeleitete Importe

Diese aktiven Fälle wurden lokal durch `make smoke-common` mit beobachtet
`BUILD_ROOT=<local-build-root>`; Sowohl Apache als auch NGINX wurden zurückgegeben
die erwarteten HTTP 403.

| Fall | Quelle | Status |
| --- | --- | --- |
| `multipart_files_value_block.yaml` | `variable-FILES.json` | vollständig importiert-gemeinsam |
| `multipart_files_names_block.yaml` | `variable-FILES_NAMES.json` | vollständig importiert-gemeinsam |
| `multipart_files_combined_size.yaml` | `variable-FILES_COMBINED_SIZE.json` | vollständig importiert-gemeinsam |
| `multipart_filename_block.yaml` | `variable-MULTIPART_FILENAME.json` | vollständig importiert-gemeinsam |
| `xml_request_body_block.yaml` | `variable-XML.json` | vollständig importiert-gemeinsam |
| `v3_operator_rx_block.yaml` | `operator-rx.json` | vollständig importiert-gemeinsam |
| `v3_operator_pm_digit_block.yaml` | `operator-pm.json` | vollständig importiert-gemeinsam |
| `v3_request_cookies_block.yaml` | `variable-REQUEST_COOKIES.json` | vollständig importiert-gemeinsam |
| `v3_request_cookies_names_block.yaml` | `variable-REQUEST_COOKIES_NAMES.json` | vollständig importiert-gemeinsam |
| `v3_request_headers_names_block.yaml` | `variable-REQUEST_HEADERS_NAMES.json` | vollständig importiert-gemeinsam |
| `v3_args_names_get_block.yaml` | `variable-ARGS_NAMES.json` | vollständig importiert-gemeinsam |
| `v3_auditlog_serial_fields_block.yaml` | `auditlog.json`; `issue-2000.json` | vollständig importiert-gemeinsam |
| `v3_transformation_trim_block.yaml` | `transformations.json` | vollständig importiert-gemeinsam |
| `v3_secaction_block.yaml` | `secruleengine.json` | vollständig importiert-gemeinsam |
