**Sprache:** [English](TEST-COVERAGE-SUMMARY.md) | Deutsch

Generierte Datei – nicht manuell bearbeiten.

# Zusammenfassung der ModSecurity Connector-Testabdeckung

## Zusammenfassungsstatus
- Insgesamt YAML Fälle: **540**
- Verified/pass (`runtime_verified=true`): **0**
- Aktuelle XFAIL Fälle: **0**
- Frühere XFAIL-Fälle verfolgt: **80**
- Ausstehende Laufzeitüberprüfung (`runtime_verified=false`): **410**
- Ausstehende Laufzeitüberprüfung (`runtime_verified=unknown`): **130**
- Fälle von Verbindungslücken: **11**
- Laufzeitdifferenzfälle: **13**
- Future/experimental Fälle: **17**
- RESPONSE_BODY Fälle: **32**
- Standardmäßige zur Laufzeit ausführbare YAML-Fälle: **61**
- Alle zur Laufzeit ausführbaren YAML-Fälle erzwingen: **540**
- Apache versuchte YAML Fälle im Standard-Laufzeit-Snapshot: **54**
- NGINX versuchte YAML Fälle im Standard-Laufzeit-Snapshot: **60**
- HAProxy versuchte YAML Fälle im Standard-Laufzeit-Snapshot: **134**
- Apache hat YAML Fälle im Force-All-Laufzeit-Snapshot versucht: **133**
- NGINX versuchte YAML Fälle im Force-All-Laufzeit-Snapshot: **140**
- HAProxy hat YAML Fälle im Force-All-Laufzeit-Snapshot versucht: **133**
- Apache Force-All Raw-Laufzeit PASS/FAIL/BLOCKED/NOT_EXECUTABLE: **100** / **27** / **0** / **6**
- NGINX Force-All Raw Runtime PASS/FAIL/BLOCKED/NOT_EXECUTABLE: **95** / **39** / **0** / **6**
- HAProxy Force-All Raw Runtime PASS/FAIL/BLOCKED/NOT_EXECUTABLE: **104** / **23** / **0** / **6**
- Nur zugeordnete Importinventareinträge: **0**

## MRTS Quellenzusammenfassung
- Insgesamt MRTS importierte Fälle: **399**
- Aktive MRTS Fälle: **0**
- Ausstehende MRTS-Fälle: **399**
- Nicht klassifizierte MRTS Fälle: **399**
- Phase 4 / RESPONSE_BODY MRTS Fälle: **110**
- Zur Laufzeit ausführbare MRTS Fälle: **0**
- MRTS Overlay-Klassifizierungen: **nicht klassifiziert(399)**
- Von Apache beobachtete Klassifizierungen: **-**
- NGINX beobachtete Klassifizierungen: **-**
- Von HAProxy beobachtete Klassifizierungen: **-**

| Korpus | Kategorie | Definitionen | Goldene Prüfungen | Goldene Regeln | Framework-Fälle | Aktiv | Ausstehend | Nicht klassifiziert | Phase 4 / RESPONSE_BODY | Zur Laufzeit ausführbare Datei |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Upstream-Konfigurationstests | lauffähig | 16 | 157 | 15 | 383 | 0 | 383 | 383 | 110 | 0 |
| Feature-Demo | optional/demo | 9 | 13 | 8 | 16 | 0 | 16 | 16 | 0 | 0 |
| vorgelagert generiert | Nur Gold | - | 157 | 15 | 0 | 0 | 0 | 0 | 0 | 0 |
| Framework-kuratiert | legacy/reference | 16 | - | - | 0 | 0 | 0 | 0 | 0 | 0 |

### MRTS Golden Drift
| Referenz | Generiert | Golden | Passend | Nichtübereinstimmung | Fehlende generiert | Extra generiert |
|---|---:|---:|---:|---:|---:|---:|
| upstream_tests | 157 | 157 | 157 | 0 | 0 | 0 |
| upstream_rules | 15 | 15 | 15 | 0 | 0 | 0 |
| feature_demo_tests | 13 | 13 | 0 | 0 | 13 | 13 |
| feature_demo_rules | 8 | 8 | 7 | 1 | 0 | 0 |

- Doppelte MRTS-Regel-IDs in importierten runnable/demo-Korpora: **13**
- Nur-Gold-Referenzen unter `tools/MRTS/generated/**` und `tools/MRTS/feature_demo/generated/**` sind nur Drifteingaben.
- Feature-Demo-Fälle sind im Bericht als optional/demo sichtbar und ausstehend, es sei denn, `MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO=1` besteht die Kollisionsprüfungen.

## Wichtige Berichtssemantik
- PASS/FAIL werden nur aus Live-Laufzeitnachweisen gerendert, die in Connector-Zusammenfassungen und decision/result-Artefakten aufgezeichnet wurden.
- BLOCKED bleibt für Harness-, Umgebungs-, Abhängigkeits-, Build- oder Laufzeitblocker reserviert.
- NOT_EXECUTABLE bedeutet, dass der Fall für diesen connector/run-Modus strukturell nicht zuordbar ist; Es ist kein Blocker und kein Pass.
- Alle Nachweise erzwingen stuft nicht hoch die Funktionsunterstützung von YAML.
- RESPONSE_BODY bleibt experimental/non-promoted, einschließlich begrenzter Phase-4- und strikter Abbruchnachweise.

## Framework-Integration
- Diese Framework-eigene Datei ist die Quelle der Wahrheit für die Root-Coverage-Berichterstattung: `TEST-COVERAGE-SUMMARY.md` in `ModSecurity-test-Framework`.
- Connector-Repositorys sollten auf diese Framework-Zusammenfassung verlinken, anstatt ihre eigene Root-Coverage-Zusammenfassung zu verwalten.
- Freigegebene YAML-Fälle, Runner, Normalisierer, Generatoren und detaillierte Testdokumentation sind Eigentum von `ModSecurity-test-Framework`.
- Das Connector-Repository besitzt Connector-Quelle, Harnesses, Adaptermetadaten, `config/testing/import-status.json` und Connector-spezifisch generierte Nachweise unter `reports/testing/`.
- `FRAMEWORK_ROOT` und `CONNECTOR_ROOT` sind explizite Integrationspfade; Es gibt keinen absoluten Workspace-Fallback.

## Fallinventar
- Häufige YAML Fälle: **533**
- Apache-spezifische YAML-Fälle: **0**
- NGINX-spezifische YAML Fälle: **7**
- Aktuelle XFAIL Fälle: **0**
- Frühere XFAIL-Fälle verfolgt: **80**
- Nur zugeordnete Importinventareinträge: **0** (wird nicht als ausführbare YAML Fälle gezählt)
- Laufzeitblockierte Importinventareinträge: **0** (environment/harness Blocker, nicht PASS Werbeaktionen)
- Pending/future Kompatibilitätsfälle: **17** future/experimental; **540** nicht laufzeitverifiziert

## Statusklassen
| Status | Zählen |
|---|---:|
| aktiv | 8 |
| importiert | 133 |
| ausstehend | 399 |

## Umfang
| Umfang | Zählen |
|---|---:|
| häufig | 533 |
| Apache | 0 |
| Nginx | 7 |
| unbekannt | 0 |

## Abdeckung nach Variable/Sammlung
| Variable / Sammlung | Zählen |
|---|---:|
| `ARGS` | 121 |
| `ARGS_NAMES` | 62 |
| `REQUEST_HEADERS` | 5 |
| `REQUEST_HEADERS_NAMES` | 5 |
| `REQUEST_COOKIES` | 62 |
| `REQUEST_COOKIES_NAMES` | 64 |
| `REQUEST_URI` | 7 |
| `REQUEST_BODY` | 10 |
| `FILES` | 2 |
| `FILES_NAMES` | 2 |
| `XML` | 8 |
| `RESPONSE_HEADERS` | 11 |
| `RESPONSE_BODY` | 28 |
| `AUDIT_LOG` | 0 |

## Abdeckung nach Phase
| Phase | Zählen |
|---|---:|
| Phase 1 | 105 |
| Phase 2 | 192 |
| Phase 3 | 114 |
| Phase 4 | 126 |

## Berichterstattung nach Thema
| Thema | Zählen |
|---|---:|
| Betreiber | 523 |
| Transformationen | 32 |
| Mehrteilig / FILES | 11 |
| JSON | 7 |
| XML | 8 |
| Unicode / Kodierung | 17 |
| XSS-ähnliche Kompatibilitätsprüfungen | 2 |
| SQLi-ähnliche Kompatibilitätsprüfungen | 2 |
| Audit-Log-Prüfungen | 24 |
| Antwort-Header-Prüfungen | 11 |
| Experimentelle Sonden des Reaktionskörpers | 10 |

## Laufzeitmatrixstatus
| Status | Apache | NGINX | HAProxy |
|---|---:|---:|---:|
| PASS | 54 | 60 | 105 |
| FAIL | 0 | 0 | 23 |
| NOT_EXECUTABLE | 486 | 480 | 412 |

- Apache hat YAML Fälle aus der Standardzusammenfassung versucht: **54**
- NGINX versuchte YAML Fälle aus der Standardzusammenfassung: **60**
- HAProxy versuchte YAML Fälle aus der Standardzusammenfassung: **134**
- Apache NOT EXECUTED YAML Zeilen: **0**
- NGINX NOT EXECUTED YAML Zeilen: **0**
- HAProxy NOT EXECUTED YAML Zeilen: **0**
- Apache NOT_EXECUTABLE YAML Zeilen: **486**
- NGINX NOT_EXECUTABLE YAML Zeilen: **480**
- HAProxy NOT_EXECUTABLE YAML Zeilen: **412**
- Nur zugeordnete Importinventareinträge: **0**
- Details zur Laufzeitmatrix: `docs/testing/generated/runtime-matrix.generated.md`
- Apache-Ergebnisse pro Fall: `docs/testing/generated/apache-runtime-results.generated.md`
- NGINX Einzelfallergebnisse: `docs/testing/generated/nginx-runtime-results.generated.md`
- HAProxy-Ergebnisse pro Fall: `docs/testing/generated/haproxy-runtime-results.generated.md`
- Die PASS/BLOCKED/FAIL-Zählungen stammen hier nur aus nachverfolgten Laufzeit-Snapshot-Nachweisen.
- RESPONSE_BODY bleibt auch dann nicht verifiziert, wenn ein Pass-Through-Runtime-Fall HTTP 200 zurückgibt.

- HAProxy erzwingt alle versuchten YAML Fälle: **133**
- HAProxy Force-All-Ergebnis JSONL: `/src/ModSecurity-conector-build/results/force-all/haproxy-results.jsonl`
- HAProxy erzwingt alle Einzelfall-Nachweiswurzeln: `/src/ModSecurity-conector-build/logs/haproxy-runtime`
- Force-All-Nachweise sind nachvollziehbare Laufzeitbeweise, fördern aber nicht die pending/future/gap-Funktionsunterstützung.

## Status der Framework-Prüfung
| Befehl | Status | Einzelheiten |
|---|---|---|
| make setup-dev | PASS | Entwicklungsabhängigkeiten sind in .venv verfügbar |
| `make lint` | PASS | Repository-Lint-Prüfungen bestanden |
| Machen Sie eine Testmatrix generieren | PASS | Generierte Abdeckungsdokumente, aktualisiert aus aktuellen Metadaten |
| Check-Test-Matrix erstellen | PASS | Die generierten Abdeckungsdokumente stimmten mit der Generatorausgabe überein, nachdem die generierten Dokumente bereitgestellt wurden |
| Machen Sie einen Schnellcheck | PASS | Prüfungen des Lightweight-Frameworks bestanden |
| Machen Sie einen Cloud-Schnellcheck | PASS | Framework/generator-only Cloud-Check bestanden |
| .venv/bin/python -m py_compile modules/ModSecurity-test-Framework/tests/normalizers/*.py modules/ModSecurity-test-Framework/tests/runners/*.py modules/ModSecurity-test-Framework/ci/*.py | PASS | Framework-Python-Dateien, die über den Connector-Modulpfad kompiliert wurden |
| sh -n ci/*.sh connectors/apache/harness/*.sh connectors/nginx/harness/*.sh | PASS | POSIX Shell-Syntaxprüfung für Connector-Integrations-Shell-Skripte bestanden |
| bash -n ci/*.sh connectors/apache/harness/*.sh connectors/nginx/harness/*.sh | PASS | Bash-Syntaxprüfung für Connector-Integrations-Shell-Skripte bestanden |
| git diff --check | PASS | Es wurden keine Leerzeichenfehler gemeldet |
| diff -u /tmp/pre-connector.diff /tmp/post-connector.diff | PASS | Der Connector-Quell-Diff-Snapshot bleibt unverändert; Es wurden keine neuen Änderungen an der Connector-Quelle eingeführt |
| git diff --exit-code -- connectors/apache/src connectors/nginx/src | BLOCKED | Ungleich Null, da connectors/apache/src/mod_security3.c vor diesem Fix bereits eine nicht verwandte lokale Änderung hatte; Der pre/post Connector-Diff-Snapshot bleibt unverändert |
| git ls-files .venv | PASS | Keine verfolgten .venv-Dateien |

## Bereitschafts-/Abrufstatus
| Befehl | Status | Einzelheiten |
|---|---|---|
| Fetch-Deps erstellen | NOT_RUN | Wird während der Framework-Modul-Migration nicht erneut ausgeführt. runtime-matrix-all verwendete den konfigurierten lokalen Quellbaum und den Build-Ausgabespeicherort |
| optional installierte Bereitschaft | BLOCKED | Die Bereitschaft des Systems Apache/APXS/NGINX/libmodsecurity bleibt nur für die Diagnose bestehen und ist für Source-Build-Smokes nicht erforderlich |
| runtime-matrix-all erstellen | PASS | Force-All-Matrix-Orchestrierung abgeschlossen und Apache/NGINX Einzelfallnachweise aufgezeichnet; Erwartete Laufzeitfehler bleiben Nachweise und stellen keine PASS-Promotionen dar |

## Smoke-Status zur Laufzeit
- Schnappschuss: **2026-06-07** (2026-06-07 13:02:53 CEST)
- Git: branch `integrate-new-connectors-local`, commit `b5b983d`
- BUILD_ROOT: `/src/ModSecurity-conector-build`
- Snapshot-Datei: `docs/testing/runtime-validation-snapshot.json`

### Standardmäßiger Smoke-Status zur Laufzeit
| Connector | Befehl | Status | Ausstieg | Versucht | PASS | FAIL | BLOCKED | NOT_EXECUTABLE | Nachweise |
|---|---|---|---|---|---|---|---|---|---|
| Apache | Machen Sie Smoke-Apache | PASS | 0 | 54 | 54 | 0 | 0 | 0 | /src/ModSecurity-conector-build/results/apache-summary.json |
| Nginx | Machen Sie Smoke-Nginx | PASS | 0 | 60 | 60 | 0 | 0 | 0 | /src/ModSecurity-conector-build/results/nginx-summary.json |
| haproxy | Machen Sie Smoke-Haproxy | FAIL | 2 | 134 | 105 | 23 | 0 | 6 | /src/ModSecurity-conector-build/results/haproxy-summary.json |
| alle | REFRESH=1 Smoke-All machen | NOT_RUN | not_run | 0 | unbekannt | unbekannt | unbekannt | unbekannt | nicht verfügbar |

### Smoke-Status zur Laufzeit erzwingen
| Connector | Befehl | Status | Ausstieg | Versucht | PASS | FAIL | BLOCKED | NOT_EXECUTABLE | Nachweise |
|---|---|---|---|---|---|---|---|---|---|
| Apache | FORCE_ALL_CASES=1 mache Smoke-Apache | FAIL | 1 | 133 | 100 | 27 | 0 | 6 | /src/ModSecurity-conector-build/results/force-all/apache-summary.json |
| Nginx | FORCE_ALL_CASES=1 Smoke-Nginx erstellen | FAIL | 1 | 140 | 95 | 39 | 0 | 6 | /src/ModSecurity-conector-build/results/force-all/nginx-summary.json |
| haproxy | FORCE_ALL_CASES=1 Smoke-Haproxy erstellen | FAIL | 2 | 133 | 104 | 23 | 0 | 6 | /src/ModSecurity-conector-build/results/force-all/haproxy-summary.json |

## Laufzeitverfügbarkeit des Connectors
| Connector | Status | Bauen | Ergebnisse pro Fall | Versuchte Fälle | Zusammenfassende Nachweise | Hinweis |
|---|---|---|---|---:|---|---|
| Apache | PASS | unbekannt | verfügbar | 54 | /src/ModSecurity-conector-build/results/apache-summary.json | Die Einzelfallergebnisse werden aus der lokalen Smoke-Zusammenfassung JSON kopiert. Sie dienen lediglich als Laufzeitbeweis. |
| NGINX | PASS | unbekannt | verfügbar | 60 | /src/ModSecurity-conector-build/results/nginx-summary.json | Die Einzelfallergebnisse werden aus der lokalen Smoke-Zusammenfassung JSON kopiert. Sie dienen lediglich als Laufzeitbeweis. |
| HAProxy | FAIL | unbekannt | verfügbar | 134 | /src/ModSecurity-conector-build/results/haproxy-summary.json | Die Einzelfallergebnisse werden aus der lokalen Smoke-Zusammenfassung JSON kopiert. Sie dienen lediglich als Laufzeitbeweis. |

## Laufzeit FAIL Details

### Apache FAIL Details
Es wurden keine Details zur Apache-Laufzeit FAIL gemeldet.

### NGINX FAIL Details
Es wurden keine NGINX Laufzeit-FAIL Details gemeldet.

### HAProxy FAIL Details
| Fall | Erwartet | Tatsächlich | Bewertung | Nachweise |
|---|---|---|---|---|
| Duplikat_args_encoded_separator_edge | 403 | 200 | Die Laufzeitzusammenfassung hat als nicht bestanden gemeldet | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=duplicate_args_encoded_separator_edge; status=fehlgeschlagen; erwartet=403; tatsächlich=200 |
| double_header_case_normalization_gap | 403 | 200 | Die Laufzeitzusammenfassung hat als nicht bestanden gemeldet | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=duplicate_header_case_normalization_gap; status=fehlgeschlagen; erwartet=403; tatsächlich=200 |
| edge_semicolon_query_args_names | 403 | 200 | Die Laufzeitzusammenfassung hat als nicht bestanden gemeldet | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=edge_semicolon_query_args_names; status=fehlgeschlagen; erwartet=403; tatsächlich=200 |
| files_names_mixed_case_filename_gap | 403 | 501 | Die Laufzeitzusammenfassung hat als nicht bestanden gemeldet | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=files_names_mixed_case_filename_gap; status=fehlgeschlagen; erwartet=403; tatsächlich=501 |
| multipart_duplicate_field_names_gap | 403 | 501 | Die Laufzeitzusammenfassung hat als nicht bestanden gemeldet | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=multipart_duplicate_field_names_gap; status=fehlgeschlagen; erwartet=403; tatsächlich=501 |
| parser_xml_partial_body_future_target | 403 | 501 | Die Laufzeitzusammenfassung hat als nicht bestanden gemeldet | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=parser_xml_partial_body_future_target; status=fehlgeschlagen; erwartet=403; tatsächlich=501 |
| phase3_response_headers_multi_value_connector_gap | 403 | 200 | Die Laufzeitzusammenfassung hat als nicht bestanden gemeldet | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=phase3_response_headers_multi_value_connector_gap; status=fehlgeschlagen; erwartet=403; tatsächlich=200 |
| phase3_response_headers_set_cookie_multi_gap | 403 | 200 | Die Laufzeitzusammenfassung hat als nicht bestanden gemeldet | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=phase3_response_headers_set_cookie_multi_gap; status=fehlgeschlagen; erwartet=403; tatsächlich=200 |
| phase4_auditlog_outbound_multiline_section_gap | 403 | 200 | Die Laufzeitzusammenfassung hat als nicht bestanden gemeldet | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=phase4_auditlog_outbound_multiline_section_gap; status=fehlgeschlagen; erwartet=403; tatsächlich=200 |
| Response_headers_multi_value_runtime_gap | 403 | 200 | Die Laufzeitzusammenfassung hat als nicht bestanden gemeldet | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=response_headers_multi_value_runtime_gap; status=fehlgeschlagen; erwartet=403; tatsächlich=200 |
| sqli_like_keyword_spacing_probe | 403 | 200 | Die Laufzeitzusammenfassung hat als nicht bestanden gemeldet | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=sqli_like_keyword_spacing_probe; status=fehlgeschlagen; erwartet=403; tatsächlich=200 |
| sqli_like_quote_encoding_runtime_difference | 403 | 200 | Die Laufzeitzusammenfassung hat als nicht bestanden gemeldet | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=sqli_like_quote_encoding_runtime_difference; status=fehlgeschlagen; erwartet=403; tatsächlich=200 |
| tfn_chain_lowercase_trim_pass_through | 200 | 0 | Die Laufzeitzusammenfassung hat als nicht bestanden gemeldet | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=tfn_chain_lowercase_trim_pass_through; status=fehlgeschlagen; erwartet=200; tatsächlich=0 |
| unicode_double_encoded_uri_runtime_difference | 403 | 200 | Die Laufzeitzusammenfassung hat als nicht bestanden gemeldet | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=unicode_double_encoded_uri_runtime_difference; status=fehlgeschlagen; erwartet=403; tatsächlich=200 |
| unicode_whitespace_normalization_gap | 403 | 200 | Die Laufzeitzusammenfassung hat als nicht bestanden gemeldet | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=unicode_whitespace_normalization_gap; status=fehlgeschlagen; erwartet=403; tatsächlich=200 |
| v3_action_nolog_pass_no_audit | 200 | 200 | Die Laufzeitzusammenfassung hat als nicht bestanden gemeldet | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=v3_action_nolog_pass_no_audit; status=fehlgeschlagen; erwartet=200; tatsächlich=200 |
| v3_request_cookies_names_case_runtime_difference | 403 | 200 | Die Laufzeitzusammenfassung hat als nicht bestanden gemeldet | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=v3_request_cookies_names_case_runtime_difference; status=fehlgeschlagen; erwartet=403; tatsächlich=200 |
| v3_request_headers_names_lowercase_runtime_difference | 403 | 200 | Die Laufzeitzusammenfassung hat als nicht bestanden gemeldet | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=v3_request_headers_names_lowercase_runtime_difference; status=fehlgeschlagen; erwartet=403; tatsächlich=200 |
| xml_deep_nesting_future_target | 403 | 501 | Die Laufzeitzusammenfassung hat als nicht bestanden gemeldet | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=xml_deep_nesting_future_target; status=fehlgeschlagen; erwartet=403; tatsächlich=501 |
| xml_namespace_edge_connector_gap | 403 | 501 | Die Laufzeitzusammenfassung hat als nicht bestanden gemeldet | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=xml_namespace_edge_connector_gap; status=fehlgeschlagen; erwartet=403; tatsächlich=501 |
| xml_request_body_malformed_connector_gap | 403 | 501 | Die Laufzeitzusammenfassung hat als nicht bestanden gemeldet | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=xml_request_body_malformed_connector_gap; status=fehlgeschlagen; erwartet=403; tatsächlich=501 |
| xss_like_encoded_angles_normalization_probe | 403 | 200 | Die Laufzeitzusammenfassung hat als nicht bestanden gemeldet | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=xss_like_encoded_angles_normalization_probe; status=fehlgeschlagen; erwartet=403; tatsächlich=200 |
| xss_like_mixed_case_script_token_gap | 403 | 200 | Die Laufzeitzusammenfassung hat als nicht bestanden gemeldet | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=xss_like_mixed_case_script_token_gap; status=fehlgeschlagen; erwartet=403; tatsächlich=200 |

## Laufzeitüberprüfter Status
- Die Laufzeitmatrix zeichnet aktuelle lokale Apache-, NGINX- und HAProxy-Smoke-Nachweise pro Fall auf, sofern verfügbar.
- PASS in diesem Schnappschuss bedeutet, dass der Fall vom Smoke-Harness dieses Connectors ausgeführt wurde und der Fallerwartung im zusammenfassenden JSON entsprach.
- Ausstehender, Connector-Lücke-, Laufzeitdifferenz-, zukünftiger und nur zugeordneter Bestand werden von diesem Snapshot nicht hochgestuft.
- FORCE_ALL_CASES=1 versucht alle materialisierbaren YAML Fälle, in denen sie auf den Connector anwendbar sind.
- HAProxy PASS ist nur auf Live-HAProxy-Nachweise ausgelegt; Die aktuelle HAProxy-Abdeckung ist eine teilweise anforderungsseitige YAML-Ausführung.
- RESPONSE_BODY bleibt non-verified/non-promoted.
- Laufzeit verstrichen, aber die RESPONSE_BODY-Unterstützung wird dadurch nicht überprüft.
- make Smoke-all wurde nicht von runtime-matrix ausgeführt; Die Anzahl der Vollraucher PASS bleibt unbekannt.

## Öffnen Sie Laufzeitprobleme
- Nur zugeordnete Importinventareinträge sind nicht ausführbare YAML Laufzeitfälle.
- Pending/future/connector-gap/runtime-difference-Themen erfordern einen Live-Nachweis vor einem Supportanspruch.
- RESPONSE_BODY bleibt experimental/non-verified.

## Offene Bereiche / Lücken
- Laufzeitüberprüfung ausstehend: Fälle mit `runtime_verified=false` oder `runtime_verified=unknown` sind kein Laufzeit-PASS-Nachweis.
- RESPONSE_BODY bleibt nicht verifiziert und nicht hochgestuft.
- GitHub/Codex-Prüfungen sind absichtlich leichtgewichtig und beweisen keine Laufzeitkompatibilität.
- Ausstehende, zukünftige, Connector-Gap- und Laufzeitunterschiede-Themen erfordern einen lokalen Laufzeitnachweis, bevor ein Supportanspruch geltend gemacht werden kann.
- Laufzeitblockierte Importeinträge sind Umgebungs- oder Harness-Blocker und implizieren keine connector-gap/runtime-difference-Hochstufung.
- `installed-readiness` ist eine Diagnoseerkennung, keine Laufzeitausführung.
- Es gibt keinen separaten Smokeweg für die Wiederverwendung von Artefakten. Die Laufzeitvalidierung nutzt die Source-Build-Ausführung.
- `make smoke-all` ist nur dann maßgeblich, wenn es tatsächlich erfolgreich ausgeführt wird.

## Befehle
- `make quick-check`
- `make quick-all`
- `make cloud-quick-check`
- `make installed-readiness`
- `make runtime-matrix`
- `make runtime-matrix-all`
- `make runtime-matrix-haproxy`
- `make smoke-apache`
- `make smoke-nginx`
- `make smoke-haproxy`
- `make smoke-all`
- `make generate-test-matrix`
- `make check-test-matrix`

## Detailberichte
- `docs/testing/test-coverage-overview.md`
- `docs/testing/generated/case-matrix.generated.md`
- `docs/testing/generated/coverage-summary.generated.md`
- `docs/testing/generated/xfail-summary.generated.md`
- `docs/testing/generated/connector-gap-summary.generated.md`
- `docs/testing/generated/phase-coverage.generated.md`
- `docs/testing/generated/runtime-matrix.generated.md`
- `docs/testing/generated/apache-runtime-results.generated.md`
- `docs/testing/generated/nginx-runtime-results.generated.md`
- `docs/testing/generated/haproxy-runtime-results.generated.md`
- `docs/testing/runtime-validation-snapshot.json`

## Wichtiger Hinweis
Die generierte Abdeckung dient nur der Berichterstattung. Es ist kein Laufzeitbeweis für sich.
Die vollständige Laufzeitvalidierung erfolgt lokal und evidenzbasiert.
GitHub/Codex-Prüfungen sind absichtlich leichtgewichtig.
Ausstehende, zukünftige und Lückenthemen erfordern vor der Heraufstufung eine lokale Laufzeitvalidierung.
`make smoke-all` ist nur dann maßgebend, wenn es tatsächlich erfolgreich ausgeführt wurde.
Aus dieser Datei werden keine PASS-Nummern abgeleitet, wenn `make smoke-all` nicht erfolgreich ausgeführt wurde.
Phase 4 / RESPONSE_BODY bleibt nicht hochgestuft; Begrenzte strikte Abbruchbeweise werden nur als Laufzeitbeweise gemeldet.
