# PR #377 Importkarte testen

**Sprache:** [English](pr377-test-import-map.md) | Deutsch

Status: umgesetzt

Dieses Dokument ordnet ModSecurity-nginx PR #377-Tests diesem Repository zu
Von der Quelle abgeleitete YAML-Sonden. Die PR wurden anhand einer temporären Checkout unter überprüft
`$BUILD_ROOT`, nicht durch Ändern eines Referenz-Checkouts für den übergeordneten Arbeitsbereich.

Upstream PR: https://github.com/owasp-modsecurity/ModSecurity-nginx/pull/377

Beobachtet PR Kopf: `3d72b004ff27a78ea19c6b945870e2cae62a97ac`

## Entscheidungen importieren

| Originalpfad | Zweck | Phase4_Modus | Anfrage | Antwortvorrichtung | erwartetes Verhalten | tragbar | Zielort | Status | Grund | erforderliche_Kapazitäten | bekannte_Einschränkungen |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `tests/modsecurity-phase4-modes.t` | Der Minimalmodus protokolliert späte Interventionen der Phase 4, ohne die Reaktion des Kunden zu ändern | `minimal` | `GET /m` | `Hello minimal` | HTTP 200 Körper erhalten; Das Phase4-Protokoll enthält `actual_action=log_only`, `reason=mode_minimal` und keine Antworttextdaten | Nein | `tests/cases/connector-specific/nginx/nginx_phase4_minimal_log_only.yaml` | importiert, neueste NGINX Smoke PASS | Der letzte vom Quellcode erstellte NGINX hat HTTP 200 nach der Korrektur der Harness-Berechtigung zurückgegeben; Dabei handelt es sich um NGINX-spezifische Phase-4-Log-Only-Nachweise, nicht um Antworttext-Blockierungsbeweise | Antworttext, Phase4, Protokollierung, Passthrough | Keine `RESPONSE_BODY` blockierende Aktion |
| `tests/modsecurity-phase4-modes.t` | Der abgesicherte Modus protokolliert späte Phase-4-Interventionen, ohne die Client-Reaktion zu ändern | `safe` | `GET /s` | `Hello safe` | HTTP 200 Körper erhalten; Das Phase4-Protokoll enthält `actual_action=log_only`, `reason=mode_safe` und keine Antworttextdaten | Nein | `tests/cases/connector-specific/nginx/nginx_phase4_safe_log_only.yaml` | importiert, neueste NGINX Smoke PASS | Der letzte vom Quellcode erstellte NGINX hat HTTP 200 nach der Korrektur der Harness-Berechtigung zurückgegeben; Dabei handelt es sich um NGINX-spezifische Phase-4-Log-Only-Nachweise, nicht um Antworttext-Blockierungsbeweise | Antworttext, Phase4, Protokollierung, Passthrough | Keine `RESPONSE_BODY` blockierende Aktion |
| `tests/modsecurity-phase4-modes.t` | Der strikte Modus bricht ab, nachdem bereits Header gesendet wurden | `strict` | `GET /x` | `Hello strict` | Test::Nginx erwartet leere Antwort und Phase4-Protokoll hat `actual_action=connection_abort` | Nein | `tests/cases/connector-specific/nginx/nginx_phase4_strict_connection_abort.yaml` | importiert | Das aktuelle Smoke-Schema zeichnet Nachweise für leere Antworten auf, ohne die RESPONSE_BODY-Blockierung zu fördern | Antwortkörper, Phase4, Intervention, Protokollierung | Erfordert eine explizite empty-reply/connection-abort-Behauptung vor der Heraufstufung |
| `tests/modsecurity-phase4-content-types.t` | Inhaltstyp innerhalb des Gültigkeitsbereichs mit Abbrüchen im strikten Modus | `strict` | `GET /json` | `HIT JSON` mit `default_type application/json` | Leere Antwort; Phase4-Protokollsätze `content_type=application/json` und `actual_action=connection_abort` | Nein | Nur zugeordnet | Nur zugeordnet | Erfordert Verbindungsabbruchzusicherungen im strikten Modus; nicht als aktiv importiert YAML | Antworttext, Phase4, Protokollierung | Keine stabile Antwortzusicherung HTTP |
| `tests/modsecurity-phase4-content-types.t` | Inhaltstypen außerhalb des Gültigkeitsbereichs werden protokolliert, die Antwort bleibt jedoch erhalten | `strict` | `GET /unknown` | `HIT UNKNOWN` mit `default_type image/png` | HTTP 200 Körper erhalten; Das Phase4-Protokoll enthält `reason=content_type_not_in_scope` und keine Antworttextdaten | Nein | `tests/cases/connector-specific/nginx/nginx_phase4_content_type_out_of_scope.yaml` | importiert, neueste NGINX Smoke PASS | Der letzte vom Quellcode erstellte NGINX hat HTTP 200 nach der Korrektur der Harness-Berechtigung zurückgegeben; Dabei handelt es sich um NGINX-spezifische Phase-4-Log-Only-Nachweise, nicht um Antworttext-Blockierungsbeweise | Antworttext, Phase4, Protokollierung, Passthrough | Nachweist nicht die Blockierung des Antwortkörpers |
| `tests/modsecurity-phase4-content-types.t` | Der leere Inhaltstyp liegt außerhalb des Gültigkeitsbereichs | `strict` | `GET /emptytype` | `HIT EMPTY` mit leerem Standardtyp | HTTP 200 Körper erhalten; Das Phase4-Protokoll zeichnet Verhalten außerhalb des Gültigkeitsbereichs auf | Nein | Nur zugeordnet | Nur zugeordnet | Ähnlich dem importierten Fall außerhalb des Gültigkeitsbereichs; bleibt zugeordnet, um eine redundante Connector-spezifische Abdeckung zu vermeiden, bis das Schema wächst | Antworttext, Phase4, Protokollierung | Kein neues Verhalten über die importierte Probe hinaus, die außerhalb des Gültigkeitsbereichs liegt |
| `tests/modsecurity-phase4-invalid-config.t` | Ungültigen Inhaltstyp-Glob-Eintrag ablehnen | n/a | `nginx -t` Konfigurationstest | `phase4-invalid.conf` mit `text/*` | In der Konfigurationstestausgabe wird ein ungültiger Inhaltstypeintrag erwähnt | Nein | Nur zugeordnet | Nur zugeordnet | Der aktuelle YAML-Runner ist HTTP-Smoke-orientiert und modelliert erwartete Konfigurationstestfehler nicht | config, Antworttext | Benötigt einen speziellen Konfigurationsvalidierungs-Harness |
| `tests/modsecurity-phase4-regression.t` | Die große Reaktion bleibt im Minimalmodus intakt und das Protokoll verliert keinen Text | `minimal` | `GET /big` | 70,000 `A` Bytes plus `TAIL` | HTTP 200, Körperpräfix und -ende bleiben erhalten, Phase4-Protokoll enthält `log_only`, aber keine großen Körperdaten | Nein | Nur zugeordnet | Nur zugeordnet | Eine große fixture/log-leak-Abdeckung ist nützlich, erfordert jedoch vor dem aktiven Import eine spezielle Ergonomie der Vorrichtung | Antworttext, Phase4, Protokollierung, Passthrough | Aktuelle minimale YAML können es umständlich ausdrücken; aufgeschoben, um spröde große Vorrichtungen zu vermeiden |
| `tests/modsecurity-response-body.t` | Vorhandene Antworttextblockierung TODO | implizite Reaktionsphase | `GET /body1` | `BAD BODY` | Der Upstream-Test bleibt TODO für die HTTP 403 Antworttextblockierung bestehen | teilweise | `tests/cases/response/body/response_body_basic_block.yaml` | non-promoted/mapped-only | Der Shared-Response-Body-Blockierungstest erzeugt immer noch keine stabilen HTTP 403 über Apache und NGINX | Antwortkörper, Phase4, Intervention | `RESPONSE_BODY` bleibt von `verified_variables` ausgeschlossen |

## Hochstufungsgrenze

Die drei importierten Nur-NGINX-Probes PR #377 dienen der Validierung von Phase 4
logging/mode Verhalten und Erhaltung der Pass-Through-Antwort. Spätestens
Beim lokalen NGINX Quellcode-Lauf gaben sie HTTP 200 nach der Harness-Berechtigung zurück
reparieren. Sie zählen immer noch nicht als `RESPONSE_BODY` blockierende Validierung, weil
sie erwarten absichtlich HTTP 200.

Die Hochstufung von `RESPONSE_BODY` erfordert einen separaten Nachweisschritt mit einem definierten
Blockierungsfall, stabile reale HTTP-Semantik und ein explizites Apache/NGINX-Common
oder reine NGINX-Klassifizierungsentscheidung.
