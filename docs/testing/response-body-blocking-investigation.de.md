# Untersuchung der Blockierung des Antwortkörpers

**Sprache:** [English](response-body-blocking-investigation.md) | Deutsch

Status: ehemals expected-failure/mapped-only

Bei dieser Untersuchung wird geprüft, ob ein gemeinsamer `RESPONSE_BODY`-Sperrfall vorliegen kann
zur aktiven gemeinsamen Connector-Abdeckung befördert. Es werden nur echte Verbindungspfade verwendet:

```text
Client -> Apache/NGINX -> connector module -> libmodsecurity -> RESPONSE_BODY -> HTTP response
```

Der direkte libmodsecurity API Smoke wird hier nicht mitgezählt.

Zugehörige Upstream-PR: https://github.com/owasp-modsecurity/ModSecurity-nginx/pull/377
Zugehöriges Upstream-Repository: https://github.com/owasp-modsecurity/ModSecurity-nginx
Beobachtet PR #377 Kopf: `3d72b004ff27a78ea19c6b945870e2cae62a97ac`

## Quellennachweis

| Quelle | Nachweise | Importentscheidung |
| --- | --- | --- |
| `ModSecurity-apache/tests/regression/config/10-response-directives.t` aus https://github.com/owasp-modsecurity/ModSecurity-apache | Enthält `SecResponseBodyAccess On`, `SecResponseBodyMimeType text/plain null` und eine `RESPONSE_BODY`-Verweigerungsregel, die HTTP 403 erwartet. | Von der Quelle abgeleiteter Sondenkandidat |
| `ModSecurity-nginx/tests/modsecurity-response-body.t` aus https://github.com/owasp-modsecurity/ModSecurity-nginx | Enthält einen vergleichbaren `RESPONSE_BODY`-Verweigerungstest, aber der Upstream-Test::Nginx-Fall markiert ihn als `TODO: not yet`. PR #377 dokumentiert den phase-4/late Interventionsthemenraum. | ehemalige Quelle erwarteter Fehler |
| `ModSecurity_V2/tests/regression/config/10-response-directives.t` aus https://github.com/owasp-modsecurity/ModSecurity | Historische Abdeckung der Antwortanweisungen, einschließlich Erwartungen an die Blockierung des Antwortkörpers. | Kompatibilitätsreferenz |
| `ModSecurity_V3/test/test-cases/regression/variable-RESPONSE_BODY.json` aus https://github.com/owasp-modsecurity/ModSecurity | Die V3-Regression erwartet, dass `SecRule RESPONSE_BODY "@contains denystring" ... deny` HTTP 403 zurückgibt. | Engine/reference Nachweise |

## §PR #377 Quellenaufnahme

Phase 9 wendet die relevanten PR #377 Quelländerungen auf die Adapter-eigenen NGINX an.
Nur Dateien:

- `connectors/nginx/src/ngx_http_modsecurity_body_filter.c`
- `connectors/nginx/src/ngx_http_modsecurity_common.h`
- `connectors/nginx/src/ngx_http_modsecurity_module.c`

Der PR führt die phase-4/late-intervention-Konfiguration ein, z
`modsecurity_phase4_mode`, `modsecurity_phase4_content_types_file` und
`modsecurity_phase4_log`. Rohe PR-Tests und -Dokumente werden nicht in die aktiven kopiert
Smokesuite.

Diese Quellenaufnahme ändert nichts an der nachstehenden Klassifizierung. Eine vorübergehende Quelle
build und `smoke-nginx` beweisen nur, dass die dem Adapter gehörende NGINX-Quelle kompiliert wird
und bewahrt das aktive Smokeverhalten. `RESPONSE_BODY` erfordert noch eine separate
Echter Apache+NGINX Blockierungsnachweis vor der Hochstufung.

Es wurde keine Upstream-Testdatei kopiert. Der lokale YAML ist eine minimal abgeleitete Sonde bei
`tests/cases/response/body/response_body_basic_block.yaml`.

Phase 10 inventarisiert die PR #377 Tests in `pr377-test-import-map.md`. Drei
Nur NGINX-mode/log-Probes wurden nach 3/3 stabilen NGINX PASS-Ergebnissen importiert.
aber sie erwarten absichtlich HTTP 200 Pass-Through und führen daher keine Überprüfung durch
Blockierung des Antwortkörpers.

## Sonde

Befehl:

```sh
BUILD_ROOT=$HOME/.local/state/ModSecurity-conector-build make probe-response-body || true
```

Sonden-Standardeinstellungen:

- `RESPONSE_BODY_PROBE_REPEAT=3`
- Sondenwurzel: `$BUILD_ROOT/response-body-probe`
- Zusammenfassung: `$BUILD_ROOT/response-body-probe/results/response-body-probe-summary.json`

Der Sondenfall ermöglicht die serielle Audit-Protokollierung und erfordert das ModSecurity-Audit
Eintrag für Regel `1801`. Dadurch wird verhindert, dass ein servergenerierter 403 gezählt wird
als ModSecurity-Antwortblock.

## Beobachtetes Ergebnis

Lokal beobachtet am 17.05.2026 nach der Phase 9 NGINX Quelle im Besitz des Adapters
Migration und PR #377 Quellaufnahme:

| Connector | Wiederholt | HTTP Ergebnis | Nachweise | Klassifizierung |
| --- | ---: | --- | --- | --- |
| Apache | 0 bestanden / 3 nicht bestanden / 0 blockiert | HTTP 200 bei jedem Lauf | Antworttext enthielt `safe response-attack body`; Das Audit-Protokoll war leer. | scheitern |
| NGINX | 0 bestanden / 3 nicht bestanden / 0 blockiert | HTTP 200 bei jedem Lauf | Der aktive Response-Body-Blockierungstest hat HTTP 403 immer noch nicht zurückgegeben. | scheitern |

Die vorherige NGINX-Probe vor Phase 9 beobachtete eine leere Client-Antwort nach a
Phase-4-Match. Die aktuelle PR #377 Quellenaufnahme ändert das beobachtete Symptom,
aber es liefert immer noch nicht die erforderlichen echten HTTP 403. Das ist kein
Connector PASS gemäß den Regeln dieses Repositorys.

Relevante Protokolle unter den konfigurierten `BUILD_ROOT`:

- Apache-Wiederholung 1:
  `$BUILD_ROOT/response-body-probe/logs/apache/repeat-1/response_body_basic_block/`
- NGINX Wiederholung 1:
  `$BUILD_ROOT/response-body-probe/logs/nginx/repeat-1/response_body_basic_block/`

## Entscheidung

`response_body_basic_block` bleibt `former expected-failure`/`mapped-only`.

Es wird nicht hochgestuft für:

- `tests/cases/`
- `tests/cases/connector-specific/apache/`
- `tests/cases/connector-specific/nginx/`

`RESPONSE_BODY` bleibt von `verified_variables` ausgeschlossen. Aktiv
`response_body_pass.yaml` ist nur eine Pass-Through-Probe mit Zugriff auf den Antworttext
aktiviert; Es ist kein Nachweis für die Blockierung des Antwortkörpers. In der neuesten NGINX Laufzeit
Snapshot, diese Durchgangssonde hat HTTP 200 nach dem Harness zurückgegeben
Berechtigungskorrektur. Dies ist nur request/runtime Pass-Through-Nachweis; das tut es nicht
Hochstufung der `RESPONSE_BODY`-Unterstützung oder Antwortkörper-Blockierungskompatibilität.

## Nächste Schritte

- Untersuchen Sie, warum Apache die `RESPONSE_BODY`-Regel der Phase 4 nicht auf die anwendet
  statische Befestigung in diesem minimalistischen Gurtzeug.
- Untersuchen Sie, warum die Quellaufnahme NGINX PR #377 immer noch die gemeinsame Quelle verlässt
  Blockierungsprüfung bei HTTP 200 anstelle von HTTP 403.
- Probieren Sie einen Connector-spezifischen Antwort-Fixture-Pfad erst aus, nachdem Sie dokumentiert haben, warum
  Der aktuelle statische Vorrichtungspfad ist unzureichend.

## Zusätzliche experimentelle Sonden der Phase 4 (19.05.2026)

Eine dedizierte ehemalige Erweiterung für erwartete Fehler fügte experimentelle Phase-4-Response-Body-Probes (empty/unicode/chunk/compressed/html-Annahmen) sowie ausgehende Audit-Log-Probes hinzu. Hierbei handelt es sich lediglich um Kompatibilitätsverfolgungsartefakte, die die nicht verifizierte RESPONSE_BODY-Klassifizierung nicht ändern.

## Follow-up-Phase-4-Sondenwelle (19.05.2026)

Zusätzliche Phase-4-Antworttext- und ausgehende Prüfprüfungen wurden nur als frühere expected-failure/future/connector-gap-Verfolgung hinzugefügt. Sie ändern nichts an der RESPONSE_BODY nicht überprüften Entscheidung.
