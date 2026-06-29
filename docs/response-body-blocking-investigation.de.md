# Untersuchung der Blockierung des Antwortkörpers

**Sprache:** [English](response-body-blocking-investigation.md) | Deutsch

Status: ehemals expected-failure/mapped-only

Bei dieser Untersuchung wird geprüft, ob ein gemeinsamer `RESPONSE_BODY`-Sperrfall vorliegen kann
zur aktiven gemeinsamen Connector-Abdeckung befördert. Es werden nur echte Verbindungspfade verwendet:

```text
Client -> Apache/NGINX -> connector module -> libmodsecurity -> RESPONSE_BODY -> HTTP response
```

Der direkte libmodsecurity API Smoke wird hier nicht mitgezählt.

## Quellennachweis

| Quelle | Nachweise | Importentscheidung |
| --- | --- | --- |
| `ModSecurity-apache/tests/regression/config/10-response-directives.t` | Enthält `SecResponseBodyAccess On`, `SecResponseBodyMimeType text/plain null` und eine `RESPONSE_BODY`-Verweigerungsregel, die HTTP 403 erwartet. | Von der Quelle abgeleiteter Sondenkandidat |
| `ModSecurity-nginx/tests/modsecurity-response-body.t` | Enthält einen vergleichbaren `RESPONSE_BODY`-Verweigerungstest, aber der Upstream-Test::Nginx-Fall markiert ihn als `TODO: not yet`. | ehemalige Quelle erwarteter Fehler |
| `ModSecurity_V2/tests/regression/config/10-response-directives.t` | Historische Abdeckung der Antwortanweisungen, einschließlich Erwartungen an die Blockierung des Antwortkörpers. | Kompatibilitätsreferenz |
| `ModSecurity_V3/test/test-cases/regression/variable-RESPONSE_BODY.json` | Die V3-Regression erwartet, dass `SecRule RESPONSE_BODY "@contains denystring" ... deny` HTTP 403 zurückgibt. | Engine/reference Nachweise |

Es wurde keine Upstream-Testdatei kopiert. Der lokale YAML ist eine minimal abgeleitete Sonde bei
`tests/cases/response/body/response_body_basic_block.yaml`.

## Sonde

Befehl:

```sh
BUILD_ROOT=/src/ModSecurity-test-Framework-build make probe-response-body || true
```

Sonden-Standardeinstellungen:

- `RESPONSE_BODY_PROBE_REPEAT=3`
- Sondenwurzel: `/src/ModSecurity-test-Framework-build/response-body-probe`
- Zusammenfassung: `/src/ModSecurity-test-Framework-build/response-body-probe/results/response-body-probe-summary.json`

Der Sondenfall ermöglicht die serielle Audit-Protokollierung und erfordert das ModSecurity-Audit
Eintrag für Regel `1801`. Dadurch wird verhindert, dass ein servergenerierter 403 gezählt wird
als ModSecurity-Antwortblock.

## Beobachtetes Ergebnis

Lokal beobachtet am 15.05.2026:

| Connector | Wiederholt | HTTP Ergebnis | Nachweise | Klassifizierung |
| --- | ---: | --- | --- | --- |
| Apache | 0 bestanden / 3 nicht bestanden / 0 blockiert | HTTP 200 bei jedem Lauf | Antworttext enthielt `safe response-attack body`; Das Audit-Protokoll war leer. | scheitern |
| NGINX | 0 bestanden / 3 nicht bestanden / 0 blockiert | Curl beobachtet `000` / leere Antwort | NGINX error/audit Protokolle zeigen Phase 4 `RESPONSE_BODY` Regel `1801` überein, dann NGINX protokolliert `header already sent while sending response to client`. | scheitern |

Wichtiger Unterschied: NGINX hat libmodsecurity erreicht und abgeglichen
`RESPONSE_BODY`, aber es wurde kein stabiles HTTP 403 an den Client zurückgegeben. Das ist
kein Connector PASS gemäß den Regeln dieses Repositorys.

Relevante Protokolle:

- Apache-Wiederholung 1:
  `/src/ModSecurity-test-Framework-build/response-body-probe/logs/apache/repeat-1/response_body_basic_block/`
- NGINX Wiederholung 1:
  `/src/ModSecurity-test-Framework-build/response-body-probe/logs/nginx/repeat-1/response_body_basic_block/`

## Entscheidung

`response_body_basic_block` bleibt `former expected-failure`/`mapped-only`.

Es wird nicht hochgestuft für:

- `tests/cases/`
- `tests/cases/connector-specific/apache/`
- `tests/cases/connector-specific/nginx/`

`RESPONSE_BODY` bleibt von `verified_variables` ausgeschlossen. Aktiv
`response_body_pass.yaml` beweist weiterhin nur Pass-Through-Verhalten mit
Zugriff auf den Antworttext aktiviert; Es ist kein Nachweis für die Blockierung des Antwortkörpers.

## Nächste Schritte

- Untersuchen Sie, warum Apache die `RESPONSE_BODY`-Regel der Phase 4 nicht auf die anwendet
  statische Befestigung in diesem minimalistischen Gurtzeug.
- Untersuchen Sie den NGINX-Filterpfad, der mit `RESPONSE_BODY` übereinstimmt, aber einen erzeugt
  leere Client-Antwort anstelle von HTTP 403.
- Probieren Sie einen Connector-spezifischen Antwort-Fixture-Pfad erst aus, nachdem Sie dokumentiert haben, warum
  Der aktuelle statische Vorrichtungspfad ist unzureichend.
