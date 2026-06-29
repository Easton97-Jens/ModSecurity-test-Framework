# PR Zusammenfassung der Nachweise

**Sprache:** [English](pr-evidence-summary.md) | Deutsch

Status: umgesetzt

Dieses Repository bündelt das aktuelle evidence/validation-Framework für zwei
Aktive ModSecurity-Überprüfungsthemen:

- ModSecurity PR #3564: RAW Argumentsammlungen für URL-codierte Parameter.
- ModSecurity-nginx PR #377: Phase-4 / `RESPONSE_BODY` Behandlung.

Der Rahmen ist bewusst evidenzorientiert. Es zeichnet auf, was beobachtet wurde
über echte Verbindungspfade und sorgt dafür, dass nicht unterstütztes oder instabiles Verhalten abgebildet wird
oder nicht hochgestuft, anstatt gefälschte PASS-Ergebnisse zu melden.

## Realer Verbindungspfad

Connector PASS bedeutet, dass die Anfrage diesen vollständigen Pfad durchlaufen hat:

```text
Client -> Apache/NGINX -> connector module -> libmodsecurity -> rule variables -> HTTP response
```

Der Connector-freie API-Smoke unter `src/v3-api-smoke/` ist ein nützlicher API-Nachweis,
es wird jedoch nicht als Apache- oder NGINX Connector-Proof gezählt.

## Evidenzbasierte Variablen

Connector-Zusammenfassungen können diese Variablenfamilien in `verified_variables` auflisten.
Beim Übergeben realer Apache- und NGINX-Fälle werden diese unterstützt:

- `ARGS`
- `ARGS_NAMES`
- `REQUEST_HEADERS`
- `REQUEST_BODY`
- `REQUEST_COOKIES`
- `REQUEST_URI`
- `FILES`
- `XML`
- `AUDIT_LOG`
- `RESPONSE_HEADERS`

`RESPONSE_BODY` ist nicht verifiziert. Der Sperrfall bleibt wegen non-promoted/mapped-only bestehen
Die dedizierte Sonde hat über beide Anschlüsse keine stabilen HTTP 403 erzeugt.
Standardmäßiger Smoke-PASS-Nachweis, Force-All-Laufzeitmatrix-Nachweis, nur zugeordnet
Inventar, frühere Sonden mit erwartetem Ausfall und reine API-Smoke-Nachweise bleiben getrennt.

## PR #3564: RAW Argumentsammlungen

Öffentliche Quelle: https://github.com/owasp-modsecurity/ModSecurity/pull/3564

Der PR führt diese RAW URL-codierten Argumentsammlungen ein:

- `ARGS_RAW`
- `ARGS_GET_RAW`
- `ARGS_POST_RAW`
- `ARGS_NAMES_RAW`
- `ARGS_GET_NAMES_RAW`
- `ARGS_POST_NAMES_RAW`

In der öffentlichen PR-Beschreibung heißt es, dass RAW-Werte vorher erfasst werden
libmodsecurity URL Dekodierung und das bestehende dekodierte `ARGS*` Verhalten bleibt erhalten
unverändert.

Aktuelle lokale Nachweise:

- `<workspace>/ModSecurity_V3` ist immer noch der beobachtete `v3/master` lokal
  Referenz.
- Eine Suche in dieser lokalen Quelle ergab keine RAW-Sammlungsimplementierung oder
  Regressionsdateien.
- `sh ci/check-raw-args-support.sh` führt die gleiche schreibgeschützte Prüfung für durch
  konfiguriert `MODSECURITY_V3_SOURCE_DIR`.
- Daher werden RAW-Sammlungen als `mapped-only` / klassifiziert.
`unsupported-local-source` in diesem Repository.

Der detaillierte RAW-Status wird in `docs/raw-args-pr3564.md` gepflegt.

Promotion-Regel:

1. Eine konfigurierte `MODSECURITY_V3_SOURCE_DIR` muss RAW-Sammlungsunterstützung enthalten.
2. Von der Quelle abgeleitete YAML-Fälle können dann für jede RAW-Sammlung hinzugefügt werden.
3. Fälle zählen erst dann als aktive PASS, wenn Apache und NGINX beide das zurückgeben
   erwartetes echtes HTTP-Verhalten durch `make smoke-all`.

## PR #377: RESPONSE_BODY / Phase 4

Öffentliche Quelle: https://github.com/owasp-modsecurity/ModSecurity-nginx/pull/377

Die PR dokumentieren konfigurierbare Phase-4-Handhabungsmodi, Spätintervention
Einschränkungen nach der Antwort headers/body können bereits gesendet und strukturiert sein
Phase-4-Protokollierung. Dies entspricht der aktuellen Entscheidung des Rahmenwerks, a nicht zu behandeln
Phase-4-Regelübereinstimmung als Connector PASS, es sei denn, der Client beachtet das Erwartete
HTTP Ergebnis.

Aktuelle lokale Nachweise:

- `tests/cases/response/body/response_body_basic_block.yaml` ist explizit
  abgeleitete, nicht hochgestufte Sonde.
- `make probe-response-body` führt den nicht hochgestuften Fall über Apache und NGINX aus.
- Die letzte dokumentierte Untersuchung behielt den Fall non-promoted/mapped-only:
  - Apache hat HTTP 200 ohne den erforderlichen Prüfnachweis zurückgegeben.
  - NGINX zeigte Phase-4-Übereinstimmungsnachweise, gab jedoch keine stabilen HTTP 403 zurück
    der Kunde.

`RESPONSE_BODY` muss aus `verified_variables` herausbleiben, bis beide Anschlüsse vorhanden sind
Erzeuge stabile HTTP 403 für einen aktiven gemeinsamen Fall.

## Reproduktion

```sh
BUILD_ROOT=/src/ModSecurity-test-Framework-build make lint
BUILD_ROOT=/src/ModSecurity-test-Framework-build make smoke-all
BUILD_ROOT=/src/ModSecurity-test-Framework-build make probe-response-body || true
```

Die Ergebnisse sind unter:

- `$BUILD_ROOT/logs`
- `$BUILD_ROOT/results`
- `$BUILD_ROOT/apache-runtime`
- `$BUILD_ROOT/nginx-runtime`
- `$BUILD_ROOT/response-body-probe`
