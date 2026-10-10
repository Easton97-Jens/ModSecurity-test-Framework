# Change Record

**Sprache:** [English](20261009-43-nginx-repeatable-set-cookie-wire.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261009-43-nginx-repeatable-set-cookie-wire |
| UTC-Datum | 2026-10-09 |
| Framework-Basisrevision | 567d36acc010a68882462b5ffe23b9e94bff5d73 |
| Issue oder Pull Request | Draft-Framework-PR #137 Follow-up |

## Motivation und Problemstellung

Vier echte NGINX-MIME-Invocations bewahrten zwei getrennte `Set-Cookie`-
Wire-Felder aus der vorhandenen gemeinsamen Response-Header-Fixture auf.
Content-Type und HTTP/1.1-Framing waren eindeutig und korrekt, aber der
Framework-MIME-Parser lehnte jeden wiederholten Feldnamen ab, bevor er den
MIME-Vertrag prüfen konnte.

## Betroffene Komponenten und Sicherheitsgrenzen

Der wiederverwendbare NGINX-MIME-Wire-Parser und seine MIME-/Event-Boundary-
Consumer. Raw-Bytes, Digests, Source-Authority, Receipts, Rollen, Cleanup,
Content-Type- und Framing-Prüfungen bleiben unverändert.

## Akzeptanzkriterien

Wiederholte `Set-Cookie`-Felder akzeptieren, ohne sie zu einem Feld
zusammenzuführen. Doppelte Content-Type-, Content-Length- und
Transfer-Encoding-Felder, gemischtes Content-Length-/Transfer-Encoding-
Framing, ungültige Syntax, unvollständige Antworten und Body-Längenfehler
weiterhin ablehnen.

## Untersuchte Alternativen

Das Entfernen der wiederholten Cookies aus der Parent-Fixture wurde verworfen,
weil sie ein absichtlicher gemeinsamer Multi-Value-Response-Header-Vertrag
sind. Die Freigabe aller doppelten Header wurde verworfen, weil sie Singleton-
MIME- und Framing-Evidence mehrdeutig machen würde.

## Implementierungsentscheidung

Nur `Set-Cookie` wird in `wire_fields` ohne Beachtung der Schreibweise als
wiederholbar deklariert. Der Parser prüft weiterhin jede physische Feldzeile
und verbindet Cookie-Werte nie mit Kommas. Das authentifizierte Raw-Artefakt
bleibt die exakte Quelle aller Feldinstanzen; der zurückgegebene Lookup wird
nur für strikte MIME-/Framing-Felder verwendet.

## Geänderte Dateien und Tests

`tests/runners/nginx_mime_operations.py`,
`tests/no_crs/test_nginx_mime_operations.py`,
`tests/no_crs/test_nginx_event_boundaries.py` und dieses Record-Paar. Die
Positivkontrollen verwenden die beiden in der Runtime beobachteten Werte.
Negativkontrollen erhalten die Ablehnung doppelter Singleton-Felder und
mehrdeutigen Framings.

## Befehle und Ergebnisse

Der fokussierte Befehl war:

```text
rtk proxy env PYTHONDONTWRITEBYTECODE=1 "${FRAMEWORK_PYTHON}" -B -m unittest tests.no_crs.test_nginx_mime_operations tests.no_crs.test_nginx_event_boundaries -v
```

Vor der Implementierung endete er mit Exit 1, 12 bestandenen Tests und 2
Fehlern bei `invalid or duplicate wire header`; danach endete er mit Exit 0
und allen 14 bestandenen Tests. Die Ergänzung von
`tests.no_crs.test_nginx_http11_framing` und
`tests.no_crs.test_nginx_native_operation_bundle` im selben Befehl endete mit
Exit 0 und 43 bestandenen Tests.

Der folgende lesende Diagnosebefehl spielte den aktuellen Helper gegen die
vier unveränderten originalen Receipts/Raw-Artefakte der sicheren Run-ID
`nginx_all_required_20261009_r11`; er endete mit Exit 0, 4 akzeptierten und 0
abgelehnten Fällen:

```text
rtk proxy env PYTHONDONTWRITEBYTECODE=1 "${FRAMEWORK_PYTHON}" -B <external-task-analysis-root>/replay-r11-mime-current-helper.py
```

Der payload-freie Diagnose-Log hat den SHA-256
`567fa0ffeed676b16a545086185d5d0569cec44163a5560785ff32f3009e236e`.
Dies war kein neues versiegeltes oder Canonical-Replay, weil die originale
Source-Map korrekt an die ursprüngliche Framework-Revision gebunden bleibt.

`FRAMEWORK_PYTHON` bezeichnet den geprüften Framework-eigenen Interpreter;
sein exakter Hostpfad und das Diagnoseskript verbleiben im externen
Task-Handoff statt in versionierter Repository-Dokumentation.

`rtk make test-no-crs-contract` mit dem Framework-Interpreter und allen
Framework-/Build-/Tmp-/Output-Roots, die ausdrücklich an diesen Worktree und
`<external-task-root>/r11-mime-fix` gebunden waren,
endete mit Exit 0: 407 Tests bestanden in 161,838 Sekunden. `rtk make
check-documentation` mit denselben Roots endete mit Exit 0.

Nach Zusammenführung aller drei unabhängigen R11-Framework-Follow-ups endete
dasselbe Ziel `test-no-crs-contract` mit Exit 0: 410 Tests bestanden in
165,181 Sekunden ohne Failure-, Error- oder Skip-Marker. Der Log-SHA-256 ist
`076340b756dc78ea0c2b4a88c6174a1227ef2f1b0f409555f0b1a14980787739`.

Der vollständige Framework-Lint endete auf dem zusammengesetzten aktuellen
R11-Follow-up-Tree mit Exit 0; `PYTHON`, `FRAMEWORK_ROOT`, `CONNECTOR_ROOT`,
`OUTPUT_ROOT`, `CI_ROOT` und alle Task-Daten-Roots waren ausdrücklich an den
geprüften Worktree oder das externe Validierungs-Root gebunden. Der Log-SHA-256
ist `08672fd886ab8aebb02af89b77114a08c344f3e54a9c4b935bf55ba4f755ff17`;
es gab keinen Failure-, Error- oder Skip-Marker. Zwei frühere Aufrufe endeten
mit Exit 2 wegen eines schreibgeschützten Sandbox-Output-Roots beziehungsweise
eines nicht unterstützten externen Output-Roots; sie bleiben als
Aufrufdiagnose erhalten und sind keine Source-Testfehler.

## Sicherheitsauswirkung

Kein Validator oder Authority-Guard wird deaktiviert. Die Ausnahme bleibt auf
das HTTP-Feld begrenzt, dessen getrennte Wire-Instanzen für Cookie-Semantik
erforderlich sind; sicherheitsrelevante MIME- und Framing-Felder bleiben
eindeutig und scheitern geschlossen.

## Dokumentation und Runtime-Evidenz

Dieses englisch/deutsche Change-Record-Paar dokumentiert den Framework-Vertrag.
Der originale R11-Parent-Lifecycle bleibt terminale FAIL-Evidence und wird
nicht als Post-Fix-Runtime-Nachweis umetikettiert.

## Nicht ausgeführte Prüfungen

Remote-CI/Sonar, Parent-Gitlink-Integration, ein frischer Build und der
Required97-Lifecycle liefen noch nicht.

## Einschränkungen und Restrisiko

Synthetische Tests und lesendes Replay aufbewahrter Bytes ersetzen keine
frische source-gebundene Root/nobody-Runtime. R11 legte außerdem getrennte
Phase-4-Reject- und Engine-Timeout-Vertragsfehler offen, die diese Änderung
absichtlich nicht behebt.

## Finaler Diff- und Review-Status

Fokussiertes RED/GREEN, die ursprüngliche 407-Test- und die kombinierte
410-Test-Suite, Dokumentationsprüfungen, unabhängige Code-/Security-Prüfung
sowie breiter Lint sind ohne Findings abgeschlossen. Keine Secrets,
Zugangsdaten, Request-Bodys oder sensiblen
Raw-Payloads wurden in diesen Record aufgenommen. Commit/Push/Readback und
Parent-Integration stehen aus. Kein Merge, History-Rewrite oder MRTS-Änderung.
