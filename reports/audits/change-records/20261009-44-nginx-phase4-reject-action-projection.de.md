# Change Record

**Sprache:** [English](20261009-44-nginx-phase4-reject-action-projection.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261009-44-nginx-phase4-reject-action-projection |
| UTC-Datum | 2026-10-09 |
| Framework-Basisrevision | 567d36acc010a68882462b5ffe23b9e94bff5d73 |
| Issue oder Pull Request | Draft-Framework-PR #137 Follow-up |

## Motivation und Problemstellung

Der Validator für `phase4_body_reject` erwartete auch nach Response-Commit
das serialisierte `action=deny`. Das Common-Event-Protokoll projiziert die
tatsächliche Host-Aktion nach `action`: Eine Ablehnung nach Commit erhält
`requested_action=deny`, serialisiert aber `action` und `actual_action` als
`abort_connection`. Vor Commit bleiben beide Aktionsfelder `deny`.

## Betroffene Komponenten und Sicherheitsgrenzen

Diese Änderung betrifft den Framework-Validator für Phase-4 Reject und seine
synthetischen Vertragstests. Parent/Common-Event-Serialisierung,
Runtime-Verhalten, Receipt-Authority, Source-Provenance, Wire-Prüfung und
Cleanup bleiben unverändert.

## Akzeptanzkriterien

Die exakte Common-Aktionsprojektion für Ablehnungen nach und vor Commit
verlangen. Abweichende angeforderte Aktion, tatsächliche Aktion und
Transport-Ergebnisse weiterhin ablehnen. Eine Ablehnung nach Commit muss
weiterhin sichtbare Response-Header und unvollständiges Framing nachweisen;
HTTP 0 mit curl Exit 52 bleibt abgelehnt.

## Untersuchte Alternativen

Eine Änderung der Common-Serialisierung würde den etablierten Vertrag des
Producers für die tatsächliche Host-Aktion verändern. Beide Aktionen nach
Commit zu akzeptieren würde ein inkonsistentes Event verdecken. Leere
Wire-Evidence zu akzeptieren würde internen NGINX-Commit mit einer für den
Client sichtbaren Antwort gleichsetzen.

## Implementierungsentscheidung

Bei `response_committed=true` wird `action=abort_connection` geprüft,
ansonsten `action=deny`, passend zur bestehenden `actual_action`-Anforderung.
`requested_action=deny` bleibt in beiden Fällen erforderlich. Keine HTTP-,
Framing-, Identitäts- oder Cleanup-Erwartung wird gelockert.

## Geänderte Dateien und Tests

`tests/runners/nginx_phase4_operations.py`,
`tests/runners/test_nginx_phase4_operations.py` und dieses englisch/deutsche
Record-Paar. Die Fixture bildet jetzt die Common-Projektion ab.
Negativkontrollen lehnen Aktions-/Transport-Abweichungen und die in R11
beobachtete echte Empty-Reply-Form ab.

## Befehle und Ergebnisse

Die Befehle liefen im Framework-Worktree mit dem Framework-eigenen Interpreter.
Die folgenden Befehle ersetzen für Portabilität nur dessen lokalen
Executable-Pfad durch `"${FRAMEWORK_PYTHON}"`; Argumente, Wrapper und Ergebnisse
bleiben unverändert. Die exakten lokalen Invocations bleiben in der
Task-Evidence erhalten. Der fokussierte RED/GREEN-Befehl war:

```text
rtk proxy env PYTHONDONTWRITEBYTECODE=1 "${FRAMEWORK_PYTHON}" -m unittest discover -s tests/runners -p test_nginx_phase4_operations.py -v
```

RED endete mit Exit 1: 10 Tests liefen mit 2 fehlschlagenden Subtests.
GREEN endete mit Exit 0: Alle 10 Tests bestanden. Der benachbarte
Phase-4-Befehl endete mit Exit 0 und 19 bestandenen Tests:

```text
rtk proxy env PYTHONDONTWRITEBYTECODE=1 "${FRAMEWORK_PYTHON}" -m unittest discover -s tests/runners -p 'test_nginx_phase4*.py' -v
```

Die Prüfung des Implementierungs-Diffs endete mit Exit 0:

```text
rtk git diff --check -- tests/runners/nginx_phase4_operations.py tests/runners/test_nginx_phase4_operations.py
```

Die Dokumentationsprüfungen bestanden mit Exit 0:

```text
rtk make check-doc-links check-bilingual-docs check-change-records PYTHON="${FRAMEWORK_PYTHON}"
rtk make check-documentation PYTHON="${FRAMEWORK_PYTHON}" FRAMEWORK_ROOT="${FRAMEWORK_ROOT}" CONNECTOR_ROOT="${FRAMEWORK_ROOT}" OUTPUT_ROOT="${FRAMEWORK_ROOT}" BUILD_ROOT="${VALIDATION_ROOT}/build" TMP_ROOT="${VALIDATION_ROOT}/tmp" LOG_ROOT="${VALIDATION_ROOT}/logs" MRTS_BUILD_ROOT="${VALIDATION_ROOT}/mrts" SOURCE_ROOT="${VALIDATION_ROOT}/source" EVIDENCE_ROOT="${VALIDATION_ROOT}/evidence" CI_ROOT="${FRAMEWORK_ROOT}/ci"
```

`FRAMEWORK_ROOT` bezeichnet den aktiven Framework-Worktree; `VALIDATION_ROOT`
bezeichnet dessen externen Task-Validierungsroot. Ein früherer
Dokumentationsversuch endete mit Exit 2, weil absolute Developer-Pfade in den
Records standen. Nur diese lokalen Pfade durch die erklärte portable
Notation zu ersetzen behob den Dokumentationsfehler ohne Checker-Änderung.

Der vollständige Framework-Lint auf dem zusammengesetzten aktuellen
R11-Follow-up-Worktree endete mit Exit 0:

```text
rtk make lint PYTHON="${FRAMEWORK_PYTHON}" FRAMEWORK_ROOT="${FRAMEWORK_ROOT}" CONNECTOR_ROOT="${FRAMEWORK_ROOT}" OUTPUT_ROOT="${FRAMEWORK_ROOT}" BUILD_ROOT="${VALIDATION_ROOT}/build" TMP_ROOT="${VALIDATION_ROOT}/tmp" LOG_ROOT="${VALIDATION_ROOT}/logs" MRTS_BUILD_ROOT="${VALIDATION_ROOT}/mrts" SOURCE_ROOT="${VALIDATION_ROOT}/source" EVIDENCE_ROOT="${VALIDATION_ROOT}/evidence" CI_ROOT="${FRAMEWORK_ROOT}/ci"
```

Sein Log hat den SHA-256
`08672fd886ab8aebb02af89b77114a08c344f3e54a9c4b935bf55ba4f755ff17`.
Es gab keine FAIL-, ERROR- oder SKIP-Marker. Seine abschließende
Dokumentationsprüfung validierte 300 zweisprachige Paare und 915 Dateien.
Dies validiert den zusammengesetzten Framework-Worktree und ist keine
Runtime-Evidence für diesen Fall.

Die zusammengesetzte aktuelle Framework-Vertragssuite endete ebenfalls mit
Exit 0:

```text
rtk make test-no-crs-contract PYTHON="${FRAMEWORK_PYTHON}" FRAMEWORK_ROOT="${FRAMEWORK_ROOT}" CONNECTOR_ROOT="${FRAMEWORK_ROOT}" OUTPUT_ROOT="${FRAMEWORK_ROOT}" BUILD_ROOT="${VALIDATION_ROOT}/build" TMP_ROOT="${VALIDATION_ROOT}/tmp" LOG_ROOT="${VALIDATION_ROOT}/logs" MRTS_BUILD_ROOT="${VALIDATION_ROOT}/mrts" SOURCE_ROOT="${VALIDATION_ROOT}/source" EVIDENCE_ROOT="${VALIDATION_ROOT}/evidence" CI_ROOT="${FRAMEWORK_ROOT}/ci"
```

Sie führte 410 Tests in 165,181 Sekunden ohne FAIL-, ERROR- oder SKIP-Marker
aus. Ihr Log hat den SHA-256
`076340b756dc78ea0c2b4a88c6174a1227ef2f1b0f409555f0b1a14980787739`.
Die separate Runner-Invocation mit 19 Tests oben deckt diesen Phase-4-Helper
direkt ab; die Suite mit 410 Tests liefert das breitere Framework-Vertragsgate.

## Sicherheitsauswirkung

Der Validator folgt jetzt dem bestehenden Producer-Vertrag und verlangt
weiterhin exakte Felder in beiden Commit-Zuständen. Falsche Aktionen,
fehlende Wire-Header, HTTP 0/curl 52 und unvollständige Authority-Evidence
bleiben Fehler. Kein Validator oder Guardrail wird deaktiviert.

## Dokumentation und Runtime-Evidenz

Dieses Paar dokumentiert eine Korrektur der Framework-Validierung. Die Run-ID
`nginx_all_required_20261009_r11` bleibt terminale FAIL-Evidence. Ihre
Phase-4-Reject-Invocation ergab HTTP 0/curl 52: Der separate Wire-Flush-Defekt
im Parent bleibt offen. Die synthetischen GREEN-Ergebnisse belegen weder
Post-Fix-Runtime noch Canonical PASS.

## Nicht ausgeführte Prüfungen

Remote-CI/Sonar, Parent-Gitlink-Integration
und ein frischer Required97-Lifecycle stehen für diese Änderung noch aus.
Im Rahmen dieser Dokumentationsaufgabe erfolgte keine neue source-gebundene
Runtime-Invocation.

## Einschränkungen und Restrisiko

Interner NGINX-Response-Commit beweist nicht, dass Header den Client erreicht
haben. Der Parent muss den Wire-Flush-Defekt beheben und eine echte Antwort
erzeugen, bevor dieser Required-Fall seinen aktuellen Vertrag erfüllt.

## Finaler Diff- und Review-Status

Fokussiertes RED/GREEN, benachbarte Tests und Implementierungs-Diff-Prüfungen
sind abgeschlossen. Die zusammengesetzte Vertragssuite mit 410 Tests,
vollständiger Framework-Lint und Dokumentationsprüfungen
bestanden; das finale Framework-Integrationsreview ist abgeschlossen.
Keine Secrets, Zugangsdaten, Request-/Response-Bodys oder sensiblen Raw-Logs
wurden aufgezeichnet. Commit, Push und Parent-Integration bleiben ausstehende
Delivery-Schritte; MRTS bleibt unverändert.
