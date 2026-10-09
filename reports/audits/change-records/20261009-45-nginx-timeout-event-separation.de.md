# Change Record

**Sprache:** [English](20261009-45-nginx-timeout-event-separation.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261009-45-nginx-timeout-event-separation |
| UTC-Datum | 2026-10-09 |
| Framework-Basisrevision | 567d36acc010a68882462b5ffe23b9e94bff5d73 |
| Issue oder Pull Request | Draft-Framework-PR #137 Follow-up |

## Motivation und Problemstellung

Die echten R11-Soft-Budget-Invocations für Phase 1 und Phase 4 erzeugten
gemessene Engine-Rückkehr-Telemetrie, bevor der Aufrufer seine terminale
Host-Aktion festlegte. Das Framework verlangte fälschlich bereits in dieser
frühen Telemetrie die späteren terminalen Commitment-, Status- und
Verbindungsabbruchfelder. Beide Invocations scheiterten deshalb an der
Validierung, obwohl ihre unterschiedlichen echten Events erhalten waren.

## Betroffene Komponenten und Sicherheitsgrenzen

Der wiederverwendbare NGINX-Lifecycle-Sequenzvalidator und seine
Engine-Budget-Tests. Die Required-Selection bleibt 97. Source-Authority,
Receipts, Event-Identität, monotone Zeitmessung, Wire-Evidence,
Root/nobody-Rollen und Cleanup bleiben erforderlich. Parent-Produktcode und
MRTS werden durch diese Framework-Änderung nicht verändert.

## Akzeptanzkriterien

Frühe Zeitmessungstelemetrie und spätere terminale Host-Aktion entsprechend
ihren jeweiligen Emissionszeitpunkten prüfen. In beiden Events dieselbe
Phase, Transaktion, URI, technische Timeout-Klassifikation und leere
Rule-Identität verlangen. Fehlende, doppelte, fremde oder widersprüchliche
Events, ungültige Budgetmessungen sowie falsche terminale Stage-,
Commitment-, Status- oder Abbruchfakten ablehnen.

## Untersuchte Alternativen

Das Kopieren terminaler Host-Aktionsfelder in die frühe Messung würde Fakten
erfinden, die bei deren Emission nicht verfügbar waren. Das Entfernen von
Event-Identitäts- oder terminalen Aktionsprüfungen würde Widersprüche
verdecken. Keiner dieser Ansätze wird verwendet.

## Implementierungsentscheidung

Gemeinsame Identitäts- und Klassifikationsprüfungen für beide Events erhalten.
Die Messung gegen ihre initialisierten Transport-Defaults und die tatsächlich
gemessene Engine-Rückkehr prüfen. Das terminale Timeout-Event separat auf
seine erforderliche Stage und finale Host-Aktion prüfen. Phase 1 behält eine
vollständige HTTP-504-Antwort; Phase 4 behält das bereits sichtbare HTTP 200
und den Verbindungsabbruch nach Commit. Die gemessene Engine-Rückkehr bleibt
1 und die abgelehnte Phase bleibt unvollständig.

## Geänderte Dateien und Tests

`tests/runners/nginx_lifecycle_sequence.py`,
`tests/no_crs/test_nginx_engine_budget_sequence.py` und dieses Record-Paar.
Regressions-Fixtures bilden die beobachtete Trennung der beiden Events ab.
Negativkontrollen verändern gemeinsame Identität, frühe Transport-Defaults
und erforderliche terminale Felder unabhängig voneinander in beiden Phasen.

## Befehle und Ergebnisse

Der fokussierte Befehl war:

```text
rtk proxy env PYTHONDONTWRITEBYTECODE=1 "${FRAMEWORK_PYTHON}" -m unittest tests.no_crs.test_nginx_engine_budget_sequence -v
```

Vor der Implementierung endete er mit Exit 1, 6 Tests und 2 Fehlern. Nach der
Implementierung endete er mit Exit 0 und allen 9 bestandenen Tests.

Der benachbarte Vertragsbefehl war:

```text
rtk proxy env PYTHONDONTWRITEBYTECODE=1 "${FRAMEWORK_PYTHON}" -m unittest tests.no_crs.test_nginx_engine_budget_sequence tests.no_crs.test_nginx_native_operation_projection tests.no_crs.test_nginx_native_operation_bundle tests.no_crs.test_nginx_lifecycle_sequence -q
```

Er endete mit Exit 0 und 61 bestandenen Tests in 4,851 Sekunden. `rtk proxy
git diff --check` endete mit Exit 0. `FRAMEWORK_PYTHON` bezeichnet den
geprüften Framework-eigenen Interpreter; hostspezifische Pfade verbleiben im
externen Task-Handoff.

`rtk make check-documentation PYTHON="${FRAMEWORK_PYTHON}"` endete mit
Exit 0: Links, zweisprachige Variablen, Repository-Pfadreferenzen und
Change Records bestanden.

Der vollständige Framework-Lint-Befehl war:

```text
rtk make lint PYTHON="${FRAMEWORK_PYTHON}" FRAMEWORK_ROOT="${FRAMEWORK_WORKTREE}" CONNECTOR_ROOT="${FRAMEWORK_WORKTREE}" OUTPUT_ROOT="${FRAMEWORK_WORKTREE}" BUILD_ROOT="${TASK_ROOT}/build" TMP_ROOT="${TASK_ROOT}/tmp" LOG_ROOT="${TASK_ROOT}/logs" MRTS_BUILD_ROOT="${TASK_ROOT}/mrts" SOURCE_ROOT="${TASK_ROOT}/source" EVIDENCE_ROOT="${TASK_ROOT}/evidence" CI_ROOT="${FRAMEWORK_WORKTREE}/ci"
```

Er endete auf dem zusammengesetzten R11-Follow-up-Worktree mit Exit 0. Der
aufbewahrte Log enthält keine FAIL-, ERROR- oder SKIP-Marker und hat den
SHA-256 `08672fd886ab8aebb02af89b77114a08c344f3e54a9c4b935bf55ba4f755ff17`.
Die finalen Dokumentationsprüfungen umfassten 300 zweisprachige Paare und
915 Dateien. `FRAMEWORK_WORKTREE` bezeichnet den geprüften Framework-Checkout
und `TASK_ROOT` dessen externen Task-Datenroot; die exakten Host-Bindungen
verbleiben im Task-Handoff.

Die Vertragssuite des zusammengesetzten Worktrees verwendete:

```text
rtk make test-no-crs-contract PYTHON="${FRAMEWORK_PYTHON}" FRAMEWORK_ROOT="${FRAMEWORK_WORKTREE}" CONNECTOR_ROOT="${FRAMEWORK_WORKTREE}" OUTPUT_ROOT="${FRAMEWORK_WORKTREE}" BUILD_ROOT="${TASK_ROOT}/build" TMP_ROOT="${TASK_ROOT}/tmp" LOG_ROOT="${TASK_ROOT}/logs" MRTS_BUILD_ROOT="${TASK_ROOT}/mrts" SOURCE_ROOT="${TASK_ROOT}/source" EVIDENCE_ROOT="${TASK_ROOT}/evidence" CI_ROOT="${FRAMEWORK_WORKTREE}/ci"
```

Sie endete mit Exit 0 und 410 bestandenen Tests in 165,181 Sekunden. Der
aufbewahrte Log enthält keine Fail-, Error- oder Skip-Marker und hat den
SHA-256 `076340b756dc78ea0c2b4a88c6174a1227ef2f1b0f409555f0b1a14980787739`.

Eine lesende Helper-Nachprüfung akzeptierte beide unveränderten originalen
R11-Timeout-Beobachtungen. Dies ist eine diagnostische Validierung erhaltener
Evidence, kein neues versiegeltes oder Canonical-Replay: Die originale
Source-Authority bleibt an ihre ursprüngliche Framework-Revision gebunden.

## Sicherheitsauswirkung

Kein Validator oder Authority-Guard wird deaktiviert. Frühe Telemetrie darf
keine spätere terminale Aktion behaupten, und terminale Evidence muss
weiterhin das erforderliche Host-Ergebnis beweisen. Required-Records
benötigen weiterhin echte Runtime-Evidence.

## Dokumentation und Runtime-Evidenz

Dieses englisch/deutsche Change-Record-Paar dokumentiert den Event-Vertrag.
Keine Runtime-Evidence wird synthetisiert oder umetikettiert. Das originale
R11 bleibt terminale FAIL-Evidence; die Akzeptanz durch den geänderten Helper
belegt kein frisches source-gebundenes Lifecycle-Ergebnis.

## Nicht ausgeführte Prüfungen

Frische Runtime, Canonical-Finalisierung, Remote-CI/Sonar und
Parent-Gitlink-Integration stehen aus.

## Einschränkungen und Restrisiko

Unit-Fixtures und lesende Nachprüfungen ersetzen keinen frischen
Root/nobody-Lauf. Der unabhängige Phase-4-Body-Reject-Fehler bleibt außerhalb
dieser Änderung. Die fokussierten Tests belegen keinen Gesamt-E2E-PASS.

## Finaler Diff- und Review-Status

Fokussiertes RED/GREEN, benachbarte Tests, die Vertragssuite mit 410 Tests, vollständiger Framework-Lint,
Dokumentationsprüfungen und Diff-Whitespace-Validierung sind abgeschlossen.
Delivery steht aus.
Keine Secrets, Zugangsdaten, Request-Bodys oder sensiblen Raw-Payloads sind
enthalten. Kein Merge, History-Rewrite oder MRTS-Änderung wird durchgeführt.
