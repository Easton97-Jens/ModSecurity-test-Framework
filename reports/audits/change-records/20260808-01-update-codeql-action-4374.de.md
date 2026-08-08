# Change Record

**Sprache:** [English](20260808-01-update-codeql-action-4374.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260808-01-update-codeql-action-4374 |
| UTC-Datum | 2026-08-08 |
| Framework-Basisrevision | `8362b569406cabc5237a41e4e46f0505fb04c51f` |
| Issue oder Pull Request | Ersatz für Dependabot-PRs #61 und #62; Ersatz-Pull-Request wird nach lokaler Validierung erstellt |

## Motivation und Problemstellung

Die ausgewählten Dependabot-PRs aktualisierten CodeQL-`init` und `analyze`
getrennt, ließen aber kanonischen Action-Lock, Provenienzleitfaden und
Change-Traceability-Evidenz zu v4.37.4 inkonsistent. Der Sicherheitsvertrag
lehnt diesen geteilten Zustand ab; der Framework-eigene Ersatz hält sie daher
konsistent.

## Betroffene Komponenten und Sicherheitsgrenzen

Betroffen sind die zwei CodeQL-Workflows, Action-Lock und englischer/deutscher
Leitfaden zur Immutable Provenance. PR-`contents: read`, nicht persistierte
Checkout-Credentials, keine Submodule und die bestehende nur für vertrauens-
würdigen Master geltende Berechtigung `security-events: write` bleiben erhalten.
Connector- und MRTS-Verhalten sind nicht betroffen.

## Akzeptanzkriterien

- Alle vier CodeQL-Action-Uses, Lock und beide Provenienztabellen benennen
  v4.37.4-Commit `f205ea1c3313d32999d8d6a48b4f6530d4437b38`.
- Workflow-Sicherheits-, Pin-, Dokumentations- und Change-Record-Checks
  bestehen ohne Änderung von Berechtigungen, Triggern, Checkout-Verhalten oder
  MRTS.
- Der Ersatz-Pull-Request wird vor dem Merge an seinem exakten Head geprüft.

## Untersuchte Alternativen

Die beiden Bot-PRs separat zu mergen wird verworfen, weil beide aktuellen
Heads verpflichtende Checks nicht bestehen. Einen Check zu lockern wird
verworfen, weil dies CI-Supply-Chain-Kontrollen schwächt. Gewählt wird ein
konsistentes kombiniertes Update.

## Implementierungsentscheidung

`init` und `analyze` in beiden CodeQL-Workflows werden auf die geprüfte Voll-
SHA und den exakten v4.37.4-Kommentar aktualisiert. Kanonischer Lock und
gepaarter Leitfaden ändern sich atomar mit. Actions, Berechtigungen, Trigger
und MRTS werden nicht geändert.

## Geänderte Dateien und Tests

- Zwei CodeQL-Workflows, `ci/tooling/security-tools.lock.yml`, gepaarte
  Workflow-Provenienz-Dokumentation und dieses gepaarte Change-Record-Paar.
- Keine Framework-Runner-, Connector- oder MRTS-Source-/Teständerung.
- Fokussierte Workflow-Contract-, Pin-, Dokumentations-, Record-, Diff- und
  Hosted-PR-Checks werden nach ihrer Ausführung erfasst.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `git diff --check origin/master...origin/pr-61` | 0 | Ausgewähltes `init`-Update ohne Whitespace-Fehler. | Isolierter Task-Klon |
| `git diff --check origin/master...origin/pr-62` | 0 | Ausgewähltes `analyze`-Update ohne Whitespace-Fehler. | Isolierter Task-Klon |
| `finalize_scan_contract.py` für #61 | 0 | Fokussierter CI-Workflow-Review ohne reportable Regression. | Task-eigener externer Scan-Report |
| `check-workflow-action-pins.py` | 0 | Alle externen Workflow-Actions sind an vollständige Git-SHAs gebunden. | Isolierter Task-Klon |
| `check-github-actions-workflows.py --check all` | 0 | Alle 16 Workflow-Dateien bestehen den Workflow-Check. | Isolierter Task-Klon |
| `make test-ci-security-contract` | 0 | 137 CI-Sicherheitsvertrags-Tests bestanden. | Isolierter Task-Klon |
| `make check-documentation` | 0 | Link-, Variablen-, Pfad- und Change-Record-Checks bestanden. | Isolierter Task-Klon |
| `git diff --cached --check` | 0 | Der finale gestagte Ersatz-Diff hat keinen Whitespace-Fehler. | Isolierter Task-Klon |
| Hosted Validierung des Ersatz-PRs | not_run | Benötigt den veröffentlichten exakten Task-Branch-Head. | GitHub Actions |

## Sicherheitsauswirkung

Dies ist CI-Supply-Chain-Provenienzpflege, keine Vulnerability-Behebung.
Voll-SHA-Pins, Least Privilege, Credential-Schutz für untrusted PRs und
No-Submodule-Verhalten bleiben erhalten. Ein fokussierter Review von #61 fand
keinen reportable neuen Befund; das passende `analyze`-Update wird vor dem
Merge am kombinierten Diff erneut geprüft.

## Dokumentation und Runtime-Evidenz

Die englischen und deutschen Workflow-Sicherheitsleitfäden stimmen nun mit
Workflow- und Lock-Identität überein. Für ein GitHub-Actions-Pin-Update gibt
es keine Connector-Runtime- oder Lifecycle-Evidenz.

## Nicht ausgeführte Prüfungen

- Connector- und MRTS-Runtime-Matrizen sind nicht anwendbar: Es ändern sich
  weder Runner-, Connector- noch MRTS-Verhalten.
- Hosted Checks des Ersatz-PRs sind bis zur Veröffentlichung seines exakten
  Task-Branches nicht gelaufen.

## Einschränkungen und Restrisiko

Die Release-zu-Commit-Identität stammt aus den Metadaten der ausgewählten
Dependabot-PRs und wird über den Immutable-Pin-Vertrag des Repositories
festgehalten. Hosted GitHub-Actions-Ergebnisse bleiben vor der Integration
separat erforderlich.

## Finaler Diff- und Review-Status

Die fokussierte lokale Validierung bestand; finaler begrenzter Review, Commit
und Exact-Head-PR-Verifikation stehen noch aus. Keine Secrets, Tokens, rohen
Payloads, Parent-Dateien oder MRTS-Änderungen sind enthalten.
