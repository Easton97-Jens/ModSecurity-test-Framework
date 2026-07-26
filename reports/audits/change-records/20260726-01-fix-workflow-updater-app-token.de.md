# Änderungsnachweis: App-Token-Publisher des Workflow-Updaters reparieren

**Sprache:** [English](20260726-01-fix-workflow-updater-app-token.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260726-01-fix-workflow-updater-app-token |
| UTC-Datum | 2026-07-26 |
| Framework-Basisrevision | 7e9a560f3acda65510c93f649b6ed4977e4cd6cb |
| Issue oder Pull Request | Task-Branch `agent/update-workflow-publisher-app-token`; Draft-PR beim Schreiben dieses Records ausstehend. Kein Merge oder Auto-Merge ist autorisiert. |

## Motivation und Problemstellung

Der geplante Framework-Workflow-Tool-Publisher validierte einen unveränderlichen Maintenance-Kandidaten mit fünf Dateien, konnte ihn aber nicht pushen, weil sein eingebautes `github.token` nicht die GitHub-App-`Workflows: write`-Autorität zum Ändern von `.github/workflows/*` hatte. Der Fehler trat nach Kandidatenvalidierung und Runner-lokalem Commit auf; eine normale Workflow-`permissions:`-Map kann die App-Level-Autorität nicht gewähren.

## Betroffene Komponenten und Sicherheitsgrenzen

- `.github/workflows/update-workflow-tools.yml` ist der einzige Schreiber. Resolver und Validator bleiben tokenfrei/read-only; nur der vertrauenswürdige, auf den Default-Branch begrenzte Publisher erhält das kurzlebige Publishing-Token.
- Das eingebaute `GITHUB_TOKEN` des Publishers wird auf `contents: read` reduziert. Die gepinnte GitHub-App-Token-Action erhält eine Repository-Variable und ein Secret, begrenzt ihr Token auf das aktuelle Repository und fordert nur `Contents`-, `Pull requests`- und `Workflows`-Write-Recht an.
- CI-Sicherheitsvertrag, fokussierte Tests, unveränderlicher Action-Lock und gepaarte Workflow-Sicherheitsdokumentation binden diese Credential-Grenze.
- Parent-Dateien, Parent-Framework-Gitlink, MRTS-Quellcode und Framework-MRTS-Gitlink liegen außerhalb dieser Framework-only-Änderung.

## Akzeptanzkriterien

- Kein `github.token`-Publishing-Fallback bleibt; nur die vier überprüften API-/Git-Consumer erhalten `publisher_app_token.outputs.token`.
- Resolver und Validator bleiben read-only ohne App-Variable oder Private-Key-Referenz.
- Die neue Action ist per vollständigem SHA gepinnt, im Lock erfasst und auf Englisch sowie Deutsch dokumentiert.
- Das Publisher-Profil weist geänderte App-Berechtigung, Repository-Begrenzung und alte Publishing-Token-Routen zurück, während der reale Workflow die nativen Verträge besteht.
- Der Source-Patch geht über einen normalen Framework-Draft-PR; der Hosted-End-to-End-Run bleibt bis zur separat autorisierten App-, Variable- und Secret-Konfiguration ausstehend.

## Untersuchte Alternativen

- `workflows: write` in der nativen Workflow-`permissions:`-Map wurde verworfen: Es kann die Repository-Berechtigung der Plattform-App nicht gewähren und wäre eine ungültige Kontrollbehauptung.
- Ein breites Personal-Access-Token wurde verworfen, weil es eine langlebige Write-Credential in einen Maintenance-Workflow einführen würde.
- Das Überspringen von Workflow-Datei-Updates oder Abschwächen der Updater-Scope-/Validierungsgates wurde verworfen, weil dadurch der Immutable-Pin-Maintenance-Pfad unvollständig bliebe.

## Implementierungsentscheidung

Der Publisher verwendet die unveränderliche Action `actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1` (`v3.2.0`). Sein exaktes Profil fordert `vars.WORKFLOW_UPDATER_APP_CLIENT_ID` und `secrets.WORKFLOW_UPDATER_APP_PRIVATE_KEY`, begrenzt die Anforderung auf das aktuelle Repository und fordert nur die drei erforderlichen Write-Rechte an. Der Action-Output ist die einzige Credential für die beiden überprüften `github-script`-Aufrufe und die beiden `PUBLISH_TOKEN`-Environments; die Standard-Post-Job-Revocation der Action bleibt aktiv.

Der Source kann weder App-Installation noch Repository-Variable oder Private-Key-Secret anlegen. Ein autorisierter Repository-Owner muss die App nur für dieses Framework-Repository installieren und exakt die dokumentierten Berechtigungen erteilen, bevor ein realer Publisher-Run den Remote-Branch-Push-Pfad beweisen kann.

## Geänderte Dateien und Tests

- `.github/workflows/update-workflow-tools.yml` und `ci/checks/security/check-ci-security-contract.py`.
- `tests/ci_security/test_ci_security_contract.py` und `tests/ci_security/test_update_workflow_tools.py` einschließlich negativer Mutationen für alten Token, Berechtigung und Repository-Scope.
- `ci/tooling/security-tools.lock.yml`, beide Sprachvarianten von `docs/github-actions-workflow-security` und dieser gepaarte Change Record.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `make test-ci-security-contract` | 0 | 134 fokussierte CI-Security-Tests bestanden, einschließlich der neuen App-Token-Regressionen. | Lokaler Framework-Task-Worktree. |
| `make test-workflow-action-pins` | 0 | 25 Immutable-Action-Pin-Regressionstests bestanden. | Lokaler Framework-Task-Worktree. |
| `make test-workflow-security-contract` | 0 | 7 Workflow-Trust-Boundary-Regressionstests bestanden. | Lokaler Framework-Task-Worktree. |
| `make check-github-actions-workflows` | 0 | Python-Version-, Immutable-Pin- und Permission-Checks akzeptierten alle 15 Workflows. | Lokaler Framework-Task-Worktree. |
| `make check-documentation` | 0 | Zweisprachige Dokumentations-, Link-, Repository-Pfad- und Change-Record-Verträge bestanden. | Lokaler Framework-Task-Worktree. |
| `make lint` | 0 | Das vollständige Repository-Lint-Ziel bestand, einschließlich Syntax, fokussierter Verträge, Pins, Workflow-Checks, Dokumentation und abschließender Whitespace-Prüfung. | Lokaler Framework-Task-Worktree. |
| `git diff --check` | 0 | Der finale unstaged Source-Diff hatte keine Whitespace-Fehler. | Lokaler Framework-Task-Worktree. |

## Sicherheitsauswirkung

Dies ist eine Remediation der CI-Credential-Grenze. Der Publisher übergibt `github.token` nicht mehr an API- oder Git-Write-Consumer. Das exakte Profil erlaubt den Private Key nur in der gepinnten App-Token-Action des Publishers und ihren Output nur in überprüften Consumern. Negative Mutationen beweisen die Zurückweisung eines alten Tokens, reduzierter Workflow-Autorität oder eines nicht überprüften Repository-Scopes. Der legitime Kontrollfall ist der unveränderte reale Workflow, der dieselben Verträge besteht; der Hosted-Branch-Push-Kontrollfall bleibt wegen externer Konfiguration ausstehend.

## Dokumentation und Runtime-Evidenz

Der englische/deutsche Workflow-Sicherheitsleitfaden dokumentiert die unveränderliche Action, Variable-/Secret-Namen, Reduktion des nativen Tokens, exakte App-Berechtigungen, Scope und No-Fallback-Regel. Es wurden keine Token-Werte, externe Konfiguration oder Connector-/MRTS-Runtime-Evidenz erfasst. Der Receipt des ursprünglichen fehlgeschlagenen Runs bleibt als Evidenz zu `FND-GITHUB-0008` im Parent-Control-Plane erhalten.

## Nicht ausgeführte Prüfungen

- Ein realer `Update pinned workflow tools`-Publisher-Run wurde nicht ausgeführt, weil Repository-App-Installation, `WORKFLOW_UPDATER_APP_CLIENT_ID` und `WORKFLOW_UPDATER_APP_PRIVATE_KEY` fehlen und außerhalb der Benutzerautorisierung liegen.
- Hosted-Actions-Checks, SonarQube Cloud, Review-Threads und Branch-Protection-Auswertung sind Controls des exakten Draft-PR-Heads und werden erst nach dem PR-Push beobachtet.

## Einschränkungen und Restrisiko

Source und lokale Verträge können nicht beweisen, dass die zukünftige GitHub-App nur auf diesem Repository installiert ist oder die angeforderten Berechtigungen tatsächlich gewährt. Bis ein autorisierter Owner sie konfiguriert und ein Workflow-Datei-Kandidat erfolgreich den eingeschränkten Draft-PR erstellt oder aktualisiert, bleibt der automatisierte Workflow-Maintenance-Pfad extern blockiert. Kein direkter `master`-Push, Permission-Bypass, Personal-Token-Fallback, Parent-Aktion oder MRTS-Aktion ist Teil dieser Änderung.

## Finaler Diff- und Review-Status

Der eingegrenzte Source-Diff und Credential-Datenfluss erhielten ein fokussiertes Security-Review; es wurde kein plausibler Source-to-Sink-Defekt gefunden. Der finale Workflow-Scan fand weder eine alte `github.token`-/`GITHUB_TOKEN`-Publishing-Route noch Private-Key-Material; der überprüfte App-Token-Output hat exakt vier Consumer. Dokumentations- und Whitespace-Validierung bestanden. Commit-, Push- und Exact-Draft-PR-Head-Receipt werden erst nach ihren beobachteten Ergebnissen erfasst. Kein Merge ist durch diesen Record autorisiert.
