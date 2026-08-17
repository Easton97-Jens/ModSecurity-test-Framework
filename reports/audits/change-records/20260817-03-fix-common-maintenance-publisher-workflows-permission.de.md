# Change Record: 20260817-03-fix-common-maintenance-publisher-workflows-permission

**Sprache:** [English](20260817-03-fix-common-maintenance-publisher-workflows-permission.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260817-03-fix-common-maintenance-publisher-workflows-permission` |
| UTC-Datum | `2026-08-17` |
| Framework-Basisrevision | `c547c7692f0226e4318b64950af0126e514ba65a` |
| Issue oder Pull Request | Der Resulting-Master-Workflow `32045596674` zeigte den Publisher-Fehler; ein korrigierender Pull Request steht noch aus. |

## Motivation und Problemstellung

Der vertrauenswürdige vollständige Common-Maintenance-Workflow löste einen sicheren Plan korrekt erneut auf und validierte ihn; seine feste erzeugte Allowlist enthält Workflow-Dateien. GitHub wies anschließend den Remote-Write des Publishers ab, weil dessen ansonsten repository-begrenztes App-Token `workflows: write` nicht anforderte. Der Fehler war fail-closed: Es wurde kein unautorisierter Update veröffentlicht, aber ein legitimer validierter Draft-PR-Publish konnte nicht abgeschlossen werden.

## Betroffene Komponenten und Sicherheitsgrenzen

Betroffen ist die Framework-CI-Grenze zwischen App-Token-Mint des Publishers in `check-common-versions.yml` und seinem Remote-Write über die unveränderliche Draft-PR-Action. Der Patch erhält das native read-only-Job-Token, den Selector für das aktuelle Repository, Trusted-Default-Branch-/Candidate-/Digest-Gates, die feste erzeugte Allowlist, Draft-only-Verhalten und die No-Auto-Merge-Regel. Parent-Quellcode und Gitlink sowie der schreibgeschützte Checkout `tools/MRTS` bleiben außerhalb des Umfangs.

## Akzeptanzkriterien

1. Nur der bestehende repository-begrenzte Common-Maintenance-Publisher fordert `contents`-, `pull-requests`- und `workflows`-Write-Recht an.
2. Der CI-Sicherheitsvertrag weist eine fehlende Workflow-Berechtigung und eine zusätzliche nicht verwandte Berechtigung zurück.
3. Das getrennte Issue-Reconciler-Token bleibt issue-only und alle bestehenden Pfad- und Veröffentlichungs-Kontrollen bleiben exakt erhalten.
4. Der vollständige Resulting-Master-Workflow kann den legitimen Publisher-Pfad abschließen, sofern die installierte App dieselbe Repository-Berechtigung `Workflows: read/write` besitzt.
5. Der korrigierende PR darf erst nach aktuellen GitHub-Checks und SonarQube Cloud mit null neuen Issues und null New-Code-Duplizierung gemergt werden.

## Untersuchte Alternativen

- Das Ersetzen des App-Tokens durch `GITHUB_TOKEN`, ein PAT oder SSH-Credentials wurde verworfen, weil es die Publisher-Trust-Grenze erweitert oder verändert.
- Eine Erweiterung des Repository-Selectors, der Pfad-Allowlist oder des App-Token-Profils über die exakt benötigte Workflow-Berechtigung hinaus wurde als unnötiges Privileg verworfen.
- Das Entfernen der Workflow-Pfade aus dem erlaubten Maintenance-Output wurde verworfen, weil kanonische CI-Pins Teil des gemeinsamen Maintenance-Plans bleiben müssen.
- GitHub-App-Installations-Einstellungen gehören nicht zu diesem Repository-Patch; fehlt der bestehenden Installation die angeforderte Berechtigung, bleibt die Hosted-Validierung ein externer Blocker.

## Implementierungsentscheidung

Das bestehende Publisher-Token fordert nun neben seinen zwei vorhandenen Write-Fähigkeiten die einzelne fehlende Fähigkeit `workflows: write` an. Der Sicherheitsvertrag pinnt das vollständige Profil, und fokussierte Tests beweisen, dass sowohl ein Entfernen der Berechtigung als auch eine nicht verwandte zusätzliche Berechtigung fehlschlagen. Der gepaarte Sicherheitsleitfaden stimmt jetzt mit der tatsächlichen festen erzeugten Allowlist überein und erklärt, warum dieser Publisher Workflow-Autorität benötigt.

## Geänderte Dateien und Tests

Der vorgesehene Umfang umfasst `check-common-versions.yml`, den CI-Sicherheitsvertrag, fokussierte Common-Maintenance- und Contract-Tests, den englischen/deutschen Workflow-Sicherheitsleitfaden und dieses gepaarte Change Record. Die neue positive Kontrolle prüft das exakte Publisher-Profil und die Trennung des Issue-Tokens; negative Kontrollen entfernen Workflow-Autorität oder fügen `actions: write` hinzu und müssen vom Vertrag zurückgewiesen werden.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk proxy gh run view 32045596674 --json ...` | `0` | Erfolgreiche Resolver-/Candidate-/Reconciler-Jobs und ein fehlgeschlagener Publisher-Write aufgrund fehlender Workflow-Berechtigung beobachtet. | GitHub-Actions-Run `32045596674` |
| Fokussierter Pre-Fix-Unittest für Publisher-Profil | `1` | Erwarteter Regressionstest-Fehler: Dem Publisher-Profil fehlte `permission-workflows: write`. | Framework-Task-Worktree |
| Fokussierte Unified-Maintenance-, CI-Sicherheitsvertrags- und Change-Record-Unittests | `0` | 52 Tests bestanden, einschließlich des exakten positiven Publisher-Profils und beider negativer Berechtigungs-Mutationen. | Framework-Task-Worktree |
| `ci/checks/security/check-ci-security-contract.py` | `0` | Der aktive CI-Sicherheitsvertrag akzeptierte das geprüfte Workflow-Profil. | Framework-Task-Worktree |
| `safe-make.sh check-github-actions-workflows` und `check-workflow-action-pins.py` | `0` | Alle Workflow-Pins und Berechtigungsprofile bestanden. | Framework-Task-Worktree |
| `safe-make.sh lint` | `0` | Die vollständige projektinterne Lint-Suite einschließlich Security-, Provenienz-, Runtime-, Workflow-, Dokumentations- und Whitespace-Prüfungen bestand. | Framework-Task-Worktree |

## Sicherheitsauswirkung

Dies ist eine fail-closed-Korrektur für Least-Privilege-Verfügbarkeit, kein Authorization-Bypass. Der ursprüngliche Pfad ist als exakte Profilregression kodiert; alternative Profile mit fehlender erforderlicher Berechtigung oder zusätzlicher `actions`-Berechtigung werden abgewiesen. Der Patch fügt keinen nativen Token-Fallback, keinen breiteren Repository-Scope, keine Pfaderweiterung, keinen Force-Push und keine Auto-Merge-Autorität hinzu.

## Dokumentation und Runtime-Evidenz

Die gepaarten englischen/deutschen Workflow-Sicherheitsleitfäden beschreiben nun dieselbe exakte Publisher-Berechtigung und die erzeugte Allowlist-Grenze einschließlich des aktuellen Draft-PR-Titels und Markers. Workflow `32045596674` ist nur Fehler-Evidenz; ein erfolgreicher Hosted-Publisher, Pull Request, SonarQube-Cloud-Ergebnis oder Merge wird noch nicht behauptet.

## Nicht ausgeführte Prüfungen

- Hosted-PR-Checks, SonarQube-Cloud-Analyse und Resulting-Master-Validierung stehen bis zum Kandidaten-Pull-Request aus.
- Es wurde keine GitHub-App-Konfigurationsänderung versucht; der installierte App-Grant wird durch den frischen Hosted-Run bewiesen oder blockiert.

## Einschränkungen und Restrisiko

Die Quellkorrektur kann keine Installationsberechtigung vergeben, die die GitHub App nicht bereits hat. Wenn das App-Token nicht mit `workflows: write` gemintet werden kann, bleibt der Workflow sicher blockiert und benötigt einen autorisierten externen App-Installations-Update statt eines Credential-Fallbacks.

## Finaler Diff- und Review-Status

Die Pre-Fix-Regression, der finale Scoped-Source-Review, der fokussierte Security-Review, der Whitespace-Check und die vollständige lokale Qualitäts-Suite sind als bestanden festgehalten. Pull-Request-, SonarQube-Cloud- und Resulting-Master-Review stehen noch aus; dieses Protokoll behauptet keinen Commit, Pull Request, Hosted-Erfolg oder Merge.
