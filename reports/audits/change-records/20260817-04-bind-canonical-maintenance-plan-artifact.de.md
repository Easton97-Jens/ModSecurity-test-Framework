# Change Record: 20260817-04-bind-canonical-maintenance-plan-artifact

**Sprache:** [English](20260817-04-bind-canonical-maintenance-plan-artifact.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260817-04-bind-canonical-maintenance-plan-artifact` |
| UTC-Datum | `2026-08-17` |
| Framework-Basisrevision | `dcf0dde410b0afe59fead01ee011c3ec3de1dbdd` |
| Issue oder Pull Request | Der Resulting-Master-Workflow `32010750544` zeigte den Plan-Digest-Fehler; der korrigierende Framework-PR [#97](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/97) wartet auf finale Exact-Head-Verifikation und regulären Merge. |

## Motivation und Problemstellung

Der vereinheitlichte Common-Maintenance-Workflow löste veränderliche Upstream-
Eingaben in Canonical-, Candidate-, Trusted-Reconciliation- und Publisher-Jobs
unabhängig auf. Eine Upstream-Änderung zwischen Jobs konnte deshalb spät im
Lauf einen fail-closed Digest-Mismatch auslösen, obwohl jede einzelne
Auflösung gültig war. Der Workflow benötigt einen auf den Aufrufer gebundenen
Plan für seine gesamte Ausführung statt wiederholter Live-Auflösung.

## Betroffene Komponenten und Sicherheitsgrenzen

Die Framework-eigene Grenze umfasst `check-common-versions.yml`, den
kanonischen Plan-Reader und Reconciler sowie den CI-Sicherheitsvertrag, der
deren Artefaktprofil erzwingt. Der Plan ist ein begrenztes JSON-/Markdown-
Artefakt mit GitHub-Run-ID und Attempt im Namen. Candidate, Trusted-Issue-
Reconciliation und der Draft-PR-Publisher validieren seine SHA-256 vor ihrer
Arbeit. Parent-Quellcode und Gitlink, Connector-Runtime-Verhalten,
GitHub-App-Konfiguration und der schreibgeschützte Checkout `tools/MRTS`
liegen außerhalb des Umfangs.

## Akzeptanzkriterien

1. Canonical Maintenance lädt genau ein an Run und Attempt gebundenes
   Plan-Artefakt mit JSON- und Markdown-Mitglied hoch.
2. Jeder Downstream-Consumer lädt genau dieses Artefakt, validiert den
   kanonischen Digest und löst keine Live-Dependency-Quellen erneut auf.
3. Der Plan-Reader bleibt auf die direkte `RUNNER_TEMP`-Grenze beschränkt;
   Digest-, Schema-, Symlink-, Traversal-, Trusted-Branch- und
   Least-Privilege-Token-Kontrollen bleiben fail-closed.
4. Fokussierte Contract- und Workflow-Regressionen, vollständiges natives
   Lint, Exact-Head-Hosted-Checks und SonarQube Cloud bestehen ohne
   Suppression oder Gate-Abschwächung.
5. Ein vollständiger Resulting-Master-`workflow_dispatch` beweist Canonical-,
   Candidate-, Reconciliation-, Publisher- und Result-Verhalten nach einem
   regulären Merge.

## Untersuchte Alternativen

- Eine erneute Auflösung in jedem Downstream-Job wurde verworfen, weil
  veränderliche Eingaben den früheren auf den Aufrufer gebundenen Digest
  ungültig machen können.
- Das Übergeben des Planinhalts über Job-Outputs wurde verworfen, weil es
  keinen begrenzten Dateitransport für beide Plan-Mitglieder bietet.
- Download in ein verschachteltes temporäres Verzeichnis oder Erweiterung des
  zulässigen Reader-Roots wurde verworfen; direktes `RUNNER_TEMP` erhält die
  feste Reader-Grenze.
- Das Übergeben eines Read-Tokens oder der Komponenten-Eingabe downstream
  wurde verworfen, weil es Live-Resolution-Autorität außerhalb von Canonical
  Maintenance wiederherstellen würde.

## Implementierungsentscheidung

Canonical Maintenance lädt jetzt das validierte JSON- und Markdown-Plan-
Artefakt über checksum-gepinntes `actions/upload-artifact` hoch. Downstream-
Jobs verwenden die passende checksum-gepinnte Download-Action direkt nach
`RUNNER_TEMP`, binden den Plan mit `--expected-plan-sha256` an den Canonical-
Output-Digest und führen keine frische Auflösung durch. Der Reconciler
validiert die Syntax des erwarteten Digests vor dem Lesen und scheitert bei
einem Mismatch vor Ausgabe oder Mutation. Der CI-Sicherheitsvertrag kodiert
die exakten Profile; sein Artefakt-Helper wurde in fokussierte fail-closed
Checks aufgeteilt und verwendet geteilte Step-Label-Konstanten, um die
task-eigenen SonarQube-Cloud-Duplikat-/Komplexitätsbefunde ohne Änderung der
Validierungsreihenfolge zu entfernen.

## Geänderte Dateien und Tests

Die Framework-Änderungen umfassen den Common-Maintenance-Workflow,
Reconciler- und Canonical-Pin-Tooling, den CI-Sicherheitsvertrag, gelockte
Artefakt-Action-Provenienz, gepaarte englische/deutsche Workflow-
Sicherheitsdokumentation, fokussierte Workflow-, Contract-, Reconciler- und
Runtime-Lock-Tests sowie dieses gepaarte Change Record. Positive Kontrollen
fordern das eine Artefakt und den passenden Digest. Negative Kontrollen weisen
fehlerhafte erwartete Digests, geänderte Artefaktnamen oder -pfade, fehlende
Downloads, verschachtelte oder unzulässige Dateien, Symlink-Escapes,
Digest-Manipulation, Downstream-Live-Resolution und Downstream-Read-Token-
Eingabe zurück.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk proxy gh run view 32010750544 --repo Easton97-Jens/ModSecurity-test-Framework --json status,conclusion,headSha,jobs` | `0` | Den ursprünglichen Full-Workflow-Plan-Digest-Fehler nach Änderung unabhängig aufgelöster Eingaben beobachtet. | GitHub-Actions-Run `32010750544` |
| Fokussierte Workflow-/Security-/Reconciler-/Canonical-Pin-/Runtime-Lock-Unittest-Suite | `0` | 166 fokussierte Tests bestanden während der Artefakt-Implementierung. | Framework-Task-Worktree |
| Finale fokussierte CI-Security-, Unified-Maintenance- und Validate-only-Unittest-Suite | `0` | 60 Tests bestanden nach der Sonar-Remediation des Artefakt-Contracts. | Framework-Task-Worktree |
| `ci/checks/security/check-ci-security-contract.py --root .` und `check-ci-security-evidence-contract.py --root .` | `0` | Überprüfte Artefakt-, Token-, Pin- und Evidence-Contracts bestanden. | Framework-Task-Worktree |
| `sync-canonical-workflow-pins.py --root . --check`, checksum-gelocktes Ruff `check` und `format --check` sowie `git diff --check` | `0` | Kanonische Pins, Source-Style und Whitespace bestanden. | Framework-Task-Worktree |
| `make lint` mit task-eigenem `FRAMEWORK_ROOT` | `0` | Die vollständige native Lint-Suite bestand. | Framework-Task-Worktree |
| Hosted Checks und SonarQube-Cloud-Check `95485455629` von PR-#97-Code-Head `7e77624ee676188b27b1fa197c5a4c0410e825f1` | `0` | Alle sichtbaren Hosted-Checks bestanden; Quality Gate hatte 0 neue/akzeptierte Issues, 0 Hotspots und 0,0 % New-Code-Duplizierung. | PR-#97-Pre-Change-Record-Evidenz |

## Sicherheitsauswirkung

Dies ist eine Reparatur für Supply-Chain-Integrität und Verfügbarkeit, keine
Berechtigungserweiterung oder Umgehung. Sie entfernt wiederholte
Live-Auflösung unterhalb des Canonical-Producers und erhält exakte gepinnte
Actions, direkte Approved-Path-Behandlung, Digest-Validierung,
Default-Branch-Gates, App-Token-Trennung, feste Output-Allowlists und
Draft-only-Publikation. Eine unabhängige Prüfung kontrollierte fehlerhafte
Artefakt- und Downstream-Input-Pfade erneut; kein neuer Trust-Boundary-Bypass
wurde gefunden.

## Dokumentation und Runtime-Evidenz

`docs/github-actions-workflow-security.md` und sein deutsches Gegenstück
dokumentieren die gelockte Artefakt-Action und den auf den Aufrufer gebundenen
Maintenance-Plan. Workflow `32010750544` bleibt Fehler-Evidenz, und der
Pre-Change-Record-Head von PR #97 liefert Hosted-Static-Analysis-Evidenz.
Dieses Record beansprucht keine erfolgreiche Resulting-Master-Maintenance-
Publikation.

## Nicht ausgeführte Prüfungen

- Hosted Checks und SonarQube Cloud für den finalen Change-Record-Commit
  liegen bei Erstellung dieses Records noch nicht vor; sie müssen für seinen
  neuen exakten PR-Head erneut laufen.
- Ein vollständiger Resulting-Master-`workflow_dispatch` kann erst erfolgen,
  wenn der PR die Nutzer-Gates besteht und regulär gemergt ist.
- Keine GitHub-App-Einstellung, kein Secret und keine Installationsberechtigung
  wurde geändert oder über normales Workflow-Verhalten hinaus untersucht.

## Einschränkungen und Restrisiko

Der Artefakttransport macht eine fehlgeschlagene Canonical-Auflösung nicht
sicher; solche Pläne bleiben fail-closed. Die installierte GitHub App muss
weiterhin ihre bereits überprüften Repository-Berechtigungen für spätere
Trusted-Reconciliation und Draft-Publikation besitzen. Bis finaler PR-Head
und resultierender Master beobachtet sind, bleibt die Reparatur `fixed`/
pending verification statt verified.

## Finaler Diff- und Review-Status

Implementierungsdiff, finaler Artefakt-Contract-Refactor, Dokumentation und
fokussierte Tests erhielten direkten und unabhängigen Security-Review; natives
Lint und der Pre-Change-Record-Hosted-Head bestanden. Dieses gepaarte Record
wird absichtlich vor finaler Delivery ergänzt, daher werden hier kein finaler
Commit, kein Merge, keine Resulting-Master-SHA und kein erfolgreicher
Resulting-Master-Workflow behauptet. Es werden keine Secrets oder rohen
sensiblen Payloads dokumentiert.
