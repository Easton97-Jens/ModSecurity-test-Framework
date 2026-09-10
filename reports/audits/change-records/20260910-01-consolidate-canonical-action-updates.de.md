# Change Record

**Sprache:** [English](20260910-01-consolidate-canonical-action-updates.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260910-01-consolidate-canonical-action-updates` |
| UTC-Datum | 2026-09-10 |
| Framework-Basisrevision | `86451b45ae7bb7953baf9f81f2c2dad07395a808` |
| Issue oder Pull Request | Draft-PR steht vor der normalen Framework-Delivery aus; kein bestehender PR wurde verändert. |

## Motivation und Problemstellung

Framework-PRs #113 und #114 teilen ein CodeQL-Release in getrennte,
Dependabot-generierte Workflow-only-PRs auf. Beide scheitern am kanonischen
Pin-Vertrag, weil `ci/lib/common.sh` und nicht die generierten Workflow-Views
die Quelle der Wahrheit ist. Auch der vorhandene kanonische Single-Draft-PR-
Publisher war blockiert: Sein Proposed-Tree regenerierte vor dem exakten
Output-Vergleich keinen Node-abgeleiteten Workflow-Wert.

## Betroffene Komponenten und Sicherheitsgrenzen

- `ci/tools/update-workflow-tools.py` regeneriert nur den isolierten
  Proposed-Tree aus der vertrauenswürdigen kanonischen Quelle vor dem
  Bytevergleich.
- `.github/dependabot.yml` deaktiviert nur reguläre `github-actions`-
  Versions-PRs; Sicherheitsupdates bleiben außerhalb dieses
  Dependabot-Versionslimits.
- Der kanonische Trusted-Default-Publisher, unveränderliche SHA-Pins, feste
  Draft-PR, begrenztes App-Token, `pull_request`-Grenzen sowie No-Merge-/
  No-Force-Haltung bleiben unverändert.

Parent- und MRTS-Source, Gitlinks, Branches und Delivery-Zustände bleiben
unverändert.

## Akzeptanzkriterien

1. Ein kombinierter Action-/Tool- und Node-Runtime-Kandidat besteht die
   kanonische Generated-Candidate-Validierung.
2. Eine veraltete oder fehlerhafte Generated-View bleibt fail-closed.
3. Reguläre Action-Releases verwenden nur den vorhandenen festen kanonischen
   Draft-PR-Publisher, während die nicht verwandte `pip`-Konfiguration
   unverändert bleibt.
4. Workflow-Metadaten-, Immutable-Pin- und CI-Security-Contracts bestehen.
5. PRs #113 und #114 werden weder gemergt noch geschlossen oder anderweitig
   verändert.

## Untersuchte Alternativen

- Eine Dependabot-Gruppe für `github/codeql-action/**` würde einen größeren
  einzelnen PR erzeugen, änderte aber weiterhin generierte Views ohne
  `common.sh` oder Lock und bliebe ungültig.
- Eine Wildcard-Dependabot-Gruppe würde unabhängige Actions unnötig koppeln
  und behielte denselben kanonischen Source-Defekt.
- Alle Dependabot-Updates zu ignorieren könnte Sicherheitsupdates unterdrücken.

Der gewählte Ansatz repariert den vorhandenen kanonischen Publisher und
unterdrückt ausschließlich reguläre Dependabot-Versionsupdates mit dem
dokumentierten Null-Limit.

## Implementierungsentscheidung

Nach dem Anwenden eines begrenzten Action-/Tool-Kandidaten auf seinen
`RUNNER_TEMP`-Proposed-Tree ruft der native Helper den vertrauenswürdigen
kanonischen Synchronizer auf diesem Tree auf, bevor er alle verwalteten Outputs
bytegenau vergleicht. Regressionstests modellieren jetzt sowohl einen
Action-plus-Node-Plan als auch den kanonischen Pre-Apply-Snapshot. Die
Dependabot-Konfiguration setzt die `github-actions`-Versions-Parallelität auf
null; der kanonische Workflow bleibt der einzige feste Draft-PR-Publisher.
Zweisprachige Security-/Tooling-Dokumentation hält die Grenze fest.

## Geänderte Dateien und Tests

- `.github/dependabot.yml`
- `ci/tools/update-workflow-tools.py`
- `tests/ci_security/test_update_workflow_tools.py`
- `tests/ci_security/test_unified_common_maintenance_workflow.py`
- `docs/security/ci-security-tooling.{md,de.md}`
- `docs/github-actions-workflow-security.{md,de.md}`
- dieses gepaarte Change Record

Die Updater-Regression deckt kanonische Action-/Runtime-Generated-Views ab;
der Workflow-Contract-Test beweist die reguläre Action-Publisher-Grenze und
lässt das `pip`-Limit unverändert.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `python -m unittest tests.ci_security.test_update_workflow_tools -v` | 0 | 41 Updater- und Negativ-Control-Tests bestanden. | Isolierter Framework-Worktree |
| `python -m unittest tests.ci_security.test_unified_common_maintenance_workflow -v` | 0 | 15 Unified-Publisher-/Contract-Tests bestanden. | Isolierter Framework-Worktree |
| `python ci/tools/sync-canonical-workflow-pins.py --check --root .` | 0 | Kanonische Generated-Views sind aktuell. | Isolierter Framework-Worktree |
| `python ci/checks/security/check-github-actions-workflows.py --check all` | 0 | Alle 16 Workflows bestanden die statische Metadaten-/Security-Validierung. | Isolierter Framework-Worktree |
| `python ci/checks/security/check-workflow-action-pins.py --workflow-root .github/workflows` | 0 | Alle externen Actions bleiben volle unveränderliche SHAs. | Isolierter Framework-Worktree |
| `python ci/checks/security/check-ci-security-contract.py --root .` | 0 | CI-Sicherheitsvertrag bestand. | Isolierter Framework-Worktree |
| `python -m unittest tests.ci_security.test_ci_security_contract -v` | 0 | 34 CI-Security-Contract-Tests bestanden. | Isolierter Framework-Worktree |
| `python -m unittest discover -s tests/security_regression -p test_workflow_action_pins.py -v` | 0 | 25 Action-Pin-Regressionstests bestanden. | Isolierter Framework-Worktree |
| `python -m unittest discover -s tests/security_regression -p test_workflow_security_contract.py -v` | 0 | 9 Workflow-Security-Contract-Regressionen bestanden. | Isolierter Framework-Worktree |
| `actionlint -color=false .github/workflows/*.yml` | 0 | Alle Workflow-Syntax- und Expression-Prüfungen bestanden. | Isolierter Framework-Worktree |
| `zizmor --offline .github` | 0 | Keine Findings; 35 repositoryverwaltete Suppressions. | Isolierter Framework-Worktree |
| Native Dokumentations-Link-, Variablen-, Pfadreferenz- und Change-Record-Checks | 0 | Zweisprachigkeits- und Traceability-Checks bestanden. | Isolierter Framework-Worktree |
| `git diff --check` | 0 | Keine Whitespace-Fehler im finalen lokalen Diff. | Isolierter Framework-Worktree |

## Sicherheitsauswirkung

Dies ist eine Korrektur eines fail-closed-Validierungspfads, keine Lockerung
eines Security-Controls. Der Proposed-Tree bleibt privat und begrenzt; der
Synchronizer nutzt die vertrauenswürdige eingecheckte Quelle und schreibt nur
in diesen Tree. Bytegenauer Vergleich, Action-Pin-Anforderung, Token-Scope und
Trusted-Default-Publishing-Grenze bleiben aktiv. Der alternative Pfad eines
Generated-View-only-Dependabot-PRs wird weiterhin von kanonischen Checks
zurückgewiesen.

## Dokumentation und Runtime-Evidenz

Englische und deutsche CI-Tooling- und Workflow-Security-Dokumentation
beschreiben jetzt den einzigen regulären Publisher und den separaten
Dependabot-Sicherheitsupdate-Pfad. Hosted-Lauf `34440400760` liefert die
ursprüngliche Failure-Evidence. Kein neuer Hosted-Lauf wird ausgelöst: Vor
einem Merge checkt der vertrauenswürdige Workflow bewusst `master` aus und ein
Dispatch würde diesen Task-Branch nicht testen.

## Nicht ausgeführte Prüfungen

Exakte Hosted-PR-Checks stehen bis zur normalen Draft-PR-Delivery aus. Ein
späterer vertrauenswürdiger kanonischer Maintenance-Lauf steht ebenfalls aus,
weil er die ausgelieferte Default-Branch-Quelle verwenden muss. `ruff` ist
lokal nicht verfügbar und wurde nicht installiert; die vollständige
Produkt-Lint-Suite wurde nicht abgeschlossen. Der historische Lint-Lauf
`34391779761` betrifft nicht diese Workflow-/Updater-Änderung, sondern
unabhängige Produktdateien.

## Einschränkungen und Restrisiko

Dependabot-Sicherheitsupdates werden bewusst nicht mit regulären
Versionsupdates gebündelt und der kanonische Updater konsumiert
Dependabot-Sicherheitsalerts nicht. Sie bleiben ein separater Alert-/Review-
Pfad. Es wird nicht zugesichert, dass die zwei bereits offenen externen
Dependabot-PRs verschwinden; ihre Veränderung erfordert eine separate
Nutzerautorisierung.

## Finaler Diff- und Review-Status

Der isolierte Worktree hat die aufgeführten lokalen Checks und `git diff --check`
bestanden. Der unabhängige Security-Diff-Review ergab kein neues
Security-Finding, und Dokumentationsprüfungen sowie finaler Scope-Review
bestanden. Commit und normale Draft-PR-Delivery stehen noch aus. Kein Merge,
Default-Branch-Write, Force-Push oder Parent-Gitlink-Update ist autorisiert.
