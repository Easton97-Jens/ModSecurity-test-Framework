# Change Record

**Sprache:** [English](20260821-03-consolidate-workflow-tool-maintenance.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260821-03-consolidate-workflow-tool-maintenance` |
| UTC-Datum | 2026-08-21 |
| Framework-Basisrevision | `4f212afbd83ea183c721b0aa43821ed640c9b355` |
| Issue oder Pull Request | [Framework-PR #101](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/101) nach `master` |

## Motivation und Problemstellung

Der Nutzer hat ausdrücklich einen Workflow-Updater ausgewählt, wenn der
kanonische Common-Version-Wartungspfad und der Updater für gepinnte
Workflow-Tools überlappen. Beim Zusammenführen dürfen keine Schutzmaßnahmen
des eigenständigen Updaters verloren gehen: Kandidaten-/Basis-Identitätsbindung,
Asset-Prüfsummenprüfung, isolierte Proposed-Tree-Contracts und exakte
Draft-PR-Statuskontrollen.

## Betroffene Komponenten und Sicherheitsgrenzen

- `.github/workflows/check-common-versions.yml`: der einzige vertrauenswürdige
  Wartungs-Orchestrator. Er läuft weiterhin nur geplant/manuell auf dem
  vertrauenswürdigen Default-Branch und behält sein repositorybegrenztes
  Publisher-App-Token.
- `ci/tools/update-workflow-tools.py`: bleibt der enge Lock-/Pin-Helper; er
  sichert nun die Eingabefläche vor dem Plan und validiert den vom kanonischen
  Plan erzeugten nativen Kandidaten, statt einen zweiten Publisher zu besitzen.
- `ci/checks/security/check-ci-security-contract.py` und direkte Tests:
  binden Snapshot-, Kandidaten-Digest-, Asset-, Proposed-Tree-, Draft-PR-,
  Token-, Trigger- und Branch-Scope-Kontrollen exakt.

Parent-Quelltext und Gitlink bleiben unverändert. MRTS bleibt read-only und
unverändert.

## Akzeptanzkriterien

1. `check-common-versions.yml` ist der einzige Workflow-Publisher für
   kanonische Action-/Tool-Wartung; `.github/workflows/update-workflow-tools.yml`
   ist entfernt.
2. Candidate und Publisher sichern die festen Updater-Eingaben vor Anwendung
   des Caller-gebundenen Plans und leiten danach den nativen Kandidaten
   unabhängig ab.
3. Beide Ableitungen bewahren Release-Provenance, Prüfsummen geänderter Tools
   und isolierte Proposed-Tree-Validierung. Der Publisher muss die SHA-256 des
   Candidate-Jobs abgleichen.
4. Der Publisher bleibt nur für den vertrauenswürdigen Default-Branch,
   verwendet dasselbe eng begrenzte App-Token und nutzt nur eine exakte
   Draft-PR mit Allowlist-Branch-Diff wieder, deren nativer Workflow-Tool-Teil
   dem aus der Basis abgeleiteten Ergebnis entspricht. Es werden weder
   PR-Trigger noch Force-Push, Merge, Permission- oder Token-Erweiterung
   eingeführt.
5. Die Regressions-/Negativtests für nativen Helper und vereinigten Workflow
   sowie Action-Pin-, Workflow-, Canonical-View-, CI-Security-, Dokumentations-
   und Change-Record-Prüfungen bestehen.

## Untersuchte Alternativen

Zwei Publisher beizubehalten wurde verworfen, weil dies dieselbe gepinnte
Action-/Tool-Wartungsfläche dupliziert. Den Helper zu entfernen oder seine
Prüfungen zu schwächen wurde verworfen, weil dies unabhängige Supply-Chain-
und Publisher-Grenz-Kontrollen verlieren würde.

## Implementierungsentscheidung

Der kanonische Common-Version-Workflow ist der einzige Publisher, während der
native Helper der unabhängig testbare Lock-/Pin-Kandidatenvalidator bleibt.

## Geänderte Dateien und Tests

- Der eigenständige Workflow und seine aktiven Generated-Path-/Allowlist-
  Einträge wurden entfernt.
- Begrenzte `RUNNER_TEMP`-Snapshot-Verzeichnisse und die Validierung des vom
  kanonischen Plan erzeugten Kandidaten wurden dem nativen Helper hinzugefügt.
- Snapshot- und Validierungsschritte wurden zu kanonischen Candidate- und
  Publisher-Jobs hinzugefügt, einschließlich eines Job-übergreifenden
  Kandidaten-SHA-256-Abgleichs.
- Eine geprüfte `github-script`-Kontrolle für festen Branch, Titel, Marker,
  Draft-Status, Default-Basis, Ancestry und exakte Generated-Path-Allowlist
  wurde ergänzt.
- Vor der Wiederverwendung eines bestehenden kanonischen Draft-Branches wird
  dessen nativer Helper-Teil gegen Basis-Lock-Identität und bytegenaues
  abgeleitetes Ergebnis geprüft; vor dem Helper-Aufruf wird das temporäre
  Fetch-Credential entfernt.
- Der Security-Contract, direkte Negativtests, zweisprachige Workflow-
  Security-/Tooling-Dokumentation und dieses Record-Paar wurden aktualisiert.

Keine Parent-, MRTS-, Release-, Settings-, Secret-, Dependency- oder
Default-Branch-Änderung ist enthalten.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Evidenz |
| --- | --- | --- | --- |
| Fokussierte Updater-/Unified-/Contract-Tests | 0 | 87 Tests bestanden, einschließlich Snapshot-Containment, Kandidaten-Digest-Mismatch, Asset-/Proposed-Tree-Anforderungen und exakten/zurückgewiesenen wiederverwendeten kanonischen Branches. | Lokaler Task-Worktree |
| `python ci/checks/security/check-ci-security-contract.py --root .` | 0 | Konsolidierter CI-Sicherheitsvertrag besteht. | Lokaler Task-Worktree |
| `python ci/checks/security/check-github-actions-workflows.py --check all` | 0 | Alle 16 verbliebenen Workflows bestanden Metadaten-, Pin-, Permission- und Checkout-Prüfungen. | Lokaler Task-Worktree |
| `python ci/checks/security/check-workflow-action-pins.py` | 0 | Jede externe Action bleibt auf eine volle Commit-SHA gepinnt. | Lokaler Task-Worktree |
| `python ci/tools/sync-canonical-workflow-pins.py --check --root .` | 0 | Kanonische Workflow-Pins bestehen. | Lokaler Task-Worktree |
| `python ci/tools/check-common-versions.py --validate-canonical` | 0 | Kanonische common.sh-Pins bestehen. | Lokaler Task-Worktree |
| Gesperrte Ruff-Lint- und Format-Prüfungen | 0 | Das exakt SHA-gesperrte Ruff 0.16.3 akzeptierte die geänderten Python- und Testpfade nach mechanischer Formatierung. | Lokaler Task-Worktree |
| Vollständige CI-Security-Suite | 0 | 286 Tests bestanden. | Lokaler Task-Worktree |
| Dokumentations- und Change-Record-Prüfungen | 0 | Links, zweisprachige Variablen, Repository-Pfade, Change-Record-Überschriften und 4 Change-Record-Contract-Tests bestanden. | Lokaler Task-Worktree |
| Finaler Diff | 0 | `git diff --check` bestand. | Lokaler Task-Worktree |
| Security-Diff-Review | task-eigenes Artefakt | Der unveränderliche finale Report bleibt außerhalb des Worktrees, weil er Scanner-Evidenz und keinen Produktquelltext enthält. | `workflow-consolidation-diff-post-ruff/report.md` |

## Sicherheitsauswirkung

Die Zusammenführung bewahrt den vertrauenswürdigen Default-Checkout,
top-level-`contents: read`, den getrennten read-only-Candidate-Job, das
repositorybegrenzte App-Token, die feste Draft-PR sowie die No-Force-/No-Merge-
Haltung. Der neue Snapshot akzeptiert nur dem Runner gehörende, nicht
symlinkte `RUNNER_TEMP`-Verzeichnisse. Der Helper bleibt auf explizite
Lock-/Workflow-/Dokumentationspfade begrenzt und führt kein heruntergeladenes
Asset aus. Wiederverwendete kanonische Branches müssen sowohl dem überprüften
Scope als auch dem nativ aus der Basis abgeleiteten Inhalt entsprechen; vor dem
Helper-Aufruf wird das App-Token entfernt.

## Dokumentation und Runtime-Evidenz

Die zweisprachigen Workflow-Security-/CI-Tooling-Dokumente und dieses gepaarte
Change Record beschreiben die Single-Publisher-Grenze und die beibehaltenen
nativen Kontrollen. Lokale Tests liefern Quelltext-Evidenz für diese Contracts.

## Nicht ausgeführte Prüfungen

Keine Hosted-Ausführung des neuen Quelltexts wurde ausgeführt: Vor einem
autorisierten Merge checkt der vertrauenswürdige Workflow absichtlich `master`
aus; ein Dispatch würde daher den alten Default-Branch-Quelltext statt diesem
PR-Quelltext ausführen.

## Einschränkungen und Restrisiko

Ein vertrauenswürdiger geplanter/manueller Post-Merge-Run bleibt für Live-
GitHub-API-, Artefakt- und Publisher-Environment-Evidenz erforderlich. Dieser
Record autorisiert keinen Default-Branch-Dispatch und keinen Merge.

## Finaler Diff- und Review-Status

Der finale fokussierte Diff enthält keine Whitespace-Fehler; es sind keine
Secrets oder rohen sensiblen Materialien dokumentiert. Der task-eigene
Security-Diff-Report ist die maßgebliche unveränderliche Evidenz für den
fertigen Quelltext-Snapshot. Der bestehende PR wurde nach dem Delivery-Preflight
mit einem normalen Follow-up-Commit aktualisiert; Merge, Force-Push,
Default-Branch-Write und Parent-Gitlink-Update sind nicht autorisiert.
