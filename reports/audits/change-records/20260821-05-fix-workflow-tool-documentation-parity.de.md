# Change Record

**Sprache:** [English](20260821-05-fix-workflow-tool-documentation-parity.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260821-05-fix-workflow-tool-documentation-parity` |
| UTC-Datum | 2026-08-21 |
| Framework-Basisrevision | `473d2adad32e2db19e24e2339d9eb392040ab226` |
| Issue oder Pull Request | `FND-FRAMEWORK-0110`; Draft-PR ausstehend |

## Motivation und Problemstellung

Der vertrauenswürdige kanonische Maintenance-Candidate erreichte seine native
Updater-Prüfung, aber die beiden Generatoren serialisierten Versions- und
Immutable-Commit-Zellen der Action-Tabelle unterschiedlich. Die kanonische
Maintenance verwendete reine Markdown-Zellen, während der native Helper
Backticks schrieb. Der fail-closed Bytevergleich stoppte den Candidate deshalb
korrekt vor einer Veröffentlichung bei der deutschen generierten Ansicht.

## Betroffene Komponenten und Sicherheitsgrenzen

- `ci/tools/update-workflow-tools.py`: native Serialisierung von
  Action-Tabellenzellen, einschließlich Kompatibilität mit historischen
  Backtick-Zellen.
- `tests/ci_security/test_update_workflow_tools.py`: Parität von nativem und
  kanonischem Pfad sowie absichtliche Abweichung der deutschen Ansicht.
- `docs/github-actions-workflow-security.md` und `.de.md`: entfernen veraltete
  Aussagen über einen ausgemusterten separaten Publisher, ohne generierte
  Pin-Zeilen manuell zu bearbeiten.

Die Candidate-SHA-Bindung, der isolierte `RUNNER_TEMP`-Proposed-Tree, der
Byte-für-Byte-Vergleich, die Publisher-Allowlist, die App-Token-Grenze und die
Draft-PR-Prüfungen sind sicherheitsrelevant und bleiben unverändert.

## Akzeptanzkriterien

1. Kanonische und native Ableitung erzeugen für denselben gültigen
   Action-Candidate bytegleiche englische und deutsche Action-Tabellenansichten.
2. Eine veränderte deutsche Ansicht schlägt weiter fail-closed mit ihrem
   exakten Pfad fehl, bevor ein Publisher aktiv wird.
3. Historische Backtick-Zellen werden als Eingabe akzeptiert und in die
   kanonische reine Zellform normalisiert.
4. Repository-native Updater-, Vertrags-, Workflow-, Pin-, Dokumentations- und
   Diff-Prüfungen bestehen vor der Auslieferung.
5. Ein Hosted-Candidate-Lauf für den aktuellen PR-Head wird beobachtet; ein
   resultierender Master-Dispatch bleibt bis zu einer ausdrücklich autorisierten
   Integration und einem Merge getrennt.

## Untersuchte Alternativen

- Das Entfernen oder Lockern des Bytevergleichs wurde verworfen, weil dadurch
  kanonische und native Generatoren vor einem privilegierten Publisher
  auseinanderlaufen könnten.
- Die Umstellung des kanonischen Outputs auf Backticks wurde verworfen, weil
  der kanonische Output die etablierte generierte Darstellung ist.
- Eine Normalisierung nur einer Dokumentationssprache wurde verworfen, weil
  beide Ansichten Teil derselben begrenzten Output-Oberfläche sind.

## Implementierungsentscheidung

Der native Updater schreibt nun die kanonische reine Zellform. Er erkennt
historische Backtick-Zellen weiterhin und konvertiert nur eine passende
Action-Zeile in dieselbe Darstellung. Weder die veränderbare Pfadinventarliste,
die Validierungseingabe, die Release-Provenance-Regel noch das
Veröffentlichungsverhalten ändern sich.

## Geänderte Dateien und Tests

- `ci/tools/update-workflow-tools.py`
- `tests/ci_security/test_update_workflow_tools.py`
- `docs/github-actions-workflow-security.md`
- `docs/github-actions-workflow-security.de.md`
- dieses gepaarte Change Record

Die neue Regression erzeugte zuerst den kanonischen Output aus einem
aktualisierten `ci/lib/common.sh` und verlangte dann exakte native/kanonische
Gleichheit für beide Dokumentationsansichten. Sie ändert außerdem nur die
deutsche generierte Zeile und beweist, dass der exakte Vergleich sie weiter
ablehnt. Der bestehende Test für gepaarte Dokumentation prüft zusätzlich
historische Backtick-Eingaben.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk proxy …python -m unittest …test_canonical_generated_candidate_matches_native_documentation_views` | 1 | Die Pre-Fix-Regression reproduzierte die erwartete Byteabweichung der deutschen Ansicht. | Lokaler Task-Worktree; ursprünglicher Hosted-Fehler `32517027013` |
| `rtk proxy …python -m unittest …test_canonical_generated_candidate_matches_native_documentation_views` | 0 | Post-Fix-Parität und absichtliche deutsche Abweichungsprüfung bestanden. | Lokaler Task-Worktree |
| `rtk proxy …python -m unittest tests.ci_security.test_update_workflow_tools` | 0 | 41 Updater-Tests bestanden, einschließlich gepaarter Plain-/Backtick-Kompatibilität. | Lokaler Task-Worktree |
| `rtk proxy …python -m unittest tests.ci_security.test_sync_canonical_workflow_pins` | 0 | 12 Tests des kanonischen Generators bestanden. | Lokaler Task-Worktree |
| `rtk proxy …python -m unittest tests.ci_security.test_unified_common_maintenance_workflow tests.ci_security.test_ci_security_contract` | 0 | 47 Tests für Workflow-Topologie und CI-Sicherheitsvertrag bestanden. | Lokaler Task-Worktree |
| `rtk proxy …python -m unittest discover -s tests/ci_security -q` | 0 | Finale vollständige CI-Sicherheits-Suite: 287 Tests bestanden. | Lokaler Task-Worktree |
| `rtk proxy …python ci/tools/sync-canonical-workflow-pins.py --check --root .` | 0 | Kanonische generierte Ansichten haben keinen Drift. | Lokaler Task-Worktree |
| `rtk proxy …python ci/checks/security/check-github-actions-workflows.py --check all` | 0 | Alle 16 Workflow-Metadaten-, Pin- und Berechtigungsprüfungen bestanden. | Lokaler Task-Worktree |
| `rtk proxy …python ci/checks/security/check-workflow-action-pins.py` | 0 | Jede externe Workflow-Action ist per SHA gepinnt. | Lokaler Task-Worktree |
| `rtk proxy …python ci/checks/security/check-ci-security-contract.py --root .` | 0 | Der CI-Sicherheitsvertrag bestand. | Lokaler Task-Worktree |
| `rtk proxy …python ci/checks/documentation/check-{doc-links,variable-documentation,repository-path-references,change-records}.py` | 0 | Alle vier Dokumentations- und Change-Record-Prüfungen bestanden. | Lokaler Task-Worktree |
| `rtk proxy …python -m py_compile ci/tools/update-workflow-tools.py tests/ci_security/test_update_workflow_tools.py` | 0 | Geänderte Python-Dateien kompilierten. | Lokaler Task-Worktree |
| `rtk proxy …/ruff check` und `…/ruff format --check` | 0 | Hash-gesperrte Ruff-Lint- und Formatprüfungen für Updater und CI-Sicherheitstests bestanden. | Task-eigenes externes Tool-Root |
| `rtk proxy git diff --cached --check` | 0 | Der gestagte Sechs-Dateien-Diff hat keine Whitespace-Fehler. | Lokaler Task-Worktree |

Der gestagte Diff wurde manuell auf Umfang und Secrets geprüft; der unabhängige
Security-Diff-Review fand keine Regression bei Publishern oder Kontrollen.
Hosted-Evidenz für den aktuellen Head wird erst dokumentiert, nachdem der
Draft-PR existiert.

## Sicherheitsauswirkung

Dies ist eine Verfügbarkeitsreparatur der CI-Maintenance, kein Bypass. Der
ursprüngliche Pfad wurde reproduziert und der legitime Post-Fix-Pfad besteht im
fokussierten Test. Eine absichtlich veränderte deutsche generierte Zeile wird
weiter vom unveränderten Bytevergleich abgelehnt. Kein Publisher-Credential,
keine Berechtigung, kein Checkout und keine erlaubte Schreiboberfläche wurde
erweitert.

## Dokumentation und Runtime-Evidenz

Die englische und deutsche Workflow-Sicherheitsdokumentation beschreibt jetzt
den einzigen kanonischen Publisher korrekt. Connector-Runtime-Verhalten wurde
nicht verändert oder getestet. Hosted-Runtime-Evidenz für diesen neuen Branch
steht aus; Run `32517027013` bleibt ausschließlich Pre-Fix-Evidenz für den
fehlgeschlagenen Candidate.

## Nicht ausgeführte Prüfungen

Lokales Pyright lief nicht, weil `node` in dieser Ausführungsumgebung fehlt.
Hosted-PR-Checks, SonarQube Cloud, Review-Threads und ein Workflow-Dispatch-
Smoke-Test stehen aus, bis der Draft-PR existiert. Ein manueller resultierender
Master-Dispatch kann erst nach einer aktuellen ausdrücklichen
Master-Integrationsautorisierung und dem Merge laufen.

## Einschränkungen und Restrisiko

Der Fix kann GitHub-gehostete Credentials, Actions oder Publisher-Verhalten
nicht allein beweisen. Diese Kontrollen erfordern aktuelle Hosted-Checks für
den Head, gefolgt von einer separat autorisierten Master-Integration und einem
Dispatch.

## Finaler Diff- und Review-Status

Beim Staging sind genau die oben aufgeführten sechs Dateien enthalten, ohne
unstaged Task-Dateien. Whitespace-, Umfangs- und Secret-Review bestanden; der
normale Task-Branch-Commit, der Draft-PR und die Hosted-Checks sind die
nächsten Auslieferungsschritte.
