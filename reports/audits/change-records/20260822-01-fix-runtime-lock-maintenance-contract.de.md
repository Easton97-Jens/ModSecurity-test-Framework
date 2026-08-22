# Change Record

**Sprache:** [English](20260822-01-fix-runtime-lock-maintenance-contract.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260822-01-fix-runtime-lock-maintenance-contract` |
| UTC-Datum | 2026-08-22 |
| Framework-Basisrevision | `b5575f7bbf53ca901a813d9bc32945f3b460c156` |
| Issue oder Pull Request | `FND-FRAMEWORK-0111`; Framework-Draft-PR ausstehend |

## Motivation und Problemstellung

Der vertrauenswürdige Master-Maintenance-Lauf `32543831249` erzeugte
Framework-PR #106 mit einem gültigen NGINX-Update. Seine Lint-Checks scheiterten,
weil der Runtime-Lock-Test den alten `release-1.31.3`-Tag, das Archiv und den
Digest als einzige gültige Umgebung behandelte, obwohl der generierte Lock
korrekt `release-1.31.4` verwendete. Der Candidate-Workflow führte die
Runtime-Lock-Suite nicht vor dem Veröffentlichen des Draft-PR aus.

## Betroffene Komponenten und Sicherheitsgrenzen

- `tests/security_regression/test_runtime_component_lock.py`: leitet den
  legitimen `nginx-h1`-Umgebungs-Tupel aus dem kanonischen Runtime-Lock ab und
  erhält einen Tag-Drift-Negativ-Control.
- `.github/workflows/check-common-versions.yml`: führt die Runtime-Lock-Suite
  in den Candidate-Focused-Controls aus, bevor der Publisher-Job laufen kann.
- `ci/checks/security/check-ci-security-contract.py`: aktualisiert das
  geprüfte, hash-gebundene Candidate-Run-Profil für diesen expliziten neuen
  Control.
- `tests/ci_security/test_unified_common_maintenance_workflow.py` und
  `tests/ci_security/test_ci_security_contract.py`: schützen die
  Pre-Publication-Runtime-Lock-Anforderung und weisen ihre Entfernung zurück.

Die Candidate-/Publisher-Abhängigkeit, Byte-für-Byte-Candidate-Validierung,
Publisher-Allowlist, Draft-only-Reuse-Guard, repository-limited App-Token und
Branch-Protections bleiben unverändert.

## Akzeptanzkriterien

1. Der aktuelle `nginx-h1`-Lock-Tupel wird akzeptiert; ein anderer Tag mit
   aktuellem Asset und SHA-256 wird abgelehnt.
2. Candidate-Focused-Controls führen die Runtime-Lock-Suite vor
   Publisher-Credentials oder jedem Draft-PR-Write-Pfad aus.
3. Der präzise Candidate-Run-Body bleibt hash-gebunden und ein Test weist die
   Entfernung des Runtime-Lock-Controls zurück.
4. Fokussierte und vollständige repository-native Validierung besteht ohne
   Parent-Gitlink- oder MRTS-Änderung.
5. Ein künftiger Framework-Draft-PR hat Current-Head-CI-, SonarQube-Cloud-,
   Review- und Thread-Evidence vor jedem separat autorisierten Merge.

## Untersuchte Alternativen

- Die Erweiterung der Publisher-Allowlist zum Umschreiben von Testsource wurde
  verworfen: Ein Updater darf keine breitere Source-Write-Autorität erhalten,
  um einen Test zu reparieren.
- Das Hartcodieren des aktuellen NGINX-Releases wurde verworfen, weil jedes
  gültige künftige Update denselben Testdrift erneut erzeugen würde.
- Das Entfernen des strikten Run-Body-Digests wurde verworfen, weil es das
  geprüfte Candidate-Sicherheitsprofil abschwächen würde.

## Implementierungsentscheidung

Der positive Test liest `source_provenance`, `asset_name` und `sha256` aus dem
eingecheckten `nginx-h1`-Lock-Profil. Der negative Test ändert nur den
abgeleiteten Release-Tag. Der Candidate führt das bestehende vollständige
Runtime-Lock-Testmodul aus; sein exakter Run-Body wird bewusst im
Security-Contract neu gehasht. Dieser Korrekturbranch änderte keinen
generierten PR, keine Write-Allowlist, keinen Token-Scope und keinen
veränderbaren Runtime-Pin.

## Geänderte Dateien und Tests

- `.github/workflows/check-common-versions.yml`
- `ci/checks/security/check-ci-security-contract.py`
- `tests/security_regression/test_runtime_component_lock.py`
- `tests/ci_security/test_unified_common_maintenance_workflow.py`
- `tests/ci_security/test_ci_security_contract.py`
- dieses gepaarte Change Record

Der legitime Control ist der aus dem aktuellen Lock abgeleitete Tupel. Der
negative Control verwendet dasselbe Asset und denselben Digest, aber einen
anderen Tag, und muss die bestehende Diagnose `NGINX_RELEASE_TAG drift`
ausgeben. Der Contract-Mutation-Test entfernt das neue Testmodul und muss am
exakten geprüften Workflow-Profil scheitern.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk proxy …python -B -m unittest tests.security_regression.test_runtime_component_lock -v` | 0 | 13 Runtime-Lock-Tests bestanden, einschließlich der Lock-abgeleiteten NGINX-Positiv- und Negativ-Controls. | Isolierter Framework-Worktree |
| `rtk proxy …python -B -m unittest tests.ci_security.test_unified_common_maintenance_workflow -v` | 0 | 14 Unified-Workflow-Contract-Tests bestanden, einschließlich Candidate-Pre-Publication-Runtime-Lock-Coverage. | Isolierter Framework-Worktree |
| `rtk proxy make … test-runtime-component-lock` | 0 | Native Lock-Checker und 13-Test-Target bestanden. | Task-eigenes externes Build-/TMP-Root |
| `rtk proxy …python -B -m unittest tests.ci_security.test_ci_security_contract tests.ci_security.test_framework_ci_security_contract -v` | 0 | 47 CI-Security-Contract-Tests bestanden; Entfernung des Runtime-Lock-Controls wird abgelehnt. | Isolierter Framework-Worktree |
| `rtk proxy …python -B ci/checks/security/check-ci-security-contract.py --root .` | 0 | Exaktes geprüftes Workflow-Sicherheitsprofil bestand. | Isolierter Framework-Worktree |
| `rtk proxy make … lint` | 0 | Vollständiger nativer Framework-Lint bestand, einschließlich 288 CI-Security-Tests sowie Runtime-/Pin-/Workflow-Contracts und Dokumentationsprüfungen. | Isolierter Framework-Worktree und task-eigenes Build-/TMP-Root |

## Sicherheitsauswirkung

Dies repariert die Verfügbarkeit der CI-Maintenance, ohne einen privilegierten
Sink zu ändern. Die ursprüngliche Reproduktion bleibt ausschließlich ein
veraltetes Fixture; ein geänderter Tag scheitert weiter, und die Entfernung des
neuen Candidate-Controls wird vom exakten Workflow-Profil abgelehnt. Direkte
Caller wurden geprüft: Der Candidate bleibt ein read-only Job und `publish`
erfordert weiterhin Candidate-Erfolg vor seinen repository-limited Token-Schritten.

## Dokumentation und Runtime-Evidenz

Dieses englische/deutsche Change Record dokumentiert die Framework-eigene
Änderung. Der aufbewahrte Hosted-Fehlernachweis ist im kanonischen Parent-
Evidence-Ledger `FND-FRAMEWORK-0111` erfasst (SHA-256
`0c932428f325f94d5fcbcfceecdb66cdd020f04402a828fb9ff1225a7565a7e0`).
Keine Connector-Runtime wurde geändert oder ausgeführt.

## Nicht ausgeführte Prüfungen

Current-Head-Hosted-CI, SonarQube Cloud und Review-/Thread-Validierung stehen
bis zur Erstellung des korrigierenden Draft-PR noch aus. Für diese Änderung
besteht keine Master-Merge-Autorisierung.

## Einschränkungen und Restrisiko

Der Branch kann GitHub-gehostete Publisher-Credentials oder die vollständige
Check-Suite eines künftigen generierten PR nicht selbst beweisen. Der bestehende
PR #106 wurde extern von Draft auf bereit für Review gestellt; diese Reparatur
ändert diesen PR nicht und behauptet keinen automatischen Draft-State-Bypass.

## Finaler Diff- und Review-Status

Die Implementierung liegt in einem isolierten task-eigenen Framework-Worktree.
Vollständiger nativer Lint und fokussierter Security-Diff-Review bestanden;
finaler Scope-/Whitespace-/Secret-Review, Commit, PR und Current-Head-Hosted-
Evidence müssen noch abgeschlossen werden, bevor die Auslieferung als
`verified_pr` gemeldet wird.
