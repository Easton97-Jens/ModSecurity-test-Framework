# Change Record

**Sprache:** [English](20260821-01-consolidate-github-workflows.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260821-01-consolidate-github-workflows` |
| UTC-Datum | 2026-08-21 |
| Framework-Basisrevision | `bd69ee96e0e7082317d4afe1232bee625665eb9a` |
| Issue oder Pull Request | [Framework-Draft-PR #101](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/101) nach `master`; Hosted-Rerun nach Follow-up-Reparatur ausstehend |

## Motivation und Problemstellung

Siebzehn Framework-Workflows enthielten wiederholte hash-locked
CI-Abhängigkeits-Bootstrap-Schritte, während ihre Workflow-Semantik bewusst
unterschiedlich ist. Diese Änderung teilt nur die exakte gemeinsame
Bootstrap-Implementierung und erhält die umgebenden Workflow-Wrapper. Eine
statische Prüfung fand außerdem zwei Availability-Hardening-Lücken: öffentliche
GitHub-Issue-Daten wurden ohne explizite Byte-Budgets akkumuliert, und ein
existierender MRTS-Maintenance-PR wurde ohne explizite First-Party-
Head-Repository-Identität abgeglichen.

## Betroffene Komponenten und Sicherheitsgrenzen

- `.github/workflows/`: Grenzen für untrusted PRs, trusted Maintenance-Jobs,
  unveränderliche Action-Pins, Berechtigungen, Event-Filter und stabile
  Check-Namen.
- `ci/tools/install-hash-locked-ci-dependencies.sh`: gemeinsame Grenze für
  locked CI-Paketinstallation und `pip check`.
- `ci/tools/reconcile-common-version-review-issues.py`: Grenze von
  öffentlichen GitHub-Issue-Metadaten zur trusted Reconciliation.
- `.github/workflows/update-submodules.yml`: Grenze von GitHub-PR-Metadaten
  zur trusted Wiederverwendung eines First-Party-Maintenance-Branches.
- `ci/checks/security/check-ci-security-contract.py` und
  `tests/ci_security/`: ausführbare Regressions-Controls für beide Änderungen.

Parent-Source und Gitlink sind unverändert. MRTS-Source, Revision, Branch und
Gitlink sind read-only und unverändert.

## Akzeptanzkriterien

1. Alle 17 Source-Workflows sind auditiert und behalten ihr beabsichtigtes
   Verhalten.
2. Nur exakte, verhaltenskompatible Dependency-Bootstrap-Duplikation wird
   geteilt; kein ganzer Workflow wird gelöscht oder zusammengeführt.
3. Der Helper bleibt hash-locked, schlägt bei unerwarteten Argumenten fehl und
   ist durch den CI-Security-Contract gebunden.
4. Öffentliche Issue-Reconciliation hat explizite Bounds pro Antwort,
   Aggregate-Bytes und beibehaltene Einträge und bricht vor unsicherer
   Aggregation ab.
5. Bestehendes MRTS-Maintenance-PR-Matching verlangt den festen Branch und die
   exakte First-Party-`GITHUB_REPOSITORY`-Identität.
6. Relevante lokale Checks bestehen; nicht verfügbare Hosted-Validierung bleibt
   explizit und wird nicht als bestanden dargestellt.

## Untersuchte Alternativen

- Ähnliche Workflows zusammenführen oder löschen: verworfen. Die 17 Workflows
  unterscheiden sich in Event-/Trust-Modell, Berechtigungen, Artefakten,
  Publisher-Gates oder Required Checks. Insbesondere bleiben CodeQL-PR-Analyse
  und trusted Security-Upload getrennt.
- Maintenance-Publisher-Bodies extrahieren: verworfen. Ihre überprüften
  Job-Profile, Token-Scopes und Contract-Hashes sind bewusst streng und nicht
  identisch.
- `update-workflow-tools.yml` wegen eines historischen Rate-Limits ein Token
  hinzufügen: verworfen. Der standalone Resolver ist bewusst credential-free;
  dies ist eine operative Einschränkung, kein sicherer opportunistischer
  Workflow-Change.
- PRs nur mit owner-qualified CLI-Query abgleichen: allein nicht ausreichend.
  Die gewählte Lösung fordert und validiert First-Party-Head-Metadaten explizit
  und schlägt bei fehlenden oder abweichenden Daten fail-closed fehl.

## Implementierungsentscheidung

`ci/tools/install-hash-locked-ci-dependencies.sh` wurde hinzugefügt. Der
Helper löst das Framework-Root auf, akzeptiert keine Argumente, führt die
bestehende `requirements-ci.lock`-Installation mit `--require-hashes` aus und
startet `python3 -m pip check`. Acht gewöhnliche/read-only Workflows rufen ihn
nun auf, behalten ihre bisherigen sichtbaren Step-Namen und ergänzen ihn in
relevanten Path-Filtern. Strikte Maintenance-Publisher-Workflows behalten ihren
inline Bootstrap, da ihre überprüften Profile absichtlich verschieden sind.

Der trusted `pull-request-head`-Job von `ci-security-osv.yml` behält ebenfalls
bewusst seinen überprüften inline Bootstrap: Er checkt die trusted PR-**Base**-
Revision aus, in der ein nur vom PR-Head eingeführter Helper nicht verfügbar ist
und nicht in diesen Job geholt werden darf. Sein Default-Branch-Advisory-Job
verwendet den Helper. Hosted PR #101 Run `32436667389` belegte diese
Verfügbarkeitsgrenze mit initialem Exit 127; der Follow-up-Contract-
Regression-Guard lehnt nun Helper-Nutzung im Trusted-Base-Job ab.

Der Security-Contract bindet den Helper per SHA-256 und verlangt die erwarteten
Aufrufanzahlen pro Workflow. Er bindet auch das Submodule-Publisher-Profil,
nachdem ein expliziter Filter für `headRefName`, `headRepository` und
`headRepositoryOwner` ergänzt wurde.

Die Issue-Reconciliation begrenzt jetzt eine GitHub-Antwort auf 1.000.000 Byte,
akkumulierte Issue-Payloads auf 16.000.000 Byte und beibehaltene Issues auf
25.600; alle Limits schlagen fail-closed fehl. Kein Token, keine Berechtigung,
kein Trigger, Branch-Filter, Artefakt, Retention, Check-Name, keine
CodeQL-Trennung, kein Parent-Gitlink und keine MRTS-Source wurden geändert.

## Geänderte Dateien und Tests

| Workflow | Entscheidung | Erhaltenes Verhalten / Validierung |
| --- | --- | --- |
| `check-action-versions.yml` | nur Helper | PR/push-Filter sowie Action-/Version-Contract-Checks bleiben erhalten. |
| `check-common-versions.yml` | auditiert, unverändert | Einzigartiges trusted Maintenance-/Reconciliation-/Publisher-Profil bleibt inline. |
| `check-python-version.yml` | auditiert, unverändert | Einzigartiges Candidate- und Draft-PR-Publisher-Profil bleibt inline. |
| `ci-security-codeql-pr.yml` | auditiert, unverändert | Untrusted-PR-Analyse bleibt von trusted Upload getrennt. |
| `ci-security-codeql.yml` | auditiert, unverändert | Trusted push/schedule Security-Upload bleibt getrennt. |
| `ci-security-dependency-review.yml` | auditiert, unverändert | Einzigartiges Dependency-Review-Action-Verhalten bleibt. |
| `ci-security-osv.yml` | Helper + trusted-base inline | Trusted PR-Base-Job behält inline Bootstrap; Default-Branch-Advisory-Job verwendet Helper. |
| `ci-security-quality.yml` | nur Helper | Ruff- und hosted Pyright-Quality-Gate bleiben. |
| `ci-security-scorecard.yml` | nur Helper | PR/current-head- und Advisory-Verhalten bleiben. |
| `ci-security-secrets.yml` | nur Helper | PR-Diff- und Full-History-Gitleaks-Verhalten bleiben. |
| `ci-security-workflow-lint.yml` | nur Helper | actionlint, ShellCheck, zizmor und CI-Security-Test-Gates bleiben. |
| `cleanup-artifacts.yml` | auditiert, unverändert | Die einzigartige `actions: write`-Cleanup-Berechtigung bleibt eingegrenzt. |
| `five-connectors-with-crs-no-mrts-contract.yml` | nur Helper | Portabler no-MRTS-Contract bleibt read-only. |
| `lint.yml` | nur Helper | Framework-Lint-Target und Check-Name bleiben. |
| `test-common.yml` | auditiert, unverändert | Case-Materialisierung und Runner-Outputs bleiben unabhängig. |
| `update-submodules.yml` | gehärtet | First-Party-PR-Head-Identität ist jetzt explizit; nur `tools/MRTS`-Gitlink-Maintenance-Semantik bleibt. |
| `update-workflow-tools.yml` | auditiert, unverändert | Credential-free standalone Resolver bleibt; historisches API-Rate-Limit ist dokumentiert. |

Hinzugefügte oder angepasste Tests:

- `tests/ci_security/test_ci_security_contract.py`: Helper-Digest/-Referenz,
  Trusted-Base-OSV-Inline-Bootstrap und negative Controls für First-Party-PR-
  Identität.
- `tests/ci_security/test_common_version_review_reconciler.py`: Controls für
  übergroße Antworten, Aggregate-Byte/Anzahl und gewöhnliche Seiten.
- `tests/ci_security/test_five_connector_with_crs_no_mrts_contract.py`:
  Assertions für gemeinsamen Helper-Lock und `pip check`.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Locked `pip install --require-hashes -r requirements-ci.lock` | 0 | Bestehendes locked `PyYAML==6.0.3` erfüllt. | `/var/tmp/codex/ModSecurity-conector/workflow-consolidation-20260820` |
| `python -m pip check` | 0 | Keine defekten Requirements. | Derselbe Task-Evidence-Root. |
| `actionlint -shellcheck=… .github/workflows/*.yml` | 0 | Alle Workflow-YAML- und Shell-Steps bestehen. | Derselbe Task-Evidence-Root. |
| `zizmor --offline .github` | 0 | Keine reportable Findings; konfigurierte Suppressions bleiben. | Derselbe Task-Evidence-Root. |
| Unsafe-zizmor-Fixture | 14 (erwartet) | Dangerous-trigger/template-injection-Control wurde abgelehnt. | Derselbe Task-Evidence-Root. |
| Ruff-Check und Format-Check für CI-Scope | 0 | Nach Formatierung der berührten Python-Dateien sauber. | Derselbe Task-Evidence-Root. |
| `python -m unittest discover -s tests/ci_security -q` | 0 | 286 Tests bestanden. | Derselbe Task-Evidence-Root. |
| `ci/checks/security/check-ci-security-contract.py --root .` | 0 | CI-Security-Contract bestanden. | Derselbe Task-Evidence-Root. |
| `ci/checks/security/check-github-actions-workflows.py --check all` | 0 | Alle 17 Source-Workflows bestehen Pin- und Permissions-Checks. | Derselbe Task-Evidence-Root. |
| `ci/checks/security/check-workflow-action-pins.py` | 0 | Alle externen Actions verwenden volle Commit-SHAs. | Derselbe Task-Evidence-Root. |
| `ci/tools/safe-make.sh lint` | 0 | Vollständiges Framework-Lint und breitere Regression-/Dokumentations-Checks bestanden. | Derselbe Task-Evidence-Root. |
| `bash ci/tools/install-hash-locked-ci-dependencies.sh unexpected-argument` | 2 (erwartet) | Helper lehnte Argumente vor Paketarbeit ab. | Derselbe Task-Evidence-Root. |
| Hosted PR #101 OSV `pull-request-head` initialer Run | 127 | Trusted-Base-Checkout konnte PR-Head-Helper nicht sehen; schmale Inline-Bootstrap-Reparatur wartet auf neuen Exact-Head-Run. | [Run 32436667389](https://github.com/Easton97-Jens/ModSecurity-test-Framework/actions/runs/32436667389) |

## Sicherheitsauswirkung

Die Reconciliation-Remediation hat eine bestätigte Source-to-Sink-
Resource-Boundary-Lücke: öffentliche Issue-Bodies und Seitenergebnisse
erreichten In-Memory-Aggregation eines trusted Maintenance-Jobs ohne explizite
Byte-Limits. Der ursprüngliche unsichere Pfad ist durch fokussierte
Oversized-Response- und Aggregate-Controls abgedeckt; ein normaler
One-Page-Control bleibt akzeptiert. Source-Fix, fokussierte Tests, komplette
CI-Security-Suite und Framework-Lint bestehen lokal. Der Status bleibt lokal
`fixed`, bis Exact-PR-Head-Hosted-Evidence und Resulting-Master-Reproduktion
vorliegen.

Die PR-Head-Identity-Reparatur ist Security-Hardening für eine plausible
Availability/Correctness-Kollision. Source- und Contract-Mutation-Tests belegen
das neue Control; eine Live-Fork-Query-Reproduktion wird nicht behauptet. Eine
unabhängige read-only Final-Diff-Security-Prüfung fand keinen high-, critical-
oder Release-blocking-Defekt.

Die Hosted-OSV-Regression bestätigt, dass ein Trusted-Base-Job keinen
PR-Head-Helper nur zum Teilen des Setups beziehen darf. Die Reparatur erhält
den ursprünglichen überprüften Inline-Bootstrap und lässt den Security-Contract
fehlschlagen, wenn dieser Job den Helper aufruft; Token, Checkout-Erweiterung
oder Trust-Boundary-Änderung werden nicht verwendet.

## Dokumentation und Runtime-Evidenz

Dieser englische Change Record und sein vollständiges deutsches Gegenstück
dokumentieren Workflow-Matrix, Sicherheitsgrenze, Validierung, Einschränkung
und Rollback. Der sealed prompt-only Codex Security Scan wird außerhalb des
Repositorys unter
`/var/tmp/codex/ModSecurity-conector/workflow-consolidation-20260820/security-scan/`
aufbewahrt. Sein sealed Snapshot liegt vor einer reinen Warning-`CDPATH=''`-
ShellCheck-Portabilitätskorrektur im gemeinsamen Helper und dem dazugehörigen
Contract-Digest-Update; er wurde nicht rückwirkend verändert. Der finale
Source-Snapshot und seine fokussierten Post-Scan-Controls liegen unter
`/var/tmp/codex/ModSecurity-conector/workflow-consolidation-20260820/post-security-scan-validation.md`
(SHA-256 `7494c2b5b1b7fd785a5e60b72917172aaae9e5c5c928fd3873ccc1dff403a1ae`).
`bash -n`, ShellCheck, CI-Contract-/Workflow-/Pin-Checks, fokussiertes Ruff und
die CI-Security-Suite mit 286 Tests bestanden auf diesem finalen Source-
Snapshot. Der breitere `safe-make.sh lint`-Pass lief vor dieser rein
syntaktischen Korrektur und wird nur mit diesem exakten Scope berichtet.
Es wird kein Connector-Runtime-, Produktionsservice-, Parent-Change- oder
MRTS-Runtime-Claim gemacht.

## Nicht ausgeführte Prüfungen

- Lokales Pyright wurde nicht ausgeführt, weil Node.js nicht verfügbar ist
  (`node --version` Exit 1). Der locked hosted Quality-Workflow bleibt für
  PR-Readiness erforderlich.
- Hosted-PR-#101-Checks starteten auf dem initialen Exact Head. Sein OSV-
  `pull-request-head`-Job schlug mit Exit 127 fehl, weil der Trusted-Base-
  Checkout den PR-Head-Helper nicht enthielt; eine schmale lokale Reparatur ist
  fertig und ihr neuer Exact-Head-Hosted-Rerun bleibt erforderlich. SonarQube
  Cloud und ein Live-Fork-Collision-Szenario bleiben ebenfalls ausstehend/nicht
  ausgeführt.
- Kein Maintenance-Workflow wurde manuell dispatcht, da PR-getriggerte Checks
  die geänderten read-only Pfade abdecken und keine token-tragende
  Maintenance-Aktion für lokale Validierung benötigt wird.

## Einschränkungen und Restrisiko

Der standalone Workflow-Tool-Resolver kann weiterhin durch GitHubs
unauthenticated API-Quota rate-limited werden. Ein Token würde seine überprüfte
Credential-Grenze ändern und bleibt bewusst außerhalb dieser Änderung. Der neue
First-Party-PR-Filter verhindert eine Metadatenkollision konservativ; Hosted-
GitHub-Verhalten benötigt weiterhin Current-Head-Validierung. Die Helper-
Hash-Bindung ist ein Post-Execution-Contract-Control im bestehenden
Pull-Request-Workflow-Trust-Modell, kein unabhängiger Review-before-Execution-
Mechanismus.

## Finaler Diff- und Review-Status

Der initiale Framework-only Diff wurde mit `git diff --check`, Vorbereitung von
exaktem Path-Staging und einem Secret-Candidate-Review geprüft. Der Hosted-
OSV-Fehler erfordert einen separat geprüften Follow-up-Commit und vollständige
Current-Head-Validierung. Parent-Worktree, Parent-Gitlink und MRTS-Status
bleiben unverändert. Delivery bleibt ein Draft-PR nach `master`; kein Merge,
Force-Push, Settings-Change oder Default-Branch-Change ist autorisiert.
