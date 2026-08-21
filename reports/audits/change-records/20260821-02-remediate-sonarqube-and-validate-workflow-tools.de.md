# Change Record

**Sprache:** [English](20260821-02-remediate-sonarqube-and-validate-workflow-tools.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260821-02-remediate-sonarqube-and-validate-workflow-tools` |
| UTC-Datum | 2026-08-21 |
| Framework-Basisrevision | `414149cf7b73abacd65db67ed290f46f2c98e59c` |
| Issue oder Pull Request | [Framework-PR #101](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/101) nach `master` |

## Motivation und Problemstellung

Obwohl die Quality Gate bestand, hatte der exakte initiale Head von PR #101
zwei offene SonarQube-Cloud-New-Issues. Der Nutzer verlangt für diese Zahl
null sowie Evidenz dafür, dass der GitHub-Action-Version-Checker und der
Pinned-Tool-Updater funktionieren. Die Befunde sind task-eigene Python-
Wartbarkeitsbefunde und kein Sonar-Konfigurationsproblem: einer wiederholt das
exakte OSV-Workflow-Literal, ein Test enthält zwei möglicherweise auslösende
Aufrufe in einem `assertRaises`-Body.

## Betroffene Komponenten und Sicherheitsgrenzen

- `ci/checks/security/check-ci-security-contract.py`: Framework-
  CI-Sicherheitsvertrag; unveränderliche Action-Pins, hash-locked
  Dependency-Bootstrap und Workflow-Permissions müssen ihr exaktes Verhalten
  behalten.
- `tests/ci_security/test_common_version_review_reconciler.py`: fail-closed
  Regressionstest für die GitHub-Response-Größe.
- `ci/tools/update-workflow-tools.py` und
  `tests/ci_security/test_update_workflow_tools.py`: der private
  Proposed-Tree-Validierungskontext des Updaters und seine direkte
  Regressionstestabdeckung.
- `.github/workflows/check-action-versions.yml` und
  `.github/workflows/update-workflow-tools.yml`: nur auditiert. Quelltext,
  Permissions, Pins, Trigger, Checkout-Semantik und Publisher-Policy werden
  durch diesen Record nicht geändert.

Parent-Quelltext und Gitlink bleiben unverändert. MRTS ist standardmäßig
read-only, unverändert und im Task-Worktree nicht initialisiert.

## Akzeptanzkriterien

1. Der finale Head von PR #101 meldet null offene SonarQube-Cloud-New-Issues,
   ohne Regel-, Profil-, Quality-Gate-, Exclusion- oder Suppression-Änderung.
2. Der OSV-Workflowname hat genau eine modulweite Literaldefinition und das
   bestehende CI-Sicherheitsvertragsverhalten bleibt erhalten.
3. Der Response-Größen-Test enthält genau einen möglicherweise auslösenden
   Aufruf in seiner Exception-Assertion und bewahrt seinen fail-closed Control.
4. Der lokale Action-Version-Vertrag und die vollständige CI-Security-Suite
   bestehen.
5. Ein nachfolgender PR-Head-`check-action-versions`-Run besteht, während ein
   `update-workflow-tools`-Run auf einem Non-default-Ref den Resolver beweist
   und seinen Publisher strukturell überspringt. Sein Proposed-Tree-Validator
   muss alle festen, read-only kanonischen Eingaben erhalten, die die geprüften
   Verträge verlangen.

## Untersuchte Alternativen

- Die beiden Sonar-Befunde akzeptieren, unterdrücken, eine Regel/ein Profil
  ändern, `NOSONAR` hinzufügen oder Code ausschließen: verworfen. Jede Option
  versteckt einen echten, einfach behebbaren task-eigenen Defekt und verletzt
  die verlangte Nullzahl.
- Den Updater-Resolver auf `GITHUB_TOKEN` umstellen: für diese Reparatur
  verworfen. Das würde eine geprüfte Credential-Grenze verändern; der Updater
  hat bereits einen sicheren Non-default-Ref-Validierungspfad und eine
  getrennte Sicherheitsentscheidung wäre für eine Credential-Erweiterung
  erforderlich.
- Den Updater auf `master` dispatchen: verworfen. Bei einem verfügbaren Update
  kann sein Publisher einen Maintenance-Branch und Draft-PR erstellen oder
  verändern.

## Implementierungsentscheidung

Die vorhandene Konstante `OSV_WORKFLOW` wird neben die Map der
CI-Dependency-Installer-Workflows verschoben und für den Map-Eintrag sowie den
Scanner-Branch verwendet. Literal und jedes akzeptierte Verhalten bleiben
identisch. Der Reconciler-`GitHubClient` wird vor der Exception-Assertion
angelegt, sodass nur `request()` in `assertRaises` verbleibt. Kein
Workflow-Quelltext, Action-Pin, Dependency, Permission, Token oder Trigger
wird geändert. `ALLOWED_UPDATE_PATHS` des Updaters bleibt seine vollständige
Publisher-Write-Allowlist. Ein getrenntes, festes
`PROPOSED_VALIDATION_INPUT_PATHS` fügt nur `ci/lib/common.sh` und
`ci/tools/install-hash-locked-ci-dependencies.sh` zum temporären
Validierungs-Input-Tree hinzu. Dies sind read-only Checker-Inputs: Sie sind
weder für Candidate-Änderungen noch für Staging oder Publishing zulässig.

## Geänderte Dateien und Tests

- `ci/checks/security/check-ci-security-contract.py`: Eine gemeinsame
  `OSV_WORKFLOW`-Konstantenreferenz ersetzt zwei duplizierte Literale.
- `tests/ci_security/test_common_version_review_reconciler.py`: Bewahrt die
  Oversized-Response-Assertion mit einem Aufruf in ihrem Assertion-Kontext.
- `ci/tools/update-workflow-tools.py`: kopiert die zwei festen kanonischen
  Helper-Inputs, die für die Validierung eines Proposed Tree nötig sind, ohne
  die Publisher-Allowlist zu erweitern.
- `tests/ci_security/test_update_workflow_tools.py`: fügt einen echten
  Tool-only-Proposed-Tree-Validator-Regressionstest hinzu, der ohne diese
  read-only Inputs scheitern würde.
- Dieser englische Record und sein vollständiger deutscher Begleiter
  dokumentieren Reparatur und Grenzen.

Bestehende direkte Tests decken die positiven und mutierten CI-Sicherheits-
Pfade, den fail-closed Response-Größen-Pfad, die Trennung von Updater-
Resolver/Validator/Publisher, Publisher-Scope, No-update-Verhalten und
vollständige SHA-Action-Pins ab.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Fokussierte Drei-Datei-Unittest-Suite | 0 | 91 Tests bestanden, einschließlich beider reparierter Verträge und Updater-Tests. | `framework-pr101-sonar-zero-20260821` |
| Direkte Action-Version-Workflow-Prüfkette | 0 | Pins, CI-Sicherheitsvertrag/-evidenz, kanonische Python-/Workflow-Pins, Runtime-Komponenten und CRS-Views bestanden nach der Updater-Korrektur. | `evidence/workflow-contract-chain-after-updater-fix.log` |
| `tests.ci_security.test_update_workflow_tools` | 0 | 35 Tests bestanden, einschließlich der neuen Tool-only-Proposed-Tree-Regression. | `evidence/test-update-workflow-tools-after-context-fix.log` |
| `ci/tools/safe-make.sh test-ci-security-contract` | 0 | Vollständige `tests/ci_security`-Suite: 287 Tests bestanden. | `evidence/test-ci-security-contract-after-updater-fix.log` |
| PR-Head-`check-action-versions`-Run `32448256402` | 0 | Alle Hosted-Schritte bestanden für `4ab08112debe3162bee4b4d07b12b931ce8891c8`. | GitHub Actions |
| SonarQube-Cloud-PR-Abfrage | 0 | `total: 0`, leere Issue-Liste für PR #101 am vorherigen reparierten Head. | `framework-pr101-sonar-zero-20260821` |
| Non-default-Updater-Run `32448284801` | 2 | Resolver bestand und Publisher wurde übersprungen; Validator scheiterte fail-closed, weil seinem Proposed Tree die zwei kanonischen Helper-Inputs fehlten. | `evidence/workflow-updater-proposed-tree-failure.md` |
| `git diff --check` | 0 | Kein Whitespace-Fehler. | Task-Worktree |
| Exakte Literalanzahl | 0 | `"ci-security-osv.yml"` kommt im reparierten Checker einmal vor. | Task-Worktree |
| `ci/tools/safe-make.sh lint` | 130 | Nach der registrierten Zwei-Minuten-Grenze abgebrochen; nicht als bestanden gezählt. | `evidence/make-lint.log` |

## Sicherheitsauswirkung

Es wird keine Security-Remediation beansprucht. Der betroffene Checker bleibt
ein sicherheitsrelevanter CI-Vertrag, deshalb sind seine unveränderten
positiven/mutierten Tests und die vollständige CI-Security-Suite die
legitimen Controls. Die Quelländerungen erweitern weder Credentials,
Permissions, vertraute Eingaben, Netzwerkziele, Download-Verhalten,
Publishing-Bedingungen, Publisher-Write-Scope noch die Parent-/MRTS-Grenze.
Der Updater kopiert die neuen Dateien weiter über seinen vorhandenen
Regular-File- und Symlink-resistenten Resolver; der CI-Checker parst
`common.sh`, ohne sie auszuführen.

## Dokumentation und Runtime-Evidenz

Dieser englische Record und der passende deutsche Record sind die versionierten
Dokumentationsänderungen. Es erfolgten kein Connector-Runtime-, Service-,
Package-Installations-, Parent-, MRTS- oder Default-Branch-Workflow-Dispatch.
Der vorherige reparierte Head hat Hosted-Sonar-Evidenz mit null Issues und
einen erfolgreichen `check-action-versions`-Run. Der sichere Updater-Dispatch
legte einen echten Validierungskontextdefekt offen und übersprang dabei korrekt
den schreibfähigen Publisher. Der korrigierte Quelltext ist lokal bewiesen und
wartet auf einen normalen Follow-up-Push des PR sowie frische Current-Head-
Checks.

## Nicht ausgeführte Prüfungen

- Das vollständige `lint`-Aggregat erreichte vor seiner registrierten
  Zeitgrenze keinen terminalen Pass und wird ausdrücklich nicht als bestanden
  gewertet.
- Kein Default-Branch-Updater-Dispatch wurde ausgeführt, weil er einen Branch
  und Draft-PR erstellen oder aktualisieren kann.
- Der Hosted-Updater kann diese Quelltextkorrektur auf dem PR-Ref noch nicht
  ausführen: Sein geprüfter Workflow checkt absichtlich `master` aus. Ein
  Re-run vor einem autorisierten Merge würde den alten Default-Branch-Updater
  statt des korrigierten PR-Codes ausführen. Dies wird als sichere
  Proof-Einschränkung festgehalten und nicht durch geänderte Checkout-,
  Credential- oder Publisher-Bedingungen umgangen.
- Keine Credential-gebundene Resolver-Änderung, externe Package-Installation,
  Service-Ausführung, vollständige Connector-Matrix oder MRTS-Test war für
  diese enge Framework-only-Reparatur erforderlich.

## Einschränkungen und Restrisiko

Der unauthentifizierte Resolver des Updaters kann weiter ein GitHub-Public-
API-Rate-Limit treffen. Unmittelbarer zeigte der sichere Hosted-Run, dass dem
alten Default-Branch-Updater zwei read-only Validierungs-Inputs fehlen; die
enge PR-Quelltextkorrektur kann erst nach einem autorisierten Merge ein
Exact-Hosted-Updater-Success-Ergebnis erhalten. Der schreibfähige Publisher
bleibt absichtlich unausgeführt. Frische Hosted-Sonar- und PR-Checks bleiben
für den finalen Follow-up-Head erforderlich.

## Finaler Diff- und Review-Status

Der fokussierte unstaged Diff enthält die zwei Sonar-Reparaturen, die enge
Updater-Validierungs-Input-Korrektur, ihren direkten Test und dieses
Record-Paar. `git diff --check` bestand; keine Secret-haltigen Dateien oder
Parent-/MRTS-Pfade sind enthalten. Der nächste Status ist ein normaler
fokussierter Follow-up-Commit auf dem bestehenden PR-#101-Branch mit frischer
Exact-Head-Sonar- und PR-Check-Validierung. Kein Merge, Force-Push,
Settings-Wechsel, Default-Branch-Wechsel oder Parent-Gitlink-Update ist
autorisiert.
