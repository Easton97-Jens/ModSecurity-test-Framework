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
- `.github/workflows/check-action-versions.yml` und
  `.github/workflows/update-workflow-tools.yml`: nur auditiert. Quelltext,
  Permissions, Pins und Trigger werden durch diesen Record nicht geändert.

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
5. Ein nachfolgender PR-Head-`check-action-versions`-Run und ein
   `update-workflow-tools`-Run auf einem Non-default-Ref liefern aktuelle
   Hosted-Evidenz; der Updater-Publisher muss für diesen Proof-Run übersprungen
   werden.

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
wird geändert.

## Geänderte Dateien und Tests

- `ci/checks/security/check-ci-security-contract.py`: Eine gemeinsame
  `OSV_WORKFLOW`-Konstantenreferenz ersetzt zwei duplizierte Literale.
- `tests/ci_security/test_common_version_review_reconciler.py`: Bewahrt die
  Oversized-Response-Assertion mit einem Aufruf in ihrem Assertion-Kontext.
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
| Direkte Action-Version-Workflow-Prüfkette | 0 | Pins, CI-Sicherheitsvertrag/-evidenz, kanonische Python-/Workflow-Pins, Runtime-Komponenten und CRS-Views bestanden. | `framework-pr101-sonar-zero-20260821` |
| `ci/tools/safe-make.sh test-ci-security-contract` | 0 | Vollständige `tests/ci_security`-Suite: 286 Tests bestanden. | `evidence/ci-security-tests.log` |
| `git diff --check` | 0 | Kein Whitespace-Fehler. | Task-Worktree |
| Exakte Literalanzahl | 0 | `"ci-security-osv.yml"` kommt im reparierten Checker einmal vor. | Task-Worktree |
| `ci/tools/safe-make.sh lint` | 130 | Nach der registrierten Zwei-Minuten-Grenze abgebrochen; nicht als bestanden gezählt. | `evidence/make-lint.log` |

## Sicherheitsauswirkung

Es wird keine Security-Remediation beansprucht. Der betroffene Checker bleibt
ein sicherheitsrelevanter CI-Vertrag, deshalb sind seine unveränderten
positiven/mutierten Tests und die vollständige CI-Security-Suite die
legitimen Controls. Die Quelländerungen erweitern weder Credentials,
Permissions, vertraute Eingaben, Netzwerkziele, Download-Verhalten,
Publishing-Bedingungen noch die Parent-/MRTS-Grenze.

## Dokumentation und Runtime-Evidenz

Dieser englische Record und der passende deutsche Record sind die versionierten
Dokumentationsänderungen. Es erfolgten kein Connector-Runtime-, Service-,
Package-Installations-, Parent-, MRTS- oder Default-Branch-Workflow-Dispatch.
Aktuelle Hosted-Evidenz steht bis zum normalen Follow-up-Push des PR aus: Der
PR-Trigger von `check-action-versions` wird den reparierten Vertrag ausführen,
und ein Updater-Dispatch auf einem Non-default-Ref wird
Resolver/Validator/Outcome beweisen, während der Default-Branch-Publisher-
Guard den schreibfähigen Job überspringt.

## Nicht ausgeführte Prüfungen

- Das vollständige `lint`-Aggregat erreichte vor seiner registrierten
  Zeitgrenze keinen terminalen Pass und wird ausdrücklich nicht als bestanden
  gewertet.
- Kein Default-Branch-Updater-Dispatch wurde ausgeführt, weil er einen Branch
  und Draft-PR erstellen oder aktualisieren kann.
- Keine Credential-gebundene Resolver-Änderung, externe Package-Installation,
  Service-Ausführung, vollständige Connector-Matrix oder MRTS-Test war für
  diese enge Framework-only-Reparatur erforderlich.

## Einschränkungen und Restrisiko

Der unauthentifizierte Resolver des Updaters kann weiter ein GitHub-Public-
API-Rate-Limit treffen; der jüngste historische Default-Branch-Run tat dies.
Lokale Tests und ein isolierter Hosted-Run auf Non-default-Ref können seinen
read-only-Pfad beweisen, der schreibfähige Publisher-Pfad ist jedoch durch
historische erfolgreiche Runs belegt und wird hier nicht erneut ausgeführt.
Hosted Sonar und Current-Head-Checks bleiben erforderlich, bevor der PR als
verifiziert gelten kann.

## Finaler Diff- und Review-Status

Der fokussierte unstaged Diff enthält nur die zwei Reparaturen und dieses
Record-Paar. `git diff --check` bestand; keine Secret-haltigen Dateien oder
Parent-/MRTS-Pfade sind enthalten. Der nächste Status ist ein normaler
fokussierter Follow-up-Commit auf dem bestehenden PR-#101-Branch mit frischer
Exact-Head-Hosted-Validierung. Kein Merge, Force-Push, Settings-Wechsel,
Default-Branch-Wechsel oder Parent-Gitlink-Update ist autorisiert.
