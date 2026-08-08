# Change Record: PR-#67-SonarQube-Cloud-S1192-Duplizierung der Outcome-Bedingung beheben

**Sprache:** [English](20260808-04-remediate-pr67-sonar-s1192.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260808-04-remediate-pr67-sonar-s1192 |
| UTC-Datum | 2026-08-08 |
| Framework-Basisrevision | a8c7210fe57d4ff4fd0206c6d18554f63b0680b0 |
| Issue oder Pull Request | Framework-PR #67, fix/maintenance-publisher-outcomes nach master; der aktuelle User autorisierte die geschützte Framework-Master-Integration ausdrücklich, nachdem alle Gates bestanden sind. |

## Motivation und Problemstellung

Die aktuelle SonarQube-Cloud-Analyse von PR #67 meldet einen offenen
task-eigenen python:S1192-Code-Smell, AZ_i2zXawr7A0FAxa6fT. Seine Quality Gate
besteht, aber der PR kann keinen Status ohne offene task-eigene Befunde
beanspruchen, solange die Annotation offen ist. Der Befund meldet drei Kopien
der exakten Terminal-Outcome-Bedingung ${{ always() }} im CI-Sicherheitsvertrag.

## Betroffene Komponenten und Sicherheitsgrenzen

- ci/checks/security/check-ci-security-contract.py verwendet eine geprüfte
  Bedingung in den terminalen Outcome-Prüfungen für Python-Version,
  Workflow-Tool-Updater und Common-Version.
- Die Bedingung ist ein CI-Workflow-Trust-Boundary-Control: nur die exakte Form
  ${{ always() }} wird akzeptiert; fehlende, success(), fehlerhafte oder alternative
  Bedingungen bleiben fail-closed.
- Dies ist eine Wartbarkeitsreparatur, keine Sicherheitslückenbehebung. Keine
  Parent-Datei, kein Parent-Gitlink, keine MRTS-Quelle und kein MRTS-Gitlink
  ändern sich.

## Akzeptanzkriterien

1. Die drei Terminal-Outcome-Vergleiche verwenden eine modulweite
   ALWAYS_CONDITION-Konstante mit dem unveränderten exakten Literal ${{ always() }}.
2. Bestehende positive Workflow-Profile bestehen, und gleichgrenzige
   success()-Mutationen bleiben abgelehnt.
3. Es wird keine Sonar-Suppression, Exclusion, Regel-/Profil-/Gate-Änderung
   oder unzusammenhängende Refaktorierung eingeführt.
4. Aktuelle Exact-Head-Lokal-, Hosted-, SonarQube-Cloud-, Review-,
   Conversation- und Protection-Evidenz besteht vor dem autorisierten
   geschützten Merge.

## Untersuchte Alternativen

- Den Sonar-Befund zu unterdrücken oder zu akzeptieren wurde abgelehnt, weil
  der aktuelle User keine Suppression autorisierte und eine kleine native
  Reparatur möglich ist.
- Die eng benannte COMMON_VERSION_RESULT_IF-Konstante wiederzuverwenden wurde
  abgelehnt, weil das ihre Verwendung in nicht zugehörigen Python-Version- und
  Updater-Validierungspfaden verschleiern würde.
- Das Terminal-Workflow-Verhalten oder das akzeptierte Literal zu ändern wurde
  abgelehnt, weil das den geprüften CI-Sicherheitsvertrag verändern oder
  schwächen würde.

## Implementierungsentscheidung

ALWAYS_CONDITION ist der einzige modulweite Ausdruck für das geprüfte Literal
${{ always() }}. Die drei bestehenden Vergleiche referenzieren ihn nun. Die
semantische Akzeptanzmenge und Fehlerpfade sind unverändert.

## Geänderte Dateien und Tests

- ci/checks/security/check-ci-security-contract.py
- Dieser gepaarte englische/deutsche Change Record.

Die fokussierte Suite tests.ci_security.test_ci_security_contract deckt die
unveränderte positive Workflow-Kontrolle sowie negative Python-Version-,
Workflow-Tool-Updater- und Common-Version-Outcome-Bedingungsmutationen ab.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | ---: | --- | --- |
| Current-Head-Sonar-Check-, Annotation-, PR-Issue- und Source-Diff-Reads | 0 | Ein offener task-eigener python:S1192-Befund bestätigt; rohe API-Payloads wurden nicht gespeichert. | 20260808T200500Z-framework-pr67-sonar-s1192 |
| Explizite Framework-virtuelle-Umgebungsprüfung | 0 | Die gewählte Framework-.venv ist eine virtuelle Umgebung, und keine Abhängigkeit wurde installiert. | Lokaler Framework-Task-Worktree |
| python -m unittest tests.ci_security.test_ci_security_contract -v | 0 | 34 fokussierte positive und negative CI-Sicherheits-Contract-Tests bestanden nach der Reparatur. | Lokaler Framework-Task-Worktree |
| `make lint` mit der gewählten Framework-.venv und externen Task-Roots | 0 | Vollständiges repository-native Aggregat bestand, einschließlich Shell-/Python-Syntax, 142 CI-Sicherheits-Tests, Change-Record-/Dokumentations-Checks, Workflow-Contracts, Action-Pins und finalem `git diff --check`. | 20260808T200500Z-framework-pr67-sonar-s1192 |

## Sicherheitsauswirkung

Es wurde keine Security-Remediation durchgeführt. Der geänderte Checker
erzwingt sicherheitsrelevante Workflow-Kontrollen, daher wurden das
ursprüngliche positive Outcome-Job-Profil und die Ablehnung der alternativen
success()-Bedingung erneut ausgeführt. Die Reparatur fügt kein Token, Secret,
keine Permission, kein Workflow- oder Publish-Verhalten hinzu.

## Dokumentation und Runtime-Evidenz

Dieser gepaarte Change Record und FND-FRAMEWORK-0062 dokumentieren den
Sonar-Befund. Es wurde keine Connector-Runtime, GitHub-App-Installation,
kein Credential-Wert, kein roher Hosted-Log, keine Parent- oder MRTS-Evidenz
erfasst oder geändert.

## Nicht ausgeführte Prüfungen

Current-Head-Hosted-Checks, SonarQube-Cloud-Readback nach dem Follow-up-Push,
Reviews, Conversations, Branch-Protection-Evidenz und resultierende-Master-
Workflow-Checks sind bis zum normalen Task-Branch-Commit und Push offen. Sie
werden nicht aus dem älteren PR-Head abgeleitet. Kein lokaler Check wurde als
Ersatz für diese Hosted-Gates verwendet.

## Einschränkungen und Restrisiko

Der exakte Befund schließt erst, wenn eine frische SonarQube-Cloud-Analyse für
den Follow-up-PR-Head seine Abwesenheit meldet. Die erforderliche geschützte
Master-Integration bleibt außerdem von allen Current-Head-Review-, Protection-
und Post-Merge-Verifikationsgates abhängig.

## Finaler Diff- und Review-Status

Der Source-Diff ist bewusst auf eine gemeinsame Bedingungskonstante und drei
Referenzen beschränkt. Fokussierte positive/negative Validierung und das
vollständige lokale Aggregat bestanden, einschließlich Whitespace-,
Dokumentations-, Change-Record- und Workflow-Contract-Checks. Finaler
Secret-/Diff-Review sowie Hosted-, Sonar-, Review-, Merge- und
resultierende-Master-Evidenz stehen noch aus. Keine Suppression oder sensiblen
Werte sind dokumentiert.
