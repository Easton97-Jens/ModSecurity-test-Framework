# Framework-PRs 39–41 konsolidieren

**Sprache:** [English](20260722-01-consolidate-framework-pr-39-41.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260722-01-consolidate-framework-pr-39-41` |
| UTC-Datum | 2026-07-22 |
| Framework-Basisrevision | `f73f8842f45318e2df8aff1d31855eeb7c20a22f` |
| Issue oder Pull Request | Quellen: Framework-PRs #39 (`0b0c20f686fcc2fd76a7035daf691bc17566d2e1`), #40 (`c274460a3e27b9fc0dfe904e1ce5eba33042f444`) und #41 (`f5e13dceeebc2b3c13248786861c6f1c984bb4a2`); Auslieferungsbranch: `agent/framework-pr-39-41-consolidation`. |

## Motivation und Problemstellung

Die freigegebene Python-3.13-Contract-Migration, die Workflow-Tool-
Provenienzhärtung und das PyYAML-Lower-Bound-Update werden zu einer prüfbaren,
Framework-eigenen Änderung verbunden. Die Abstimmung hat einen OSV-
Pull-Request-Bootstrap-Fehler (`FND-FRAMEWORK-0046`) und eine von der YAML-
Schreibweise abhängige Action-Lock-Umgehung (`FND-FRAMEWORK-0047`) offengelegt;
beide müssen vor der Integration behoben sein. Der lokale Workflow-Security-
Scanner fand außerdem eine direkte Repository-Metadaten-Template-Expansion im
token-tragenden Workflow-Tool-Publisher (`FND-FRAMEWORK-0048`), die in derselben
Konsolidierung behoben wird.

## Betroffene Komponenten und Sicherheitsgrenzen

Die Änderung bleibt im Framework-Repository: GitHub-Actions-Workflows,
CI-Security-Contract-Checker, Workflow-Tool-Updater, sein Lock, Tests und
englische/deutsche Sicherheitsdokumentation. Sie schützt die Grenze von
nicht vertrauenswürdigem PR-Head zu vertrauenswürdiger OSV-Basis, die immutable
Action-Provenienz unmittelbar vor tokenführenden Publishern und die kontrollierte
CI-Python-Versionsgrenze. Sie schützt außerdem die Repository-Default-Branch-
Metadatengrenze vor Shell-Parsing im schreibfähigen Workflow-Tool-Publisher.
Parent-Code, Gitlinks, Connector-Laufzeitverhalten und
die schreibgeschützte Grenze `tools/MRTS` werden nicht geändert.

## Akzeptanzkriterien

- Alle drei Quell-PR-Änderungen lassen sich sauber auf die verifizierte
  Framework-Basis anwenden.
- Jede `setup-python`-Auswahl verwendet die kanonische `.python-version`,
  ausgenommen die zwei ausdrücklich eingeschränkten Runner-Temporärdateien.
- Der OSV-PR-Job liest, begrenzt, validiert und schreibt die verifizierte
  Head-`.python-version` als Daten, ohne PR-Head-Source auszuchecken oder
  auszuführen.
- Jede geparste nicht lokale Action-Referenz ist an den überprüften Action-Lock
  gebunden, einschließlich Quoted-Key- und Flow-Mapping-Schreibweisen.
- Repository-Default-Branch-Metadaten erreichen Publisher-Shell-Code nur als
  überprüfte step-lokale Daten, werden vor Verwendung als Branch-Ref validiert
  und nicht direkt im Shell-Source expandiert.
- Publisher-Allowlist, Lock, Workflow-Referenzen, Tests und gepaarte
  Dokumentation bleiben konsistent.
- Lokale Contracts, fokussierte Tests, Dokumentationsprüfungen und finaler
  Diff-Review bestehen; gehostete Required Checks und das SonarQube-Cloud-Gate
  des resultierenden Masters bleiben vor der Master-Integration erforderlich.

## Untersuchte Alternativen

- Die Quell-PRs getrennt behalten. Verworfen, weil ihre überlappenden Action-,
  Python-Versions- und Lock-Änderungen einen gemeinsamen Contract-Review
  erfordern.
- Den OSV-Job durch PR-Head-Checkout wiederherstellen. Verworfen, weil in diesem
  vertrauenswürdigen Scanner-Pfad kein nicht vertrauenswürdiger PR-Code oder
  Workflow-Inhalt laufen darf.
- Sich ausschließlich auf Source-Zeilen `uses:` stützen. Verworfen, weil
  valides YAML äquivalente Keys oder Flow-Mappings ausdrücken kann, die ein
  Literal-Zeilen-Matching umgehen.
- Mutable Tags oder eine generische temporäre Versionsdatei-Ausnahme erlauben.
  Verworfen, weil dies entweder immutable Provenienz oder die PR-Datengrenze
  schwächt.

## Implementierungsentscheidung

Die Konsolidierung behält den vertrauenswürdigen Basis-Checkout und holt nur die
nummerierte PR-Head-Referenz nach SHA-Verifikation. Sie materialisiert einen
begrenzten, per Newline geprüften Wert `3.13.<patch>` einmalig im privaten
Runner-Temporärspeicher für OSV-`setup-python`; es wird kein Head ausgecheckt
oder ausgeführt. Der CI-Security-Contract untersucht nun rekursiv geparste
`uses`-Werte und vergleicht jeden externen Action-SHA mit
`security-tools.lock.yml`; die Raw-Source-/Kommentarvalidierung bleibt Defense
in Depth. Der Python-Version-Checker erlaubt die OSV-Datei nur für
`ci-security-osv.yml`/`pull-request-head` und die bestehende Kandidatendatei
nur im überprüften Validierungsjob. Der Action-Lock enthält die verifizierte
Tag-Bindung `peter-evans/create-pull-request` v8.1.1 und der Updater erlaubt den
passenden Python-Version-Workflow ausdrücklich. Der schreibfähige Workflow-
Tool-Publisher erhält seinen Default Branch über step-lokale `DEFAULT_BRANCH`-
Environment-Maps, validiert ihn mit `git check-ref-format --branch`, verwendet
gequotete Shell-Expansion und ist durch das exakte Publisher-Profil gebunden.

## Geänderte Dateien und Tests

- `.python-version`, ausgewählte Framework-Workflows, Makefile,
  `requirements-ci.lock` und `requirements-dev.txt` tragen den Python-3.13-
  Contract aus PR #39 und das PyYAML-Kompatibilitätsupdate aus PR #41.
- `ci/checks/security/check-ci-security-contract.py` und
  `ci/checks/security/check-python-version.py` implementieren die zwei
  eingeschränkten Remediations; `ci/tools/update-workflow-tools.py` behält die
  Updater-Härtung aus PR #40 und entfernt die gemeldeten Duplicate-Literal- und
  Always-Return-Smells.
- `ci/tooling/security-tools.lock.yml` und betroffene Workflow-Pins verwenden
  ein verifiziertes gemeinsames Action-Inventar, einschließlich des explizit
  erlaubten Python-Updater-Workflows.
- `tests/ci_security/test_ci_security_contract.py`,
  `tests/ci_security/test_framework_ci_security_contract.py` und
  `tests/ci_security/test_python_version_contract.py` sowie
  `tests/ci_security/test_update_workflow_tools.py` decken aktuelles gültiges
  Verhalten, die OSV-Ausnahmegrenze, Quoted-Key- und Flow-Mapping-
  Alternativumgehungen, die Zurückweisung einer abweichenden Voll-SHA und das
  eingeschränkte Publisher-Profil ab.
- Die nach der Veröffentlichung ergänzte Pyright-Korrektur gibt dem
  Release-URL-Validator vor dem Regular-Expression-Matching stabile
  String-Werte und typisiert die Test-Lock-Fixture entsprechend ihrer
  verschachtelten Datenform; Download-, Provenance-, Lock-, Publisher- und
  Berechtigungs-Controls werden nicht verändert.
- `docs/github-actions-workflow-security.{md,de.md}` und
  `docs/security/ci-security-tooling.{md,de.md}` dokumentieren korrigiertes
  Inventar, Sicherheitskontrollen und Token-/Checkout-Semantik.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `git ls-remote https://github.com/peter-evans/create-pull-request.git refs/tags/v8.1.1 refs/tags/v8.1.1^{}` | 0 | `v8.1.1` wurde auf `5f6978faf089d4d20b00c7766989d076bb2fc7f1` verifiziert. | Konsolidierungsrun `20260722T153352Z-framework-pr-39-41-consolidation-54ccc60e` |
| `python3 -B ci/checks/security/check-ci-security-contract.py --root .` | 0 | Aktueller Workflow- und Lock-Contract bestand nach der Remediation. | Derselbe Run, lokaler Framework-Worktree |
| `python3 -B ci/checks/security/check-python-version.py --root .` | 0 | Kanonischer CPython-Contract und enge OSV-Ausnahme bestanden. | Derselbe Run, lokaler Framework-Worktree |
| `python3 -B -m unittest -v tests.ci_security.test_ci_security_contract tests.ci_security.test_framework_ci_security_contract tests.ci_security.test_python_version_contract tests.ci_security.test_update_workflow_tools tests.ci_security.test_fetch_security_tool` | 0 | 85 fokussierte CI-Security-Tests einschließlich OSV-Bootstrap- und geparster-Action-Lock-Regressionen bestanden. | Derselbe Run, lokaler Framework-Worktree |
| `make test-ci-security-contract` | 0 | 124 CI-Security-Tests bestanden. | Derselbe Run, lokaler Framework-Worktree |
| `make test-makefile-contract`, `make test-workflow-action-pins` und `make test-workflow-contract` | 0 | Die 3 Makefile-, 25 Action-Pin- und 3 Workflow-Contract-Tests bestanden. | Derselbe Run, lokaler Framework-Worktree |
| `make check-documentation` und `make test-change-record-contract` | 0 | Dokumentationslinks, bilinguale Variablenchecks, Repository-Referenzen und alle 4 Change-Record-Contract-Tests bestanden. | Derselbe Run, lokaler Framework-Worktree |
| `make lint` | 0 | Das native aggregierte Lint-Ziel bestand: Shell-Syntax, Python-Kompilierung, Contracts, Security-Tests, Provenance-Regression-Suites und Dokumentationschecks. | Derselbe Run, lokaler Framework-Worktree |
| Prüfsummenverifiziertes `ruff check` / `ruff format --check` über den exakten CI-Quality-Scope | 0 | Lint bestand; alle 20 begrenzten Dateien sind formatiert. | Derselbe Run, `runner-temp/framework-ci-security-tools` |
| Prüfsummenverifiziertes `actionlint` und `zizmor --offline .github` | 0 | Workflow-Syntax bestand; Zizmor meldet keine aktiven Findings (26 behaltene Suppressions). | Derselbe Run, `runner-temp/framework-ci-security-tools` |

## Sicherheitsauswirkung

`FND-FRAMEWORK-0046` wird behoben, indem ein vertrauenswürdiger Basis-Checkout
beibehalten und Head-Daten erst nach Exact-Reference-Verifikation, begrenztem
Blob-Read, nicht überschreibendem Regular-File-Write und strikter
`3.13.<patch>`-Inhaltsvalidierung akzeptiert werden. Der ursprüngliche Pfad
einer fehlenden Basis-`.python-version` wird durch den isolierten Bootstrap
ersetzt; die alternative unsichere Remediation (PR-Head-Checkout oder
Ausführung) bleibt im Workflow-Contract ausgeschlossen.

`FND-FRAMEWORK-0047` wird durch geparste-YAML-Action-Lock-Enforcement behoben.
Der ursprüngliche literale unquoted-`uses:`-Pfad wird weiterhin auf den
Release-Kommentar geprüft; Quoted-Key- und Flow-Mapping-Actions mit
abweichender Voll-SHA scheitern jetzt am Lock-Vergleich. Die Regression-Suite
enthält beide alternativen Umgehungen und eine legitime Current-Lock-Kontrolle.
Kein Security-Control, Quality Gate, Branch-Protection-Regel oder Scanner wird
abgeschwächt.

`FND-FRAMEWORK-0048` wird behoben, indem Default-Branch-Metadaten aus dem
Publisher-Shell-Source in exakte `DEFAULT_BRANCH`-Environment-Maps verschoben
werden. Der Maintenance-Branch-Step validiert den Wert als Branch-Ref vor der
Ref-Konstruktion, während das gehashte Publisher-Profil die Source-Form
prüfbar hält. Ein prüfsummenverifizierter Pre-Fix-Zizmor-Scan meldete vier
Template-Injection-Findings; der Post-Fix-Scan meldet keine.

## Dokumentation und Runtime-Evidenz

Die gepaarten englischen/deutschen Workflow-Security- und CI-Tooling-Guides
beschreiben nun das aktuelle Action-Inventar, den read-only Common-Version-
Checker, den eingeschränkten OSV-Version-Bootstrap und den geparsten Action-
Lock-Control. Lokal wurde nur statische/Contract-Evidenz erfasst. Dieser
Framework-Record behauptet keine GitHub-Actions-, Connector-Runtime-, MRTS-,
Integrations- oder Lifecycle-Evidenz.

## Nicht ausgeführte Prüfungen

- Pyright konnte lokal nicht laufen, weil die erforderliche Node.js-Runtime
  fehlt; der eingecheckte Workflow provisioniert reviewed Node 24.18.0 vor dem
  Aufruf des prüfsummenverifizierten Pyright-Bundles.
- Der lokale Interpreter ist CPython 3.14.4, nicht die überprüfte Runtime
  3.13.14. Hosted CI muss das tatsächliche Runner-Verhalten beweisen.
- Ein Live-OSV-PR-Context-Run, Publisher-Verhalten, erforderliche GitHub-Checks
  und der SonarQube-Cloud-Status des resultierenden Masters sind Hosted-
  Evidenz und noch nicht beobachtet.
- Der veröffentlichte PR-#42-Head
  `22747d460a9f7be02760edf05c311be376492457` führte Hosted Pyright aus und
  scheiterte mit fünf Typdiagnosen: zwei wiederholte dynamische Dictionary-
  Lookups für Regular-Expression-Matching und eine als flache Object-Map
  typisierte Test-Lock-Fixture. Die eingegrenzte Folgekorrektur ist als
  `FND-FRAMEWORK-0049` erfasst; ihr neuer exakter Head muss Hosted Pyright und
  alle Required Checks erneut ausführen.
- Ein explorativer vollständiger `ruff check ci tests` ist nicht das Projekt-
  CI-Ziel und endet mit 54 Diagnosen außerhalb des CI-Security-Quality-Scopes;
  der oben genannte exakte begrenzte Befehl besteht. Diese Konsolidierung macht
  keine unabhängigen Formatierungs- oder Lint-Baseline-Änderungen.

## Einschränkungen und Restrisiko

Statische Controls und Unit-Tests können GitHubs Event-Kontext,
`runner.temp`-Dateisystemverhalten, Ref-Verfügbarkeit oder gehostete Branch
Protection nicht beweisen. Die Konsolidierung darf erst mergen, wenn ihr
exakter PR-Head die erforderlichen Hosted Checks besteht und die
SonarQube-Cloud-Anforderung des resultierenden Masters erfüllt oder vom
aktuellen User spezifisch risikakzeptiert ist. `FND-SONAR-0002` wird durch
diesen Record weder geschlossen noch erlassen.

## Finaler Diff- und Review-Status

Der kombinierte Branch hat seine begrenzten lokalen Contracts, Tests,
Dokumentationschecks, actionlint- und Offline-Zizmor-Scans bestanden. Es bleibt
die finale Exact-Diff-/Security-Evidence-Reconciliation, ein reviewbarer
Framework-PR, seine Exact-Head-Hosted-Checks und der normale protected-master-
Merge-Pfad. Es sind keine Parent-/MRTS-Änderungen enthalten und ein direkter
Master-Push wird nicht verwendet.
