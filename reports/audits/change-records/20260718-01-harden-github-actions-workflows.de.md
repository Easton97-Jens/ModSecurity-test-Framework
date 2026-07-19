# Change Record: 20260718-01-harden-github-actions-workflows

**Sprache:** [English](20260718-01-harden-github-actions-workflows.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260718-01-harden-github-actions-workflows` |
| UTC-Datum | 2026-07-18 |
| Framework-Basisrevision | `9954b99a31fab0006cdf903ab477c8158c50fea8` |
| Issue oder Pull Request | Framework-PR #29; Master-Integration ist erst nach frischen Exact-Head-Checks und Review autorisiert. |

## Motivation und Problemstellung

Die Framework-Workflows verwendeten veränderliche Action-Major-Version-Tags
und einen Inline-Pin-Check, der solche Tags akzeptierte und `.yaml`-Workflows
ignorierte. Vier direkte Checkouts behielten Credentials standardmäßig bei,
und ein vertrauenswürdiger Wartungsworkflow gab ein schreibfähiges
`GITHUB_TOKEN` an jeden Job-Schritt weiter. Diese Bedingungen schwächen die
Action-Lieferkette und die GitHub-Actions-Vertrauensgrenze.

## Betroffene Komponenten und Sicherheitsgrenzen

Diese Framework-eigene Änderung aktualisiert alle fünf
`.github/workflows/`-Dateien, ihren quellcodeverwalteten Validierungsvertrag,
fokussierte Fixtures und gepaarte Anleitung. Sie betrifft unveränderliche
Drittanbieter-Action-Auswahl, Workflow-/Job-Berechtigungen,
Checkout-Credential-Persistenz, Pull-Request-Ausführung, Secret-Referenzen,
Submodule, YAML-Parsing und Token-Exposition. Sie ändert keinen Connector,
keine Parent-Produktdatei oder keinen Gitlink, keinen MRTS-Quellcode oder
Gitlink, keinen Artifact-Upload, SARIF-Upload, CodeQL-Upload oder Default-
Branch.

## Akzeptanzkriterien

1. Jede Framework-Remote-Action verwendet ihren validierten 40-stelligen
   offiziellen Release-SHA in Kleinbuchstaben mit einem benachbarten
   Release-Kommentar.
2. Jeder Workflow hat standardmäßig `contents: read`; vertrauenswürdige
   Write-Berechtigungen sind nur dem notwendigen Job zugeordnet.
3. Jeder direkte Checkout deaktiviert persistierte Credentials, PR-Workflows
   besitzen keinen Write-, Secret- oder Submodule-Pfad und
   `pull_request_target` ist verboten.
4. Der Pin- und Berechtigungsvertrag deckt `.yml`- und `.yaml`-Workflows ab
   und besitzt Regressionsevidenz für echte Workflows sowie sichere und
   unsichere Fixtures.
5. Englische/deutsche Anleitung und dieser Change Record beschreiben
   identische Action-Provenienz, Vertrauensgrenzen, Validierung,
   Einschränkungen und Scope.
6. Es dürfen nur der autorisierte normale Framework-Commit, Push, PR-Integration
   und die Exact-Head-Gate-Sequenz verwendet werden; Parent-Gitlink-Update oder
   MRTS-Änderung sind nicht erlaubt.

## Untersuchte Alternativen

- Das Beibehalten von Major-Version-Tags wurde verworfen, weil ein Tag nach
  dem Review verschoben werden kann und der ursprüngliche Validator ihn
  nachweislich akzeptierte.
- Das Duplizieren des alten Inline-Shell-/Python-Checks wurde verworfen, weil
  er `.yaml` ausließ, keine Provenienzkommentare erzwang und nicht
  unit-testbar war.
- Das Entfernen des vertrauenswürdigen Updaters oder des Artifact-Cleanup-
  Workflows wurde verworfen, weil ihre Funktionen notwendig bleiben;
  Job-lokale Berechtigungen erhalten sie mit weniger Standardautorität.
- Das Geben von Write-Berechtigungen oder Secrets an einen PR-Job wurde
  verworfen, weil PR-Quellcode einschließlich Fork-Quellcode standardmäßig
  nicht vertrauenswürdig ist.

## Implementierungsentscheidung

Die fünf Action-Referenzen verwenden jetzt geprüfte SHAs für
`actions/checkout` `v7.0.0`, `actions/setup-python` `v6.3.0`,
`actions/github-script` `v9.0.0` und `peter-evans/create-pull-request`
`v8.1.1`, jeweils aus ihrem offiziellen MIT-Upstream und in der gepaarten
Anleitung dokumentiert.

`ci/checks/security/check-github-actions-workflows.py` trennt einen
Standardbibliothek-Pin-Modus von einem PyYAML-Berechtigungs-/Vertrauensgrenzen-
Modus. Er weist veränderliche oder dynamische Remote-Referenzen, fehlende
Release-Kommentare, Block-Scalar-`uses`-Werte, YAML-Flow-Collections, explizite
Mapping-Keys, YAML-Tags/Anker/Aliase/Merge-Keys in Key- oder Value-Position,
escapte doppelt zitierte Mapping-Keys, YAML-Dokumentmarker auch nach einem
UTF-8-BOM sowie doppelte/
verankerte/aliasierte/gemergte YAML,
`pull_request_target`, PR-Writes, Secret-Referenzen, Secret-
Weitergabe an wiederverwendbare Workflows, Workflow- oder Job-Level-Umgebungen,
die `github.token` unter irgendeinem Namen bereitstellen, Credential-Persistenz
und PR-Submodule zurück. Das Makefile exportiert unabhängige Pin- und
Berechtigungs-Targets und der vorhandene Workflow-Self-Check läuft bei
Änderungen seines Checkers, seiner Fixtures, seines Tests oder des Makefiles.

Die aktuelle Abgleichung basiert auf `9954b99a31fab0006cdf903ab477c8158c50fea8`.
Sie behält den bereits gemergten Action-Pin-Checker und seine Regression-Suite
bei, während der kanonische Checker verschachtelte `.yml`- und `.yaml`-
Workflow-Pfade rekursiv abdeckt. Vor dem Lesen einer Datei muss ihr aufgelöster
Pfad unterhalb der aktuellen Repository-Wurzel bleiben; ein über einen Symlink
ausbrechender Pfad wird übersprungen. Fokussierte Regressionen beweisen sowohl
verschachtelte Discovery als auch die Containment-Ablehnung.

`check-common-versions` bleibt trusted-only und besitzt Job-lokale
Repository-Content- und Pull-Request-Write-Berechtigungen. Seine Shell-
Umgebung `GITHUB_TOKEN` ist auf den Update-Schritt begrenzt; GitHub-
Berechtigungen bleiben Job-spezifisch, sodass dies die direkte Shell-
Exposition reduziert, aber keine nicht vorhandene Schritt-
Berechtigungsprimitive erzeugt. `cleanup-artifacts` behält nur Job-lokales
`actions: write`.

### 2026-07-19 CI-Security-Kompatibilitätsabgleich

Die Synchronisierung von PR #27 mit Framework-Master
`7a12073c28e62a67492dd501b6513b9914fe5df8` machte zuvor nicht validierte
CI-Security-Workflows sichtbar, die der kanonische Checker zu Recht
fail-closed zurückwies: Flow-Style-Event-Collections sind keine akzeptierte,
reviewbare Workflow-Syntax und ein CodeQL-`pull_request`-Job besaß
`security-events: write`. Der Validator wurde nicht gelockert.

Die Korrektur verwendet für nicht vertrauenswürdige Pull Requests den
read-only-Workflow `ci-security-codeql-pr.yml` mit exaktem PR-Head. Er
deaktiviert sowohl den CodeQL-Ergebnis- als auch den Datenbank-Upload. Der
bestehende Workflow `ci-security-codeql.yml` ist nun ausschließlich ein
vertrauenswürdiger Uploader (`push` auf `master`, Zeitplan und manueller
Dispatch) und der einzige Workflow mit der eng begrenzten
`security-events: write`-Berechtigung. Alle betroffenen Event-Collections
verwenden kanonisches Block-YAML. `cleanup-artifacts` deklariert die
kanonische Top-Level-Baseline `contents: read` und behält `actions: write`
auf seinen notwendigen Job begrenzt. CI-Security-Evidence- und Contract-
Regressionen weisen sowohl einen PR-ausgelösten vertrauenswürdigen Uploader
als auch eine PR-Write-Berechtigung zurück; die legitimen read-only-PR- und
Trusted-Writer-Controls bleiben abgedeckt. Dieser Abgleich wird als erneut
geöffnetes Least-Privilege-Finding `FND-FRAMEWORK-0013` und als separates
Strict-YAML-Contract-Finding `FND-FRAMEWORK-0019` verfolgt, bis lokale und
frische Exact-Head-Verifikation abgeschlossen sind.

## Geänderte Dateien und Tests

Versionierte Framework-Änderungen:

- `.github/workflows/check-action-versions.yml`,
  `.github/workflows/check-common-versions.yml`,
  `.github/workflows/cleanup-artifacts.yml`, `.github/workflows/lint.yml` und
  `.github/workflows/test-common.yml`.
- `ci/checks/security/check-github-actions-workflows.py` und
  `ci/checks/documentation/check-workflow-yaml.py`.
- `Makefile` und
  `tests/security_regression/test_workflow_security_contract.py`.
- `tests/fixtures/workflow_security_contract/` mit sicheren und unsicheren
  Fixtures.
- `docs/github-actions-workflow-security.md` und die deutsche Begleitdatei,
  die gepaarten Dokumentationsindizes und dieses Change-Record-Paar.

Die Regression-Suite validiert alle echten Workflows, sichere Read-only-PR-
und Trusted-Writer-Fälle sowie unsichere veränderliche/dynamische Referenzen,
`.yaml`, fehlende Kommentare, Block-Scalar-`uses`-Werte, YAML-Flow-Collections,
explizite Mapping-Keys, YAML-Tags/Anker/Aliase/Merge-Keys in Key- oder Value-
Position, escapte doppelt zitierte Mapping-Keys, YAML-Dokumentmarker auch nach
einem UTF-8-BOM und doppelte YAML,
`pull_request_target`, Berechtigungs-, Credential-, Workflow-/Job-Token-
Exposition unter üblichen oder umbenannten Variablen, Submodule-, Secret-
Referenz- und Secret-Weitergabe-Fälle, verschachtelte Workflow-Discovery sowie
Symlink- oder explizite Root-Pfade, die die aktuelle Repository-Wurzel
verlassen.

## Befehle und Ergebnisse

Alle schreibfähigen Befehle verwendeten einen registrierten Nachfahren des
Task-Runs; sensible Werte und lokale Workstation-Pfade werden absichtlich nicht
in diesem Record aufgeführt.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | ---: | --- | --- |
| `rtk env <registered roots> python3 ci/checks/security/check-github-actions-workflows.py --check all` | 0 | Alle fünf echten Workflows bestanden Immutable-Pin- und Berechtigungs-/Vertrauensprüfungen | `20260718T081429Z-framework-workflow-hardening-320e9322` |
| `rtk env <registered roots> python3 -m unittest discover -s tests/security_regression -p 'test_workflow_security_contract.py' -v` | 0 | 4 Tests bestanden, einschließlich sicherer und unsicherer Fixtures | `20260718T081429Z-framework-workflow-hardening-320e9322` |
| `rtk env <registered roots> make check-documentation` | 0 | Links, Zweisprachigkeit und Repository-Pfad-Referenzen bestanden | `20260718T081429Z-framework-workflow-hardening-320e9322` |
| `rtk env <registered roots> make lint` | 0 | Vollständiger Framework-Static-Lint, Workflow-Vertrag, Fixtures, Katalog-, Dokumentations- und Diff-Checks bestanden | `20260718T081429Z-framework-workflow-hardening-320e9322` |
| `rtk shellcheck -x ci/lib/common.sh ci/checks/catalog/check-common-helpers.sh` | 1 | Bestehende Warnungen wurden im sauberen Framework-Checkout unverändert reproduziert | Bestehender `FND-FRAMEWORK-0002`-Kontext; kein task-eigener Quellcode geändert |
| `rtk actionlint --version` | 127 | Blockiert: `actionlint` ist nicht installiert; kein Tool wurde bereitgestellt | Lokale Umgebungsevidenz |
| `rtk zizmor --version` | 127 | Blockiert: `zizmor` ist nicht installiert; kein Tool wurde bereitgestellt | Lokale Umgebungsevidenz |
| Wörtlicher `test-common / common-structure`-Count-Guard über `rtk` | 1 | Bestehende Baseline `expected 141 YAML cases, found 179` reproduziert | `FND-FRAMEWORK-0001`; Task-Run-Evidenz `common-structure-baseline-recheck.md` |
| `rtk gh run list --workflow test-common.yml --branch master --limit 5 --json ...` | 0 | Der aktuelle `master`-Run `29527830684` ist bereits bei der Basisrevision fehlgeschlagen | `FND-FRAMEWORK-0001` |
| `rtk git diff --check` | 0 | Keine Whitespace-Fehler zum dokumentierten Review-Zeitpunkt | Nicht zutreffend |

## Sicherheitsauswirkung

Dies ist eine Security-Remediation. Die Akzeptanz eines veränderlichen `@v7`
und das Auslassen von `.yaml` durch den ursprünglichen Validator wurden vor dem
Patch reproduziert; der neue Validator weist beides zurück. Regression-
Fixtures testen auch alternative Umgehungen erneut: dynamische Referenzen,
fehlende Versionskommentare, Block-Scalar-`uses`-Werte, YAML-Flow-Collections,
explizite Mapping-Keys, YAML-Tags/Anker/Aliase/Merge-Keys in Key- oder Value-
Position, escapte doppelt zitierte Mapping-Keys, YAML-Dokumentmarker auch nach
einem UTF-8-BOM, doppelte YAML, breite Berechtigungen, Workflow-/Job-weite
Token-Exposition unter
üblichen oder umbenannten Variablen, `pull_request_target`, PR-Secrets
einschließlich Secret-Weitergabe an wiederverwendbare Workflows sowie statische
oder dynamische Submodule. Der
aufbewahrte Scan enthält neun Report-Instanzen; der Workflow-Vertrag schließt
ihre direkten Quellpfade, ohne erforderliches vertrauenswürdiges Updater- oder
Cleanup-Verhalten zu entfernen.

## Dokumentation und Runtime-Evidenz

Die gepaarte Anleitung dokumentiert Action-Provenienz, exakte Versionen und
SHAs, Berechtigungen, Fork-PR-Modell, Local-Action-Behandlung,
Artifact-/SARIF-Inventar, Pin-Update-Verfahren und Tool-Einschränkungen.
Dieser Change Record ist ein vollständiges englisches/deutsches Paar.

Es wurde keine Connector-Runtime- oder Lifecycle-Evidenz erfasst, weil diese
Änderung auf statische GitHub-Actions-Konfiguration und Validierung begrenzt
ist. Statische Workflow-Tests sind kein Beleg dafür, dass GitHub-gehostete
Lifecycle-Controls gelaufen sind.

## Nicht ausgeführte Prüfungen

- Current-Head-GitHub-Actions, CodeQL, Scorecard, SonarQube Cloud, Review und
  Review-Thread-Checks stehen bis zum autorisierten Draft PR aus.
- `actionlint` und `zizmor` sind blockiert, weil keines der Executables lokal
  installiert ist; kontrollierte Tool-Bereitstellung war nicht Teil dieser
  Änderung.
- Das wörtliche `test-common / common-structure`-Workflow-Gate scheitert an
  der bestehenden `FND-FRAMEWORK-0001`-Baseline, nicht an diesem Diff.
- Connector-Runtime, CRS/MRTS-Matrizen, Aktualisierung generierter Berichte
  und C/C++-Builds sind für eine statische Framework-Workflow-only-Änderung
  nicht zutreffend und würden den autorisierten Scope erweitern.

## Einschränkungen und Restrisiko

Der Repository-Checker ergänzt GitHub-Branch-Protection, menschliches
Workflow-Review, Upstream-Release-Verifikation, actionlint, zizmor, CodeQL,
Scorecard und SonarQube Cloud, ersetzt sie aber nicht. Eine Job-Berechtigung
kann in GitHub Actions nicht pro Schritt eingeschränkt werden; vertrauenswürdige
Writer-Jobs bleiben daher auf Nicht-PR-Trigger beschränkt. Das bekannte
vorbestehende `FND-FRAMEWORK-0001`-Gate kann `verified_pr` blockieren, selbst
wenn die Controls dieses Tasks und andere PR-Checks bestehen. Kein Risiko wurde
akzeptiert und keine Security-Control wurde geschwächt.

## Finaler Diff- und Review-Status

Der Pre-Commit-Framework-Diff wurde auf Scope, unveränderliche Pins,
Berechtigungszuordnungen, Credential-Persistenz, Testabdeckung,
Vermeidung generierter Dateien, Whitespace und sensible Inhalte geprüft. Der
Parent und sein Gitlink, MRTS und sein Gitlink sowie jeder Default-Branch
bleiben außerhalb des Scopes. Framework-Commit, Push, Exact-SHA-Gleichheit
und Current-Head-Review-/CI-Status stehen noch aus. Der aktuelle Benutzer
autorisiert die Framework-Master-Integration erst, nachdem diese Gates als
bestanden beobachtet wurden; kein Parent-Gitlink- oder MRTS-Change ist
autorisiert.
