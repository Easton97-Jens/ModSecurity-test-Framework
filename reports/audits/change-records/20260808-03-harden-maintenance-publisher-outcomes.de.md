# Änderungsnachweis: Maintenance-Publisher-Ergebnisse härten

**Sprache:** [English](20260808-03-harden-maintenance-publisher-outcomes.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260808-03-harden-maintenance-publisher-outcomes |
| UTC-Datum | 2026-08-08 |
| Framework-Basisrevision | da28e6da58fa8b1135d3631612a78e73ff98584b |
| Issue oder Pull Request | Task-Branch `fix/maintenance-publisher-outcomes`. Draft-PR ausstehend; kein Merge oder Auto-Merge ist autorisiert. |

## Motivation und Problemstellung

Den beiden geplanten/manuellen Maintenance-Workflows fehlte ein eindeutiges
terminales Ergebnis. Ein Fehler des Workflow-Tool-Publishers konnte hinter
übersprungenen Folgearbeiten verborgen werden, und der CPython-Publisher
verwendete noch das native Job-Token. Beobachtete Hosted-Receipts für die
angeforderten Source-Revisionen zeigen den Fehlschlag des Workflow-Tool-
Publishers beim Minting seines App-Tokens und den Fehlschlag des CPython-
Publishers beim Erstellen oder Aktualisieren seines Draft-PR. Der Hosted-
Logkörper war für diese Aufgabe nicht verfügbar; daher wird hier kein nicht
beobachteter Fehlertext festgehalten.

## Betroffene Komponenten und Sicherheitsgrenzen

- `.github/workflows/update-workflow-tools.yml` bindet nun die kanonische
  Base64-Kandidaten- und SHA-256-Identität des Resolvers durch Validator und
  Publisher, prüft die konfigurierten App-IDs ohne Werte anzuzeigen und endet
  in einem read-only terminalen Outcome-Job.
- `.github/workflows/check-python-version.yml` verwendet nun dieselbe
  repository-begrenzte App-Konfiguration, erlaubt nur `Contents`- und `Pull
  requests`-App-Write-Recht, verifiziert einen eingeschränkten Draft-Branch/PR
  und endet in einem read-only terminalen Outcome-Job.
- `ci/tools/update-workflow-tools.py`, der statische CI-Sicherheitsvertrag und
  fokussierte Tests binden das Source-Verhalten. Der gepaarte englische/
  deutsche Leitfaden dokumentiert es.
- Parent-Source, Parent-/Framework-Gitlinks, MRTS-Source und MRTS-Gitlinks
  liegen außerhalb dieser Framework-only-Änderung.

## Akzeptanzkriterien

- Nur der exakte No-Update-Zustand ist grün; fehlende, fehlerhafte, unbekannte
  oder fehlgeschlagene Resolver-/Validator-/Publisher-/App-Zustände schlagen
  fail-closed fehl.
- No-Update erstellt oder verändert keinen Branch, Commit oder Pull Request.
- Workflow-Tool-Consumer validieren die exakte SHA-256-Identität des
  Resolver-Kandidaten und verlangen ein nicht leeres Update vor der Anwendung.
- Beide Publisher verwenden die konfigurierte GitHub-App ohne native Token-,
  PAT- oder Secret-Fallbacks; Konfigurationsfehler sind rot und geben keine
  Werte preis.
- CPython verwendet nur die notwendigen App-Scopes, bewahrt einen festen
  Branch-/Titel-/Draft-/Marker-/Pfadvertrag und merged nie.
- Der statische Vertrag, negative Tests, gepaarte Dokumentation und dieser
  Change Record erfassen das finale Source-Verhalten.

## Untersuchte Alternativen

- Jeden übersprungenen Publisher als grünes No-Update zu behandeln wurde
  verworfen: Resolver-Output- und Publishing-Fehler wären mehrdeutig.
- Dem nativen Job-Token breitere Rechte zu geben oder `github.token` als
  Fallback zu behalten wurde verworfen, weil dies die Credential-Grenze
  erweitert.
- Für No-Update einen PR, Branch oder Commit zu erzeugen wurde verworfen, weil
  dies unnötigen Maintenance-Zustand anlegt.

## Implementierungsentscheidung

Jeder Publisher behält sein eingebautes Token bei `contents: read`. Die
Publisher-Vorprüfung prüft nur, ob
`WORKFLOW_UPDATER_APP_CLIENT_ID` und `WORKFLOW_UPDATER_APP_PRIVATE_KEY`
vorhanden sind; keiner der Werte wird ausgegeben. Die gepinnte App-Token-Action
ist die einzige Publishing-Credentialquelle. Das CPython-Token fordert nur
`contents`- und `pull-requests`-Write-Recht an; das Workflow-Tool-Token
zusätzlich `workflows`-Write-Recht, weil es Workflow-Dateien ändern kann.

Die neuen `outcome`-Jobs laufen mit `always()` und leeren Berechtigungen. Sie
validieren alle vorgelagerten Job-Ergebnisse und Outputs, bevor sie
zweisprachige Zusammenfassungen schreiben. Sie weisen nicht erkannte Outputs
und fehlgeschlagenes Publishing explizit zurück, statt sie als No-Op zu
maskieren. Die bestehenden strikten Workflow-Tool-Draft-PR-Kontrollen bleiben;
CPython erhält gleichwertige Prüfungen für festen Branch, Titel, Marker, Draft,
Basis und erlaubten Pfad.

## Geänderte Dateien und Tests

- `.github/workflows/check-python-version.yml`
- `.github/workflows/update-workflow-tools.yml`
- `ci/tools/update-workflow-tools.py`
- `ci/checks/security/check-ci-security-contract.py`
- `ci/checks/security/check-github-actions-workflows.py`
- `tests/ci_security/test_update_workflow_tools.py`
- `tests/ci_security/test_update_python_version.py`
- `tests/ci_security/test_ci_security_contract.py`
- `tests/ci_security/test_framework_ci_security_contract.py`
- `tests/security_regression/test_workflow_security_contract.py`
- `docs/github-actions-workflow-security.md` und
  `docs/github-actions-workflow-security.de.md`
- Dieser gepaarte Change Record.

Positive Abdeckung beweist die realen Workflow-Profile; negative Mutationen
weisen fehlende Outcome-Jobs, nicht leere Outcome-Berechtigungen,
Token-Exposition, unbekannte Terminalbedingungen, entfernte
Kandidaten-Identitätsbindung, entfernte App-Vorprüfung, native Token-Fallbacks,
breitere App-Scopes, abgeschwächte Draft-Kontrollen, force-artige
Cleanup-Maskierung, grüne Publisher-Fehlerpfade, CPython-Read-Scope auf
Workflow-Ebene und eine fehlende CPython-Reader-Job-Berechtigung zurück.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Fokussierte Updater-/Contract-Unit-Suiten | 0 | Workflow-Tool-Updater (26), CPython-Updater (12) und CI-Sicherheitsvertrag (33) bestanden. | Lokaler Framework-Task-Worktree. |
| Expliziter Unit-Befehl für vier Module | 0 | 80 Updater-/Contract-Tests bestanden. | Lokaler Framework-Task-Worktree. |
| `make test-ci-security-contract` | 0 | 141 CI-Sicherheitsvertrags- und Regressionstests bestanden. | Lokaler Framework-Task-Worktree. |
| `make test-workflow-action-pins` | 0 | 25 Tests für unveränderliche Action-Pins bestanden. | Lokaler Framework-Task-Worktree. |
| `make test-workflow-security-contract` | 0 | 9 Workflow-Sicherheitsvertrags-Tests bestanden. | Lokaler Framework-Task-Worktree. |
| `make check-github-actions-workflows` | 0 | Source-kontrollierte Workflow-Pin- und Berechtigungsprüfungen bestanden. | Lokaler Framework-Task-Worktree. |
| `make check-documentation` | 0 | Dokumentation, zweisprachige Parität und Change-Record-Prüfungen bestanden vor der finalen Record-Abstimmung. | Lokaler Framework-Task-Worktree. |
| `make lint` | 0 | Vollständige repository-definierte lokale Lint-/CI-Sicherheitsaggregation bestand. | Lokaler Framework-Task-Worktree. |
| Gesperrte Ruff-`0.15.22`-Lint- und Format-Checks | 0 | Die exakte Hosted-Dateimenge bestand nach der eng begrenzten Format-Remediation. | Prüfsummenverifizierter task-lokaler Tool-Abruf. |
| SonarCloud-Quality-Gate | 1 | Der aktuelle Head `72b2904` von PR #67 meldete nur die konkreten task-eigenen Static-Analysis-Anmerkungen, die dieses Follow-up behebt. | GitHub-Check-Run `93130371506`; kein roher Hosted-Log wird aufbewahrt. |
| `ci/checks/security/check-ci-security-contract.py --root .` und YAML-Parse | 0 | Die überprüften Workflow-Verträge und beide geänderten Workflow-YAML-Dokumente bestanden. | Lokaler Framework-Task-Worktree. |
| Codex-Security-Working-Tree-Diff-Scan | 0 | Alle 14 geänderten Dateien erhielten Full-File-Receipts; kein reportierbarer Fund überlebte Discovery. | Versiegelte task-lokale Scan-Evidenz (nicht versioniert). |

## Sicherheitsauswirkung

Dies ist eine Härtung der CI-Credential-Grenze und Ergebnisintegrität. Der
ursprüngliche Workflow-Tool-Credential-Minting-Fehler bleibt rot; der CPython-
Publisher verwendet das native Job-Token nicht mehr zum Publishing und beginnt
ohne eingebautes Workflow-Level-Token. Sein Resolver, Kandidatenvalidator und
Publisher erhalten nur jeweils ihr eingebautes `contents: read`-Token, während
das Outcome leer bleibt. Die Verträge pinnen Vorprüfung, App-Scope,
Kandidaten-Identität, strikten Draft-PR-Zustand, job-begrenzten Read-Zugriff
und terminale Report-Bodies. Fokussierte alternative Bypass-Mutationen wurden
durch die statischen Vertrags-Tests erneut ausgeführt und zurückgewiesen. Die
legitimen Kontrollen sind die unveränderten lokalen Workflows und ihre
fokussierten Test-Suiten.

## Dokumentation und Runtime-Evidenz

Die englischen und deutschen Workflow-Sicherheitsleitfäden beschreiben jetzt
die gemeinsamen App-Konfigurationsnamen, die No-Value-Vorprüfung,
unterschiedliche App-Scopes, die No-Fallback-Regel, exakte No-Update-Zustände,
strikten Draft-PR-Zustand, job-begrenzte CPython-Reader-Berechtigungen und
normale PR-Checks. Es wurden keine Credential-Werte, Repository-Setting-
Änderungen, Hosted-App-Installationsnachweise oder Connector-/MRTS-Runtime-
Evidenz erfasst.

## Nicht ausgeführte Prüfungen

- Ein Hosted-No-Update- und Update-present-Run beider Workflows wurde noch
  nicht ausgeführt. Die App-Installations-/Berechtigungsverifikation erfordert
  einen Repository-Owner und ist durch die verfügbare Command-Response nicht
  belegt.
- Hosted-PR-Checks, Review-Status, Branch-Protection und SonarQube Cloud sind
  Controls des exakten Draft-PR-Heads. Der bereits gepushte Head wurde
  inspiziert; der exakte Head dieses Follow-ups muss vor einem Merge-Review
  gepusht und erneut geprüft werden.
- `actionlint`, `zizmor` und `pyright` sind lokal nicht installiert und wurden
  nicht heruntergeladen. Nachdem der initiale Draft-PR-Check sechs reine
  Ruff-Formatänderungen meldete, lieferte der prüfsummenverifizierte Fetcher
  des Repositories gesperrtes Ruff `0.15.22` im task-lokalen Speicher; seine
  exakten Lint- und Format-Checks bestanden. Das installierte ShellCheck ist
  das überprüfte `0.11.0`, aber die repository-native Workflow-Ausführung
  benötigt actionlint-Integration; daher wurde kein nicht gleichwertiger
  Standalone-Extraktionscheck ersetzt.

## Einschränkungen und Restrisiko

Source und lokale Tests können nicht beweisen, dass die GitHub-App nur auf
diesem Repository installiert ist oder die angeforderten Berechtigungen hat.
Der Hosted-Publisher-Pfad bleibt von dieser externen Konfiguration abhängig.
Kein direkter `master`-Push, Merge, Auto-Merge, PAT-Fallback, Parent-Änderung
oder MRTS-Änderung ist enthalten.

## Finaler Diff- und Review-Status

Der ursprüngliche Task-Commit wurde gepusht und genau ein Draft-PR geöffnet.
Sein initialer Fehler `python-ci-security-quality` beschränkte sich auf
Ruff-Formatierung; der exakte gesperrte Formatter erzeugte ein enges Follow-up
für sechs Dateien, das lokale Lint-/Format-Checks und die vollständige lokale
Aggregation bestand. Dessen Security-Quality-, Actionlint-/Contract-, Zizmor-,
CodeQL-, Action-Version-, Secret-Scanning-, Scorecard-, OSV- und Common-
Structure-Checks bestanden; SonarCloud meldete stattdessen die oben erfassten
konkreten task-eigenen Anmerkungen. Dieses Follow-up behebt sie vor einem
normalen Push und einem neuen Check des exakten Heads. Der versiegelte
eingegrenzte Security-Diff-Scan fand keine reportierbare Regression. Dieser
Record enthält keinen Credential-Wert und keinen rohen Hosted-Log.
