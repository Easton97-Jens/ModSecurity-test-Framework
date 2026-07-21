# 20260720-03-reconcile-codex-cloud-framework-security — kumulativer Framework-Sicherheitsabgleich

**Sprache:** [English](20260720-03-reconcile-codex-cloud-framework-security.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260720-03-reconcile-codex-cloud-framework-security` |
| UTC-Datum | 2026-07-20 |
| Framework-Basisrevision | `2f4a5d7` (normaler lokaler Merge des aktuellen Framework-master in den bestehenden PR-Branch) |
| Issue oder Pull Request | Codex-Cloud-Export `4836e7…45daf`; Framework-PR #37 auf `agent/master-post36-sonar-remediation` (Draft zum Zeitpunkt der ursprünglichen Record-Erfassung) |

## Motivation und Problemstellung

Der bereitgestellte Codex-Cloud-Export enthält 41 Framework-Zeilen. Der
ursprüngliche Benutzerauftrag verlangte einen kumulativen Framework-PR,
verbot zu diesem Zeitpunkt ausdrücklich eine `master`-Integration und schloss
Parent-Repository und MRTS aus. Die Änderungen gleichen deshalb jede Zeile auf
einem Branch ab und bewahren getrennte Root-Cause-Kontrollen sowie ehrliche
Evidenz. Der aktuelle Delivery-Zustand ist getrennt geregelt: Eine spätere
aktuelle, ausdrückliche Framework-spezifische Autorisation darf nur den
geschützten PR-Workflow nach finaler Exact-Head-Verifikation verwenden.

## Betroffene Komponenten und Sicherheitsgrenzen

Die Behebung betrifft GitHub-Actions-Vertrauensgrenzen, Cache-/Provenance- und
Runtime-Root-Containment, Generated-Report-Integrität, Response-/Evidence-
Promotion, Protocol-Payload-Sicherheit, CRS-/MRTS-Generated-Output-Containment
und Framework-Dokumentationsvalidierung. Sie ändert keine Connector-Host-
Implementierung, keinen Parent-Git-Zustand, keinen Parent-Gitlink, keinen MRTS-
Inhalt und keinen MRTS-Gitlink.

## Akzeptanzkriterien

- Jede der 41 Cloud-IDs in einem englischen, deutschen und JSON-Framework-
  Record ausweisen.
- Bestätigte ausführbare Kontrollen und ihre Negative-/Control-Regressionen
  auf dem einen bestehenden PR-#37-Branch halten.
- Jeden direkten `master`-Push verbieten. Ein Merge ist nur zulässig, wenn
  eine aktuelle ausdrückliche Framework-spezifische Autorisation PR #37
  auswählt und sein finaler Exact Head die Repository-Delivery-Controls erfüllt.
- High-Impact-Kontrollen bewahren oder konkrete Already-safe-/Historical-
  Evidence erfassen; keinen Scanner unterdrücken und keinen Test schwächen.
- Den Cloud-Rescan-Status explizit halten, wenn kein authentifiziertes Cloud-
  Tool verfügbar ist.

## Untersuchte Alternativen

Einen separaten PR zu öffnen, Root Causes aufzuteilen, PR-Checkout-Code in
einem privilegierten OSV-Workflow auszuführen oder generische CRS-Evidence zu
akzeptieren, wurde verworfen. Die gewählte Implementierung verwendet den
bestehenden Branch, ein data-only-verifiziertes PR-Objekt für OSV und präzise
Evidence-Gates.

## Implementierungsentscheidung

Der OSV-Job ist ein enger nicht privilegierter `pull_request`-Job, der nur die
vertrauenswürdige Basisrevision auscheckt, die nummerierte GitHub-Pull-Request-
Head-Referenz holt, ihre SHA verifiziert und nur begrenzte Dependency-Blobs
liest. Er hat ausschließlich `contents: read`, keine Secrets, keine
persistierten Credentials und keine Submodule. Die Actions-Validatoren
verbieten jede `pull_request_target`-Nutzung. Generated Outputs, Runtime-Pfade
und MRTS-Generated-Roots sind contained;
nicht promotierbare Observations können nicht PASS werden. Der 401-CRS-
Override benötigt nun lokale Regel `2320` im Audit-Record. Hash-Integrität
umfasst rohe Event-Werte vor der Display-Normalisierung. Das SonarCloud-
Follow-up lässt die HAProxy-Case-Extraktion direkt das bereits normalisierte
Mapping verwenden und trennt Curl-Output-Option-Parsing von der Zielerfassung;
beides bewahrt die Payload-Capture- und Promotion-Controls und beseitigt die
gemeldeten Reliability-/Complexity-Defekte. Die verbleibenden Static-Findings
auf Warning-Level sind ebenfalls entfernt, ohne die No-CRS-Source-Failure-,
Snapshot-Promotion- oder Negative-Evidence-Contracts zu ändern.

## Geänderte Dateien und Tests

Änderungen bleiben auf Framework-Workflows, CI-Checks/Helper/Reporting,
Framework-YAML-Cases und fokussierte Regressionstests, die gepaarten
englischen/deutschen Workflow-Security-Leitfäden, diesen Change Record und die
gepaarten Cloud-Finding-Abgleichdateien beschränkt. Das vollständige per-ID-
Mapping steht in
`reports/audits/findings/20260720-01-codex-cloud-framework-reconciliation.*`.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Prägnantes Ergebnis |
| --- | ---: | --- |
| Gewählte Framework-Virtual-Environment: `python -m unittest tests.security_regression.test_workflow_security_contract tests.ci_security.test_ci_security_contract tests.ci_security.test_ci_security_evidence_contract` | 0 | 35 Workflow-Security- und Semantic-Evidence-Tests bestanden. |
| `python ci/checks/security/check-github-actions-workflows.py --workflow-root .github/workflows --check all` | 0 | Alle Framework-Workflows erfüllen Immutable-Pin- und Permission-/Trust-Controls. |
| `python ci/checks/security/check-ci-security-evidence-contract.py --root .` | 0 | OSV-, CodeQL-, Scorecard-, Gitleaks- und Boundary-Contracts bestanden. |
| `python ci/checks/security/check-ci-security-contract.py --root .` | 0 | Framework-CI-Security-Contract bestanden. |
| `python ci/checks/security/check-security-data-flow-normalizers.py` | 0 | Normale und volatile-Field-Tampering werden abgewiesen. |
| `python -m unittest tests.security_regression.test_ci_root_bootstrap_hardening.CiRootBootstrapHardeningTests.test_prepare_crs_rejects_source_and_runtime_paths_outside_task_roots` | 0 | Beide CRS-Root-Escape-Negative-Cases wurden abgewiesen. |
| `python -m unittest tests.security_regression.test_second_remediation.SecondRemediationTests.test_with_crs_status_override_requires_the_local_rule_audit_evidence` | 0 | Generischer CRS-Block schlägt fehl; lokale-Rule-Audit-Control besteht. |
| `python -m unittest tests.no_crs.test_no_crs_baseline` | 0 | 76 No-CRS-Baseline-Tests bestanden. |
| `python ci/checks/documentation/check-variable-documentation.py` und `check-repository-path-references.py` | 0 | Documentation-Pairing- und Path-Reference-Checks bestanden. |
| `python -m unittest discover -s tests/security_regression -q` | 0 | Die aggregierte Security-Regression-Suite bestand (252 Tests), einschließlich Response-Body-Display-PASS mit Non-Promotion. |
| `python -m unittest discover -s tests/no_crs -q` | 0 | Die aggregierte No-CRS-Suite bestand; erwartete Rejection-Diagnosen wurden beobachtet. |
| `python -m unittest discover -s tests/ci_security -q` | 0 | 69 CI-Security-Tests bestanden. |
| `python -m unittest discover -s tests/protocol_client -q` | 0 | 24 Protocol-Client-Tests bestanden. |
| `python -m unittest discover -s tests/workflow_contract -q` | 0 | 2 Workflow-Contract-Tests bestanden. |
| Gelocktes Ruff `check` und `format --check` über den CI-Security-Scope | 0 | Alle 14 konfigurierten Dateien bestanden nach deterministischer Formatierung. |
| Gelocktes `zizmor --offline .github` | 0 | Keine nicht unterdrückten Workflow-Befunde; `pull_request_target` fehlt. |
| `python -m unittest tests.protocol_client.test_check_protocol_evidence tests.security_regression.test_generate_case_matrix_sonar -q` | 0 | 31 fokussierte Parser- und HAProxy-Matrix-Tests bestanden. |
| `python -m unittest discover -s tests/protocol_client -q` | 0 | 24 Protocol-Client-Tests bestanden nach dem Parser-Follow-up. |
| `python -m unittest discover -s tests/security_regression -q` | 0 | 253 Security-Regression-Tests bestanden nach dem HAProxy-Follow-up. |
| `sh -n` für jeden geänderten Framework-Shell-Entrypoint und `git diff --check` | 0 | Shell-Syntax und der vollständige ausstehende Diff bestanden. |

## Sicherheitsauswirkung

Fokussierte Regressionen reproduzieren die relevante Negative Condition und
bewahren eine legitime Kontrolle: unsichere Cache-/Provenance-Eingaben,
Path-Escape, Symlink- oder Freshness-Bypass, generischer CRS-Status,
serialisierte Workflow-Kontexte und volatile Hash-Tampering werden abgewiesen.
Der OSV-Job checkt nur Framework-Quellcode und Helper der Basisrevision aus;
sein PR-Event hat keine erhöhte Berechtigung. Keine Sicherheitskontrolle wurde
geschwächt.

## Dokumentation und Runtime-Evidenz

Die gepaarten Workflow-Leitfäden dokumentieren die nicht privilegierte OSV-
Grenze. Der
gepaarte Finding-Record und das kanonische JSON weisen jede bereitgestellte
Zeile aus. Es wird kein Connector-Runtime-/Lifecycle-Run behauptet; die
erfasste Evidence ist statisch oder Framework-Test-Harness-Evidence.

## Nicht ausgeführte Prüfungen

Die vollständige GitHub-CI-Matrix, ein externer SonarCloud-Readback und ein
frischer Codex-Cloud-Scan wurden lokal nicht ausgeführt. Der verfügbare
Framework-Interpreter ist CPython 3.14.4, während CI CPython 3.13.14 lockt;
lokale fokussierte Checks sind Behavioral Evidence, kein Ersatz für CI-Evidence.
Kein authentifiziertes Codex-Cloud-Connector/API/UI-Tool ist verfügbar; die
Cloud-Closure ist daher `blocked_permissions`.

## Einschränkungen und Restrisiko

Der OSV-Workflow ist bewusst ein `pull_request`-Workflow; damit kann ein nicht
vertrauenswürdiger PR seine eigene Workflow-Definition nur unter dem
schreibgeschützten PR-Token und ohne Secrets ändern. Der Job selbst checkt
Basisrevisions-Quellcode aus und liest den SHA-verifizierten PR-Head nur als
Daten. Der finale PR-Head benötigt weiterhin beobachtete GitHub-Checks, Review
und Sonar-Evidence. Dieser Record autorisiert selbst keinen Merge von PR #37;
jede aktuelle Benutzerautorisierung bleibt an geschützten PR-, Review- und
Post-Merge-Anforderungen gebunden.

## Finaler Diff- und Review-Status

Zum Zeitpunkt der ursprünglichen Record-Erfassung enthielt der Worktree den
lokal verifizierten kumulativen Framework-only-Change-Set für PR #37. Parent
und MRTS bleiben unberührt, und dieser Arbeitsschritt änderte keinen
`master`-Ref. Für eine aktuelle ausdrücklich autorisierte Framework-Integration
sind die verbleibenden Delivery-Schritte ein frischer Exact-Remote-Head-,
GitHub-Check-, Review- und Sonar-Abgleich, das Bereitmachen des PR, wenn
angemessen, und ein Exact-Head-gebundener konventioneller geschützter PR-Merge.
Direkte `master`-Pushes und Bypässe bleiben verboten.
