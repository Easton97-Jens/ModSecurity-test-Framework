# Change Record

**Sprache:** [English](20261007-01-fix-crs-maintenance-contract.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20261007-01-fix-crs-maintenance-contract` |
| UTC-Datum | 2026-10-07 |
| Framework-Basisrevision | `dd637f30b249e92274290df9c8507694a29874d9` |
| Issue oder Pull Request | [Framework PR #136](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/136) |

## Motivation und Problemstellung

Das CRS-Update auf v4.30.0 synchronisierte die kanonischen Pins, Fixture und
Schemas korrekt. Zwei CI-Läufe scheiterten jedoch an historischen Literalen
für Commit und Regelprüfsumme im portablen Vertragstest. Die Prüfung vor der
Veröffentlichung automatischer Wartungs-PRs führte diese Testsuite nicht aus.
Die native Gesamtprüfung zeigte danach eine zweite fehlende abgeleitete Ansicht:
Der öffentliche Paketkatalog enthielt noch die vorherige CRS-Provenienz.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-Vertragstests und die Kandidatenprüfung in
`.github/workflows/check-common-versions.yml` sowie deren exaktes geprüftes
Skriptprofil in `ci/checks/security/check-ci-security-contract.py`, die kanonische
Orchestrierung generierter Ansichten und der Paketkatalog. Provenienzprüfung,
Publisher-Permissions, Action-Pins und exakte Veröffentlichungspfadkontrollen
bleiben erhalten.
Parent-Gitlink und MRTS werden nicht geändert.

## Akzeptanzkriterien

- Der ursprüngliche Fehler wird reproduziert und durch den Testfix behoben.
- Ein weiterer synthetischer CRS-Wechsel besteht die gesamte portable Suite
  nach Synchronisierung; veraltete Fixture- und Schema-Daten werden abgewiesen.
- Der öffentliche Paketkatalog folgt der synchronisierten CRS-Fixture und wird
  mit den anderen generierten Ansichten geprüft, veröffentlicht und bei Fehlern
  wiederhergestellt.
- Fehler dieser Suite verhindern `validated=true` vor der Veröffentlichung.
- Relevante lokale Prüfungen und die CI des neuen PR-Heads werden dokumentiert.

## Untersuchte Alternativen

Neue historische Literale würden beim nächsten Update erneut veralten.
Das Entfernen der Provenienzprüfung würde eine gültige Kontrolle schwächen.

## Implementierungsentscheidung

Die Erwartungen folgen den geprüften Pins aus `ci/lib/common.sh`. Jede
vorhandene CRS-Schemakonstante wird dagegen geprüft. Der Offline-Regressionstest
ändert Tag, Commit und Prüfsumme in einer isolierten Kopie und verwendet den
echten Synchronisierer sowie alle 29 portablen Vertragstests. Zusätzliche
Negativkontrollen erkennen fehlende Synchronisierung und Schema-Drift.
Die Kandidatenprüfung führt die Suite unter `set -euo pipefail` vor
`validated=true` aus; ein Workflowtest prüft diese Reihenfolge.
Der CI-Sicherheitsvertrag vergleicht das Skript weiterhin exakt mit dem
geprüften Profil, das die zusätzliche Suite enthält.
Die kanonische Wartung erzeugt und prüft den öffentlichen Katalog nach der
CRS-Synchronisierung. Nur dessen exakter generierter Pfad wird in die bestehenden
Kandidaten- und Publisher-Allowlists sowie Transaktionssicherungen aufgenommen.
Die Regression weist einen veralteten Katalog ab und prüft die neue
Profilprovenienz. Der Rollback-Test prüft die Wiederherstellung, wenn eine
teilweise erzeugte Katalogansicht bei der Validierung scheitert.

## Geänderte Dateien und Tests

- `.github/workflows/check-common-versions.yml`
- `ci/checks/security/check-ci-security-contract.py`
- `ci/tools/canonical_maintenance.py`
- `modsecurity_test_framework/data/framework-contract-catalog.json`
- `docs/framework-contract-api.md` und die deutsche Begleitdatei
- `tests/ci_security/test_canonical_maintenance.py`
- `tests/ci_security/test_five_connector_with_crs_no_mrts_contract.py`
- `tests/ci_security/test_sync_crs_contract_views.py`
- `tests/ci_security/test_unified_common_maintenance_workflow.py`
- `tests/ci_security/test_ci_security_contract.py`
- dieser englisch/deutsche Change Record

## Befehle und Ergebnisse

Alle Shellprüfungen verwenden RTK. Die Befehle unten sind die ausgeführten
Befehle mit portablen Aliasnamen statt maschinenspezifischer Pfade; die exakte
Zuordnung bleibt im taskeigenen Ausführungsplan. `FRAMEWORK_PYTHON` bezeichnet
den Framework-Interpreter, `PR136_ROOT` den isolierten Checkout,
`PR136_TMP_ROOT`, `PR136_DOC_TMP_ROOT` und `PR136_DOC_BUILD_ROOT` die jeweils
verwendeten externen Task-Verzeichnisse, `PR136_BUILD_ROOT` das externe
Build-Verzeichnis, `PR136_EVIDENCE_ROOT` die externe
Task-Evidenz und `ACTIONLINT_BIN` das vorhandene Actionlint-Programm.

| Befehl | Exit-Code | Ergebnis | Evidenz |
| --- | --- | --- | --- |
| `rtk proxy env TMPDIR="$PR136_TMP_ROOT" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "$FRAMEWORK_PYTHON" -m unittest tests.ci_security.test_five_connector_with_crs_no_mrts_contract.FiveConnectorWithCrsNoMrtsContractTest.test_canonical_profile_fixture_and_schema_are_closed -v` | 1 → 0 | Historischer Commit reproduziert; korrigierter kanonischer Test bestanden. | `$PR136_ROOT/.codex/plans/pr136-ci-repair.md; runs 37312711723, 37312711744` |
| `rtk proxy env TMPDIR="$PR136_TMP_ROOT" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "$FRAMEWORK_PYTHON" -m unittest tests.ci_security.test_sync_crs_contract_views.SyncCrsContractViewsTests.test_next_crs_release_preserves_portable_contract_and_rejects_drift -v` | 0 | Zukünftiges CRS-Update und veraltete Fixture-/Schema-Kontrollen bestanden. | `$PR136_ROOT/.codex/plans/pr136-ci-repair.md` |
| `rtk proxy env TMPDIR="$PR136_TMP_ROOT" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "$FRAMEWORK_PYTHON" -m unittest tests.ci_security.test_five_connector_with_crs_no_mrts_contract tests.ci_security.test_sync_crs_contract_views tests.ci_security.test_unified_common_maintenance_workflow -q` | 0 | 54 Tests bestanden. | `$PR136_ROOT/.codex/plans/pr136-ci-repair.md` |
| `rtk proxy env TMPDIR="$PR136_TMP_ROOT" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "$FRAMEWORK_PYTHON" -m unittest tests.ci_security.test_unified_common_maintenance_workflow tests.security_regression.test_common_version_descriptor_series tests.security_regression.test_runtime_component_lock tests.ci_security.test_five_connector_with_crs_no_mrts_contract -v` | 0 | 61 Kandidatentests bestanden. | `$PR136_EVIDENCE_ROOT/maintenance-gate-validation.md` |
| `rtk proxy env TMPDIR="$PR136_TMP_ROOT" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "$FRAMEWORK_PYTHON" -m unittest tests.ci_security.test_ci_security_contract tests.ci_security.test_framework_ci_security_contract tests.ci_security.test_update_workflow_tools.WorkflowToolUpdaterTests.test_proposed_tree_validation_accepts_a_tool_only_candidate tests.ci_security.test_unified_common_maintenance_workflow` | 0 | 64 Sicherheits- und Publishertests bestanden. | `$PR136_EVIDENCE_ROOT/maintenance-gate-validation.md` |
| `rtk proxy env TMPDIR="$PR136_TMP_ROOT" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "$FRAMEWORK_PYTHON" -m unittest tests.ci_security.test_canonical_maintenance tests.ci_security.test_unified_common_maintenance_workflow tests.ci_security.test_ci_security_contract tests.ci_security.test_framework_ci_security_contract tests.ci_security.test_update_workflow_tools.WorkflowToolUpdaterTests.test_proposed_tree_validation_accepts_a_tool_only_candidate` | 0 | 77 Katalog-, Rollback-, Sicherheits- und Publishertests bestanden. | `$PR136_EVIDENCE_ROOT/maintenance-gate-validation.md` |
| `rtk proxy env TMPDIR="$PR136_TMP_ROOT" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "$FRAMEWORK_PYTHON" -m unittest tests.ci_security.test_ci_security_contract.CiSecurityContractTest.test_unified_common_maintenance_rejects_catalog_publication_scope_regressions` | 0 | Nachträgliche Negativregression für den Veröffentlichungsscope bestanden. | `$PR136_EVIDENCE_ROOT/maintenance-gate-validation.md` |
| `rtk proxy env TMPDIR="$PR136_TMP_ROOT" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "$FRAMEWORK_PYTHON" ci/tools/generate-framework-contract-catalog.py` | 0 | Generierter Katalog durch seinen Quellvertrag korrigiert; nur CRS-Tag und Commit geändert. | `$PR136_ROOT/.codex/plans/pr136-ci-repair.md` |
| `rtk proxy env TMPDIR="$PR136_TMP_ROOT" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 make test-contract-api PYTHON="$FRAMEWORK_PYTHON" FRAMEWORK_ROOT="$PR136_ROOT" BUILD_ROOT="$PR136_BUILD_ROOT" TMP_ROOT="$PR136_TMP_ROOT"` | 0 | Aktualitätsprüfung und alle 23 Paket-API-Tests bestanden. | `$PR136_EVIDENCE_ROOT/contract-api.log` |
| `rtk proxy env TMPDIR="$PR136_TMP_ROOT" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 make test-ci-security-contract PYTHON="$FRAMEWORK_PYTHON" FRAMEWORK_ROOT="$PR136_ROOT" BUILD_ROOT="$PR136_BUILD_ROOT" TMP_ROOT="$PR136_TMP_ROOT"` | 0 | Finales natives CI-Security-Target: 313 Tests bestanden. | `$PR136_EVIDENCE_ROOT/ci-security-final.log` |
| `rtk proxy env TMPDIR="$PR136_TMP_ROOT" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PYTHON="$FRAMEWORK_PYTHON" FRAMEWORK_ROOT="$PR136_ROOT" CONNECTOR_ROOT="$PR136_ROOT" OUTPUT_ROOT="$PR136_EVIDENCE_ROOT" BUILD_ROOT="$PR136_BUILD_ROOT" TMP_ROOT="$PR136_TMP_ROOT" bash "$PR136_EVIDENCE_ROOT/lint-remainder.sh"` | 1 | Dependency-, YAML-, Python-/Workflow-Verträge und 9 Workflow-Sicherheitstests bestanden; der Prüfharness verwendete danach einen unzulässigen Output-Root. | `$PR136_EVIDENCE_ROOT/lint-remainder.sh; lint-remainder.log` |
| `rtk proxy env TMPDIR="$PR136_TMP_ROOT" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PYTHON="$FRAMEWORK_PYTHON" FRAMEWORK_ROOT="$PR136_ROOT" CONNECTOR_ROOT="$PR136_ROOT" OUTPUT_ROOT="$PR136_ROOT" BUILD_ROOT="$PR136_BUILD_ROOT" TMP_ROOT="$PR136_TMP_ROOT" bash "$PR136_EVIDENCE_ROOT/lint-remainder-final.sh"` | 0 | Korrigierter nur lesender Evidenz-Root; übrige native Guards, Kataloge, Dokumentation und Whitespaceprüfungen bestanden. | `$PR136_EVIDENCE_ROOT/lint-remainder-final.sh; lint-remainder-final.log` |
| `rtk proxy "$PR136_EVIDENCE_ROOT/tools/ruff" check --no-cache ci/tools/canonical_maintenance.py ci/checks/security/check-ci-security-contract.py tests/ci_security` | 0 | Lint bestanden. | `$PR136_ROOT/.codex/plans/pr136-ci-repair.md` |
| `rtk proxy "$PR136_EVIDENCE_ROOT/tools/ruff" format --check ci/tools/canonical_maintenance.py ci/checks/security/check-ci-security-contract.py tests/ci_security` | 0 | 25 Dateien bestehen die Formatprüfung. | `$PR136_ROOT/.codex/plans/pr136-ci-repair.md` |
| `rtk proxy "$ACTIONLINT_BIN" .github/workflows/check-common-versions.yml` | 0 | Workflow bestanden. | `$PR136_ROOT/.codex/plans/pr136-ci-repair.md` |
| `rtk proxy env TMPDIR="$PR136_TMP_ROOT" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 make check-documentation PYTHON="$FRAMEWORK_PYTHON" FRAMEWORK_ROOT="$PR136_ROOT" BUILD_ROOT="$PR136_DOC_BUILD_ROOT" TMP_ROOT="$PR136_DOC_TMP_ROOT"` | 0 | Vier Dokumentationsprüfungen bestanden. | `$PR136_ROOT/.codex/plans/pr136-ci-repair.md` |
| `rtk proxy git ls-remote --tags https://github.com/coreruleset/coreruleset.git 'refs/tags/v4.30.0' 'refs/tags/v4.30.0^{}'` | 0 | Tag auf freigegebenen CRS-Commit aufgelöst. | `$PR136_ROOT/.codex/plans/pr136-ci-repair.md` |
| `rtk proxy git ls-remote --tags https://github.com/aws/aws-lc.git 'refs/tags/v5.11.0' 'refs/tags/v5.11.0^{}'` | 0 | Tag entspricht freigegebenem AWS-LC-Commit. | `$PR136_ROOT/.codex/plans/pr136-ci-repair.md` |
| `rtk proxy curl -fsSL --max-time 30 -o "$PR136_EVIDENCE_ROOT/crs-rule.conf" https://raw.githubusercontent.com/coreruleset/coreruleset/e03a4f6dabc7a30ebd8c52c97d28a154f590a48f/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf` | 0 | Regel am exakten Commit heruntergeladen. | `$PR136_EVIDENCE_ROOT/crs-rule.conf` |
| `rtk proxy sha256sum "$PR136_EVIDENCE_ROOT/crs-rule.conf"` | 0 | Erwartete 8dadc742af2bb6b7e5b48570cb0201930cd9cfe9e3de94776e736605ea7be228 bestätigt. | `$PR136_EVIDENCE_ROOT/crs-rule.conf` |
| `rtk proxy git diff --check` | 0 | Whitespaceprüfung bestanden. | `$PR136_ROOT/.codex/plans/pr136-ci-repair.md` |

## Sicherheitsauswirkung

Keine Security-Remediation; vorhandene Kontrollen bleiben aktiv. Die zusätzliche
Prüfung verhindert die Veröffentlichung eines fehlerhaften Kandidaten.

## Dokumentation und Runtime-Evidenz

Dieser gepaarte Record dokumentiert die Korrektur. Es wird keine neue
Connector- oder Lifecycle-Runtime-Evidenz erhoben oder daraus abgeleitet.

## Nicht ausgeführte Prüfungen

Lokales Pyright ist wegen fehlendem Node.js nicht ausführbar. Die CI führt
Pyright mit dem kanonischen Node.js aus. Lokales Python ist 3.14.7; die CI
prüft separat mit der kanonischen Version 3.14.8.

## Einschränkungen und Restrisiko

Die native Gesamtprüfung zeigte den fehlenden Katalog, nachdem die vorherigen
Targets bestanden waren. Nach Neuerzeugung bestehen das API-Target und die
fortgesetzten nativen Prüfungen; das betroffene CI-Security-Target besteht am
finalen Korrekturstand alle 313 Tests. Die neue PR-Head-CI steht bei Commit-Vorbereitung
noch aus. Die Wartungs-Allowlist ergänzt nur den abgeleiteten
Katalog; manuelle Test-/Recordänderungen bleiben außerhalb. Kein Merge oder
Parent-Gitlink-Update ist autorisiert.

## Finaler Diff- und Review-Status

Der finale eingegrenzte Diff und die exakten geprüften Workflow-Hashes wurden
unabhängig ohne wesentliche Findings geprüft. Whitespace, Dokumentation und
relevante lokale Prüfungen bestehen. Die Korrektur wird als normaler Folgecommit
für PR #136 vorbereitet; aktuelle Head-gebundene CI-Evidenz wird im PR und
Ausführungsplan ergänzt.
Dieser Change Record enthält keine Secrets oder sensiblen Rohdaten.
