# NGINX maintenance handoffs

[English](20261102-05-nginx-maintenance-handoffs.md)

## Identität

| Change-ID | `20261102-05-nginx-maintenance-handoffs` |
| --- | --- |
| UTC-Datum | 2026-11-02 |
| Framework-Basis | `1b0885a2aa9b91b3faad76de6df8250bf8147eef` |
| PR | Nach dem Commit separat erstellt; kein Merge autorisiert. |

## Motivation und Problemstellung

Die kanonische common.sh wählte NGINX 1.31.8, während reguläre Übergaben weiterhin 1.31.6 verlangten. Dies blockierte Kandidatenvalidierung und aktuelle Runtime-Verbraucher.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-Exact-Head-Composite, Runtime-Provisionierung/-Bereitschaft und aktuelle Exact-Head-Evidenz-/Broker-Verbraucher. Unveränderliche historische Root-Broker-Pins 1.31.4 und historische I12-Evidenz bleiben erhalten. Parent-Änderungen und Gitlink-Updates bleiben separat; MRTS unverändert.

## Akzeptanzkriterien

Reguläre Verbraucher stimmen mit 1.31.8 und Archivdigest `0652b760b3b772d2ec17b47c2fc15d9a95e6fe35cd5b877eadc1a62d9bc75af1` überein; Generierung ist idempotent und erhält Dateimodi. Raw-Wrapper-Prüfung deckt beide Richtungen von Checkout/Auswahl ab und weist falsche Pins/fehlende Blobs zurück.

## Untersuchte Alternativen

Manuelle Änderungen aller künftigen Projektionen wurden verworfen, weil Wartung den Konflikt erneut erzeugen könnte. Provenienzprüfungen bleiben aktiv.

## Implementierungsentscheidung

Der vorhandene statische Runtime-Synchronisierer erhält eine geschlossene Menge aktueller NGINX-Ausgaben. Die kanonische Wartung berücksichtigt diese Sichten. Atomare Ausgabe erhält den vorhandenen Modus. Kandidatendaten bleiben in Verifier-Regressionen nicht ausführbar; vertrauenswürdiger Parser stammt aus dem committed Parent-Gitlink.

## Geänderte Dateien und Tests

Geändert: `ci/tools/sync-runtime-components.py`, `ci/tools/canonical_maintenance.py`, sieben aktuelle Übergabeausgaben, aktuelle Pin-Fixtures und gezielte Synchronisierer-/Git-Kontext-Regressionen. Inventar-Quelldigests und On-Demand-Archiv wurden mit dem nativen Generator erneuert. Dieses EN/DE-Protokoll wurde ergänzt; Standardauswahl unverändert.

## Befehle und Ergebnisse

Framework cwd: `/var/tmp/codex/ModSecurity-conector/worktrees/fix-framework-nginx-maintenance-pins`.
Interpreter: `/var/tmp/codex/ModSecurity-test-Framework/venv/bin/python`.
All commands use `rtk bypass`; `PYTHONDONTWRITEBYTECODE=1`.

- `python ci/tools/sync-runtime-components.py --check`: initially exit 1, identified stale ordinary handoffs; after generation exit 0.
- `python ci/tools/sync-runtime-components.py --write`: exit 0; repeated generation byte-idempotent.
- `python -m unittest tests.security_regression.test_runtime_component_sync -v`: exit 0, 20 tests; mode-preservation assertion rerun after review, exit 0.
- `python -m unittest tests.ci_security.test_canonical_maintenance.CanonicalMaintenanceTests.test_maintenance_test_views_follow_catalog_after_crs_views_in_both_modes -v`: exit 0, 1 test.
- `python ci/tools/generate-framework-contract-catalog.py --check`: exit 0.
- `python ci/tools/sync-maintenance-test-views.py --write --root /var/tmp/codex/ModSecurity-conector/worktrees/fix-framework-nginx-maintenance-pins`: exit 0; source bindings and archive regenerated without adding default cases.

- `python ci/tools/sync-maintenance-test-views.py --check --root /var/tmp/codex/ModSecurity-conector/worktrees/fix-framework-nginx-maintenance-pins`: exit 0.
- `python ci/checks/documentation/check-change-records.py`: exit 0.
- `python ci/checks/documentation/check-doc-links.py`: exit 0.
- `python ci/checks/documentation/check-variable-documentation.py`: exit 0, 374 pairs.
- `git diff --check`: exit 0.

Connector tests use explicit `CONNECTOR_ROOT=/var/tmp/codex/ModSecurity-conector/worktrees/fix-submodule-candidate-context`, `CONNECTOR_REVISION=a18ffca3b5bb54887c0b8859ece95478e83cf262`, `TEST_ROOT` and `FRAMEWORK_ROOT` equal to the Framework cwd, `PYTHONPATH` equal to that cwd plus its `/connector_suite`, and `ON_DEMAND_TESTS=1`.

- `python -m unittest modsecurity_connector_tests.test_verify_framework_candidate_contract.VerifyFrameworkCandidateGitContextTests modsecurity_connector_tests.test_verify_framework_candidate_contract.VerifyFrameworkCandidateContractTests.test_checked_out_framework_common_passes_the_data_contract -v`: exit 0, 5 tests against the separate Parent verifier repair.
- `python -m unittest modsecurity_connector_tests.test_nginx_functional_evidence -v`: exit 0, 11 tests. Initial run exposed a stale job-level env lookup; corrected to inspect the single source-owned composite step handoff.
- `python -m unittest modsecurity_connector_tests.test_nginx_exact_head_result_collector.CollectorPinContractTests modsecurity_connector_tests.test_nginx_exact_head_result_collector.CollectorTests.test_rejects_previous_release_and_crossed_runtime_pins modsecurity_connector_tests.test_nginx_exact_head_root_launcher.RootLauncherContractTests.test_rejects_previous_release_and_crossed_candidate_pins -v`: exit 0, 3 tests.


## Sicherheitsauswirkung

Quellrepository, Archivdigest, Provenienzflags und Fehlerverhalten bleiben durchgesetzt. Negativtests erhalten die Zurückweisung gekreuzter Pins, falscher Revisionen, fehlender Git-Blobs, doppelter Zuweisungen und ausführbaren Kandidaten-Pythons. Keine neuen CI-Rechte oder historische Broker-Autorität.

## Dokumentation und Runtime-Evidenz

Nur dieses Protokollpaar ist neue leserorientierte Dokumentation. Keine Host-Runtime- oder Lifecycle-Ausführungsevidenz erzeugt.

## Nicht ausgeführte Prüfungen

Vollständige Tests, Connector-Builds, Host-Runtime, I12/Matrizen und Remote-Quality-Gate wurden lokal nicht ausgeführt: außerhalb der gezielten Reparatur. Ruff fehlt in der Framework-venv (`python -m ruff --version`, Exit 1); kein Paket installiert.

## Einschränkungen und Restrisiko

Parent-Integration erfordert separate Reparatur und Pin-Update. Git-Objekttests prüfen die Verifier-Datengrenze, keine Hosted-Runtime-Bereitschaft. Aktuelle GitHub-Head-Prüfungen sind nach dem Push als Delivery-Evidenz zu prüfen.

Hosted-Lint und Action-Version-Prüfungen am ersten Head585bf6e fanden den Whole-Source-Migrationsdigest der Exact-Head-Action und eine redundant kopierte kanonische URL. Der vorherige einzelne Quelleneintrag wurde gegen den Basiscommit authentifiziert; genau dieser Action-Digest in `ci/tooling/connector-actions.lock.json` und sein Aggregat in `ci/checks/security/connector_action_pins.py` wurden erneuert. Register, Action-Records und Autorität bleiben erhalten. Dieser gepflegte Snapshot hat keinen eingecheckten Generator. Das doppelte URL-Literal wurde durch einen SHA-256-Vertrauensanker ersetzt. `rtk bypass env PYTHONDONTWRITEBYTECODE=1 /var/tmp/codex/ModSecurity-test-Framework/venv/bin/python ci/tools/check-common-versions.py --validate-canonical` bestanden; `python -m unittest tests.ci_security.test_connector_action_pins -v`6 Tests bestanden;2 gezielte Synchronisierertests bestanden. Das unveränderliche Snapshot-Gate verlangt weiterhin separate Prüfung, wenn künftige Wartung Composite-Quellbytes ändert.

CI-Autoritätstests am aktuellen Head wiesen automatische Veröffentlichung des Integration-Composites zurück. Die vorhandene Read-Only-Publisher-Grenze bleibt erhalten: Generator/Rollback berücksichtigen die Action; native automatische Veröffentlichung schließt sie aus. Explizit geprüfte Wartung muss den Quellsnapshot wie oben erneuern. `python -m unittest tests.ci_security.test_canonical_maintenance.CanonicalMaintenanceTests.test_native_workflow_publisher_outputs_have_exact_transaction_authority -v` nach Korrektur bestanden.

## Finaler Diff- und Review-Status

Finaler fokussierter Diff geprüft; keine Geheimnisse oder sensiblen Rohlogs erfasst. Review fand Verlust des atomaren Dateimodus; gezielte Regression deckt dessen Erhalt jetzt ab. Keine Parent-/MRTS-Änderungen oder Merge.
