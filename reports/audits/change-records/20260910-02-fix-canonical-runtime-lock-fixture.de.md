# Change Record

**Sprache:** [English](20260910-02-fix-canonical-runtime-lock-fixture.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260910-02-fix-canonical-runtime-lock-fixture` |
| UTC-Datum | 2026-09-10 |
| Framework-Basisrevision | `9bb956e1b4bfaea1e1e6bbee5745c937d91d4726` |
| Issue oder Pull Request | Separater Framework-Draft-PR steht aus; kein Merge, Dispatch oder bestehende-PR-Änderung ist autorisiert. |

## Motivation und Problemstellung

Der vertrauenswürdige kanonische Wartungslauf `34464725066` aktualisierte Envoy korrekt von `1.39.0` auf `1.39.1`, aber ein Post-Apply-Positiv-Control verwendete weiterhin das alte wörtliche Tuple. Der Runtime-Lock-Checker schlug korrekt fail-closed fehl, daher wurde der einzelne kanonische Draft-PR-Publisher nicht erreicht. Diese Framework-only-Korrektur ändert das Regression-Fixture, nicht Runtime-Metadaten, Updater, Workflow-Berechtigungen, Token, Downloader oder einen ausführbaren Pfad.

## Betroffene Komponenten und Sicherheitsgrenzen

Die einzige Verhaltensänderung liegt in `tests/security_regression/test_runtime_component_lock.py`. Die relevante Grenze ist der statische Lock-Profile-Checker im vertrauenswürdigen kanonischen Maintenance-Candidate; Workflow-Token, Action-Pins, Publisher-Scope, Runtime-URL, Digest, Downloader und ein ausführbarer Sink ändern sich nicht.

## Akzeptanzkriterien

- Das positive Override folgt dem aktuellen geprüften Envoy-Profil und liefert `0`.
- Die veränderte Version bleibt mit `77` und `ENVOY_VERSION drift` blockiert.
- Kein Runtime-Lock-Control und keine Publisher-Autorität wird erweitert.

## Untersuchte Alternativen

Das Festschreiben des nächsten Envoy-Releases würde dasselbe Fixture erneut veralten lassen. Das Abschwächen des Checkers würde ein gültiges Provenance-Control entfernen. Beide Alternativen werden verworfen.

## Implementierungsentscheidung

Das positive Envoy-Override leitet jetzt Version, URL und Digest aus dem aktuellen `envoy-ext-authz`-Lock-Profil ab. Der Negativ-Control leitet eine eindeutig veränderte Patch-Version ab und muss weiterhin `ENVOY_VERSION drift` mit Exit `77` melden. Die Korrektur bleibt daher datenabgeleitet und test-only.

## Geänderte Dateien und Tests

- `tests/security_regression/test_runtime_component_lock.py`
- dieses gepaarte Change Record

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Evidenz |
| --- | --- | --- | --- |
| `python3 -m unittest tests.security_regression.test_runtime_component_lock -v` | 0 | 13 Runtime-Lock-Tests bestanden, einschließlich geänderter positiver und negativer Controls. | Isolierter Korrektur-Worktree |
| `python3 -m unittest tests.security_regression.test_runtime_component_sync -v` | 0 | 19 Runtime-Synchronisations- und Fail-closed-Tests bestanden. | Isolierter Korrektur-Worktree |
| `.venv/bin/python -m unittest tests.ci_security.test_update_workflow_tools -v` | 0 | 41 Updater- und Native-Candidate-Controls bestanden. | Bestehende Python-Umgebung des Repositorys |
| `.venv/bin/python -m unittest tests.ci_security.test_unified_common_maintenance_workflow -v` | 0 | 15 Trusted-Publisher- und Workflow-Contract-Tests bestanden. | Bestehende Python-Umgebung des Repositorys |
| `python3 -m py_compile tests/security_regression/test_runtime_component_lock.py ci/tools/check-runtime-component-lock.py ci/tools/sync-runtime-components.py` | 0 | Relevante Python-Quellen kompilierten. | Task-eigener Pycache-Root |
| `bash -n ci/lib/common.sh` | 0 | Die unveränderte kanonische Shell-Quelle bleibt syntaktisch gültig. | Isolierter Korrektur-Worktree |
| `python ci/tools/check-runtime-component-lock.py --lock ci/provisioning/runtime-component-lock.json --common ci/lib/common.sh --manifest ci/provisioning/runtime-components.manifest.json` | 0 | Der eingecheckte Runtime-Lock bestand. | Bestehende Python-Umgebung des Repositorys |
| `python ci/tools/sync-runtime-components.py --check` | 0 | Die eingecheckten Runtime-Komponenten sind aktuell. | Bestehende Python-Umgebung des Repositorys |
| `python ci/checks/documentation/check-change-records.py` | 0 | Der gepaarte Change-Record-Contract bestand. | Bestehende Python-Umgebung des Repositorys |
| `git diff --check` | 0 | Keine Whitespace-Fehler. | Isolierter Korrektur-Worktree |

## Sicherheitsauswirkung

Dies repariert ein fail-closed Test-Fixture und lockert kein Security-Control. Der alternative Control mit veränderter Version bleibt aktiv. Keine Security-Remediation oder Lockerung einer Sicherheitsgrenze wird vorgenommen.

## Dokumentation und Runtime-Evidenz

Dieses englische/deutsche Record dokumentiert die test-only-Korrektur. Hosted-Lauf `34464725066` und sein aufbewahrter caller-bound Plan sind die Runtime-/Lifecycle-Evidenz; kein neuer Dispatch wird ausgelöst.

## Nicht ausgeführte Prüfungen

Dem System-`python3` fehlt PyYAML, doch die bestehende Python-Umgebung des Repositorys stellte es bereit und die verwandten Tests bestanden. Ruff ist dort und auf `PATH` nicht verfügbar und wurde nicht installiert. Exact-Head-Hosted-Checks stehen bis zu einem Draft-PR aus.

## Einschränkungen und Restrisiko

Ein neuer Master-Merge, ein zweiter Canonical-Maintenance-Dispatch und das Schließen von #113/#114 benötigen eine neue aktuelle Nutzerautorisierung. Parent, MRTS, Gitlinks und bestehende PRs bleiben unverändert.

## Finaler Diff- und Review-Status

Lokale Implementierung und fokussierte Controls sind abgeschlossen; finaler Diff-, Whitespace-, Security-Review und Delivery-Evidence stehen aus. Es werden kein Default-Branch-Write, keine Force-Operation und kein Branch-Protection-Bypass verwendet.
