# Change Record

**Sprache:** [English](20260719-02-bind-phase4-evidence-identity.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260719-02-bind-phase4-evidence-identity` |
| UTC-Datum | 2026-07-19 |
| Framework-Basisrevision | `9a729226d2e040d07d7e7a4acebf201faf06ab37` |
| Issue oder Pull Request | FND-CROSS-0006; [Framework-PR #34](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/34). Dieser Record hält verifizierte Delivery-Evidenz des vorherigen Heads fest; sein Status-Nachtrag erfordert vor dem Merge eine neue Exact-Head-Verifikation. |

## Motivation und Problemstellung

FND-CROSS-0006 zeigte, dass das autoritative strenge Phase-4-Gate ein kopiertes Regel-1100301-Event allein durch übereinstimmende First-Byte-Felder akzeptieren konnte, ohne es an die ausgewählte Workload zu binden.

## Betroffene Komponenten und Sicherheitsgrenzen

- `ci/checks/evidence/check_full_lifecycle_evidence.py`
- `tests/no_crs/test_no_crs_baseline.py`

Die Sicherheitsgrenze ist die Promotion kanonischer Evidenz. Event, Resultat, Manifest und der spezifische ausgewählte live ausgeführte Phase-4-PASS-Record für jeden Claim müssen bei Connector, nicht-leerer Run-ID, Integrationsmodus und Transaktionsidentität sowie Regel und Phase übereinstimmen.

## Akzeptanzkriterien

- Fremde oder fehlende Event-Run-ID, Connector, Integrationsmodus oder Transaktionsidentität schlagen fail-closed fehl.
- Eine Workload-Identitätsabweichung zwischen Resultat und Manifest schlägt fail-closed fehl.
- Eine Event-Transaktionsidentität, die nicht vom ausgewählten live ausgeführten Phase-4-PASS-Record geliefert wird, kann dessen Claim nicht erfüllen.
- Die identitätskonsistente ausgewählte Kontrolle besteht die First-Byte-, No-Full-Buffering-, Event-Privacy- und Promotion-Prüfungen.
- Parent-Dateien, Parent-Gitlink und MRTS bleiben unverändert.

## Untersuchte Alternativen

Parent-Consumer-Wiring, Dateinamenabgleich, PASS-only-Auswahl und reine Event-Metadaten wurden verworfen, weil sie das unabhängig autoritative Framework-Prädikat nicht reparieren. Ein Host-Runtime-Lauf kann die deterministische Framework-Checker-Abdeckung nicht ersetzen.

## Implementierungsentscheidung

Der strenge Matcher leitet die ausgewählte Identität aus Resultat und Manifest ab, fordert sie in dem spezifischen live ausgeführten ausgewählten Phase-4-PASS-Record für den Claim und verlangt, dass die Event-Transaktions-ID zu diesem Record gehört, bevor First-Byte-Felder verglichen werden. Fehlende oder abweichende Identität einschließlich einer Workload-Identitätsabweichung eines ausgewählten Phase-4-Records schlägt fail-closed fehl. Die unabhängige, im Source bereits behobene CI-Parser-Kontrolle FND-FRAMEWORK-0017 bleibt ausgeschlossen.

## Geänderte Dateien und Tests

- `ci/checks/evidence/check_full_lifecycle_evidence.py`: bindet strenges Event-Matching an die ausgewählte Workload-Identität.
- `tests/no_crs/test_no_crs_baseline.py`: ergänzt eine identitätskonsistente Kontrolle, Regressionen für fremde/fehlende Identität, einen Resultat/Manifest-Mismatch und eine Identitätsabweichung eines ausgewählten Phase-4-Records.
- Dieses englische/deutsche Change-Record-Paar dokumentiert die Framework-eigene Remediation.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Fokussierter Vier-Methoden-Framework-`unittest` mit externem Temp-Root | 0 | Ausgewählte Kontrolle bestand; fremde/fehlende Event-Identität, Resultat/Manifest-Mismatch und eine Identitätsabweichung eines ausgewählten Phase-4-Records wurden abgewiesen. | `20260719T224634Z-framework-phase4-blocker-remediation-46e971f1` |
| `python -m py_compile` für die zwei geänderten Python-Dateien mit externem Bytecode-Root | 0 | Beide Dateien kompilierten. | `20260719T224634Z-framework-phase4-blocker-remediation-46e971f1` |
| `make -C "$FRAMEWORK_ROOT" ... test-no-crs-contract` mit externen Roots | 0 | 84 No-CRS-Vertragstests bestanden. | `20260719T224634Z-framework-phase4-blocker-remediation-46e971f1` |
| `make -C "$FRAMEWORK_ROOT" ... lint` mit externen Build- und Temp-Roots | 0 | Repository-Lint, Security/Data-Flow-, Dokumentations-, Change-Record-, Katalog- und Whitespace-Prüfungen bestanden. | `20260719T224634Z-framework-phase4-blocker-remediation-46e971f1` |
| Framework-`git diff --check` | 0 | Keine Whitespace-Fehler im Task-Diff. | lokaler Pre-Commit-Review |
| Fokussierter finaler Security-Diff-Review | PASS | Kein validierter Restbefund; der Cross-Case-Kandidat mit Transaktions-Pooling schlägt durch claim-spezifische Case-Bindung fail-closed fehl. | lokaler Pre-Commit-Review |

## Sicherheitsauswirkung

Die ursprüngliche Akzeptanzkontrolle mit fehlender Run-ID wurde vor dem Fix reproduziert. Die neuen Regressionen prüfen erneut fremde und fehlende Run-ID, Connector, Integrationsmodus, Transaktionsidentität, Resultat/Manifest-Mismatch und eine Identitätsabweichung eines ausgewählten Phase-4-Records; die legitime ausgewählte Kontrolle bleibt akzeptiert. Keine Sicherheitskontrolle oder MRTS-Grenze wurde gelockert.

## Dokumentation und Runtime-Evidenz

Dieses Change-Record-Paar ist die einzige leserorientierte Framework-Dokumentationsänderung. Es wurde keine Connector-Host-Runtime erfasst: Dies ist eine Framework-Validator-Reparatur, während Host-Runtime-Evidenz Parent-eigen bleibt.

## Nicht ausgeführte Prüfungen

Beim vorherigen PR-Head `d7b9e67bb11435c7bf7ce8a84bc73724dd943ac6` bestanden die anwendbaren GitHub Actions, SonarQube Cloud meldete ein bestandenes Quality Gate und es gab keine Reviews oder Review-Threads. Dieser Status-Nachtrag ändert den PR-Head; deshalb müssen Exact-Head-GitHub-Actions, SonarQube Cloud sowie Review-/Thread-Verifikation vor dem Merge erneut erfolgen. Der lokale Framework-Interpreter ist CPython 3.14.4, während der eingecheckte CI-Vertrag CPython 3.13 vorsieht; lokale Tests sind daher keine CI-Paritäts-Evidenz. MRTS-Tests sind nicht anwendbar.

## Einschränkungen und Restrisiko

Die Reparatur etabliert nur den wiederverwendbaren Framework-Identitätsvalidierungsvertrag; sie erzeugt oder promotet keine Connector-Host-Artefakte. FND-GITHUB-0006 bleibt ein unabhängiges Default-Setup/Advanced-CodeQL-Uploader-Thema. Für FND-CROSS-0006 wird kein Risiko akzeptiert; aktuelle Exact-Head-CI-/Sonar-Evidenz bleibt für `verified_pr` erforderlich.

## Finaler Diff- und Review-Status

Implementierung, fokussierte/vollständige No-CRS-Validierung, Repository-Lint, Whitespace-Review und finaler Security-Diff-Review wurden vor Erstellung von PR #34 abgeschlossen. Beim vorherigen Exact-Head bestanden die anwendbaren GitHub Actions und SonarQube Cloud, und es gab kein Review-Feedback. Dieser Delivery-Status-Nachtrag erzeugt einen neuen Head; neue Exact-Head-CI-, Sonar-, Review-, Merge- und resultierende-Master-Evidenz bleiben erforderlich und werden ohne selbstreferenzielle Commit-Schleife in der Task-Completion-Evidenz festgehalten.
