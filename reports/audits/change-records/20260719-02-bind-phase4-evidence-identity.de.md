# Change Record

**Sprache:** [English](20260719-02-bind-phase4-evidence-identity.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260719-02-bind-phase4-evidence-identity` |
| UTC-Datum | 2026-07-19 |
| Framework-Basisrevision | `9a729226d2e040d07d7e7a4acebf201faf06ab37` |
| Issue oder Pull Request | FND-CROSS-0006; Framework-PR ausstehend |

## Motivation und Problemstellung

FND-CROSS-0006 zeigte, dass das autoritative strenge Phase-4-Gate ein kopiertes Regel-1100301-Event allein durch übereinstimmende First-Byte-Felder akzeptieren konnte, ohne es an die ausgewählte Workload zu binden.

## Betroffene Komponenten und Sicherheitsgrenzen

- `ci/checks/evidence/check_full_lifecycle_evidence.py`
- `tests/no_crs/test_no_crs_baseline.py`

Die Sicherheitsgrenze ist die Promotion kanonischer Evidenz. Event, Resultat, Manifest und der spezifische ausgewählte live ausgeführte Phase-4-PASS-Record für jeden Claim müssen bei Connector, nicht-leerer Run-ID, Integrationsmodus und Transaktionsidentität sowie Regel und Phase übereinstimmen.

## Akzeptanzkriterien

- Fremde oder fehlende Event-Run-ID, Connector, Integrationsmodus oder Transaktionsidentität schlagen fail-closed fehl.
- Eine Workload-Identitätsabweichung zwischen Resultat und Manifest schlägt fail-closed fehl.
- Eine Transaktion eines Phase-4-PASS-Cases kann den First-Byte-Claim des anderen Cases nicht erfüllen.
- Die identitätskonsistente ausgewählte Kontrolle besteht die First-Byte-, No-Full-Buffering-, Event-Privacy- und Promotion-Prüfungen.
- Parent-Dateien, Parent-Gitlink und MRTS bleiben unverändert.

## Untersuchte Alternativen

Parent-Consumer-Wiring, Dateinamenabgleich, PASS-only-Auswahl und reine Event-Metadaten wurden verworfen, weil sie das unabhängig autoritative Framework-Prädikat nicht reparieren. Ein Host-Runtime-Lauf kann die deterministische Framework-Checker-Abdeckung nicht ersetzen.

## Implementierungsentscheidung

Der strenge Matcher leitet die ausgewählte Identität aus Resultat und Manifest ab, fordert sie in dem spezifischen live ausgeführten ausgewählten Phase-4-PASS-Record für den Claim und verlangt, dass die Event-Transaktions-ID zu genau diesem Record gehört, bevor First-Byte-Felder verglichen werden. Fehlende oder abweichende Identität einschließlich case-übergreifender Identitätsmischung schlägt fail-closed fehl. Die unabhängige, im Source bereits behobene CI-Parser-Kontrolle FND-FRAMEWORK-0017 bleibt ausgeschlossen.

## Geänderte Dateien und Tests

- `ci/checks/evidence/check_full_lifecycle_evidence.py`: bindet strenges Event-Matching an die ausgewählte Workload-Identität.
- `tests/no_crs/test_no_crs_baseline.py`: ergänzt eine identitätskonsistente Kontrolle, Regressionen für fremde/fehlende Identität, einen Resultat/Manifest-Mismatch und eine case-übergreifende Identitätsmischung.
- Dieses englische/deutsche Change-Record-Paar dokumentiert die Framework-eigene Remediation.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Fokussierter Vier-Methoden-Framework-`unittest` mit externem Temp-Root | 0 | Ausgewählte Kontrolle bestand; fremde/fehlende Event-Identität, Resultat/Manifest-Mismatch und case-übergreifende Identitätsmischung wurden abgewiesen. | `20260719T224634Z-framework-phase4-blocker-remediation-46e971f1` |
| `python -m py_compile` für die zwei geänderten Python-Dateien mit externem Bytecode-Root | 0 | Beide Dateien kompilierten. | `20260719T224634Z-framework-phase4-blocker-remediation-46e971f1` |
| `make -C "$FRAMEWORK_ROOT" ... test-no-crs-contract` mit externen Roots | 0 | 84 No-CRS-Vertragstests bestanden. | `20260719T224634Z-framework-phase4-blocker-remediation-46e971f1` |
| `make -C "$FRAMEWORK_ROOT" ... lint` mit externen Build- und Temp-Roots | 0 | Repository-Lint, Security/Data-Flow-, Dokumentations-, Change-Record-, Katalog- und Whitespace-Prüfungen bestanden. | `20260719T224634Z-framework-phase4-blocker-remediation-46e971f1` |
| Framework-`git diff --check` | 0 | Keine Whitespace-Fehler im Task-Diff. | lokaler Pre-Commit-Review |
| Fokussierter finaler Security-Diff-Review | PASS | Kein validierter Restbefund; der Cross-Case-Kandidat mit Transaktions-Pooling schlägt durch claim-spezifische Case-Bindung fail-closed fehl. | lokaler Pre-Commit-Review |

## Sicherheitsauswirkung

Die ursprüngliche Akzeptanzkontrolle mit fehlender Run-ID wurde vor dem Fix reproduziert. Die neuen Regressionen prüfen erneut fremde und fehlende Run-ID, Connector, Integrationsmodus, Transaktionsidentität, Resultat/Manifest-Mismatch und case-übergreifende Identitätsmischung; die legitime ausgewählte Kontrolle bleibt akzeptiert. Keine Sicherheitskontrolle oder MRTS-Grenze wurde gelockert.

## Dokumentation und Runtime-Evidenz

Dieses Change-Record-Paar ist die einzige leserorientierte Framework-Dokumentationsänderung. Es wurde keine Connector-Host-Runtime erfasst: Dies ist eine Framework-Validator-Reparatur, während Host-Runtime-Evidenz Parent-eigen bleibt.

## Nicht ausgeführte Prüfungen

Exact-Head-GitHub-Actions, SonarQube Cloud sowie Review-/Thread-Verifikation stehen bis zum Framework-PR aus. Der lokale Framework-Interpreter ist CPython 3.14.4, während der eingecheckte CI-Vertrag CPython 3.13 vorsieht; lokale Tests sind daher keine CI-Paritäts-Evidenz. MRTS-Tests sind nicht anwendbar.

## Einschränkungen und Restrisiko

Die Reparatur etabliert nur den wiederverwendbaren Framework-Identitätsvalidierungsvertrag; sie erzeugt oder promotet keine Connector-Host-Artefakte. FND-GITHUB-0006 bleibt ein unabhängiges Default-Setup/Advanced-CodeQL-Uploader-Thema. Für FND-CROSS-0006 wird kein Risiko akzeptiert; aktuelle Exact-Head-CI-/Sonar-Evidenz bleibt für `verified_pr` erforderlich.

## Finaler Diff- und Review-Status

Implementierung, fokussierte/vollständige No-CRS-Validierung, Repository-Lint, Whitespace-Review und finaler Security-Diff-Review sind abgeschlossen. Commit, Push, PR-Erstellung und Exact-Head-CI-/Sonar-/Review-Verifikation stehen noch aus.
