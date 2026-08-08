# Change Record: 20260808-03-fix-portable-apache-audit-fixture

**Sprache:** [English](20260808-03-fix-portable-apache-audit-fixture.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260808-03-fix-portable-apache-audit-fixture` |
| UTC-Datum | 2026-08-08 |
| Framework-Basisrevision | `da28e6da58fa8b1135d3631612a78e73ff98584b` |
| Issue oder Pull Request | Zugehöriger Parent-Lauf `31258666144`, no-CRS-Job `93105942184`; Task-Branch `fix/apache-portable-audit-fixture`, Framework-Pull-Request ausstehend. |

## Motivation und Problemstellung

Der gemeinsame portable Fall `action_status_401_phase1_block` erzeugte im
beobachteten Parent-no-CRS-Smoke fachlich korrekt HTTP 401. Sein Vertrag
verlangte dennoch Audit-Evidence, während seine eigenen Regeln die kanonischen
`SecAudit*`-Direktiven ausließen, die diese Evidence erzeugen. Die Framework-
Assertion schlug bei fehlender oder leerer Auditdatei korrekt fail-closed fehl.
Dies ist ein Framework-Fixture-Defekt und kein Grund, eine Parent-Assertion zu
lockern oder eine Auditdatei künstlich zu erzeugen.

## Betroffene Komponenten und Sicherheitsgrenzen

Diese reine Framework-Änderung betrifft die portable Phase-1-Fixture,
gemeinsame Runner-Validierung und -Materialisierung, fokussierte
Regressionstests, die Kataloganleitung und diesen gepaarten Record. Die Grenze
verläuft von YAML-Regeln über den gerenderten privaten Auditpfad bis zum vom
Host erzeugten Audit-Artefakt. Das Parent-Apache-Harness besitzt die
tatsächliche Pfadvorbereitung, den Apache-Start, die reale HTTP-Transaktion und
das Cleanup. Parent-Source, Parent-Gitlinks, MRTS, APR-util-Provenance,
CRS-Materialisierung und NGINX-Privilege-Handling werden hier nicht geändert.

## Akzeptanzkriterien

1. Der Fall erwartet weiterhin exaktes HTTP 401 und Rule `2320`.
2. Erforderliche Audit-Fixtures ohne `SecAuditEngine`, Serial-Typ, kanonische
   Parts oder einen der exakten Platzhalter werden bei der Validierung
   abgelehnt.
3. Fehlende, ausbrechende, symlinkte oder stale Auditziele werden abgelehnt,
   bevor die Materialisierung einen Host erreicht.
4. Eine fehlende oder leere Auditdatei bleibt ein Fehler; passende URI, Rule
   und Nachricht sind gemeinsam mit HTTP 401 erforderlich.
5. Ein anderer Request-/Run-Marker, eine andere Rule, Nachricht,
   Transaktionsidentität oder ein anderer HTTP-Status werden von den
   fokussierten Assertion-Kontrollen nicht akzeptiert.
6. Der Fixture-Renderer erzeugt keine synthetische Auditdatei.

## Untersuchte Alternativen

- Das Entfernen von `expect.audit_log.required` oder die Bewertung von HTTP
  401 allein als PASS wurde verworfen, weil es den beobachteten Evidence-
  Vertrag schwächt.
- Das Erzeugen einer Fixture-seitigen Auditdatei wurde verworfen, weil es keine
  ModSecurity-/Apache-Transaktion beweist.
- Das Hardcodieren eines Host- oder Repository-Auditpfads wurde verworfen,
  weil portable Fixtures nur unter der privaten Runtime-Output-Root
  materialisieren dürfen.
- Ein Parent-only-Workaround wurde verworfen, weil die unvollständige Fixture
  Framework-owned ist und von Connector-Runnern geteilt wird.

## Implementierungsentscheidung

Die Fixture verwendet nun die vorhandene kanonische portable Serial-
Konfiguration: `SecAuditEngine RelevantOnly`, `SecAuditLogType Serial`,
`SecAuditLogParts ABHZ` und exakte Platzhalter `@@AUDIT_LOG@@` /
`@@AUDIT_LOG_DIR@@`. Sie bindet außerdem erwartete URI, Rule-ID und Nachricht
an die erforderliche Audit-Assertion.

Für jeden runtime-materialisierbaren Fall, der ein Auditlog verlangt, fordert
der gemeinsame Runner dieselbe kanonische Konfiguration. Bei der
Materialisierung müssen beide vom Host gelieferten Pfade absolut, symlinkfrei
und Nachfahren einer vorhandenen, dem aktuellen Benutzer gehörenden Output-Root
sein, die weder gruppen- noch world-writable ist. Das Audit-Verzeichnis und der
Parent der Auditdatei müssen bereits existieren und dieselbe Ownership-Regel
erfüllen; eine schon vorhandene Auditdatei wird vor Serverstart als stale
Evidence abgelehnt. Der Runner ersetzt ausschließlich Platzhalter. Er erzeugt,
kopiert oder markiert keine Auditdatei als bestanden.

## Geänderte Dateien und Tests

- `tests/cases/phases/phase1/action_status_401_phase1_block.yaml` ergänzt nur
  kanonische Serial-Audit-Direktiven und stabile URI-/Nachrichten-Erwartungen.
- `tests/runners/runner_core.py` validiert Required-Audit-Fixture-Direktiven
  und private, frische Audit-Render-Ziele.
- `tests/security_regression/test_portable_audit_fixture_contract.py` deckt
  die legitime Kontrolle sowie fehlenden Engine-, Bad-Path-, Symlink-,
  Stale-Datei-, gruppenbeschreibbaren-Verzeichnis-, falschen
  Request-/Rule-/Nachrichten-/Transaktions-, Missing-File- und
  Wrong-Status-Negativfälle ab.
- `docs/catalog-and-cases.md` und `.de.md` beschreiben die portable Grenze.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | ---: | --- | --- |
| `python3 -B -m unittest -v tests.security_regression.test_portable_audit_fixture_contract` | 0 | Neun fokussierte positive und negative Fixture-/Materialisierungs-/Assertion-Tests bestanden mit dem lokalen Diagnoseinterpreter. | Task-eigener Framework-Worktree |
| `make lint` mit task-eigenen `BUILD_ROOT`, `TMP_ROOT` und `PYTHONPYCACHEPREFIX` | 0 | Shell-Syntax, Python-Kompilierung, 137 CI-Security-Tests, Provenance-Verträge, Workflow-/YAML-Checks, Dokumentation, Record-Vertrag und Whitespace-Checks bestanden. | Task-eigener Framework-Worktree |

## Sicherheitsauswirkung

Der ursprüngliche defekte Pfad wird durch die Missing-Engine- und
Missing-/Stale-Audit-Ziel-Kontrollen erneut geprüft: Eine Fixture kann keine
Required-Audit-Evidence beanspruchen und zugleich die kanonische Konfiguration
weglassen, und eine frühere Datei kann nicht wiederverwendet werden.
Gruppenbeschreibbare Audit-Verzeichnisse werden ebenfalls abgelehnt. Die
alternativen Path-/Rule-/Nachrichten-/Transaktions-/Status-Kontrollen schlagen
fail-closed fehl. Diese Änderung behauptet nicht, dass ein lokaler
synthetischer Test ein hosterzeugter Audit-Record ist; exakte Hosted-
Runtime-Evidence bleibt vor dem Merge erforderlich.

## Dokumentation und Runtime-Evidenz

Das englisch/deutsche Katalogpaar dokumentiert nun Required-Audit-
Konfiguration, private Pfadmaterialisierung, Stale-Datei-Ablehnung und die
Host-Verantwortung für reale Audit-Erzeugung und Cleanup. Der aufbewahrte
Parent-Lauf `31258666144` beobachtet nur das Fehlerbild vor dem Fix – HTTP 401
und fehlende Auditdatei – und ist keine Evidence für diese uneingereichte
Framework-Änderung.

## Nicht ausgeführte Prüfungen

- Repository-erforderliche CPython-3.14.6-Prüfungen sind ausstehend; lokal
  läuft Python 3.14.4.
- Apache-Konfigurationsprüfung und eine reale Apache-401-/Audit-Transaktion
  sind als exakte Hosted- oder kontrollierte Host-Validierung ausstehend.
- Sonar, Review, Branch Protection, Framework-Merge,
  Parent-Gitlink-Update und Parent-Full-Smoke-Evidence sind ausstehend.

## Einschränkungen und Restrisiko

Die lokalen Tests beweisen Schema, private Pfadmaterialisierung,
Stale-Datei-Ablehnung und Assertion-Verhalten. Sie erzeugen keinen Apache-
Audit-Record und behaupten kein Host-Cleanup. Ein späterer Hosted Parent-Smoke
auf dem exakten Head muss beweisen, dass dieser konkrete 401-Request ein
frisches nichtleeres Auditlog innerhalb seiner privaten Root erzeugte und dass
der Host nach Erfolgs- und Fehlerpfaden aufräumt.

## Finaler Diff- und Review-Status

Beim Verfassen besitzt dieser task-eigene Framework-Worktree einen unstaged,
fokussierten Diff; `git diff --check` bestand und es wurde kein
Secret-haltiges Material ergänzt. Er ist weder committet, gepusht noch
eingereicht. Dieser Record behauptet keine Framework-PR-Nummer, kein
Branch-Protection-Ergebnis, keine Freigabe, kein Sonar-Ergebnis, keinen Merge,
kein Parent-Gitlink-Update und kein Parent-PR-Ergebnis.
