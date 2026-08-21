# Change Record

**Sprache:** [English](20260821-04-fix-common-version-updater-bootstrap.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260821-04-fix-common-version-updater-bootstrap |
| UTC-Datum | 2026-08-21 |
| Framework-Basisrevision | 798bff0c921ab8c7f10b2ca949304d58e7f205a2 |
| Issue oder Pull Request | Bei Erstellung dieses Records keiner; die Auslieferung erstellt einen task-eigenen Draft-PR aus dem überprüften Commit. |

## Motivation und Problemstellung

Der gehostete Common-Version-Candidate-Job scheiterte auf einem frischen Runner,
weil update-workflow-tools.py PyYAML importiert, bevor der Job die vorhandenen
hash-gesperrten CI-Abhängigkeiten installiert hatte. Der Publisher hatte
denselben latenten Reihenfolgefehler. Die Reparatur muss Lock, fail-closed
Bootstrap, Snapshot-vor-Plan-Bindung und die bestehende Publisher-Grenze
bewahren.

## Betroffene Komponenten und Sicherheitsgrenzen

- .github/workflows/check-common-versions.yml: Bootstrap der Candidate- und
  Publisher-Runner vor dem Import des nativen Helpers.
- ci/checks/security/check-ci-security-contract.py und CI-Security-Tests:
  überprüfte Body-Digests und eine semantische Reihenfolgekontrolle.
- Englische/deutsche Workflow-Sicherheitsdokumentation: die
  Fresh-Runner-Abhängigkeitsgrenze.

Parent-Source und Gitlink bleiben unverändert. MRTS bleibt read-only und
unverändert.

## Akzeptanzkriterien

1. Candidate und Publisher installieren requirements-ci.lock mit
   --require-hashes und führen pip check vor ihrem ersten Aufruf des nativen
   Workflow-Tool-Helpers aus.
2. Der Snapshot bleibt vor der Caller-gebundenen Plan-Anwendung; kein
   Workflow-Schritt, keine Berechtigung, kein Token-Pfad, kein Lock-Inhalt und
   kein Publisher-Scope ändern sich.
3. Positive und negative Tests verwerfen fehlende, auskommentierte, ausgegebene,
   späte oder vor dem Snapshot liegende Bootstraps.
4. Ein Framework-Draft-PR enthält nur die überprüfte task-eigene Änderung und
   sein exakter Head wird durch die verfügbaren Hosted Controls geprüft.

## Untersuchte Alternativen

Ein zusätzlicher Bootstrap-Schritt wurde verworfen, weil die überprüfte
Workflow-Topologie, Sensitive-Reference-Pfade und das Publisher-Profil bereits
die bestehenden Schrittpositionen binden. Eine Installation nach dem ersten
Helper-Import oder ein gelockerter Lock würde den Fehler behalten oder
Supply-Chain-Kontrollen schwächen.

## Implementierungsentscheidung

Der vorhandene gesperrte Installationsschritt und pip check werden in beiden
frischen Jobs direkt vor dem Helper in den unveränderten Snapshot-Run-Body
verschoben. Der spätere Plan-Anwendungs-Body dupliziert sie nicht mehr. Der
Security-Checker erzwingt die Befehlsreihenfolge nun unabhängig von seinen
überprüften Run-Body-Digests.

## Geänderte Dateien und Tests

- Common-Version-Workflow, Security-Contract und die fokussierten positiven und
  negativen Regressionstests aktualisiert.
- Englische/deutsche Workflow-Sicherheitsdokumentation aktualisiert.
- Dieses gepaarte Change Record ergänzt.

Die Negativfälle decken fehlende Hash-Erzwingung, fehlendes pip check,
auskommentierten oder ausgegebenen Bootstrap, einen Updater vor dem Bootstrap
und einen Updater in einem vorherigen Schritt ab.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Fokussierte Unified-Workflow- und CI-Security-Contract-Tests | 0 | 47 Tests bestanden, einschließlich der neuen positiven und negativen Reihenfolgekontrollen. | Task-eigener Framework-Worktree |
| Vollständige CI-Security-Test-Suite | 0 | 286 Tests bestanden. | Task-eigener Framework-Worktree |
| Direkter CI-Security-Contract | 0 | Der überprüfte Workflow-, Pin-, Token- und Bootstrap-Contract bestand. | Task-eigener Framework-Worktree |
| Workflow-Metadaten-, Berechtigungs- und Action-Pin-Prüfungen | 0 | Alle 16 Workflows und alle externen Action-Pins bestanden. | Task-eigener Framework-Worktree |
| Workflow-Security- und Dokumentationsprüfungen | 0 | 9 Workflow-Security-Tests sowie Link-, Bilingual-, Pfad- und Change-Record-Prüfungen bestanden. | Task-eigener Framework-Worktree |
| Gepinnte Ruff-Lint- und Formatprüfungen | 0 | Das hash-verifizierte Ruff 0.16.3 akzeptierte alle drei geänderten Python-Dateien. | Task-eigenes externes Runner-Temporary-Verzeichnis |
| Bytecode-freie Python-Syntaxkompilierung der drei geänderten Python-Dateien | 0 | Alle Dateien kompilierten ohne Bytecode im externen Worktree zu schreiben. | Task-eigener Framework-Worktree |

## Sicherheitsauswirkung

Die ursprüngliche Source-Reihenfolge wurde strukturell erneut geprüft:
Candidate und Publisher bootstrappen nun die hash-gesperrte PyYAML-Abhängigkeit
vor dem Import des Helpers. Der semantische Contract verwirft die dokumentierten
Reihenfolgeumgehungen unabhängig. Kein Credential, keine Berechtigung, kein
Checkout, Lock, Publisher oder PR-Merge-Control wurde erweitert.

## Dokumentation und Runtime-Evidenz

Die englischen/deutschen Workflow-Sicherheitsdokumente nennen nun die
Bootstrap-vor-Helper-Invariante. Bei Erstellung dieses Records gibt es keine
gehostete Ausführung des vorgeschlagenen Sources; normale PR-Checks und ein
späterer vertrauenswürdiger Default-Branch-Run liefern die verbleibende
Runtime-Evidenz.

## Nicht ausgeführte Prüfungen

Von diesem Branch wurde kein manueller gehosteter Maintenance-Dispatch
ausgeführt, weil der vertrauenswürdige Workflow die Default-Branch-Revision
auscheckt; er würde diese noch nicht gemergte Reparatur nicht ausführen.
Candidate-/Publisher-Runtime-Verhalten bleibt eine Evidenzanforderung nach der
Integration.

Der lokale gepinnte Pyright-Check wurde nicht ausgeführt, weil Node.js in dieser
Ausführungsumgebung fehlt; der normale PR-Qualitätsworkflow bleibt die
maßgebliche Type-Check-Evidenz.

## Einschränkungen und Restrisiko

Die Reparatur entfernt den fehlenden-PyYAML-Bootstrapfehler, erzeugt aber kein
Upstream-Update, um Candidate- und Publisher-Pfade auszuführen. Ein
erfolgreicher PR-Contract-Run ist Source-Level-Evidenz und kein Ersatz für
einen späteren vertrauenswürdigen Default-Branch-Maintenance-Run.

## Finaler Diff- und Review-Status

Bei Erstellung dieses Records enthält der Task-Worktree nur die begrenzte
Reparatur und wurde weder committed noch gepusht oder gemergt. Vor der
Auslieferung sind ein finaler Whitespace-, Secret-, Scope- und Exact-Head-Review
erforderlich.
