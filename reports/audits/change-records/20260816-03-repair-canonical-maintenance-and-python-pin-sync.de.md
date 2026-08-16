# Change Record: 20260816-03-repair-canonical-maintenance-and-python-pin-sync

**Sprache:** [English](20260816-03-repair-canonical-maintenance-and-python-pin-sync.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260816-03-repair-canonical-maintenance-and-python-pin-sync` |
| UTC-Datum | `2026-08-16` |
| Framework-Basisrevision | `fec22255a8d8663ed578a84b052dfd00631288ca` |
| Issue oder Pull Request | Framework-PR #85 ist ein Draft. Dieser Record autorisiert weder Merge noch direkten `master`-Write. |

## Motivation und Problemstellung

Der Dispatch-Lauf `31958961125` importierte einen YAML verwendenden Resolver, bevor die geprüfte PyYAML-Abhängigkeit installiert war. PR #84 änderte zusätzlich nur die generierte Ansicht `.python-version` auf `3.14.7`, während `CI_CANONICAL_PYTHON_VERSION` in `ci/lib/common.sh` bei `3.14.6` blieb. Die daraus folgende Source/View-Abweichung ließ die Läufe `31959220077` und `31959297702` fehlschlagen.

## Betroffene Komponenten und Sicherheitsgrenzen

Die Korrektur betrifft den vertrauenswürdigen Common-Version-Wartungsworkflow, seine hash-gesperrte Dependency-Grenze und den kanonischen Python-Source/View-Update-Pfad. Der Publisher bleibt Draft-only, nutzt seinen eingeschränkten GitHub-App-Token und darf nur die kanonische Assignment plus generierte Ansicht veröffentlichen. Parent, Connector-Runtime und MRTS liegen außerhalb des Scopes.

## Akzeptanzkriterien

1. Jeder Resolver-Job führt den geprüften hash-gesperrten Bootstrap vor dem Auflösen aus.
2. Der Updater ändert nur die kanonische Python-Assignment und der Workflow regeneriert und prüft `.python-version`.
3. Ein wiederverwendeter CPython-Draft-Branch darf exakt die erwarteten zwei Dateien und eine kandidatengebundene `common.sh`-Assignment-Hunk enthalten.
4. Contracts weisen kommentierten oder Echo-only Bootstrap-Text und jede andere Publisher- oder Source-Scope-Erweiterung zurück.

## Untersuchte Alternativen

- Eine ungepinnte Dependency-Installation wurde verworfen, weil sie den geprüften Lock umgeht.
- Ein Update nur von `.python-version` wurde verworfen, weil die Datei generiert ist.
- Eine breite `common.sh`-Allowlist, automatischer Merge oder Direct Push wurde verworfen, weil dies jeweils die Trust-Grenze schwächt.

## Implementierungsentscheidung

Jeder Resolver-Body ist nun an einen exakten geprüften SHA-256 gebunden; Kommentare oder ausgegebene Befehle reichen daher nicht aus. Der Python-Updater ersetzt atomar die eine kanonische Assignment; der Workflow synchronisiert und prüft ihre Ansicht. Bestehende Draft-Branches müssen eine einzelne Source-Assignment-Ersetzung zum frisch aufgelösten Kandidaten ohne Metadaten- oder zusätzliche `common.sh`-Änderung zeigen.

## Geänderte Dateien und Tests

- `check-common-versions.yml` bereitet Resolver-Dependencies über den bestehenden Lock vor.
- `check-python-version.yml` begrenzt Source-Updates, Ansichten und wiederverwendete Draft-Diffs.
- Updater und CI-Contract implementieren Source-Parsing, atomare Aktualisierung, exakte Run-Bindung und enge Pfad-Durchsetzung.
- Fokussierte Regressionstests decken fehlende, kommentierte und Echo-only Bootstrap-Befehle, View-only-Veröffentlichung, unbegrenzte Source-Änderungen, fehlerhafte/doppelte/stale Assignments und Symlinks ab.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Fokussierte Updater-, Python-/CI-Contract-, Framework-CI-Contract- und Maintenance-Tests | `0` | 97 Tests nach den finalen Security-Closures bestanden. | Task-Worktree; Bytecode-Writes deaktiviert. |
| Früher erweiterte fokussierte Suite einschließlich Pin-Sync und Descriptor-Series | `0` | 96 Tests vor den finalen Security-Closures bestanden. | Task-Worktree; bei Überschneidungen durch die aktuelle fokussierte Suite abgelöst. |
| Vollständiger Framework-Lint | `0` | Auf dem finalen Implementierungsstand vor dieser reinen Ergebnisaktualisierung bestanden. | Task-Worktree; Bytecode-Writes deaktiviert. |
| Initiale Hosted-Quality-Checks von PR #85 | fehlgeschlagen, dann behoben | ShellCheck fand einen ungültig eingerückten Here-Document-Terminator und Ruff Formatierungsdrift; die Korrektur behält den kandidatengebundenen Guard bei und aktualisiert seinen exakten Run-Body-Hash. | GitHub-Läufe `31964051925` und `31964051902`. |
| Wiederholter vollständiger Framework-Lint | `0` | Nach der Hosted-Quality-Korrektur bestanden. | Task-Worktree; Bytecode-Writes deaktiviert. |
| Erste korrigierte Exact-Head-SonarCloud-Analyse | nicht akzeptiert | Quality Gate bestanden und Duplizierung in neuem Code `0.0%`, aber SonarCloud meldete vier neue Code-Smell-Issues. | SonarCloud-Bot-Kommentar von PR #85; vor der finalen Delivery behoben. |
| Frische finale Exact-Head-Hosted-Checks | nach Sonar-Remediation ausstehend | Müssen den final veröffentlichten Pull-Request-Head validieren. | PR #85; bei dieser Record-Aktualisierung noch nicht verfügbar. |

## Sicherheitsauswirkung

Dies ist eine CI-Supply-Chain-Integritätskorrektur. Der ursprüngliche fehlende-PyYAML-Pfad besitzt nun einen geprüften Bootstrap. Exakte Resolver-Body-Hashes weisen Fake-Befehlstext zurück. Der ursprüngliche Pfad nur über die generierte Ansicht wird abgewiesen und ein bestehender Draft kann keinen beliebigen gesourcten `common.sh`-Content einschleusen. Es werden weder Berechtigungen, Credential-Scope, Auto-Merge- noch Direct-Push-Fähigkeiten ergänzt.

## Dokumentation und Runtime-Evidenz

Dieses englische/deutsche Paar ist die leserorientierte Dokumentationsaktualisierung.
Framework-PR #85 zeigte zunächst lokale Quality-Defekte, die behoben und lokal
erneut validiert wurden. Hosted-Evidenz bleibt erforderlich: Sein korrigierter
Exact Head muss erfolgreiche erforderliche Checks besitzen und SonarQube Cloud
muss null neue Issues melden, bevor der autorisierte Squash-Merge erfolgen darf.

Die erste Analyse des korrigierten Exact Heads meldete trotz bestandenem Quality
Gate und `0.0%` New-Code-Duplizierung noch vier neue Code-Smell-Issues. Die
finalen engen Refactorings entfernen diese Findings ohne Suppressions oder
abgeschwächte Controls; eine frische Exact-Head-Analyse muss null neue Issues
nachweisen.

## Nicht ausgeführte Prüfungen

- Frische Checks für den finalen Head, SonarQube Cloud, Review-Status,
  Exact-Head-Merge und resulting-master-Dispatches benötigen Veröffentlichung
  oder Integration.

## Einschränkungen und Restrisiko

Lokale Validierung kann weder GitHub-gehostetes App-Token-Verhalten, Protected-Branch-Durchsetzung noch SonarQube-Cloud-Analyse beweisen. Diese Controls bleiben vor der Integration verpflichtend.

## Finaler Diff- und Review-Status

Der Task bleibt auf Framework-Workflows, kanonische Pin-Updates, Contracts,
Regressionen und diesen gepaarten Record begrenzt. PR #85 existiert als Draft;
ein Merge, Parent-Gitlink-Update oder eine MRTS-Aktion fanden nicht statt.
Whitespace-, unabhängiger Security-Review und finaler Security-Diff-Review sind
bestanden; die getrackten Sonar-Refactorings und frische Hosted-Verifikation
bleiben vor der Delivery erforderlich.
