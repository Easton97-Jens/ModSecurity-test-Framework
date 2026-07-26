# Änderungsnachweis: Aktuelle Framework-Findings beheben

**Sprache:** [English](20260726-03-remediate-current-framework-findings.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260726-03-remediate-current-framework-findings` |
| UTC-Datum | 2026-07-26 |
| Framework-Basisrevision | `a7ebf5a1d9cad2b0a65a7603476a1434fdb16cf6` |
| Issue oder Pull Request | Current-State-Abgleich von `FND-FRAMEWORK-0002`, `FND-FRAMEWORK-0011`, `FND-FRAMEWORK-0053` und `FND-FRAMEWORK-0056` auf Branch `agent/framework-findings-current-state`. Ein Framework-Draft-PR ist ausstehend; kein Merge ist autorisiert. |

## Motivation und Problemstellung

Der aktuelle Framework-Master enthielt noch einen ShellCheck-Fehler, ließ
opake URL-Pfade und direkte `--resolve`-Werte in kopierte Protocol-Command-
Artefakte, enthielt ein PCRE2-Archive-Digest-Fixture, das an einem früheren
V3-Provenance-Gate stoppte, und bewahrte eine veraltete Resulting-Master-
Aussage zu PR #42 in einem gepaarten Change Record. Diese Änderung korrigiert
die aktuellen Bedingungen, ohne historische Findings umzuschreiben,
Provenance abzuschwächen oder nicht erhobene Host-Runtime-Evidenz zu behaupten.

## Betroffene Komponenten und Sicherheitsgrenzen

- `ci/lib/mrts-common.sh` bleibt ein sourcebarer POSIX-Helper und deklariert
  diese Shell jetzt ausdrücklich für ShellCheck.
- Der Protocol Client und sein unabhängiger Artefakt-Validator redigieren
  opake URL-Pfade und jeden direkten `--resolve`-Wert, bevor kanonische
  Evidenz sie behalten kann. Nur begrenzte Health-Pfade bleiben sichtbar.
- Das PCRE2-Fixture modelliert die kleinste freigegebene synthetische V3-
  Topologie über das bestehende hermetische Git-Modell. Die produktive
  `/usr/bin/git`-Bindung und der V3-Provenance-Guard bleiben unverändert.
- Das PR-#42-Change-Record-Paar unterscheidet jetzt beobachtete Merge-Evidenz
  von ungelösten Current-Master-Sonar- und wartenden-Cloudflare-Bedingungen.
- Parent-Source, Parent-Gitlink, Framework-zu-MRTS-Gitlink und MRTS-Source
  liegen außerhalb dieser reinen Framework-Änderung.

## Akzeptanzkriterien

- Framework-ShellCheck hat keinen aktuellen Error-Level-Diagnosewert aus
  `ci/lib/mrts-common.sh`.
- Synthetische opake Pfad-, Prozent-kodierte Pfad-, Query- und `--resolve`-
  Marker können nicht in einem verwalteten `client-command.txt` erscheinen;
  eine sichere `/health`-Kontrolle bleibt erhalten.
- Der unabhängige Artefakt-Validator weist ein gefälschtes Command-Artefakt
  mit diesen nicht redigierten Werten ab.
- Jeder ungültige PCRE2-Digest erreicht den vorgesehenen Digest-Blocker vor
  `tar`, während der passende Digest die lokale Extraction-Kontrolle erreicht.
- Der historische PR-#42-Record bindet den normalen Merge an
  `935cf14c676a24672be5c336e92cd13457cc35c8`, ohne ungelöste Sonar- oder
  Cloudflare-Bedingungen als bestanden zu bezeichnen.
- Die Änderung wird nur über einen normalen Framework-Draft-PR geliefert;
  weder Merge, Parent-Update noch MRTS-Aktion werden ausgeführt.

## Untersuchte Alternativen

- ShellCheck zu unterdrücken oder eine breite Source-Ausnahme hinzuzufügen
  wurde verworfen; der Helper ist POSIX und kann seinen tatsächlichen
  Interpreter deklarieren.
- Beliebige Endpunktpfade für Diagnostik zu behalten wurde verworfen, weil das
  kanonische Command-Artefakt in Evidenz kopiert wird und opake Request-Daten
  enthalten kann. Eine kleine Health-Pfad-Allowlist bewahrt die nötige
  Kontrolle.
- Den V3-Provenance-Guard zu lockern, um den PCRE2-Test wiederzubeleben,
  wurde verworfen. Stattdessen liefert das Fixture die freigegebene
  synthetische Topologie über das bestehende hermetische Testmodell.
- Parent-Findings, den gemergten PR-#42-Body oder Sonar-/Cloudflare-
  Einstellungen zu bearbeiten wurde als außerhalb dieses Framework-Source-PR
  und für die Korrektur des veralteten Records unnötig verworfen.

## Implementierungsentscheidung

Der Shell-Helper erhält nur einen POSIX-Shebang. Der Protocol-Renderer bildet
alle nicht allowlisteten Pfade auf `/[redacted-path]` ab, redigiert Query-Werte
und Resolver-Argumente sowohl getrennt als auch in `--option=value`-Form, und
der unabhängige Validator weist Command-Artefakte ab, die diese Darstellung
umgehen. Die PCRE2-Regression kopiert den realen Apache-Pfad und Shared Helper
in task-eigenen temporären Storage und ersetzt nur dessen Host-Git-Bindung durch
das bestehende Modell der exakten freigegebenen Topologie. Der historische
Change Record wird in Englisch und Deutsch mit den beobachteten normalen
Merge-Fakten und expliziten verbleibenden Grenzen korrigiert.

## Geänderte Dateien und Tests

- `ci/lib/mrts-common.sh` und die fokussierte ShellCheck-Kontrolle.
- `ci/checks/protocol/protocol_client.py` und
  `ci/checks/protocol/check_protocol_evidence.py`, mit Protocol- und no-CRS-
  Regressionen für Redigierung und Validator-Bypass-Resistenz.
- `tests/security_regression/test_pcre2_archive_digest.py` unter Verwendung
  des bestehenden freigegebenen V3-Topologie-Helpers ohne Änderung produktiver
  Provenance-Quellen.
- Das korrigierte PR-#42-Change-Record-Paar und dieses Englisch/Deutsch-Paar.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Current-Master-Workflow-, Pin-, CRS-, Protocol- und Dokumentations-Checks | 0 | Bestätigte, dass mehrere ältere aktive Records auf aktuellem Master bereits geschützt sind. | Lokale Prüfung bei `a7ebf5a1d9cad2b0a65a7603476a1434fdb16cf6` |
| Current-Master `test_pcre2_archive_digest.py` | 1 | Fünf Assertions reproduziert: Das veraltete Fixture stoppte am V3-`.gitmodules`-Provenance-Guard vor der PCRE2-Prüfung. | `FND-FRAMEWORK-0056`-Baseline |
| Current-Master Framework-ShellCheck-Error-Scope | 1 | Das einzige Error-Level-Ergebnis war `SC2148` für `ci/lib/mrts-common.sh`. | `FND-FRAMEWORK-0002`-Baseline |
| Current-Master synthetischer Protocol-Renderer-Check | 0 | Ein synthetischer opaker Pfad und direkter Resolver-Wert wurden sichtbar behalten und bewiesen FND-0011 vor der Korrektur. | Sicherer synthetischer `FND-FRAMEWORK-0011`-Reproducer |
| Framework `make lint` nach der Korrektur | 0 | Vollständige lokale Suite bestanden, einschließlich V3-Provenance (18 Tests), NGINX-/Protocol-/no-CRS-Coverage, Workflow-Contracts, Security-Data-Flow-Checks, Dokumentation und Change-Record-Validierung. | Lint-Log des Task-Worktrees |
| Framework-ShellCheck-Error-Scope nach der Korrektur | 0 | Alle Framework-Shell-Dateien außerhalb des read-only MRTS-Submoduls bestanden auf Error-Level. | `FND-FRAMEWORK-0002`-Regression |
| `git diff --check` | 0 | Keine Whitespace-Fehler im abgegrenzten Framework-Diff. | Task-Worktree |

## Sicherheitsauswirkung

Diese Änderung schließt eine Evidenz-Retention-Grenze, keine Live-Request-
Routing- oder Authorization-Grenze. Das Protocol-Command-Artefakt behält nur
eine Authority, einen allowlisteten harmlosen Pfad oder einen redigierten
Pfadmarker, einen redigierten Query-Marker und redigierte sensitive Curl-
Optionswerte. Der unabhängige Validator schützt kanonisches Kopieren vor einem
gefälschten externen Artefakt. V3-Provenance, Host-Git, Action-Pinning, CI-
Permissions und Test-Kontrollen werden nicht gelockert.

## Dokumentation und Runtime-Evidenz

Der gepaarte historische PR-#42-Record behält jetzt den beobachteten normalen
Merge korrekt und nennt seine Grenzen. Dieser neue gepaarte Record dokumentiert
nur den Framework-Source-/Test-Scope. Vor Beobachtung für diesen Draft-PR
werden keine Host-Lifecycle-, Connector-Runtime-, Python.org-Live-Updater-,
Parent-Gitlink-, MRTS-, Hosted-Exact-PR-Head-, Sonar-, Cloudflare- oder
Merge-Ergebnisse beansprucht.

## Nicht ausgeführte Prüfungen

- Native Apache- oder NGINX-Lifecycle-Validierung liegt außerhalb dieses
  Fixture-only- und Protocol-Artefakt-Scopes.
- Hosted Actions, SonarQube Cloud, Reviews, Branch Protection und Cloudflare-
  Status gelten für den zukünftigen exakten Draft-PR-Head und sind noch nicht
  beobachtet.
- Findings, die Codex-Cloud-Zugriff, External-Tool-Änderungen oder native H2-
  und Apache-Lifecycle-Evidenz benötigen, bleiben getrennt getrackt und werden
  durch diese Änderung nicht verborgen.

## Einschränkungen und Restrisiko

Die Protocol-Allowlist zeigt absichtlich nur Root und Standard-Health-Pfade.
Ein Caller, der einen anderen harmlosen Diagnosepfad benötigt, muss eine
überprüfte explizite Kontrolle ergänzen, statt sich auf beliebige
Pfad-Retention zu verlassen. Das PCRE2-Fixture validiert die Archivgrenze mit
einer exakten hermetischen Topologie; die unabhängige V3-Provenance-Suite
bleibt die maßgebliche produktive Host-Git- und Fresh-Checkout-Kontrolle.
Dieser Record schließt keine blockierten Native-Lifecycle-, External-Tool-,
Codex-Cloud-, Sonar- oder Cloudflare-Findings.

## Finaler Diff- und Review-Status

Der abgegrenzte Diff beschränkt sich auf die vier aktuellen Framework-eigenen
Finding-Pfade, ihre Regression-Coverage und erforderliche gepaarte Records.
Vollständiger lokaler Lint, ShellCheck, Dokumentation, Security-Data-Flow,
Protocol, Provenance und Diff-Format-Evidenz bestanden im Task-Worktree.
Hosted-Validierung bleibt für den zukünftigen exakten Draft-PR-Head ausstehend.
Keine Secrets, Credentials, rohen Request-Payloads, Parent-Änderungen,
MRTS-Änderungen, direkte Master-Pushes oder Merges sind enthalten.
