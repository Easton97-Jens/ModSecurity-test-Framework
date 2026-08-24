# Change Record

**Sprache:** [English](20260824-01-pin-expat-haproxy-provenance.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260824-01-pin-expat-haproxy-provenance` |
| UTC-Datum | 2026-08-24 |
| Framework-Basisrevision | `c40e924ec5c341032908e0082feba1d37ed1dfda` |
| Issue oder Pull Request | Parent-Finding `FND-PARENT-0216`; Framework-Pull-Request noch ausstehend |

## Motivation und Problemstellung

Die connector-isolierte HAProxy-Runtime erreichte Expat über eine bewegliche
`master`-Referenz und danach über einen GitHub-`releases/latest`-Abruf. Dieser
öffentliche API-Abruf wurde auf einem frischen GitHub-Runner rate-limitiert.
Die Dependency-Identität muss deshalb ein bereits geprüfter unveränderlicher
Commit sein und darf nicht durch Retries, Cache oder Token ersetzt werden.

## Betroffene Komponenten und Sicherheitsgrenzen

- `ci/lib/common.sh` liefert das vom Framework abgeleitete Expat-
  Provenance-Tupel für den Parent.
- `ci/tools/check-common-versions.py` sowie die englische/deutsche
  Variablenreferenz beschreiben die repositoryübergreifende Ownership korrekt.
- Der Parent bleibt für die connectorbezogene Beschaffung und die vollständige
  Commitprüfung zuständig; das Framework führt keine Expat-Beschaffung ein.

Keine Connector-Implementierung, kein MRTS-Inhalt, kein NGINX-Pfad, keine
GitHub-Actions-Berechtigung, keine Cache-Sharing-Policy und kein Default-Branch
werden geändert.

## Akzeptanzkriterien

1. `EXPAT_GIT_REF` ist ein kleingeschriebener vollständiger unveränderlicher
   40-Zeichen-Commit.
2. Der Commit ist der aufgelöste Commit des Upstream-Expat-Tags `R_2_8_3`.
3. Framework-Metadaten und EN/DE-Dokumentation nennen den Wert nicht länger
   ungenutzte Legacy-Abrufmetadaten.
4. Ein fokussierter Regressionstest weist die Rückkehr zu einer beweglichen
   Referenz zurück.
5. Der Parent-Gitlink wird erst nach Commit, Push und separatem Pull Request
   dieser Framework-Änderung bewegt.

## Untersuchte Alternativen

- Der aktuelle Benutzer hat das neueste stabile Upstream-Release `R_2_8_3`
  ausdrücklich ausgewählt; sein aufgelöster Commit wird aufgezeichnet, statt
  zur Laufzeit einen beweglichen Latest-Release-Endpunkt aufzulösen.
- Mehr Retries, ein PR-Token oder ein beweglicher Cache schaffen keine
  unveränderliche Provenance und wurden verworfen.
- Den Parent direkt einen Branch beschaffen zu lassen, wurde verworfen, weil
  ein Branch nach dem Review weiterwandern kann.

## Implementierungsentscheidung

Das Framework zeichnet den geprüften aufgelösten Commit
`92810461043fce37e70079b37ab1f04490a8f039` der benutzerautorisierten Quelle
`R_2_8_3` auf. Der Framework-Resolver `not_applicable` bleibt korrekt, weil das
Framework Expat nicht selbst beschafft; seine Beschreibung nennt nun den Parent
als strikten Runtime-Verbraucher. Die Parent-Änderung aktiviert die strikte
Prüfung nur in der HAProxy-Route, daher wird kein Workflowpfad anderer
Connectoren erweitert.

## Geänderte Dateien und Tests

- `ci/lib/common.sh`
- `ci/tools/check-common-versions.py`
- `docs/reference/variables.md`
- `docs/reference/variables.de.md`
- `tests/security_regression/test_checker_series_and_ci_inventory.py`
- dieses gepaarte englische/deutsche Change Record

Der fokussierte Test prüft Form und Wert des Commits und verifiziert, dass die
Registry den Parent-Verbraucher und die unveränderliche Provenance beschreibt.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- |
| `rtk proxy git ls-remote https://github.com/libexpat/libexpat.git …` | 0 | Upstream `R_2_8_3^{}` löste auf den aufgezeichneten Commit auf. | Task-Transcript, 2026-08-24 |
| `rtk proxy python3 -B -c '…compile(…)…'` | 0 | Geänderter Checker und fokussierter Test kompilieren im Speicher, ohne Bytecode in den isolierten Worktree zu schreiben. | Isolierter Framework-Worktree |
| `rtk proxy sh -n ci/lib/common.sh` | 0 | Die kanonische Shellquelle lässt sich parsen. | Isolierter Framework-Worktree |
| `rtk proxy python3 ci/tools/check-common-versions.py --validate-canonical` | 0 | Lokaler kanonischer Pin-Vertrag bestanden. | Isolierter Framework-Worktree |
| Fokussierte Expat-Regression-Funktion | 0 | Unveränderlicher Pin- und Parent-Verbrauchervertrag bestanden. | Isolierter Framework-Worktree |

## Sicherheitsauswirkung

Dies ist eine Supply-Chain- und Verfügbarkeits-Härtung. Die bisher bewegliche
Referenz wird durch einen geprüften unveränderlichen Commit ersetzt. Die
Alternativen Token-Authentifizierung, Retry-only-Verhalten und bewegliche
Cache-Wiederverwendung bleiben ausgeschlossen. Den tatsächlichen Git-Checkout
prüft weiterhin der strikte connectorbezogene Parent-Provisioner vor Nutzung.

## Dokumentation und Runtime-Evidenz

Die englische/deutsche Variablenreferenz und dieses Record-Paar beschreiben
dieselbe Framework-Grenze. In diesem Framework-Worktree wurde keine Connector-
oder MRTS-Runtime ausgeführt; der Parent muss diese Exact-Head-Validierung nach
Verfügbarkeit des Framework-PRs und kontrolliertem Gitlink-Update durchführen.

## Nicht ausgeführte Prüfungen

Framework-Hosted-Checks, SonarCloud und der Framework-Pull-Request stehen bei
Erstellung des Records aus. Vollständiges Framework-Lint und die Parent-
HAProxy-Hosted-Runtime warten auf die Parent-Änderung und den kontrollierten
Gitlink-Update.

## Einschränkungen und Restrisiko

Der Pin beweist eine feste Upstream-Quellidentität, kann jedoch keinen
Parent-Runner selbst provisionieren oder validieren. Die abhängige Parent-
Arbeit muss auf HAProxy beschränkt bleiben und den exakten Framework-Gitlink
prüfen, bevor ein Runtime-Ergebnis behauptet wird.

## Finaler Diff- und Review-Status

Alle Änderungen liegen in einem externen aufgabeneigenen Framework-Worktree.
Der Diff beschränkt sich auf Provenance-Metadaten, Dokumentation, einen
fokussierten Regressionstest und dieses Record-Paar. Bei Erstellung dieses
Records wurde kein Parent-Gitlink, MRTS-Inhalt oder Workflow-Credential gestagt.
