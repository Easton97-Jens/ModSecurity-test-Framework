# Change Record

**Sprache:** [English](20260822-02-fix-traefik-runtime-pin-fixture.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260822-02-fix-traefik-runtime-pin-fixture` |
| UTC-Datum | 2026-08-22 |
| Framework-Basisrevision | `52fe6ee334f1381c35d5c3b7140433c626469523` |
| Issue oder Pull Request | `FND-FRAMEWORK-0112`; Framework-Pull-Request bei Erstellung des Records noch ausstehend |

## Motivation und Problemstellung

Der Framework-Master-Lint-Lauf `32557675044` schlug fehl, nachdem die
vertrauenswürdige Wartungsänderung in PR #106 das überprüfte Traefik-Release-
Tuple auf `3.7.11` aktualisiert hatte. Implementierung, Lock und Manifest waren
konsistent, doch diese Regression-Fixture enthielt noch Version, Archivname und
Digest des vorherigen Releases. Ihr veraltetes Positivarchiv erreichte daher
nicht die beabsichtigte Digest-Kontrolle.

## Betroffene Komponenten und Sicherheitsgrenzen

- `tests/security_regression/test_traefik_runtime_pin_contract.py`: leitet sein
  legitimes Tuple aus dem eingecheckten Runtime-Component-Lock ab und behält
  absichtlich nicht-kanonische Negativwerte bei.
- Die geprüfte Grenze bleibt der verifizierte Traefik-Archivpfad:
  Provenance-Prüfung, SHA-256-Prüfung vor Extraktion sowie Versionsprüfung des
  gestagten Binaries.

Kein Produkt-Provisioning-Skript, keine GitHub-Actions-Berechtigung, kein
Publisher-Pfad, kein Parent-Gitlink und keine MRTS-Revision werden geändert.

## Akzeptanzkriterien

1. Die legitime Test-Fixture folgt dem aktuellen kanonischen Traefik-Lock-
   Tuple ohne manuell duplizierte Release-Version, Archiv oder Digest.
2. Ein fehlerhafter Archiv-Digest scheitert vor Extraktion oder Staging.
3. Ein verifiziertes Archiv wird im download-deaktivierten Offline-Pfad
   gestagt und ausgeführt.
4. Ein Bare Binary mit derselben Version kann das verifizierte Staging nicht
   umgehen.
5. Die nativen Lock- und Synchronisationsprüfungen bestehen; danach folgen
   Framework-Lint und Current-Head-Hosted-Evidenz vor dem Merge.

## Untersuchte Alternativen

- Nur die drei `3.7.10`-Literale zu aktualisieren wurde verworfen, weil der
  nächste überprüfte Traefik-Update denselben CI-Fehler erneut erzeugen würde.
- Die Digest- oder Staging-Assertions zu schwächen wurde verworfen, weil sie
  die Sicherheitsgrenze schützen, die diese Fixture abdeckt.
- Den Runtime-Provisioner zu ändern wurde verworfen, weil die Ursache
  Test-Fixture-Drift ist; der Provisioner scheitert bereits fail-closed.

## Implementierungsentscheidung

Der Test liest Version, Asset-Name, SHA-256, Betriebssystem und Architektur aus
allen Traefik-Profilen in `runtime-component-lock.json`, verwirft fehlende oder
divergente Profile und nutzt dieses eine Tuple ausschließlich für legitime
Kontrollen. Negative Fälle leiten zur Laufzeit eine abweichende Version,
Plattform oder einen abweichenden Digest ab. Das entfernt die veraltete
Wartungskopplung und bewahrt zugleich die unabhängigen Assertions, dass
`common.sh` dem überprüften, aus dem Lock abgeleiteten Tuple entspricht.

## Geänderte Dateien und Tests

- `tests/security_regression/test_traefik_runtime_pin_contract.py`
- dieser gepaarte englische/deutsche Change Record

Der angepasste Test deckt den Lock-abgeleiteten Positivpfad, falschen Digest vor
Extraktion, Offline-Staging verifizierter Archive, Umgebungsmanipulationen und
den Umgehungsversuch durch ein Bare Binary mit derselben Version ab.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk proxy …python -m py_compile tests/security_regression/test_traefik_runtime_pin_contract.py` | 0 | Der geänderte Test kompiliert mit der Framework-eigenen virtuellen Umgebung. | Isolierter Framework-Worktree |
| `rtk proxy …python -m unittest discover -s tests/security_regression -p test_traefik_runtime_pin_contract.py -v` | 0 | Alle 11 Traefik-Archivgrenztests bestanden. | Isolierter Framework-Worktree |
| `rtk proxy … make check-runtime-component-lock` | 0 | Das Tuple aus Common, Lock und Manifest bestand den nativen Lock-Checker. | Aufgaben-eigener externer Build-/TMP-Root |
| `rtk proxy … make check-runtime-components` | 0 | Die kanonische Runtime-Component-Synchronisation bestand. | Aufgaben-eigener externer Build-/TMP-Root |
| `rtk proxy … make … lint` | 0 | Vollständiges Framework-Lint bestand, einschließlich Runtime-Pin-, Workflow-Sicherheits-, Dokumentations- und Whitespace-Prüfungen. | Aufgaben-eigener externer Build-/TMP-Root |

## Sicherheitsauswirkung

Dies ist eine CI-Verfügbarkeitsreparatur an einer Sicherheits-Regressionsgrenze.
Der ursprüngliche Bad-Digest-Pfad erreicht und besteht nun seine fail-closed
Assertion; ein legitimes Offline-Archiv gelingt; und der alternative
Bare-Binary-Umgehungstest scheitert weiterhin vor der Ausführung. Der
verifizierte Provisioner und seine Vertrauensgrenzen bleiben unverändert.

## Dokumentation und Runtime-Evidenz

Dieser englische/deutsche Change Record dokumentiert die reine
Framework-Reparatur. Das kanonische Parent-Evidenzledger
`FND-FRAMEWORK-0112` hält den fehlgeschlagenen Hosted-Lauf und den lokalen
Reproduktionsbeleg vor. Weder Connector- noch MRTS-Runtime wurden geändert oder
ausgeführt.

## Nicht ausgeführte Prüfungen

Ein Framework-Pull-Request, Current-Head-Hosted-Checks, SonarQube Cloud,
Review-/Thread-Validierung und der geschützte Master-Merge stehen noch aus.

## Einschränkungen und Restrisiko

Die Lock-abgeleitete Fixture setzt absichtlich voraus, dass das Lock-Schema
eingecheckt und intern konsistent ist; fehlerhafte, fehlende oder divergente
Traefik-Profile lassen den Test scheitern, statt stillschweigend ein Tuple zu
akzeptieren. Hosted-Service-Verhalten bleibt bis zum Abschluss eines frischen
PRs und der resulting-master-Läufe unbestätigt.

## Finaler Diff- und Review-Status

Die Implementierung liegt in einem isolierten aufgabeneigenen
Framework-Worktree. Vollständiges Framework-Lint, Whitespace-Validierung und
die fokussierte Sicherheits-/Diff-Prüfung bestanden vor dem Commit. Kein
Parent-Gitlink und kein MRTS-Inhalt werden gestagt.
