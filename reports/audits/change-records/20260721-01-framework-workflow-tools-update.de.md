# Change Record: Framework-Workflow-Tooling-Update

**Sprache:** [English](20260721-01-framework-workflow-tools-update.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260721-01-framework-workflow-tools-update |
| UTC-Datum | 2026-07-21 |
| Framework-Basisrevision | 9dab40c2b8799dc1e4597cb2a2c223ec3f6cd72b |
| Issue oder Pull Request | Draft-Pull-Request beim Schreiben dieses Records ausstehend; kein Merge oder Auto-Merge ist autorisiert. |

## Motivation und Problemstellung

Das Framework benötigte aktuelle unveränderliche GitHub-Action-Provenienz und einen repository-eigenen Weg, spätere Action- oder prüfsummengelockte CI-Tool-Updates vorzuschlagen, ohne dass Metadaten, wiederverwendete Branches oder heruntergeladene Assets den Default-Branch beschreiben können. Die vorherigen Pins verwendeten checkout v7.0.0 und setup-python v6.3.0; ein eigener Framework-Action-/Tool-Updater existierte nicht.

## Betroffene Komponenten und Sicherheitsgrenzen

- .github/workflows erhält Checkout v7.0.1 und setup-python v7.0.0 mit vollständigen Commit-Pins sowie den eingeschränkten Updater-Workflow.
- Der bisherige Common-Version-PR-Lieferpfad ist nun read-only: Er wendet seine Prüfung nur auf eine Runner-temporäre Kopie von `common.sh` an; die force-fähige Drittanbieter-PR-Action sowie alle Branch-/PR-Lieferschritte sind entfernt.
- Tool-Lock, Updater, Fetcher und CI-Sicherheitsvertrag binden offizielle Release-URLs, Tags, Commits, Tool-Assets, SHA-256-Digests und sichere Redirect-Hosts.
- Resolver und Validator sind tokenfrei/schreibgeschützt. Der auf den Default-Branch begrenzte Publisher hat nur contents: write und pull-requests: write, erstellt oder aktualisiert einen Draft-PR und hat keinen Force-Push-, Auto-Merge- oder direkten Default-Branch-Pfad.
- tools/MRTS wurde weder initialisiert noch geändert; sein Gitlink bleibt 13aa91291adea12d5c607fdd165d010fcfb1da78. Keine Parent-Datei gehört zum Scope dieses Records.

## Akzeptanzkriterien

- Alle Framework-Action-Referenzen bleiben vollständige SHA-Pins mit passenden Lock-Records und Release-Kommentaren.
- Der Updater weist instabile Releases, fremde Redirects, Pfade außerhalb der Temp-Root, mutable oder mehrdeutige Metadaten und Änderungen außerhalb seiner exakten Allowlist zurück.
- Ein vorgeschlagener Kandidat wird in einem isolierten Baum validiert; geänderte Tool-Assets werden vor Veröffentlichung ohne Ausführung per Prüfsumme validiert.
- Wiederverwendete Maintenance-Branches müssen bytegenau aus der vertrauenswürdigen Default-Revision und einem verifizierten Kandidaten rekonstruierbar sein.
- Die Common-Version-Prüfung muss ihre Kandidatenvalidierung ohne Write-Berechtigung, Publishing-Token, Branch-Operation oder Pull-Request-Lieferpfad behalten.
- Englische/deutsche Dokumentation und dieses gepaarte Record beschreiben die finalen Grenzen ohne unbeobachtete Hosted-CI- oder Runtime-Evidenz zu behaupten.

## Untersuchte Alternativen

- Eine Erweiterung des früheren common.sh-PR-Publishers wurde verworfen, weil seine Drittanbieter-Liefer-Action Force-Updates implementiert. Seine nützliche Kandidatenprüfung bleibt als read-only Runner-Temporäroperation erhalten.
- Tag-basierte Action-Referenzen, floating Tool-URLs, unbegrenzte HTTPS-Redirects und ein einzelner schreibfähiger Updater-Job wurden verworfen, da sie unveränderliche Provenienz oder Least Privilege nicht erhalten.
- Die Wiederverwendung eines passenden Branches allein auf Basis von Pfaden wurde verworfen; die Trusted-Base-Rekonstruktion verhindert, dass eine erlaubte Datei eingeschleusten Publisher-Code trägt.

## Implementierungsentscheidung

Checkout wird auf v7.0.1 bei 3d3c42e5aac5ba805825da76410c181273ba90b1 und setup-python auf v7.0.0 bei 5fda3b95a4ea91299a34e894583c3862153e4b97 aktualisiert. Der Action-/Tool-Lock bleibt die kanonische Provenienzquelle; nicht verwandte gelockte Tool-Versionen bleiben unverändert.

Der Updater trennt Resolver, Validator und Publisher. Der Vertrag parst den Workflow und pinnt das überprüfte Schrittprofil des schreibfähigen Publishers einschließlich Befehls-/Script-Körpern, statt auf lose Textmarker zu vertrauen. Der Updater verwendet offizielle GitHub-Release-Metadaten, validiert Annotated-Tag-Identitäten und Asset-Digests und akzeptiert vor der SHA-256-Prüfung nur explizite GitHub-Release-Asset-Redirect-Hosts.

`check-common-versions.yml` veröffentlicht keinen Maintenance-Branch oder PR mehr. Er prüft und ShellCheckt eine ephemere Kopie unter `RUNNER_TEMP` mit read-only Berechtigungen, sodass der neue eingeschränkte Workflow-/Tool-Updater der einzige Framework-Pfad bleibt, der einen Draft-Maintenance-PR erstellen oder aktualisieren kann.

## Geänderte Dateien und Tests

- Betroffene .github/workflows-Pins, Lock-Records, der neue update-workflow-tools-Workflow und die nun read-only Common-Version-Kandidatenprüfung.
- ci/tools/update-workflow-tools.py, ci/tools/fetch-security-tool.py und ci/checks/security/check-ci-security-contract.py.
- Fokussierte Updater-, Fetcher- und Contract-Tests mit unsicheren Mutationen für Berechtigungen, Trigger, PR-Erstellung, Force-/Default-Pushes, Redirects, veraltete Kandidaten und Branch-Reuse.
- Englische/deutsche Workflow-Sicherheits- und CI-Tooling-Guides sowie dieses gepaarte Record und die Indexeinträge.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| python3 -m unittest discover -s tests/ci_security -v | 0 | 106 fokussierte CI-Sicherheits-Tests bestanden. | Lokale Task-Validierung; kein Payload gespeichert. |
| python3 -m unittest tests.security_regression.test_workflow_security_contract -v | 0 | 7 Workflow-Sicherheits-Regressionstests bestanden. | Lokale Task-Validierung. |
| CI-Workflow-, Action-Pin- und CI-Sicherheits-Contract-Checker | 0 | 14 Workflows, unveränderliche Pins und eingeschränktes Publisher-Profil bestanden. | Lokale Task-Validierung. |
| git diff --check | 0 | Keine Whitespace-Fehler. | Framework-Task-Worktree. |

## Sicherheitsauswirkung

Dies ist CI-Supply-Chain-Hardening. Mutable Pins, breite Redirect-Akzeptanz, Token-Exposition in read-only Jobs, unvalidierte Kandidatenbäume, Force-/Default-Pushes, Auto-Merge, doppelte PRs und injizierter wiederverwendeter Branch-Content sind durch explizite negative Tests abgedeckt. Das Entfernen des Drittanbieter-Common-Version-PR-Publishers entfernt außerdem sein force-fähiges Branch-Update-/Löschverhalten. Der Updater führt ein geändertes heruntergeladenes Tool nicht vor der Validierung von Prüfsumme und Archivlayout aus.

## Dokumentation und Runtime-Evidenz

Englische/deutsche Workflow-Sicherheits- und CI-Tooling-Dokumentation beschreibt unveränderliche Pins, Release-Provenienz, Redirect-Grenze und das Resolver-/Validator-/Publisher-Modell. Es wurde keine Connector-, MRTS- oder Runtime-/Lifecycle-Evidenz erfasst: Dies ist eine Framework-CI-Konfigurationsänderung.

## Nicht ausgeführte Prüfungen

- Lokales Ruff wurde nicht ausgeführt, weil Executable/Modul nicht verfügbar ist.
- Hosted-Actionlint-/ShellCheck-/Zizmor-Ausführung, CodeQL, Dependency Review, OSV, Scorecard, Gitleaks und ein möglicher Sonar-Check bleiben Evidenz für den exakten Draft-PR-Head und sind nach der Veröffentlichung zu beobachten.
- PR #39 wurde nicht verändert. Seine unabhängige Python-Updater-Arbeit kann in Workflow-/Dokumentationsdateien überlappen und später eine Maintainer-Konfliktauflösung erfordern.

## Einschränkungen und Restrisiko

Der Updater unterstützt absichtlich nur überprüfte Lock-Records und explizite Pfade. Neue Action-/Tool-Typen, Release-Asset-Layouts oder Workflow-Dateien benötigen eine bewusste Contract-/Profil-Aktualisierung. GitHub-hosted Checks und Review bleiben für den exakt veröffentlichten Commit erforderlich.

## Finaler Diff- und Review-Status

Der Source-Diff erhielt vor diesem Record ein unabhängiges schreibgeschütztes Security-Review, fokussierte Tests, Workflow-/Pin-/Contract-Checks und einen Whitespace-Review. Beim Erstellen dieses Records ist er uncommittet und ungepusht; finale Draft-PR-Nummer, Exact-Head-CI-Evidenz und Review-Status werden erst nach Beobachtung ergänzt.
