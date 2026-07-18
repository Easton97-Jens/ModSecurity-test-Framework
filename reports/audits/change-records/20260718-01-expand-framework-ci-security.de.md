# Change Record — Framework-CI-Security-Erweiterung

**Sprache:** [English](20260718-01-expand-framework-ci-security.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260718-01-expand-framework-ci-security |
| UTC-Datum | 2026-07-18 |
| Framework-Basisrevision | cdc91a398d6c156eaff927d742b23018a3817fb6 |
| Implementierungs-Commit | c897c481025fd005a2908d5124d238784d6182f4 |
| Issue oder Pull Request | [Framework-Draft-PR #27](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/27) |

## Motivation und Problemstellung

Das Framework verwendete mutable Action-Tags und hatte keinen Framework-eigenen
CI-Security-Scanner-/Provenienzvertrag. Das anfängliche Scanner-Action-Design
enthielt außerdem einen task-owned transitive-mutable-Container-Pfad. Diese
Änderung ersetzt ihn durch prüfsummenverifizierte CLIs und ergänzt
Framework-Kontrollen, ohne Parent-Repository, dessen Gitlink oder MRTS zu
ändern. Eigenständig geregeltes Common-Structure-Verhalten bleibt außerhalb
dieses Scopes.

## Betroffene Komponenten und Sicherheitsgrenzen

- Workflows und Dependabot: Grenzen für nicht vertrauenswürdige PR-Tokens,
  Checkout, Scanner, SARIF, Abhängigkeiten, Abbruch und Wartung.
- CI-Tooling, Downloader und Contract-Checker: Remote-Action-/Tool-Provenienz,
  Archivextraktion und Source-Level-Policy-Validierung.
- Tests, Fixtures, Makefile und Python-Tooling: positive und negative
  Kontrollabdeckung.
- Security-Dokumentation: gepaarte englische/deutsche Anleitung.

tools/MRTS wird nicht initialisiert oder geändert. Scanner-Checkouts verwenden
submodules false; CodeQL ignoriert zusätzlich tools/MRTS.

## Akzeptanzkriterien

1. Jede Remote-Action ist an einen überprüften 40-stelligen SHA mit exaktem
   Versionskommentar und Lock-Record gepinnt.
2. PR-Workflows vermeiden pull_request_target, persistierte Credentials, breite
   Default-Berechtigungen, unsicheres Cache-/Artefakt-Verhalten und unbegrenzte
   Jobs.
3. Gitleaks, OSV, CodeQL, Scorecard, Dependency Review, actionlint, ShellCheck,
   zizmor, Ruff, Pyright und Dependency Hygiene haben einen wahrheitsgemäßen
   Framework-Scope ohne automatische Remediation.
4. Der Security-Contract hat positive und negative Fixture-Evidence; er deckt
   Action-Pinning, Berechtigungsdeklarationen, Trigger, Checkout, Timeouts,
   Concurrency und Tool-Lock-Struktur ab, ohne die Common-Structure-
   Produktassertion zu ändern.
5. Dokumentation, dieser Record, fokussierte Checks, Security-Diff-Review und
   exakte PR-Head-Evidence sind vor der Delivery vollständig.

## Untersuchte Alternativen

- Mutable Major-Tags oder ungeprüfte Paketinstallation: abgelehnt, weil die
  CI-Sicherheitsgrenze immutable Provenienz erfordert.
- Unbegrenzter oder generischer Scanner-Artefakt-Upload: abgelehnt. CodeQL
  verwendet den engeren Code-Scanning-SARIF-Kanal, Gitleaks-Findings benötigen
  Redaktion, und OSV/Scorecard bewahren nur validierte, begrenzte JSON-
  Evidenz einen Tag auf.
- Go oder JavaScript/TypeScript für CodeQL: abgelehnt, weil aktuelle
  Framework-Source-Evidence nur Actions, Python und C/C++ unterstützt.
- Eine Änderung der eigenständig geregelten test-common-Kataloginvariante:
  abgelehnt, weil sie außerhalb dieser CI-/Security-Erweiterung liegt.

## Implementierungsentscheidung

Ein Framework-eigener YAML-Lock dokumentiert Action- und CLI-Provenienz. Ein
Python-Downloader prüft direkte HTTPS-GitHub-Release-Assets vor atomarem
Veröffentlichen einer Raw-Executable oder sicherer Archivextraktion in
runner-eigene Verzeichnisse. OSV-Scanner und Scorecard laufen als
prüfsummenverifizierte CLIs statt als Container-backed Actions. Workflow- und
Test-Contracts lehnen mutable Pins, unsichere Trigger, unerwartete
Write-Berechtigungen, unsichere Checkout-Einstellungen, nicht-exakte
Python-Selektion, unprovisionierte Downloader-Abhängigkeiten sowie fehlende
Timeouts/Concurrency ab. Die CI-Abhängigkeitsinstallation ist auf das
hash-gelockte PyYAML-Wheel begrenzt; eigenständige Security-CLIs bleiben
außerhalb des Checkouts.

Die geplanten Common-Version- und Artefakt-Cleanup-Workflows behalten ihre
notwendigen Schreibrechte, verwenden aber nicht persistierten Checkout, enge
Berechtigungen, exakte Action-Pins, explizite Timeouts und nicht abbrechende
Wartungs-Concurrency.

## Geänderte Dateien und Tests

- Alle vorhandenen getrackten Workflows gehärtet; CI-Security-, Qualitäts-,
  Secrets-, OSV-, CodeQL-, Scorecard- und Dependency-Review-Workflows ergänzt.
- CI-Dependency-Lock, Tool-Lock/Downloader, Security- und begrenzte-JSON-
  Evidence-Checker, siebzehn fokussierte Unit-Tests, positive/negative
  zizmor-Fixtures, Ruff-Konfiguration und Pyright-Konfiguration ergänzt.
- Englische/deutsche CI-Security-Dokumentation und Dokumentationsindex-Links
  ergänzt.
- Die `test-common.yml`-Ausführungsumgebung gehärtet, ohne deren eigenständig
  geregelte Katalog-Count-Assertion oder Materialisierungsverhalten zu ändern.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Fokussierte Framework-CI-Security- und Change-Record-Tests | 0 | Siebzehn task-owned positive/negative Contract-, Runner-Containment-, OSV/Scorecard-Evidence- und Change-Record-Tests bestanden. | `20260718T083435Z-expand-framework-ci-security-32892be1` |
| CI-Security-Contract und Workflow-YAML-Checker | 0 | Contract bestanden und alle 12 getrackten Workflow-Dateien geparst. | Gleicher Run |
| Gelockter Tool-Downloader | 0 | Acht Release-Assets, einschließlich Raw-OSV-Scanner und Scorecard, entsprachen ihren gelockten SHA-256-Werten. | Gleicher Run |
| actionlint mit gelocktem ShellCheck | 0 | Alle 12 getrackten Workflows bestanden. | Gleicher Run |
| zizmor über `.github` | 0 | Keine reportbaren Findings; zizmor meldete 19 Offline-Tool-Suppressions. | Gleicher Run |
| zizmor unsichere Fixture | 14 erwartet | Gefährlichen Trigger und PR-Title-Interpolation abgelehnt. | Gleicher Run |
| Ruff-Lint und Format-Check | 0 | Task-owned CI-Security-Python-Scope mit lokal deaktiviertem Cache bestanden. | Gleicher Run |
| OSV-Manifest-Abdeckung | 0 | OSV erkannte je ein Paket im begrenzten `requirements-dev.txt` und normalisierten CI-Lock-Manifest; anschließend bestand der JSON-Evidence-Checker. | Gleicher Run |
| OSV-Scanner- und Scorecard-CLI-Smoke-Controls | 0 | Prüfsummenverifizierte CLIs scannten den aktuellen Framework-Baum ohne Schreiben in den Checkout. | Gleicher Run |

## Sicherheitsauswirkung

Dies ist CI-/Security-Härtung und keine Connector-Runtime-Remediation. Der
ursprüngliche mutable-Action-Pfad wird durch einen lock-erzwungenen immutable
SHA-Contract ersetzt. Die entdeckten mutablen Docker-Images innerhalb der
OSV- und Scorecard-Actions werden nicht beibehalten: Beide Scanner laufen erst
nach dem unabhängigen Abruf ihres verifizierten Release-Binaries in
runner-temporären Storage. Positive Kontrollen decken aktuelle Workflows und
die sichere zizmor-Fixture ab; die negative Kontrolle beweist, dass ein
gefährlicher Trigger plus nicht vertrauenswürdige Interpolation abgelehnt wird.
Direkte Download-Validierung deckte Raw-Binary- und Archiv-Policies ab. Die
PR-OSV-Kontrolle vergleicht Exact-Base- und Exact-Head-Reports und scheitert
nur bei neu eingeführten Schwachstellengruppen; ihre aufbewahrte Evidenz ist
größen-, Regular-File- und JSON-validiert. Die fokussierte Source-Diff-
Bewertung bleibt ausstehend, bis der Implementierungsdiff finalisiert ist.

## Dokumentation und Runtime-Evidenz

Die gepaarte CI-Security-Anleitung wurde ergänzt und aus beiden
Dokumentationsindizes verlinkt. Es wurde keine Connector-Runtime- oder
Lifecycle-Evidenz erfasst oder behauptet; die beobachtete Evidence ist
statische CI-/Source-Validierung.

## Nicht ausgeführte Prüfungen

- Lokales Pyright: blockiert, weil keine lokale Node.js-Runtime installiert ist.
  CI provisioniert exaktes Node.js 24.18.0 über eine gepinnte Action.
- CodeQL, Dependency Review, Gitleaks-PR-Range, SonarQube Cloud und
  GitHub-hosted Workflow-Ausführung: exakter Draft-PR-Head und Remote-CI stehen
  aus.
- `make lint` gegen den sauberen Kandidaten, Dokumentationschecks,
  finaler Whitespace-/Secret-Review, fokussierter Security-Diff-Review, Commit,
  Push und Draft-PR-Erstellung: bestanden. Der ausgeschlossene
  FND-FRAMEWORK-0004-CRS-Validator meldete während des vollen Lints RTK-
  Read-only-`/tmp`-Diagnostik und wird nicht als bestandene CRS-Kontrolle
  behauptet.

## Einschränkungen und Restrisiko

GitHub-repositoryweite Actions-Defaults, SHA-Enforcement-Einstellungen,
Branch-Protection, Dependabot-Alerts und SonarQube-Cloud-Konfiguration sind
externe Governance-Kontrollen und werden durch diese Framework-only-Aufgabe
nicht geändert. Der aktuelle SonarQube-Cloud-Fehler bleibt separat verfolgt.
Full-History-Gitleaks und geplante OSV-Scans sind bewusst advisory, bis ihre
Findings triagiert sind.

## Finaler Diff- und Review-Status

Der Implementierungs-Commit `c897c481025fd005a2908d5124d238784d6182f4` wurde
auf `agent/expand-framework-ci-security` gepusht, und Framework-Draft-PR #27
ist offen. Der staged Diff, Whitespace-/Secret-Review und fokussierte
Security-Diff-Review bestanden vor der Delivery. Es gibt keinen Merge,
Parent-Gitlink-Update, Parent-Produkt-/Workflow-Change oder MRTS-Change.
Exakte PR-Head-CI, SonarQube Cloud, Reviews und Review-Threads müssen noch
verifiziert werden.
