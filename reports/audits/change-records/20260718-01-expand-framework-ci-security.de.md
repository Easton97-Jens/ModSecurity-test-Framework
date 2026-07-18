# Change Record — Framework-CI-Security-Erweiterung

**Sprache:** [English](20260718-01-expand-framework-ci-security.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260718-01-expand-framework-ci-security |
| UTC-Datum | 2026-07-18 |
| Framework-Basisrevision | cdc91a398d6c156eaff927d742b23018a3817fb6 |
| Commit-Historie bis zum Remote-Head des PR | `c897c481025fd005a2908d5124d238784d6182f4`; `5b17add799aac8c1c40f31264a5a4e8400740660`; `ec6448660f9e10cc633caed95f9b590c5d3bff1f`; `464c5a8d7292f017f14cbea5d32301205c9524e7`; `a63fa9963153c5aa56f4477713f02e689ee8f7fa`; `5b2a26a41e7621e7b246aa1a060149252cfe3062` |
| Issue oder Pull Request | [Framework-Draft-PR #27](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/27) |
| Aktueller Remote-Draft-PR-Head | `5b2a26a41e7621e7b246aa1a060149252cfe3062` |
| Task-owned Security-Follow-up-Commit | `768a06b5b734547f8213cc6918c26ef4a8ef9f67` (lokal committet; noch nicht durch Remote-PR-Checks abgedeckt) |
| Delivery-Status | Nur Draft-PR; finaler Dokumentationscommit, normaler Push und Exact-Head-Evidence stehen noch aus; `verified_pr` ist nicht erreicht. |

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
5. Bevor diese Arbeit als `verified_pr` gemeldet werden kann, müssen
   Dokumentation, dieser Record, fokussierte Checks, ein finalisiertes
   Source-Diff-Security-Review, ein committeter Kandidat und exakte
   Remote-PR-Head-Evidence vollständig sein. Ein offener Draft-PR kann dem
   finalen Kandidaten vorausgehen und ist keine solche Evidence.

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

Der task-owned Security-Follow-up-Commit ergänzt einen semantischen Workflow-Evidence-
Checker statt sich nur auf Texttreffer zu verlassen. Er prüft ausführbare
PR-Checkout-Referenzen, den exakten PR-Head sowie die Sprach-/Build-
Konfiguration von CodeQL und den exakten PR-Head von Gitleaks einschließlich
Git-Objekt-/Range-Prüfungen und obligatorischer Redaktion. Er lehnt außerdem
Caches sowie nicht zugelassene Artefakt-/SARIF-Kanäle in den betroffenen
Workflows ab. Das OSV-Report-Schema lehnt strukturell unvollständige oder sich
überschneidende Schwachstellengruppen ab und verlangt, dass jede gelistete
Schwachstellen-ID von genau einer Gruppe repräsentiert wird. Evidence-Reader
und Comparator-Outputs sind unter der runner-temporären Root begrenzt. Der
CRS-Version-Pinning-Helper verwendet statt eines vorhersagbaren `/tmp`-Pfads
private `mktemp`-Dateien unter einer validierten runner-temporären Root.

Die geplanten Common-Version- und Artefakt-Cleanup-Workflows behalten ihre
notwendigen Schreibrechte, verwenden aber nicht persistierten Checkout, enge
Berechtigungen, exakte Action-Pins, explizite Timeouts und nicht abbrechende
Wartungs-Concurrency.

## Geänderte Dateien und Tests

- Die getrackten Framework-Workflows im CI-Security-Scope gehärtet; CI-Security-,
  Qualitäts-, Secrets-, OSV-, CodeQL-, Scorecard- und Dependency-Review-
  Workflows ergänzt.
- CI-Dependency-Lock, Tool-Lock/Downloader, Security- und begrenzte-JSON-
  Evidence-Checker, positive/negative zizmor-Fixtures, Ruff-Konfiguration und
  Pyright-Konfiguration ergänzt.
- Der task-owned Security-Follow-up ergänzt den semantischen Workflow-
  Evidence-Checker, strikte OSV-Gruppen-Schema-Validierung, Runner-Root-
  Containment, Exact-Head-Kontrollen für CodeQL und Gitleaks sowie die private
  `mktemp`-Reparatur im CRS-Helper.
- Englische/deutsche CI-Security-Dokumentation und Dokumentationsindex-Links
  ergänzt.
- Die `test-common.yml`-Ausführungsumgebung gehärtet, ohne deren eigenständig
  geregelte Katalog-Count-Assertion oder Materialisierungsverhalten zu ändern.
- Die aktuelle lokale CI-Security-Suite enthält vierundsechzig positive und negative
  Tests. Sie deckt die ursprünglichen Contracts sowie semantische Workflow-
  Kontrollen, strikte OSV-Evidence-/Gruppenabdeckung, Downloader-Containment
  und die CRS-Temporary-Path-Regression ab.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Fokussierte Framework-CI-Security-Suite | 0 | Alle vierundsechzig lokalen positiven/negativen Contract-, Semantic-Workflow-, Strict-OSV-Evidence-, Downloader-Containment-, Lock-Path- und CRS-Temp-Path-Tests bestanden. | `20260718T084030Z-expand-framework-ci-security-be8fb24d` |
| `make test-ci-security-contract` | 0 | Dieselben vierundsechzig CI-Security-Tests bestanden über das Framework-Target. | Gleicher Task-Run |
| Semantischer Workflow-Evidence-Checker | 0 | Der task-owned Source-Commit erfüllt Exact-Head-, Artefakt-/Kanal-, Cache-, Erreichbarkeits- und OSV-Evidence-Constraints. | Gleicher Run |
| `make check-documentation` | 0 | Dokumentationslinks, Variable-Docs, Path-References und Change-Record-Contract bestanden zu diesem Zeitpunkt für den lokalen Kandidaten. | Gleicher Run |
| `make lint` | 0 | Framework-Lint schloss einschließlich Python-Compilation, CI-Security-Tests, Workflow-YAML, Security-Data-Flow, CRS und Dokumentationschecks ab. | Gleicher Run |
| actionlint mit gelocktem ShellCheck | 0 | Alle 12 getrackten Workflows bestanden. | Gleicher Run |
| zizmor über `.github` | 0 | Keine reportbaren Findings; zizmor meldete 19 Offline-Tool-Suppressions. | Gleicher Run |
| zizmor unsichere Fixture | 14 erwartet | Gefährlichen Trigger und PR-Title-Interpolation abgelehnt. | Gleicher Run |
| Ruff-Lint und Format-Check | 0 | Task-owned CI-Security-Python-Scope mit task-owned Cache-Verzeichnis bestanden. | Gleicher Run |
| Gelockter Tool-Downloader und Scanner-Smoke-Controls | 0 | Gelockte Release-Assets und OSV/Scorecard-Smoke-Controls bestanden ohne Checkout-Schreibvorgänge. | Frühere aufbewahrte Task-Evidence; kein Ersatz für Final-Head-Remote-Evidence. |

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
größen-, Regular-File- und JSON-validiert. Der lokale Follow-up ergänzt
semantische Exact-Head-Erzwingung für CodeQL und Gitleaks, strikte OSV-
Gruppenabdeckung und Runner-Root-Evidence-Containment. Die finalisierte
fokussierte Source-Diff-Bewertung bestätigte keine High- oder Critical-Feststellung;
sie remedierte drei Medium/P2-Defekte zu semantischer Erreichbarkeit und
OSV-Basisverfügbarkeit mit Regression-Coverage.

## Dokumentation und Runtime-Evidenz

Die gepaarte CI-Security-Anleitung wurde ergänzt und aus beiden
Dokumentationsindizes verlinkt. Es wurde keine Connector-Runtime- oder
Lifecycle-Evidenz erfasst oder behauptet; die beobachtete Evidence ist
statische CI-/Source-Validierung.

## Nicht ausgeführte Prüfungen

- Lokales Pyright: Remediation oder eine verfügbare lokale Node.js-Runtime
  stehen aus; das beobachtete lokale Ergebnis von `node --version` war nicht
  verfügbar. Die Deklaration eines gepinnten CI-Setups ersetzt keine
  Beobachtung des finalen Remote-Checks.
- Final-Candidate-Remote-Evidence: Der task-owned Source-Commit
  `768a06b5b734547f8213cc6918c26ef4a8ef9f67` und diese
  Dokumentationsabstimmung benötigen einen bewussten normalen Task-Branch-Push.
  Danach
  müssen GitHub-hosted PR-Workflows (einschließlich CodeQL, Dependency Review,
  Gitleaks, OSV, Scorecard und Workflow-/Quality-Checks) dem exakten Head
  zugeordnet sein. Aktuelle Remote-PR-Evidence gilt nur für `5b2a26a...`.
- Externe Governance: das anwendbare Dependency-Graph-/Dependabot-Ergebnis und
  die SonarQube-Cloud-Quality-Gate benötigen ihre normale externe Evidence auf
  dem finalen PR-Head. Die separat verfolgte SonarQube-Einschränkung wird durch
  diese lokalen Dokumentations- oder Source-Checks nicht gelöst.

## Einschränkungen und Restrisiko

GitHub-repositoryweite Actions-Defaults, SHA-Enforcement-Einstellungen,
Branch-Protection, Dependabot-Alerts und SonarQube-Cloud-Konfiguration sind
externe Governance-Kontrollen und werden durch diese Framework-only-Aufgabe
nicht geändert. Der aktuelle SonarQube-Cloud-Fehler bleibt separat verfolgt.
Full-History-Gitleaks und geplante OSV-Scans sind bewusst advisory, bis ihre
Findings triagiert sind.

## Finaler Diff- und Review-Status

Die committete Remote-Historie auf `agent/expand-framework-ci-security` endet
derzeit bei `5b2a26a41e7621e7b246aa1a060149252cfe3062`. Der lokale task-owned
Security-Follow-up-Commit ist `768a06b5b734547f8213cc6918c26ef4a8ef9f67`; diese
gepaarte Dokumentationsabstimmung ist noch uncommittet. Ihr finaler
Whitespace-/Secret-Review, Exact-Head-Remote-CI, SonarQube Cloud, Reviews und
Review-Thread-Verifikation stehen noch aus. Es gibt keinen Merge,
Parent-Gitlink-Update, Parent-Produkt-/Workflow-Change oder MRTS-Change. Dies
ist ein Draft-PR und kein `verified_pr`-Delivery-Status.
