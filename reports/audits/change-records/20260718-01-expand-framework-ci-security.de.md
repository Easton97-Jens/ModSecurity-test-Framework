# Change Record — Framework-CI-Security-Erweiterung

**Sprache:** [English](20260718-01-expand-framework-ci-security.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260718-01-expand-framework-ci-security |
| UTC-Datum | 2026-07-18 |
| Framework-Basisrevision | `9954b99a31fab0006cdf903ab477c8158c50fea8` |
| PR-Historie vor der Abstimmung | `66d90872cfc0125536267d574b776d2e88d26b23`; die weiter unten genannten älteren Commits bleiben nur historischer Kontext. |
| Issue oder Pull Request | [Framework-Draft-PR #27](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/27) |
| Aktueller Remote-Draft-PR-Head | `66d90872cfc0125536267d574b776d2e88d26b23`; er bleibt der Remote-Head, bis die lokalen Abstimmungscommits normal gepusht sind. |
| Abstimmungsstatus | Der normale Merge ohne History-Rewrite `6bd98fdfb96f65d924d5eaed8d5deb4e7faced91` verbindet diesen PR-Head mit Framework-`master` `9954b99a31fab0006cdf903ab477c8158c50fea8`; dieses gepaarte Traceability-Follow-up vervollständigt den lokalen Kandidaten. |
| Delivery-Status | Nur Draft-PR; lokale Abstimmungsvalidierung ist unten dokumentiert, während normaler Push, frische Remote-Checks, SonarCloud, Reviews, Threads und Exact-Head-Gleichheit weiter erforderlich sind. `verified_pr` ist nicht erreicht. |

## Motivation und Problemstellung

Das Framework verwendete mutable Action-Tags und hatte keinen Framework-eigenen
CI-Security-Scanner-/Provenienzvertrag. Das anfängliche Scanner-Action-Design
enthielt außerdem einen task-owned transitive-mutable-Container-Pfad. Diese
Änderung ersetzt ihn durch prüfsummenverifizierte CLIs und ergänzt
Framework-Kontrollen, ohne Parent-Repository, dessen Gitlink oder MRTS zu
ändern. Die eigenständig geregelten Common-Structure- und Action-Pin-
Kontrollen aus Framework-`master` bleiben additiv erhalten; diese Abstimmung
ersetzt sie nicht.

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
- Die `test-common.yml`-Ausführungsumgebung gehärtet und dabei den bereits auf
  `master` vorhandenen dynamischen nichtleeren Korpus- und Apache-Common-
  Auswahlvertrag erhalten; keine feste Katalogzahl wird wieder eingeführt.
- Die aktuelle lokale CI-Security-Suite enthält vierundsechzig positive und negative
  Tests. Sie deckt die ursprünglichen Contracts sowie semantische Workflow-
  Kontrollen, strikte OSV-Evidence-/Gruppenabdeckung, Downloader-Containment
  und die CRS-Temporary-Path-Regression ab.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Aktuelle Abstimmung: `make test-ci-security-contract test-change-record-contract test-workflow-action-pins test-workflow-contract` mit externen Roots | 0 | 65 CI-Security-Tests, 4 Change-Record-Tests, 21 immutable Action-Pin-Tests und 2 dynamische Common-Structure-Tests bestanden auf dem abgestimmten Kandidaten. | `20260719T081017Z-framework-pr-resolution-20260719-840082e0/build/pr27-reconciliation.iwDakV` |
| Aktuelle Abstimmung: NGINX- und PCRE2-Archiv-/Provenance-Regressionsmodule | 0 | Alle 15 Tests für fehlende, fehlerhafte, nicht passende und legitime Archive bestanden; Release-Tag, exaktes Asset und erforderlicher SHA-256-Contract von `master` bleiben intakt. | Gleicher zulässiger Run |
| Aktuelle Abstimmung: direkter Action-Pin-, CI-Security-, CI-Security-Evidence-, Change-Record-Check und Python-Compile | 0 | Alle vier Verträge bestanden; der Compile nutzte den registrierten externen Pycache, nachdem ein Schreibversuch im geschützten Worktree von der Umgebung abgewiesen wurde. | Gleicher zulässiger Run |
| Aktuelle Abstimmung: `make lint` mit expliziten Framework- und externen Roots | 0 | Shell-/Python-Checks, 65 CI-Security-, Action-Pin-, dynamische Workflow-, Dokumentations-, Katalog- und Diff-Checks bestanden. | Gleicher zulässiger Run |
| Historische Kandidaten-Evidenz unten | n/a | Die folgenden älteren Zeilen bleiben nur zur Traceability erhalten und sind keine Exact-Head-Merge-Evidence für den abgestimmten Kandidaten. | Früher aufbewahrte Task-Evidence |
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

Die veröffentlichte Remote-Historie auf `agent/expand-framework-ci-security`
endet derzeit bei `66d90872cfc0125536267d574b776d2e88d26b23`; der lokale
normale Merge-Kandidat ohne History-Rewrite ist
`6bd98fdfb96f65d924d5eaed8d5deb4e7faced91` mit Framework-`master`
`9954b99a31fab0006cdf903ab477c8158c50fea8` als zweitem Parent. Seine additive
Auflösung erhält das aktuelle NGINX-Release-Tag- /
Asset- / erforderliche-SHA-256-Tupel, die PCRE2-Digest-Erzwingung, den
unabhängigen Full-SHA-Action-Pin-Checker und den dynamischen
Common-Structure-Vertrag; #27 ergänzt Scanner-/Evidence-Kontrollen statt sie
zu ersetzen. Dieses gepaarte Traceability-Follow-up und sein finaler Scoped-
Diff-Review benötigen weiterhin normalen Push, Gleichheit von lokalem/Remote-/PR-Head,
frische Remote-CI- und SonarCloud-Evidence, Reviews und Review-Thread-
Verifikation. Es gibt keinen Framework-Merge, Parent-Gitlink-Update,
Parent-Produkt-/Workflow-Change oder MRTS-Change. Dies bleibt ein Draft-PR und
ist kein `verified_pr`-Delivery-Status.
