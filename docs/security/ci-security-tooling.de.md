# Framework-CI-Security-Tooling

**Sprache:** [English](ci-security-tooling.md) | Deutsch

Dieser Leitfaden beschreibt die Framework-eigenen CI-Sicherheitskontrollen. Er
gilt ausschließlich für dieses Repository. Er initialisiert, scannt, führt oder
ändert weder den schreibgeschützten Checkout `tools/MRTS` noch leitet er
Sicherheitsaussagen über Connector-Runtimes ab.

## Sicherheitsmodell

Alle Pull-Request-Workflows verwenden `pull_request`; keiner verwendet
`pull_request_target`. Routine-Jobs erhalten ausschließlich `contents: read`,
verwenden unveränderliche Action-SHAs mit überprüften Versionskommentaren und
checken mit `persist-credentials: false` sowie `submodules: false` aus. Sie
stellen keine Caches wieder her oder speichern sie und laden keine beliebigen
Artefakte hoch.

Jeder Workflow hat ein explizites Timeout und ein Concurrency-Verhalten. PR-
und normale CI-Jobs brechen überholte Runs desselben Workflow/Ref ab. Die zwei
geplanten Wartungsjobs brechen einen aktiven Run bewusst nicht ab: Der
Common-Version-Job kann einen begrenzten Update-PR erstellen, und der
Artefakt-Cleanup-Job löscht nur Artefakte nach seiner dokumentierten
Aufbewahrungsrichtlinie.

`security-events: write` ist auf CodeQL beschränkt. OSV und Scorecard verwenden
prüfsummenverifizierte Release-CLIs außerhalb des Checkouts, erhalten kein
GitHub-Token und veröffentlichen kein SARIF. Ihre PR-Jobs können daher
Fork-Heads mit ausschließlich `contents: read` analysieren. Kein Workflow
verwendet `id-token: write`. OSV bewahrt nur validierte JSON-Vergleichsevidenz
an festen Pfaden auf; Scorecard-PR-Jobs bleiben artefaktfrei.

## Workflows und Scope

| Workflow | Trigger und Vertrauensgrenze | Kontrolle |
| --- | --- | --- |
| `ci-security-workflow-lint.yml` | PR, Default-Branch-Push, manuell | Prüfsummenverifiziertes actionlint mit ShellCheck, offline zizmor, Contract für immutable Pins/Berechtigungen/Checkout sowie sichere und unsichere Fixtures. |
| `ci-security-quality.yml` | PR- und Default-Branch-Änderungen am CI-Security-Python-Scope | Prüfsummenverifiziertes Ruff-Lint/-Format und Pyright mit exakt festgelegter Node.js-Runtime. Der Scope umfasst CI-Security- und Change-Record-Checker, Downloader und deren Tests. |
| `ci-security-secrets.yml` | PR, Zeitplan, manuell | Gitleaks scannt exakt den Bereich Merge-Base bis PR-Head mit `--redact=100`; die gesamte Historie ist geplant/manuell advisory, bis Findings triagiert sind. |
| `ci-security-osv.yml` | PR; Zeitplan und manuell auf dem Default-Branch | Ein prüfsummenverifiziertes OSV-Scanner-Binary vergleicht ohne Remediation exakte PR-Basis- und Head-Abhängigkeitsblobs und scheitert nur bei neu eingeführten OSV-Schwachstellengruppen. Jede Revision muss `requirements-dev.txt` enthalten; `requirements-ci.lock` wird gescannt, wenn es in der Revision existiert. Basis-, Head- und Vergleichs-JSON werden erst nach Regular-File-, Größen- und JSON-Validierung einen Tag aufbewahrt. Die benannten Eingaben traversieren niemals `tools/MRTS`; geplante/manuelle Default-Branch-Scans sind advisory. |
| `ci-security-codeql.yml` | PR, Default-Branch-Push, Zeitplan, manuell | CodeQL analysiert tatsächliche Framework-Sprachen: GitHub Actions, Python und C/C++. Es wählt das mit der gepinnten Action ausgelieferte `linked`-Tool-Bundle und ignoriert `tools/MRTS/**`; Go oder JavaScript/TypeScript werden nicht behauptet, weil diese Framework-Quellsprachen nicht vorhanden sind. C/C++ nutzt CodeQL `build-mode: none`, weil dieser begrenzte Quellscan keine Connector- oder MRTS-Abhängigkeiten provisionieren darf. |
| `ci-security-scorecard.yml` | PR; Default-Branch-Push, Zeitplan, manuell auf dem Default-Branch | Ein prüfsummenverifiziertes OpenSSF-Scorecard-Binary bewertet den exakten lokalen PR-Checkout ohne GitHub-Token. Das PR-Ergebnis wird JSON-validiert, bleibt aber artefaktfrei. Vertrauenswürdige Default-Branch-Jobs verwenden die exakte `github.sha`, bewahren eine validierte begrenzte JSON-Datei einen Tag auf und bleiben advisory, weil kein Score-Schwellenwert gesetzt ist; Scanner- und JSON-Validierungsfehler sind nicht advisory. SARIF wird nicht hochgeladen. |
| `ci-security-dependency-review.yml` | PRs mit Abhängigkeitsänderungen | Dependency Review prüft hochschwere Schwachstellen und Runtime-/Development-Scopes ohne automatische Remediation oder PR-Kommentare. |

Die vorhandenen Workflows `lint.yml`, `test-common.yml`, Action-Version-Check,
Common-Version-Wartung und Artefakt-Cleanup verwenden denselben Contract für
immutable Actions, Berechtigungen, Checkout, Timeouts und Concurrency.
Dieser Scope härtet nur die Workflow-Ausführung von `test-common.yml`; seine
eigenständig geregelte Common-Case-Katalog-Assertion und
Materialisierungssemantik sind kein CI-Security-Produktfix.

## Provenienz- und Abhängigkeitskontrollen

`ci/tooling/security-tools.lock.yml` ist der maßgebliche Record für jede
Remote-Action und jede heruntergeladene CLI in diesem CI-Scope. Er dokumentiert
Name, Version, immutable Release-Commit, Upstream-Release, Lizenz, Zweck,
Plattform, Update-Verfahren sowie bei heruntergeladenen Binaries/Packages das
exakte Release-Asset und SHA-256.

`ci/tools/fetch-security-tool.py` akzeptiert ausschließlich benannte
Lock-Records, direkte HTTPS-GitHub-Release-Assets und ein absolutes,
symlinkfreies striktes Child des dem aktuellen User gehörenden
`RUNNER_TEMP`-Verzeichnisses. Das Tool prüft SHA-256 vor dem Veröffentlichen
einer Raw-Executable oder vor dem Entpacken eines Archivs, lehnt unsichere
Archivpfade, Links und Devices ab, extrahiert nur die gelockte Executable oder
den gelockten Package-Tree und veröffentlicht das Ergebnis atomar. Es
installiert kein Paket in den Framework-Checkout.

`requirements-ci.lock` pinnt das CI-PyYAML-Wheel für überprüftes CPython
3.12.13 auf Linux x86_64 und verlangt dessen offiziellen PyPI-SHA-256.
Workflows wählen diesen exakten Patch mit `check-latest: false` und
installieren ihn anschließend mit `--require-hashes`, `--only-binary=:all:`
und `pip check`. Dependabot überwacht sowohl `github-actions` als auch `pip`;
ein vorgeschlagenes Update bleibt aber dem Lock-/Provenienzreview und dem
Immutable-Pin-Contract unterworfen. Kein Workflow behebt Abhängigkeiten
automatisch.

Der aktuelle OSV-Scope ist absichtlich explizit. Sein `.lock`-Suffix ist kein
Python-Requirements-Dateiname, den OSV Scanner direkt akzeptiert. Deshalb
materialisiert der Workflow den exakten Git-Blob als `requirements-ci.txt` im
privaten Runner-Temporärspeicher, bevor er ihn scannt. Dies ist ein
Eingabekompatibilitätsadapter, keine Dependency-Umschreibung,
Source-Tree-Änderung oder automatische Behebung. `pyproject.toml` enthält
derzeit CI-Tool-Konfiguration statt Projektabhängigkeiten, und das Framework
besitzt keine Constraints- oder Go-Modul-Verträge. Ein zukünftiger
Manifesttyp benötigt ein explizites Lock-, Scanner-Scope- und Contract-Update
statt stiller rekursiver Erkennung.

Zum Aktualisieren eines Records müssen Upstream-Release-Tag-zu-Commit-Identität,
Lizenz, Asset-Dateiname/-Member und SHA-256 geprüft werden. Aktualisiere Lock,
passende Workflow-Versionskommentare, Contract-Tests und diesen Leitfaden in
einer geprüften Änderung. Ersetze niemals einen SHA-Pin durch einen mutablen
Tag.

## Evidence, Aufbewahrung und SonarQube Cloud

Die Security-Workflows veröffentlichen absichtlich keine beliebigen
Scanner-Artefakte. Gitleaks redigiert Findings. Nur CodeQL verwendet den
GitHub-Code-Scanning-SARIF-Kanal. OSV validiert seine exakte-Basis-, exakte-
Head- und Vergleichsdateien vor der Aufbewahrung der Vergleichsevidenz für
einen Tag als reguläre begrenzte JSON-Objekte. Scorecard validiert sein PR-
Ergebnis ohne Artefakt und bewahrt seine begrenzte Current-Revision-JSON-
Evidenz einen Tag auf. Keiner der Scanner lädt SARIF hoch. Für CodeQL-
Plattform-Records, begrenzte OSV- und Scorecard-Artefakte und Workflow-Logs
gelten deshalb getrennte GitHub-Aufbewahrung und Zugriffskontrollen.

Die Artefaktausnahme bleibt absichtlich eng: OSV lädt nur die drei festen
PR-JSON-Pfade hoch, und OSV-/Scorecard-Default-Branch-Jobs laden nur eine
feste Current-Revision-JSON-Datei hoch. Jede Datei ist ein symlinkfreies,
reguläres UTF-8-JSON-Objekt mit höchstens 1 MiB. Namen verwenden die
GitHub-Run-ID, es gibt keine Glob-Uploads oder nachgelagerten
Artefakt-Consumer, und für die Aufbewahrung wird keine zusätzliche
GitHub-Write-Permission vergeben. Scorecard ist Governance-Evidenz, kein
kosmetisches Ziel: lokale Ergebnisse ohne Token beweisen weder Branch
Protection noch Reviews, Security Policy, SAST, Fuzzing, Maintained-Status
oder Repository-Token-Berechtigungen. Ergebnisse lösen Review und technisch
begründete Remediation aus; sie autorisieren niemals automatische Policy- oder
Dependency-Änderungen.

Das Framework erhält derzeit einen SonarQube-Cloud-GitHub-App-Check, besitzt
aber keinen Framework-eigenen Scanner-Workflow, Project-Key oder Token-Config,
die hier geändert werden könnte. Diese Änderung bewahrt die externe Integration,
indem sie weder Quality Gate, Exclusions noch Findings abschwächt. Sein aktuell
fehlgeschlagenes Gate wird separat verfolgt und muss am exakten PR-Head
bewertet werden; diese CI-Kontrollen verstecken oder klassifizieren es nicht
um.

## Lokale Validierung

Verwende eine Framework-virtuelle Umgebung sowie task-eigene Cache-/Output-
Pfade; erstelle keine virtuelle Umgebung oder Caches in `tools/MRTS`.
Fokussierte Befehle sind:

```sh
make test-ci-security-contract
make check-documentation
make lint
```

Der CI-Workflow führt außerdem die gepinnten Tools actionlint, zizmor, Ruff
und Pyright aus. Fehlt lokal eine Hilfsruntime, dokumentiere die Einschränkung,
statt eine globale oder User-Site-Installation zu verwenden.
