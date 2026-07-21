# Framework-CI-Security-Tooling

**Sprache:** [English](ci-security-tooling.md) | Deutsch

Dieser Leitfaden beschreibt die Framework-eigenen CI-Sicherheitskontrollen. Er
gilt ausschließlich für dieses Repository. Er initialisiert, scannt, führt oder
ändert weder den schreibgeschützten Checkout `tools/MRTS` noch leitet er
Sicherheitsaussagen über Connector-Runtimes ab.

## Sicherheitsmodell

Normale Pull-Request-Workflows, einschließlich `ci-security-osv.yml`,
verwenden `pull_request`. Der OSV-Job erhält ausschließlich `contents: read`,
checkt die unveränderliche PR-Basis-SHA ohne persistierte Credentials oder
Submodule aus, holt nur die nummerierte GitHub-Pull-Request-Head-Referenz,
verifiziert die gemeldete Head-SHA und liest die zwei benannten Dependency-
Manifeste als begrenzte Daten. Sein ausgecheckter Framework-Quellcode und
Scanner-Helper stammen damit aus der Basisrevision. Alle Routine-Jobs erhalten
nur `contents: read`, verwenden unveränderliche Action-SHAs mit überprüften
Versionskommentaren und checken mit `persist-credentials: false` sowie
`submodules: false` aus. Sie stellen keine Caches wieder her oder speichern
sie und laden keine beliebigen Artefakte hoch.

Jeder normale CI-Security-Pull-Request-Checkout wählt explizit den
unveränderlichen PR-Head statt des synthetischen GitHub-Merge-Refs. Jobs, die
PR- und Nicht-PR-Events bedienen, verwenden `github.event.pull_request.head.sha
|| github.sha`; vertrauenswürdige Default-Branch-Jobs verwenden `github.sha`.
Der Gitleaks-PR-Range-Job verwendet den PR-Head direkt und beweist die
ausgecheckte SHA vor dem Scan. Der OSV-PR-Job führt dagegen nur die
vertrauenswürdige Basisrevision aus und verwendet das verifizierte PR-Objekt
allein zum Lesen von Blobs. Der lokale semantische Evidence-Contract prüft
diese Mappings und die ausführbaren Scanner-Kommandos nach dem Entfernen von
Shell-Kommentaren; Bodies von Kontrollfluss, nach `exit` nicht erreichbare
Befehle und nicht aufgerufene Helper werden ausgeschlossen.

Jeder Workflow hat ein explizites Timeout und ein Concurrency-Verhalten. PR-
und normale CI-Jobs brechen überholte Runs desselben Workflow/Ref ab. Die zwei
geplanten Wartungsjobs brechen einen aktiven Run bewusst nicht ab: Der
Common-Version-Job kann einen begrenzten Update-PR erstellen, und der
Artefakt-Cleanup-Job löscht nur Artefakte nach seiner dokumentierten
Aufbewahrungsrichtlinie.

`security-events: write` ist auf den vertrauenswürdigen Nicht-PR-Upload-Job
in `ci-security-codeql.yml` beschränkt. Sein read-only PR-Pendant
`ci-security-codeql-pr.yml` analysiert den exakten PR-Head mit `upload: never`
und `upload-database: false`; es erhält nie `security-events: write`. OSV und
Scorecard verwenden prüfsummenverifizierte Release-CLIs außerhalb des
Checkouts, erhalten kein GitHub-Token und veröffentlichen kein SARIF. Ihre
PR-Jobs können daher Fork-Heads mit ausschließlich `contents: read`
analysieren. Kein Workflow verwendet `id-token: write`. OSV bewahrt nur
validierte JSON-Vergleichsevidenz an festen Pfaden auf; Scorecard-PR-Jobs
bleiben artefaktfrei.

## Workflows und Scope

| Workflow | Trigger und Vertrauensgrenze | Kontrolle |
| --- | --- | --- |
| `ci-security-workflow-lint.yml` | PR, Default-Branch-Push, manuell | Prüfsummenverifiziertes actionlint mit ShellCheck, offline zizmor, Contracts für immutable Pins/Berechtigungen/Checkout, semantische Evidence-Validierung sowie sichere und unsichere Fixtures. |
| `ci-security-quality.yml` | PR- und Default-Branch-Änderungen am CI-Security-Python-Scope | Prüfsummenverifiziertes Ruff-Lint/-Format und Pyright mit exakt festgelegter Node.js-Runtime. Der Scope umfasst CI-Security- und Change-Record-Checker, Downloader und deren Tests. |
| `ci-security-secrets.yml` | PR, Zeitplan, manuell | Gitleaks checkt den exakten PR-Head aus und beweist ihn; danach scannt es exakt den Bereich Merge-Base bis Head mit `--redact=100`. Die gesamte Historie ist geplant/manuell advisory, bis Findings triagiert sind. |
| `ci-security-osv.yml` | Begrenztes nicht privilegiertes `pull_request`; Zeitplan und manuell auf dem Default-Branch | Der PR-Job führt die vertrauenswürdige PR-Basis-SHA aus, holt die nummerierte PR-Referenz ohne Checkout, verifiziert ihre exakte Head-SHA und vergleicht nur begrenzte `requirements-dev.txt`- und `requirements-ci.lock`-Blobs ohne Remediation. Er scheitert nur bei neu eingeführten OSV-Schwachstellengruppen. Jede Revision muss `requirements-dev.txt` enthalten; der PR-Head muss `requirements-ci.lock` enthalten, während eine Basisrevision vor dessen Einführung eine begrenzte leere optionale Eingabe erhält. Basis-, Head- und Vergleichs-JSON werden erst nach Regular-File-, Größen- und JSON-Validierung einen Tag aufbewahrt. Die benannten Eingaben traversieren niemals `tools/MRTS`; geplante/manuelle Default-Branch-Scans sind advisory. |
| `ci-security-codeql-pr.yml` | PR | CodeQL analysiert den exakten PR-Head mit ausschließlich `contents: read`, dem `linked`-Tool-Bundle der gepinnten Action, `upload: never` und `upload-database: false`. Es analysiert GitHub Actions, Python und C/C++ und ignoriert `tools/MRTS/**`; es erhält nie eine Code-Scanning-Write-Berechtigung. |
| `ci-security-codeql.yml` | Default-Branch-Push, Zeitplan, manuell | Vertrauenswürdiges CodeQL analysiert die exakte `github.sha` mit demselben begrenzten Sprach-Scope und `linked`-Tool-Bundle. Seine eine Job-spezifische `security-events: write`-Berechtigung wird ausschließlich nach Nicht-PR-Ausführung zum Upload von Code-Scanning-SARIF verwendet. Go oder JavaScript/TypeScript werden nicht behauptet; C/C++ verwendet `build-mode: none`, damit der Scan keine Connector- oder MRTS-Abhängigkeiten provisioniert. |
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

`requirements-ci.lock` pinnt das CI-PyYAML-CP313-Wheel für überprüftes
CPython 3.13.14 auf Linux x86_64 und verlangt dessen offiziellen PyPI-SHA-256.
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
Scanner-Artefakte. Gitleaks redigiert Findings. Nur vertrauenswürdige
Nicht-PR-CodeQL-Ausführung verwendet den GitHub-Code-Scanning-SARIF-Kanal; das
PR-Pendant führt absichtlich keinen SARIF- oder Datenbank-Upload aus. OSV
validiert seine exakte-Basis-, exakte-Head- und Vergleichsdateien vor der
Aufbewahrung der Vergleichsevidenz für einen Tag als reguläre begrenzte JSON-
Objekte; die OSV-Eingabereports müssen zusätzlich das erwartete
Result-/Package-/Group-Schema erfüllen. Scorecard validiert sein PR-Ergebnis
ohne Artefakt und bewahrt seine begrenzte Current-Revision-JSON-Evidenz einen
Tag auf. Keiner der Scanner lädt SARIF hoch. Für CodeQL-Plattform-Records,
begrenzte OSV- und Scorecard-Artefakte und Workflow-Logs gelten deshalb
getrennte GitHub-Aufbewahrung und Zugriffskontrollen.

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

Der dedizierte semantische Workflow-Evidence-Check ist außerdem verfügbar als:

```sh
python3 ci/checks/security/check-ci-security-evidence-contract.py
```

Der CI-Workflow führt außerdem die gepinnten Tools actionlint, zizmor, Ruff
und Pyright aus. Fehlt lokal eine Hilfsruntime, dokumentiere die Einschränkung,
statt eine globale oder User-Site-Installation zu verwenden.
