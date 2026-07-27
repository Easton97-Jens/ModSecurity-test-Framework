# GitHub-Actions-Workflow-Sicherheit

**Sprache:** [English](github-actions-workflow-security.md) | Deutsch

Dieser Leitfaden definiert den Framework-eigenen Vertrag für GitHub-Actions-
Workflows. Er schützt die CI-Lieferkette und die Pull-Request-Vertrauensgrenze,
ohne Aussagen über das Laufzeitverhalten eines Connectors zu treffen.

## Geltungsbereich und Inventar

Der Vertrag umfasst jede `.yml`- und `.yaml`-Datei in `.github/workflows/`,
einschließlich verschachtelter Verzeichnisse. Der Validator löst eine
angeforderte Workflow-Datei oder ein Verzeichnis vor dem Lesen unterhalb der
aktuellen Repository-Wurzel auf und überspringt einen aufgelösten Pfad, der
diese Wurzel verlässt (zum Beispiel über einen Symlink).
Der Framework-eigene OSV-Workflow verwendet das nicht privilegierte
`pull_request`-Event. Sein enger Job checkt die vertrauenswürdige PR-Basis-SHA
aus, holt und verifiziert das nummerierte PR-Head-Objekt und liest nur benannte
Dependency-Manifest-Blobs sowie den PR-Head-Blob `.python-version`. Letzterer
ist größen- und formatbegrenzt, wird einmalig als reguläre, nicht symlinkte Datei
unter privatem `runner.temp` geschrieben und nur von `setup-python` verwendet.
Der ausgecheckte Framework-Quellcode und der Scanner-Helper stammen damit aus
der Basisrevision und nicht aus PR-Head-Dateien: Der Job checkt keinen PR-Head
aus und führt keinen PR-Head-Code aus. Kein PR-Checkout aktiviert Submodule. Die separat
dokumentierte CI-Security-Suite besitzt begrenzte OSV-/Scorecard-
Artefaktausnahmen; ihr einziger SARIF-/CodeQL-Upload ist der vertrauenswürdige Nicht-PR-Job in
`ci-security-codeql.yml`. Sein read-only-Pendant
`ci-security-codeql-pr.yml` analysiert PR-Heads ohne Upload oder Write-
Berechtigung. Durch diese Härtung wurde kein solches Verhalten entfernt.

| Workflow | Trigger | Externe Actions | Effektive Berechtigungen | Vertrauensentscheidung |
| --- | --- | --- | --- | --- |
| `check-action-versions.yml` | `workflow_dispatch`, gefilterter `pull_request` | `actions/checkout`, `actions/setup-python` | `contents: read` | PR-Quellcode ist nicht vertrauenswürdig; er läuft nur lesend und ohne persistierte Checkout-Credentials. |
| `check-common-versions.yml` | `workflow_dispatch`, Zeitplan | `actions/checkout`, `actions/setup-python`, `peter-evans/create-pull-request` | Workflow-Standard `contents: read`; nur Publisher-Job effektiv `contents: write`, `pull-requests: write` | Resolver und Kandidatenjob bleiben read-only; ein Default-Branch-Publisher löst den Kandidaten unabhängig erneut auf, bindet dessen SHA-256 und erstellt oder aktualisiert nur einen Draft-PR auf festem Branch für `ci/lib/common.sh`. |
| `check-python-version.yml` | `workflow_dispatch`, Zeitplan | `actions/checkout`, `actions/setup-python`, `peter-evans/create-pull-request` | Workflow-Standard `contents: read`; nur Publisher-Job effektiv `contents: write`, `pull-requests: write` | Resolver- und Kandidatenjobs sind read-only; der Publisher löst einen stabilen Kandidaten unabhängig erneut auf und erstellt nur einen Draft-PR auf festem Branch für `.python-version`, niemals einen Merge. |
| `cleanup-artifacts.yml` | `workflow_dispatch`, Zeitplan | `actions/github-script` | Workflow-Standard `contents: read`; Cleanup-Job effektiv `actions: write` | Geplanter/manueller Workflow vertrauenswürdiger Maintainer; sein Job kann nur Repository-Artefakte löschen. |
| `lint.yml` | `push`, `pull_request` | `actions/checkout`, `actions/setup-python` | `contents: read` | PR-Quellcode und seine Entwicklungsabhängigkeiten sind nicht vertrauenswürdig; weder Write-Berechtigung, Secret, persistierte Credentials noch Submodule sind konfiguriert. |
| `test-common.yml` | `push`, `pull_request` | `actions/checkout`, `actions/setup-python` | `contents: read` | PR-Quellcode ist nicht vertrauenswürdig; weder Write-Berechtigung, Secret, persistierte Credentials noch Submodule sind konfiguriert. |
| `ci-security-osv.yml` | begrenztes `pull_request`, Zeitplan, manuell | `actions/checkout`, `actions/setup-python`, `actions/upload-artifact` | `contents: read` | Der nicht privilegierte PR-Job führt nur die vertrauenswürdige Basisrevision aus, verifiziert ein geholtes PR-Objekt und behandelt Dependency-Manifest- und begrenzte `.python-version`-Blobs als Daten statt als ausgecheckten Code. |
| `update-workflow-tools.yml` | Zeitplan, manuell | `actions/checkout`, `actions/setup-python`, `actions/create-github-app-token`, `actions/github-script` | Reader-Jobs und das eingebaute Publisher-Token `contents: read`; sein erzeugtes App-Token hat `contents`, `pull-requests`, `workflows`: write | Der eingeschränkte Publisher läuft erst nach unabhängigen Resolver- und Validator-Jobs, begrenzt sein kurzlebiges App-Token auf dieses Repository und erstellt ausschließlich einen Draft-PR. |
| `update-submodules.yml` | Zeitplan, manuell | `actions/checkout`, `actions/setup-python` | Reader-Jobs `contents: read`; nur der validierte Default-Branch-Publisher hat `contents: write`, `pull-requests: write` | Der Resolver folgt ausschließlich `Easton97-Jens/MRTS` `refs/heads/main`; der Validator initialisiert ausdrücklich nur `tools/MRTS`, bevor er den detached Kandidaten prüft; der Publisher ändert nur `tools/MRTS`, verwendet einen normalen Push ohne Force und erstellt oder aktualisiert genau einen passenden Draft-PR. |

## Unveränderliche Action-Provenienz

Jede Remote-Action muss einen 40-stelligen Commit-SHA in Kleinbuchstaben und
einen benachbarten validierten Release-Versionskommentar verwenden. Die derzeit
zugelassenen Upstreams, Releases und Commit-Identitäten sind:

| Action | Offizieller Upstream | Release | Commit-SHA | Lizenz | Notwendige Verwendung |
| --- | --- | --- | --- | --- | --- |
| `actions/checkout` | [actions/checkout](https://github.com/actions/checkout) | `v7.0.1` | `3d3c42e5aac5ba805825da76410c181273ba90b1` | MIT | Checkt den Framework-Quellcode für Validierung oder Wartung aus. |
| `actions/setup-python` | [actions/setup-python](https://github.com/actions/setup-python) | `v7.0.0` | `5fda3b95a4ea91299a34e894583c3862153e4b97` | MIT | Wählt den exakten Interpreter aus `.python-version` für Framework-CI und kontrollierte Wartungsvalidierung aus. |
| `actions/setup-node` | [actions/setup-node](https://github.com/actions/setup-node) | `v7.0.0` | `820762786026740c76f36085b0efc47a31fe5020` | MIT | Wählt die überprüfte Node.js-Runtime für prüfsummenverifiziertes Pyright. |
| `actions/upload-artifact` | [actions/upload-artifact](https://github.com/actions/upload-artifact) | `v7.0.1` | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` | MIT | Bewahrt nur begrenzte CI-Security-Evidenz auf. |
| `actions/github-script` | [actions/github-script](https://github.com/actions/github-script) | `v9.0.0` | `3a2844b7e9c422d3c10d287c895573f7108da1b3` | MIT | Prüft eingeschränkte Draft-PRs oder führt Artefakt-Aufbewahrungsbereinigung aus. |
| `actions/create-github-app-token` | [actions/create-github-app-token](https://github.com/actions/create-github-app-token) | `v3.2.0` | `bcd2ba49218906704ab6c1aa796996da409d3eb1` | MIT | Erzeugt das kurzlebige, auf das Repository begrenzte App-Token des Workflow-Tool-Publishers. |
| `peter-evans/create-pull-request` | [peter-evans/create-pull-request](https://github.com/peter-evans/create-pull-request) | `v8.1.1` | `5f6978faf089d4d20b00c7766989d076bb2fc7f1` | MIT | Erstellt den eingeschränkten CPython-Version-Draft-PR. |
| `github/codeql-action` | [github/codeql-action](https://github.com/github/codeql-action) | `v4.37.1` | `7188fc363630916deb702c7fdcf4e481b751f97a` | MIT | Führt die begrenzte CodeQL-Analyse und den vertrauenswürdigen SARIF-Upload aus. |
| `actions/dependency-review-action` | [actions/dependency-review-action](https://github.com/actions/dependency-review-action) | `v5.0.0` | `a1d282b36b6f3519aa1f3fc636f609c47dddb294` | MIT | Prüft Abhängigkeitsänderungs-PRs ohne Remediation. |

Der Vertrag weist Tags, Branches, verkürzte oder Großbuchstaben-SHAs,
dynamische Referenzen, Docker-Referenzen, fehlerhafte oder Block-Scalar-
`uses:`-Werte, YAML-Flow-Collections, explizite Mapping-Keys, YAML-Tags/Anker/
Aliase/Merge-Keys in Key- oder Value-Position, escapte doppelt zitierte
Mapping-Keys, YAML-Dokumentmarker (auch nach einem UTF-8-BOM) und einen
fehlenden Release-Kommentar zurück. Unabhängig von der Source-Schreibweise
bindet der CI-Security-Contract jede geparste nicht lokale `uses`-Referenz
rekursiv an ihren überprüften Lock-Record und den exakten unveränderlichen
Commit; die Source-Prüfung des Release-Kommentars bleibt Defense in Depth.
Quoted-Key- und Flow-Mapping-Referenzen mit einer abweichenden Voll-SHA werden
damit zurückgewiesen, statt auf eine literale Schreibweise `uses:` zu vertrauen.
Lokale `./`-Actions sind keine Remote-
Abhängigkeiten und benötigen daher keinen Remote-Pin; derzeit existiert keine,
und jede künftige lokale Action in einem PR-Workflow bleibt der untenstehenden
nicht schreibenden PR-Vertrauensgrenze unterworfen.

## Berechtigungen und Pull-Request-Vertrauensgrenze

Jeder Workflow beginnt genau mit:

```yaml
permissions:
  contents: read
```

Nur ein vertrauenswürdiger Job darf diese Baseline durch eine kleinere,
zweckspezifische Berechtigungszuordnung ersetzen. `check-common-versions` gibt
Repository-Content- und Pull-Request-Write-Rechte erst seinem Publisher-Job,
nachdem Resolver und Kandidatenjob read-only geblieben sind;
`check-python-version` gibt diese Rechte erst seinem Publisher-Job, nachdem
Resolver und Kandidatenjob read-only geblieben sind; der separate Publisher von
`update-workflow-tools` behält `contents: read` für sein eingebautes Token und
erzeugt erst nach unabhängigen Resolver- und Validator-Jobs ein auf das
Repository begrenztes GitHub-App-Token mit `contents`-, `pull-requests`- und
`workflows`-Write-Recht; `cleanup-artifacts` benötigt nur `actions: write`, um
Artefakte zu löschen; `update-submodules` gibt `contents`- und
`pull-requests`-Write-Recht nur seinem validierten Default-Branch-Publisher;
der vertrauenswürdige Nicht-PR-CodeQL-Upload-Job benötigt `security-events:
write`. Kein PR-ausgelöster Job darf eine Write-Berechtigung vergeben.

Jede direkte Verwendung von `actions/checkout` setzt:

```yaml
with:
  persist-credentials: false
```

Dies verhindert, dass das Checkout-Credential für spätere Git-Kommandos
persistiert wird. GitHub stellt Actions dennoch ein automatisches Token im
Berechtigungsumfang des Jobs bereit, und `actions/checkout` verwendet
standardmäßig dieses job-scoped Credential, solange eine Action nicht explizit
ein anderes Credential erhält. Resolver und Kandidatenjob der Common-Versionen
deklarieren kein explizites Token oder Secret. Der Publisher ist auf geplante/
manuelle Ausführung im vertrauenswürdigen Default-Branch begrenzt und übergibt
`github.token` nur an die überprüfte, unveränderliche
`create-pull-request`-Action; er löst den Kandidaten unabhängig erneut auf,
vergleicht dessen SHA-256 mit dem read-only validierten Ergebnis und verlangt,
dass Working-Tree-Diff und `add-paths` der Action nur `ci/lib/common.sh`
enthalten. Auch Resolver und Kandidatenjob der Python-Version deklarieren
keines; sein Publisher deklariert genau ein explizites Token nur für seine
überprüfte Pull-Request-Action. Resolver und Validator des Workflow-Tools
bleiben im Source ebenfalls tokenfrei. Sein eng profilierter Publisher übergibt
`vars.WORKFLOW_UPDATER_APP_CLIENT_ID` und
`secrets.WORKFLOW_UPDATER_APP_PRIVATE_KEY` nur an den unveränderlichen
`create-github-app-token`-Step, fordert ein Token nur für das aktuelle
Repository an und übergibt dessen Output nur an seine eingeschränkten Draft-PR-
API- und normalen Push-Schritte. Er hat keinen `github.token`-Publishing-
Fallback, und die Standard-Post-Job-Token-Revocation der Action bleibt aktiv.
Die App muss nur für dieses Framework-Repository installiert sein und exakt
`Contents`-, `Pull requests`- und `Workflows`-Write-Autorität erhalten;
fehlende oder unzureichende Hosted-Konfiguration lässt den Publisher scheitern,
statt eine Credential zu erweitern. Auch MRTS-Submodule-Resolver und
Validator deklarieren kein Token oder Secret. Sein separater Publisher
verwendet das native Job-Token nur für seine überprüften GitHub-CLI- und
normalen Git-Push-Schritte, verifiziert, dass ein vorhandener Draft-Branch nur
`tools/MRTS` ändert, und weist Force-Pushes, ein Default-Branch-Ziel oder ein
PR-Event zurück. Der Contract weist eine explizite Token-/Secret-Referenz auf
Workflow-Ebene oder in jedem Reader-Job zurück und bindet die Profile der
schreibfähigen Publisher exakt. Der Python-Publisher löst den
Kandidaten unabhängig erneut auf, erlaubt nur `.python-version` sowohl im
geprüften Diff als auch in `add-paths`, fixiert den Automationsbranch, setzt
`draft: true` und weist Merge- oder Auto-Merge-Shell-Kommandos im Source-
Contract zurück. GitHub-Berechtigungen sind Job- und nicht Schritt-spezifisch:
Das Einengen einer Umgebungsvariable reduziert die direkte Shell-Exposition,
verwandelt einen vertrauenswürdigen Job mit Write-Rechten aber nicht in eine
Schritt-Berechtigungsgrenze. Jeder Publisher ist daher auf geplante oder
manuelle Trigger vertrauenswürdiger Maintainer begrenzt und enthält kein
PR-Event.

Für jeden `pull_request`-Workflow weist der Checker `pull_request_target`,
Write-Berechtigungen, Referenzen `secrets.` und `secrets[...]`, Secret-
Weitergabe an wiederverwendbare Workflows, direkte Checkouts ohne
`persist-credentials: false` sowie aktivierte oder dynamische Submodule zurück.
Der OSV-Job ist keine Ausnahme dieser Trigger-Policy: Er läuft mit
`contents: read`, ohne Secrets, persistierte Credentials und Submodule. Er
checkt zusätzlich die PR-Basis-SHA aus und ist zum Holen, SHA-Verifizieren und
Blob-Lesen des PR-Heads verpflichtet. Damit bleibt ein reiner Datenvergleich
von Abhängigkeiten für nicht vertrauenswürdige Same-Repository- und Fork-PR-
Eingaben erhalten.

## Erzwungene Prüfungen und Fixtures

`ci/checks/security/check-github-actions-workflows.py` ist der kanonische,
quellcodeverwaltete Validator. Sein Pin-Modus verwendet nur die Python-
Standardbibliothek, damit der dedizierte Action-Pin-Workflow vor der
Installation von Entwicklungsabhängigkeiten laufen kann. Sein Berechtigungs-
Modus verwendet PyYAML, weist doppelte Schlüssel, Aliase, Anker und Merge-Keys
zurück und wird vom Framework-Lint-Vertrag ausgeführt.

```sh
make check-github-actions-pins
make check-github-actions-permissions
make check-github-actions-workflows
make check-python-version
make test-workflow-security-contract
```

`ci/checks/security/check-python-version.py` fordert separat die kanonische
reguläre Datei `.python-version`, rekursive Workflow-Abdeckung, Setup vor jedem
direkten oder durch Make ausgelösten Python-Kommando, keinen hart kodierten
Patch oder Python-Matrix und kein bares `pip`. Es erlaubt genau zwei
Runner-Temporär-Dateiausnahmen: die Kandidatendatei im direkten
Validierungsjob von `check-python-version.yml` nach kanonischem Setup sowie die
OSV-Datei `pull-request-head` nach vertrauenswürdigem Basis-Checkout,
SHA-verifizierter, begrenzter und nicht symlinkter PR-Head-Blob-
Materialisierung. Der CI-Security-Contract erzwingt zusätzlich die exakten
Wartungstopologien, vertrauenswürdigen Publisher-Gates, Publisher-
Revalidierungen, festen Draft-PR-Branches und jeweiligen zugelassenen
Pfadumfänge.

Die Regression-Suite validiert zuerst die echten Workflows und beweist dann,
dass sichere Read-only-PR- und Trusted-Writer-Fixtures bestehen. Unsichere
Fixtures beweisen die Zurückweisung veränderlicher Referenzen in beiden
Endungen, Block-Maps, Flow-Maps und Flow-Sequenz-Maps, dynamischer Referenzen
und alternativer Key-Syntax, fehlender Release-Kommentare,
jeder `pull_request_target`-Nutzung, Top-Level- und PR-Job-Write-Berechtigungen,
persistierter Credentials, breiter Job-Token-Exposition, Submodule,
Secret-Referenzen und doppelter YAML-Schlüssel. `make lint` ruft den Checker
und diese Suite auf, während der gefilterte `check-action-versions`-Workflow
auch bei Änderungen seines Checkers, seiner Fixtures, seines Tests oder des
Makefiles läuft.

## Aktualisieren eines Action-Pins

Vor dem Ändern eines Action-Pins:

1. Verifiziere, dass die Action das offizielle Upstream-Repository hat, eine
   notwendige Funktion besitzt und kein unerwarteter Fork ist.
2. Verifiziere das vorgesehene Upstream-Release, die Release-zu-Commit-
   Zuordnung und die Lizenz; dokumentiere vollständigen Commit-SHA und exakten
   Versionskommentar zusammen.
3. Aktualisiere jede relevante Workflow-Referenz und erhalte den exakten
   Kommentar `# vX.Y.Z` direkt neben dem SHA.
4. Führe den YAML-Parser, beide Validator-Modi, die Workflow-Contract-Suite
   sowie die verfügbaren actionlint-, ShellCheck- und zizmor-Prüfungen aus.
5. Aktualisiere diesen englischen/deutschen Leitfaden und den Framework-
   Change Record mit den beobachteten Provenienz- und Validierungsergebnissen.

## Einschränkungen und betriebliche Erwartungen

Dieser Vertrag ist ein Repository-Control und kein Ersatz für GitHub-
Branch-Protection, Workflow-Review, Action-Provenienz-Review, actionlint,
zizmor, CodeQL, Scorecard oder SonarQube Cloud. Diese Controls müssen am
tatsächlichen Pull-Request-Head bewertet werden. Tool-Verfügbarkeit wird im
Change Record wahrheitsgemäß festgehalten; ein lokal nicht verfügbares Tool
gilt nicht als bestandene Prüfung.

Für den Python-Version-Publisher sind GitHub-Berechtigungen zum Dispatch eines
Workflows, Protected-Default-Branch-Regeln, Required Checks, SonarQube Cloud,
Review-Aktualität und der exakte Head des token-erstellten Draft-PRs gehostete
Kontrollen. Sie müssen für jeden veröffentlichten Head verifiziert werden,
bevor ein Mensch ihn merged; der Workflow selbst merged nie und aktiviert kein
Auto-Merge.

Wenn ein künftiger Workflow die dokumentierte Artefakt-/SARIF-Ausnahme ändert,
Artefakte über eine Vertrauensgrenze hinweg konsumiert, OIDC nutzt, einen
wiederverwendbaren Workflow aufruft oder eine neue Write-Berechtigung benötigt,
müssen Checker, Fixtures, Inventar und Change Record erweitert werden, bevor
sich auf das neue Verhalten verlassen wird.
