# GitHub-Actions-Workflow-Sicherheit

<!-- GENERATED PIN TABLE: values are sourced from ci/lib/common.sh. -->
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
| `check-common-versions.yml` | `workflow_dispatch`, Zeitplan | `actions/checkout`, `actions/setup-python`, `actions/create-github-app-token`, `actions/github-script`, `peter-evans/create-pull-request` | Workflow und natives Publisher-Token `contents: read`; nur das kurzlebige, repositorybegrenzte App-Token hat `contents`, `pull-requests`: write | Resolver und Kandidatenjob bleiben read-only; der Default-Branch-Publisher löst den Kandidaten unabhängig erneut auf und SHA-256-bindet ihn, bricht bei unsicherem Wartungszustand fail-closed ab und erstellt oder aktualisiert nur einen Draft-PR auf festem Branch für `ci/lib/common.sh`. |
| `check-python-version.yml` | `workflow_dispatch`, Zeitplan | `actions/checkout`, `actions/setup-python`, `actions/create-github-app-token`, `actions/github-script`, `peter-evans/create-pull-request` | Workflow-Standard `permissions: {}`; nur Resolver, Kandidatenvalidierung und Publisher erhalten eingebaute `contents: read`; das repository-begrenzte App-Token hat nur `contents`, `pull-requests`: write | Resolver- und Kandidatenjobs sind read-only. Der Default-Branch-Publisher löst einen stabilen Kandidaten unabhängig erneut auf, verifiziert genau einen festen Draft-Branch/PR und ändert nur `.python-version`; er merged nie. Ein finaler read-only-Outcome-Job macht nur den exakten No-Update-Zustand grün. |
| `cleanup-artifacts.yml` | `workflow_dispatch`, Zeitplan | `actions/github-script` | Workflow-Standard `contents: read`; Cleanup-Job effektiv `actions: write` | Geplanter/manueller Workflow vertrauenswürdiger Maintainer; sein Job kann nur Repository-Artefakte löschen. |
| `five-connectors-with-crs-no-mrts-contract.yml` | gefilterter `push`, gefilterter `pull_request` | `actions/checkout`, `actions/setup-python` | `contents: read` | PR-Quellcode ist nicht vertrauenswürdig; dieses nur lesende Gate installiert nur die hash-gesperrte Abhängigkeit aus `requirements-ci.lock` und validiert dann den portablen geschlossenen Fixture-, CRS-Provenance- und Evidenzvertrag, nie ein Connector-Host-Runtime-Ergebnis. |
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
| `actions/checkout` | [actions/checkout](https://github.com/actions/checkout) | v7.0.1 | 3d3c42e5aac5ba805825da76410c181273ba90b1 | MIT | Checkt den Framework-Quellcode für Validierung oder Wartung aus. |
| `actions/setup-python` | [actions/setup-python](https://github.com/actions/setup-python) | v7.0.0 | 5fda3b95a4ea91299a34e894583c3862153e4b97 | MIT | Wählt den exakten Interpreter aus `.python-version` für Framework-CI und kontrollierte Wartungsvalidierung aus. |
| `actions/setup-node` | [actions/setup-node](https://github.com/actions/setup-node) | v7.0.0 | 820762786026740c76f36085b0efc47a31fe5020 | MIT | Wählt die überprüfte Node.js-Runtime für prüfsummenverifiziertes Pyright. |
| `actions/upload-artifact` | [actions/upload-artifact](https://github.com/actions/upload-artifact) | v7.0.1 | 043fb46d1a93c77aae656e7c1c64a875d1fc6a0a | MIT | Bewahrt nur begrenzte CI-Security-Evidenz auf. |
| `actions/github-script` | [actions/github-script](https://github.com/actions/github-script) | v9.0.0 | 3a2844b7e9c422d3c10d287c895573f7108da1b3 | MIT | Prüft eingeschränkte Draft-PRs oder führt Artefakt-Aufbewahrungsbereinigung aus. |
| `actions/create-github-app-token` | [actions/create-github-app-token](https://github.com/actions/create-github-app-token) | v3.2.0 | bcd2ba49218906704ab6c1aa796996da409d3eb1 | MIT | Erzeugt die kurzlebigen, auf das Repository begrenzten App-Tokens der Common-Version-, CPython-Version- und Workflow-Tool-Publisher. |
| `peter-evans/create-pull-request` | [peter-evans/create-pull-request](https://github.com/peter-evans/create-pull-request) | v8.1.1 | 5f6978faf089d4d20b00c7766989d076bb2fc7f1 | MIT | Erstellt eingeschränkte Common-Version- oder CPython-Version-Draft-PRs. |
| `github/codeql-action` | [github/codeql-action](https://github.com/github/codeql-action) | v4.37.6 | 5595ccaf912efad79be6eef63a5619ff05969be3 | MIT | Führt die begrenzte CodeQL-Analyse und den vertrauenswürdigen SARIF-Upload aus. |
| `actions/dependency-review-action` | [actions/dependency-review-action](https://github.com/actions/dependency-review-action) | v5.0.0 | a1d282b36b6f3519aa1f3fc636f609c47dddb294 | MIT | Prüft Abhängigkeitsänderungs-PRs ohne Remediation. |

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

Jeder Workflow deklariert eine explizite Top-Level-Baseline. Die meisten beginnen mit:

```yaml
permissions:
  contents: read
```

`check-python-version` ist die enge explizite Ausnahme: Es beginnt mit
`permissions: {}` und gibt seinem Resolver, Kandidatenvalidator und Publisher
jeweils ein separates eingebautes `contents: read`-Token; sein Outcome-Job
bleibt leer. Dies vermeidet ambienten Tokenzugriff im finalen Statuspfad. Keine
Workflow-Top-Level-Berechtigungszuordnung vergibt Write-Rechte.
Nur ein vertrauenswürdiger Job darf diese Baseline durch eine kleinere,
zweckspezifische Berechtigungszuordnung ersetzen. `check-common-versions`
behält Resolver, Kandidat und natives Publisher-Token bei `contents: read`; nur
sein erst nach der Validierung erzeugtes, repositorybegrenztes GitHub-App-Token
erhält `contents` und `pull-requests`: write. `update-workflow-tools` behält
`contents: read` für jedes eingebaute Job-Token und erzeugt erst nach
unabhängigen Resolver- und Validator-Jobs ein auf das Repository begrenztes
GitHub-App-Token mit `contents`-, `pull-requests`- und `workflows`-Write-Recht.
Die CPython- und Common-Version-Tokens haben nur `contents`- und
`pull-requests`-Write-Recht; das Workflow-Tool-Token erhält zusätzlich
`workflows: write`, weil es Workflow-Dateien ändern kann.
`cleanup-artifacts` benötigt nur `actions: write`, um Artefakte zu löschen;
`update-submodules` gibt `contents`- und `pull-requests`-Write-Recht nur seinem
validierten Default-Branch-Publisher; der vertrauenswürdige Nicht-PR-CodeQL-
Upload-Job benötigt `security-events: write`. Kein PR-ausgelöster Job darf
eine Write-Berechtigung vergeben.

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
manuelle Ausführung im vertrauenswürdigen Default-Branch begrenzt, löst den
Kandidaten unabhängig erneut auf, vergleicht dessen SHA-256 mit dem read-only
validierten Ergebnis und verlangt, dass Working-Tree-Diff und `add-paths` der
Action nur `ci/lib/common.sh` enthalten. Sein natives Token bleibt read-only;
weder `github.token`, `GITHUB_TOKEN`, PAT, SSH-Credential noch ein Runner-Push
dürfen veröffentlichen. Er prüft die Verfügbarkeit von
`WORKFLOW_UPDATER_APP_CLIENT_ID` und `WORKFLOW_UPDATER_APP_PRIVATE_KEY`, ohne
einen Wert auszugeben; der Private-Key-Wert wird nur an die unveränderliche
`create-github-app-token`-Action übergeben. Diese Action ist auf aktuellen
Owner und Repository begrenzt und fordert nur `contents` und
`pull-requests`: write an, niemals `workflows`: write. Ihr Output wird nur vom
geprüften read-only-Zustandscheck und der unveränderlichen
`create-pull-request`-Action verwendet. Auch Resolver und Kandidatenjob der
Python-Version deklarieren kein explizites Token oder Secret. Die Common-
Version- und CPython-Publisher prüfen `WORKFLOW_UPDATER_APP_CLIENT_ID` und
`WORKFLOW_UPDATER_APP_PRIVATE_KEY`, ohne einen der Werte auszugeben. Sie
verwenden die gepinnte App-Token-Action als einzige Publisher-
Credentialquelle, haben keinen `github.token`-, `GITHUB_TOKEN`-, PAT-, SSH-
oder Runner-Publishing-Fallback und schlagen bei Konfigurations- oder
Token-Minting-Fehlern rot fehl. Resolver und Validator des Workflow-Tools
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

### GitHub-API-Authentifizierung und Redirect-Grenze

Der kanonische Maintenance-Workflow darf das bestehende read-only
jobbezogene `GITHUB_TOKEN` nur in seinen explizit überprüften Resolver-,
Reconciliation- und Re-Resolver-Schritten in `check-common-versions.yml`
verwenden. Der eigenständige Reader-
Workflow `update-workflow-tools.yml` bleibt tokenfrei; auch wenn sein Helper
aus dem kanonischen Maintenance-Pfad aufgerufen wird, erweitert dies nicht
die Berechtigungen dieses Workflows. Der Helper fügt Bearer-Credential und
GitHub-API-Medientyp nur seinem festen Request an
`https://api.github.com/repos/...` hinzu. Requests an Release-Seiten,
Downloads oder jeden anderen Host erhalten das Token nie, und das Token wird
nicht in Plänen, Zusammenfassungen, Diagnosen oder Fehlermeldungen ausgegeben.
Die bestehende Publisher-Grenze bleibt unverändert: Nur das kurzlebige,
repositorybegrenzte App-Token darf veröffentlichen.

Der API-Ursprung ist auf HTTPS `api.github.com` und repositorybezogene Pfade
festgelegt. Redirects werden vor dem Senden deaktiviert; eine Antwort, deren
finale URL von der angeforderten URL abweicht, wird abgewiesen. So kann ein
API-Bearer-Credential nicht an einen weitergeleiteten Host gelangen.
Unerwartete HTTP-, Authentifizierungs-, Rate-Limit- und Transportfehler werden
fail-closed abgewiesen.

Die Hosted-Master-Dispatches `31968050889` und `31968224482` liefen beide auf
`a5cbfff185cad3810fcafad534dc334be92a0df8` und schlugen bei der Auflösung im
Job `canonical-maintenance` mit Exit-Code 2 fehl; Dependency-Installation und
`pip check` waren zuvor erfolgreich. Diese Läufe belegen ausschließlich den
beobachteten Fehler. Die API-Grenzkorrektur, ihre exakten Hosted-Checks, die
Verifikation des resultierenden Masterstands sowie SonarQube Clouds geforderte
null neue Issues und null Duplizierung in neuem Code bleiben bis zu frischer
Beobachtung getrennte Evidenz-Gates.

## Maintenance-Publisher und terminale Ergebnisse

Die CPython- und Workflow-Tool-Maintenance-Workflows enden mit einem read-only-`outcome`-Job mit
`if: ${{ always() }}` und `permissions: {}`. Er validiert Resolver-Status,
maschinenlesbare Outputs und die tatsächlichen Ergebnisse der vorgelagerten
Jobs, bevor er eine zweisprachige Zusammenfassung schreibt. Nur die exakten
geprüften No-Update-Zustände (`current:false` für CPython und
`resolved:false` für Workflow-Tools) sind erfolgreiche No-Op-Ergebnisse; ihre
Validator-/Publisher-Jobs müssen übersprungen oder anderweitig erwartbar sein,
und es wird kein Branch, Commit oder Pull Request erstellt oder verändert.
Fehlende, fehlerhafte oder unbekannte Outputs sowie jeder Resolver-, Validator-,
Publisher-, App-Konfigurations- oder App-Token-Fehler lassen den terminalen Job
fehlschlagen, statt als No-Update dargestellt zu werden.

Bei einem Update gibt der Workflow-Tool-Resolver eine kanonische Kandidaten-
Base64- und SHA-256-Identität aus. Validator und Publisher validieren genau
diese Identität unabhängig, und der Publisher verlangt eine nicht leere
geprüfte Änderung, bevor er sie anwenden darf. CPython löst den festen
`3.14.x`-Kandidaten vor dem Update unabhängig erneut auf. Jeder Publisher
validiert genau einen passenden Draft-Branch und offenen PR: fester
Branch/Titel, Draft-Status, Marker, `master` als Basis und den erlaubten
Pfadumfang. CPython erlaubt nur `.python-version`; Workflow-Tools behalten
ihre bestehende Allowlist. Kein Publisher force-pusht, zielt direkt auf den
Default-Branch, aktiviert Auto-Merge oder maskiert Cleanup-/Publishing-Fehler.

Die gemeinsame App-Konfiguration verwendet
`vars.WORKFLOW_UPDATER_APP_CLIENT_ID` und
`secrets.WORKFLOW_UPDATER_APP_PRIVATE_KEY` nur dem Namen nach. Der
CPython- und Common-Version-Publisher fordern nur `Contents`- und `Pull
requests`-Write-Recht; der Workflow-Tool-Publisher fordert zusätzlich
`Workflows`-Write-Recht an, weil er Workflow-Dateien ändern darf. Der erzeugte
App-Draft-PR ist ein normaler PR und muss die üblichen Repository-PR-Checks und
menschliche Review vor jedem Merge bestehen; keiner dieser Workflows merged
oder aktiviert Auto-Merge.

### Common-Version-Draft-Publisher

Die Common-Version-Wartungsidentität ist fest auf Branch
`automation/update-framework-common-versions`, Titel
`chore(ci): update common.sh versions`, den Default-Branch des Repositories als
Base und `draft: true` festgelegt. Der Body enthält den Marker
`<!-- framework-common-version-updater -->`, englische und deutsche
Erklärungen, die validierten alten/neuen Variablenwerte und die validierte
Upstream-Quelle oder Release-Referenz pro geänderter Komponente. Er stellt
klar, dass kein Auto-Merge autorisiert ist. Bevor die App-Token-PR-Action einen
Branch ändern darf, akzeptiert ein read-only-GitHub-API-Check nur Zustand A
(kein Branch und kein offener passender PR) oder Zustand B (genau ein
same-repository-Draft-PR mit festem Head, Base, Titel, Marker und einem Diff
nur für `ci/lib/common.sh`). Jeder andere Zustand bricht fail-closed ab, ohne
einen Branch oder PR zu löschen oder zu überschreiben. Auch ein Fortschreiten
des vertrauenswürdigen Default-Branches während der Publisher-Revalidierung
führt zum fail-closed-Abbruch.

Der Resolver verwendet den expliziten Modus
`--defer-reviewed-provenance` nur für diesen begrenzten Wartungsablauf; die
Standard-CLI des Checkers bleibt strikt. Sein `maintenance_outcome` ist genau
`no_updates`, `manual_review_only`, `safe_updates`,
`safe_updates_with_manual_review` oder das fail-closed-Ergebnis `fatal`.
`review_required` ist ausschließlich für die bereits expliziten atomaren
CRS- und ModSecurity-v3-Tag-plus-immutable-Commit-Pfade zulässig, nachdem ihr
festes Repository, Tag-Format, Immutable-Commit-Format und die lokalen
Bindings geprüft wurden. Dieser Status enthält nie einen automatischen
Update-Plan. `unknown`, `blocked`, `error`, fehlerhafte manuelle Metadaten,
Plan-Konflikte oder jede Variablenüberschneidung bleiben fatal; lokale
Policy-Werte ohne Updater-Vertrag bleiben `not_applicable`.

Bei `manual_review_only` gibt der Resolver `update_available=false` aus,
Validator und Publisher werden übersprungen, und der Ergebnis-Job schreibt
eine ausdrückliche englische/deutsche Zusammenfassung zur manuellen Prüfung.
Es werden kein Kandidat, Branch, Commit oder Pull Request erzeugt. Bei beiden
sicheren Update-Ergebnissen vergleichen Resolver, Validator und Publisher
unabhängig Outcome, Kandidat-SHA-256, Liste automatischer Variablen, Liste
manueller Komponenten und den Nachweis erhaltener manueller Pins. Der Publisher
darf nur für diese beiden sicheren Ergebnisse laufen; sein Draft-PR-Body führt
getrennte Tabellen für automatische Änderungen und unveränderte manuelle
Provenance-Prüfungen. Der Ergebnis-Job akzeptiert keine andere
Ausgabekombination. Auch fehlende App-Konfiguration nach einem verfügbaren
Update führt klar zum Abbruch und wird nicht als fehlendes Update behandelt.
Ein mit dem App-Token erzeugter PR soll normale Pull-Request-Events auslösen;
deshalb müssen Required Checks, Workflow-/Action-Pin-Checks, Python- und
ShellCheck-Qualität, Common-Version-Provenance, Dokumentationsverträge sowie
scope-anwendbare SonarQube-/Branch-Protection-Checks am tatsächlichen PR-Head
beobachtet werden, bevor ein Mensch merged. Der Workflow selbst genehmigt,
merged oder aktiviert niemals Auto-Merge.

### Einheitlicher Scope der Common-Version-Wartung

`ci/tools/resolve-canonical-maintenance.py` ist der einzige read-only
Planungs-Entry-Point für geplante, `workflow_dispatch`-, vollständige und
komponentenbezogene Läufe. Jeder Aufruf löst die obligatorischen globalen
Scopes auf: go-ftw, Albedo, die kanonischen Python-/PyYAML-/Node-Pins, jede
kanonische Workflow-Action und alle CI-Security-Tool-Pins. Eine
`--component`-Angabe filtert ausschließlich zusätzliche Runtime-/Source-
Datensätze; sie entfernt niemals einen obligatorischen globalen Check. Das
Ergebnis ist ein deterministischer JSON-Plan mit typisierten sicheren Updates,
Manual-Review-Einträgen, Quell-/Kandidaten-Hashes und dem Status generierter
Views.

Der Plan prüft Runtime-Manifest/-Lock, Python-, Workflow- und CRS-Views
gemeinsam. Vor jedem Schreiben durch einen vertrauenswürdigen Publisher wird
er erneut validiert. Manual-Review-Issues werden ausschließlich durch einen
Default-Branch-Job mit eng begrenztem Issue-Schreibrecht und dem validierten
Plan abgeglichen; Resolver- und Pull-Request-Jobs bleiben read-only. Der
Publisher erstellt oder aktualisiert nur den festen Draft-PR und merged nie
oder aktiviert Auto-Merge. Ein fehlendes globales Ergebnis, eine unvollständige
CI-Pin-Gruppe, Drift generierter Views, ein fehlerhafter Review-Eintrag oder
ein Hash-Mismatch führt fail-closed zum Abbruch.

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
