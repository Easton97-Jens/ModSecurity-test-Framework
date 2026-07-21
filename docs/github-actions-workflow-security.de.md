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
Dependency-Manifest-Blobs. Der ausgecheckte Framework-Quellcode und der
Scanner-Helper stammen damit aus der Basisrevision und nicht aus PR-Head-
Dateien. Kein PR-Checkout aktiviert Submodule. Die separat
dokumentierte CI-Security-Suite besitzt begrenzte OSV-/Scorecard-
Artefaktausnahmen; ihr einziger SARIF-/CodeQL-Upload ist der vertrauenswürdige Nicht-PR-Job in
`ci-security-codeql.yml`. Sein read-only-Pendant
`ci-security-codeql-pr.yml` analysiert PR-Heads ohne Upload oder Write-
Berechtigung. Durch diese Härtung wurde kein solches Verhalten entfernt.

| Workflow | Trigger | Externe Actions | Effektive Berechtigungen | Vertrauensentscheidung |
| --- | --- | --- | --- | --- |
| `check-action-versions.yml` | `workflow_dispatch`, gefilterter `pull_request` | `actions/checkout` | `contents: read` | PR-Quellcode ist nicht vertrauenswürdig; er läuft nur lesend und ohne persistierte Checkout-Credentials. |
| `check-common-versions.yml` | `workflow_dispatch`, Zeitplan | `actions/checkout`, `actions/setup-python` | Workflow und Checker-Job jeweils `contents: read` | Geplanter/manueller Workflow vertrauenswürdiger Maintainer; er prüft und ShellCheckt eine unter runner-temporärem Speicher kopierte Kandidatendatei, hat absichtlich keinen Publisher und kann keinen PR-Branch erstellen, aktualisieren, mergen, force-pushen oder löschen. |
| `update-workflow-tools.yml` | `workflow_dispatch`, Zeitplan | `actions/checkout`, `actions/setup-python`, `actions/github-script` | Workflow-Standard `contents: read`; nur der Publisher-Job hat `contents: write`, `pull-requests: write` | Resolver und Validator sind tokenfrei/nur lesend; der Publisher erstellt nur einen passenden Draft-Wartungs-PR oder verwendet genau diesen wieder und force-pusht nie. |
| `cleanup-artifacts.yml` | `workflow_dispatch`, Zeitplan | `actions/github-script` | Workflow-Standard `contents: read`; Cleanup-Job effektiv `actions: write` | Geplanter/manueller Workflow vertrauenswürdiger Maintainer; sein Job kann nur Repository-Artefakte löschen. |
| `lint.yml` | `push`, `pull_request` | `actions/checkout` | `contents: read` | PR-Quellcode und seine Entwicklungsabhängigkeiten sind nicht vertrauenswürdig; weder Write-Berechtigung, Secret, persistierte Credentials noch Submodule sind konfiguriert. |
| `test-common.yml` | `push`, `pull_request` | `actions/checkout` | `contents: read` | PR-Quellcode ist nicht vertrauenswürdig; weder Write-Berechtigung, Secret, persistierte Credentials noch Submodule sind konfiguriert. |
| `ci-security-osv.yml` | begrenztes `pull_request`, Zeitplan, manuell | `actions/checkout`, `actions/setup-python`, `actions/upload-artifact` | `contents: read` | Der nicht privilegierte PR-Job führt nur die vertrauenswürdige Basisrevision aus, verifiziert ein geholtes PR-Objekt und behandelt zwei Manifest-Blobs als Daten statt als ausgecheckten Code. |

## Unveränderliche Action-Provenienz

Jede Remote-Action muss einen 40-stelligen Commit-SHA in Kleinbuchstaben und
einen benachbarten validierten Release-Versionskommentar verwenden. Die derzeit
zugelassenen Upstreams, Releases und Commit-Identitäten sind:

| Action | Offizieller Upstream | Release | Commit-SHA | Lizenz | Notwendige Verwendung |
| --- | --- | --- | --- | --- | --- |
| `actions/checkout` | [actions/checkout](https://github.com/actions/checkout) | `v7.0.1` | `3d3c42e5aac5ba805825da76410c181273ba90b1` | MIT | Checkt den Framework-Quellcode für Validierung oder Wartung aus. |
| `actions/setup-python` | [actions/setup-python](https://github.com/actions/setup-python) | `v7.0.0` | `5fda3b95a4ea91299a34e894583c3862153e4b97` | MIT | Wählt Python für die eingeschränkten Wartungs-Updater aus. |
| `actions/github-script` | [actions/github-script](https://github.com/actions/github-script) | `v9.0.0` | `3a2844b7e9c422d3c10d287c895573f7108da1b3` | MIT | Prüft oder erstellt den eingeschränkten Draft-PR des Workflow-/Tool-Updaters und ruft die GitHub-Actions-Artifact-API für die Bereinigungsaufbewahrung auf. |

Der Vertrag weist Tags, Branches, verkürzte oder Großbuchstaben-SHAs,
dynamische Referenzen, Docker-Referenzen, fehlerhafte oder Block-Scalar-
`uses:`-Werte, YAML-Flow-Collections, explizite Mapping-Keys, YAML-Tags/Anker/
Aliase/Merge-Keys in Key- oder Value-Position, escapte doppelt zitierte
Mapping-Keys, YAML-Dokumentmarker (auch nach einem UTF-8-BOM) und einen
fehlenden Release-Kommentar zurück. Lokale `./`-Actions sind keine Remote-
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
zweckspezifische Berechtigungszuordnung ersetzen. `check-common-versions`
bleibt read-only: Er validiert einen temporären Runner-Kandidaten und hat
absichtlich keinen Publisher. Nur der Publisher von
`update-workflow-tools` benötigt Repository-Content- und Pull-Request-Write-
Rechte zum Erstellen seines eingeschränkten Wartungs-Draft-PRs;
`cleanup-artifacts` benötigt nur `actions: write`, um Artefakte zu löschen;
der vertrauenswürdige Nicht-PR-CodeQL-Upload-Job benötigt
`security-events: write`. Kein PR-ausgelöster Job darf eine Write-Berechtigung
vergeben.

Jede direkte Verwendung von `actions/checkout` setzt:

```yaml
with:
  persist-credentials: false
```

Der Common-Version-Checker erhält keinen GitHub-Token, kopiert `common.sh` vor
dem Kandidaten-Update in temporären Runner-Speicher und besitzt keinen Branch-
oder Pull-Request-Publisher. Der Workflow-/Tool-Updater trennt öffentliche
Auflösung, Kandidatenvalidierung und Veröffentlichung in drei Jobs: Resolver
und Validator behalten `contents: read`, erhalten keinen Publishing-Token und
ändern den Checkout nicht. Der Publisher löst den
Kandidaten erneut auf, akzeptiert nur den festen Branch
`automation/update-framework-workflow-tools`, scheitert bei einem vorhandenen
nicht passenden oder nicht-Draft-PR und beschränkt seinen Token auf kleine
Publisher-Schritte. Er prüft geänderte Release-Assets über den bestehenden
prüfsummensicheren Downloader ohne sie auszuführen; ein abgeschlossener
Redirect darf nur auf `github.com`, `objects.githubusercontent.com` oder
`release-assets.githubusercontent.com` enden, und SHA-256 wird vor dem
Entpacken geprüft. Der Validator wendet jeden Kandidaten ausschließlich in
einer begrenzten Runner-Temporärkopie an, um die resultierenden Contracts erneut
zu prüfen. Ein wiederverwendeter Branch muss bytegenau dem vertrauenswürdigen
Basisbaum entsprechen, nachdem der eingeschränkte Updater seinen verifizierten
Kandidaten erzeugt hat. Der Publisher ändert ausschließlich eine feste
Dateiallowlist, verwendet einen normalen Push und erstellt nur einen Draft-PR.
Workflow- und Job-Level-Umgebungen dürfen `github.token` unter keinem
Variablennamen bereitstellen, auch nicht als `GITHUB_TOKEN`. GitHub-
Berechtigungen sind Job- und nicht Schritt-spezifisch: Das Einengen einer
Umgebungsvariable reduziert die direkte Shell-Exposition, verwandelt einen
vertrauenswürdigen Job mit Write-Rechten aber nicht in eine Schritt-
Berechtigungsgrenze. Daher ist dieser Job auf geplante oder manuelle Trigger
vertrauenswürdiger Maintainer begrenzt und enthält kein PR-Event. Der
Repository-Contract parst diesen exakten Triggersatz und das Publisher-
Schrittprofil und bindet jeden Publisher-`run`- und `github-script`-Body an
SHA-256; Kommentare, Aliase, zusätzliche Befehle oder Änderungen an der
Draft-/Branch-Prüfung scheitern daher geschlossen.

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
make test-workflow-security-contract
```

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

Der geplante/manuelle Workflow `update-workflow-tools.yml` kann einen
reviewbaren Kandidaten vorbereiten, ist aber absichtlich weder ein
Freigabe- noch ein Merge-Mechanismus. Er verwendet ausschließlich die vom
bestehenden Lock implizierten offiziellen GitHub-Release-/Git-APIs, prüft die
Release-Tag-zu-Commit-Identität und verlangt den veröffentlichten SHA-256 des
offiziellen Release-Assets, bevor sich ein heruntergeladenes Tool-Record ändern
kann. Release-Asset-Redirects sind auf die dokumentierte offizielle
Host-Allowlist beschränkt, und der Digest wird vor dem Entpacken geprüft. Ein
fehlgeschlagener Lookup, Digest-, Branch-, aus der Basis abgeleiteter
Branch-Inhalt-, PR-Form-, Lock-Digest- oder Allowlist-Check stoppt die
Veröffentlichung.

## Einschränkungen und betriebliche Erwartungen

Dieser Vertrag ist ein Repository-Control und kein Ersatz für GitHub-
Branch-Protection, Workflow-Review, Action-Provenienz-Review, actionlint,
zizmor, CodeQL, Scorecard oder SonarQube Cloud. Diese Controls müssen am
tatsächlichen Pull-Request-Head bewertet werden. Tool-Verfügbarkeit wird im
Change Record wahrheitsgemäß festgehalten; ein lokal nicht verfügbares Tool
gilt nicht als bestandene Prüfung.

Wenn ein künftiger Workflow die dokumentierte Artefakt-/SARIF-Ausnahme ändert,
Artefakte über eine Vertrauensgrenze hinweg konsumiert, OIDC nutzt, einen
wiederverwendbaren Workflow aufruft oder eine neue Write-Berechtigung benötigt,
müssen Checker, Fixtures, Inventar und Change Record erweitert werden, bevor
sich auf das neue Verhalten verlassen wird.
