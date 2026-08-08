# Change Record: Migration des Common-Version-Publishers auf ein GitHub-App-Token

**Sprache:** [English](20260808-02-migrate-common-version-publisher-app-token.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260808-02-migrate-common-version-publisher-app-token` |
| UTC-Datum | 2026-08-08 |
| Framework-Basisrevision | `da28e6da58fa8b1135d3631612a78e73ff98584b` |
| Issue oder Pull Request | Framework-PR [#65](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/65) zielt auf `master`. Dieser Record verfolgt seine Source-Finalisierung und autorisiert niemals einen Merge. |

## Motivation und Problemstellung

`check-common-versions.yml` löste bereits einen begrenzten `ci/lib/common.sh`-
Kandidaten auf und validierte ihn unabhängig, verwendete für den Publisher aber
den nativen GitHub-Token-Pfad. Dieser Pfad belegt weder die geforderte
repositorybegrenzte GitHub-App-Autorität noch die zuverlässige Auslösung
gewöhnlicher Pull-Request-Events. Der Hosted-Lauf `31254801083` zeigte
zusätzlich, dass die Kandidatenvalidierung vor der Publisher-Ausführung
abbricht, weil der direkt aufgerufene CRS-Provenance-Test seinen lokalen
Testhelfer nicht importieren konnte.

Während der Finalisierung von PR #65 zeigte die Prüfung außerdem, dass ein
Resolver-Ergebnis `unknown` wie ein harmloses fehlendes Update behandelt werden
konnte und kein abschließender Job den übersprungenen No-Update-Zustand bewies
oder eine operatorseitige Zusammenfassung veröffentlichte. Beide Bedingungen
erforderten einen Source-Fix, bevor der PR für die Delivery geeignet sein kann.

Der erste normale Source-Push beseitigte diese drei dokumentierten
Sonar-Befunde, doch die frische PR-Analyse meldete zwei neue offene
`python:S3776`-Befunde im selben statischen Security-Contract-Checker. Obwohl
das Sonar-Quality-Gate `OK` blieb, erfüllt das nicht die Null-Policy dieses
Tasks. Das Follow-up zerlegt deshalb ausschließlich die betroffenen
Validierungsfunktionen in begrenzte Helfer, ohne ihre geprüften Fehlermeldungen
oder fail-closed-Entscheidungen zu verändern.

## Betroffene Komponenten und Sicherheitsgrenzen

Diese reine Framework-Änderung umfasst den Common-Version-GitHub-Actions-
Publisher, seinen CI-Security-Contract und seine Mutation-Suite, die
Importgrenze des CRS-Provenance-Regressionstests, die Action-
Verwendungsmetadaten, die gepaarte Workflow-Security-Dokumentation und diesen
Record. Die Sicherheitsgrenze ist der Übergang von einem validierten
Default-Branch-Kandidaten zu einem eng begrenzten Draft-Pull-Request. Parent,
MRTS, Gitlinks, Runtime-Connectoren und ein Merge liegen außerhalb des Scopes.

## Akzeptanzkriterien

- Resolver und Validator bleiben credential-frei, `contents: read`, unabhängig
  und über einen exakten SHA-256-Kandidatendigest mit 64 Zeichen gebunden.
- Das native Publisher-Token bleibt `contents: read`; exakt ein gepinntes
  App-Token ist auf aktuellen Owner/Repository und nur `contents` sowie
  `pull-requests`: write begrenzt.
- Konfigurations-Gate, Zustandscheck, feste Wartungsidentität, Body-Marker und
  die Pfadbegrenzung `ci/lib/common.sh` brechen bei Abweichung fail-closed ab.
- Nur aktuelle update-berechtigte Quellen dürfen `update_available=false`
  erzeugen; Ergebnisse `unknown`, `blocked` und `error` schlagen vor einer
  No-Update-Entscheidung fehl. Ein credential-freier `always()`-Ergebnis-Job
  muss den Endzustand beweisen und das geprüfte englische/deutsche Ergebnis
  veröffentlichen.
- Es entstehen weder nativer-Token-, PAT-, SSH-, direkter-Default-Branch-Push-,
  Force-Push-, breites-Staging-, PR-Übernahme-, Merge- noch Auto-Merge-Pfade.
- Die erforderlichen Tests, gepaarte Dokumentation, Action-Pin-Contract,
  Change-Record-Contract und finale PR-Delivery-Evidenz werden wahrheitsgemäß
  festgehalten.

## Untersuchte Alternativen

Das native Token beizubehalten würde einen unzureichenden
Publishing-/Event-Grenzanspruch fortschreiben. PAT, Deploy-Key, langlebiges
Secret oder Runner-gesteuerter Push würden die Autorität erweitern. Eine neue
Implementierung mit eigenen Git-Pushes war nicht erforderlich, weil die
vorhandene, full-SHA-gepinnte `peter-evans/create-pull-request`-Action das
begrenzte App-Token nach einem fail-closed-Zustandscheck nutzen kann. Alle
Alternativen mit direktem `master`-Update, Token-Fallback oder künstlichem
Kandidaten wurden verworfen.

## Implementierungsentscheidung

Der Publisher validiert den Kandidaten auf der vertrauenswürdigen
Default-Revision erneut, prüft SHA-256 und exakten Diff, bewahrt die validierte
JSON-/Markdown-Ausgabe und erzeugt daraus ausschließlich einen englischen/
deutschen Draft-Body. Bei einem verfügbaren Update stoppt er mit einer klaren
Konfigurationsfehlermeldung, wenn `WORKFLOW_UPDATER_APP_CLIENT_ID` oder
`WORKFLOW_UPDATER_APP_PRIVATE_KEY` nicht verfügbar ist. Das Konfigurations-Gate
leitet nur einen nicht sensiblen Boolean ab, weil GitHub Actions keine direkte
Secret-Referenz in `if:` unterstützt. Der Private-Key-Wert wird nur an die
gepinnte App-Token-Action gegeben; das kurzlebige Ergebnis-
Token geht nur an einen read-only-GitHub-API-Zustandscheck und die gepinnte
Pull-Request-Action. Zustand A enthält keinen Branch und keinen offenen
passenden PR; Zustand B enthält exakt einen gleichnamigen, korrekt
identifizierten Same-Repository-Draft-PR, dessen Diff nur
`ci/lib/common.sh` betrifft. Jeder andere Zustand bricht fail-closed ab. Die
SHA der vertrauenswürdigen Default-Revision erreicht `github-script` über eine
benannte Action-Umgebungsvariable statt durch Template-Interpolation in
JavaScript.

Der Resolver markiert nun bewusst erfasste lokale Policy-Einträge ohne
automatisierten Updater-Vertrag als `not_applicable`, während `unknown`,
`blocked` und `error` fail-closed bleiben. Sein abschließender Ergebnis-Job
prüft immer die tatsächlichen Job-Ergebnisse. Er erlaubt `false` nur nach einem
erfolgreichen Resolver und übersprungenen Kandidaten-/Publisher-Jobs, gibt die
exakte zweisprachige No-Update-Zusammenfassung aus und erlaubt `true` nur nach
erfolgreichen drei Vorgängerjobs. Das Update-Ergebnis meldet URL oder Nummer des
begrenzten Draft-PR mit einem sachlichen Fallback, wenn die Action keines der
beiden Ergebnisse liefert; jeder andere Zustand schlägt fehl.

## Geänderte Dateien und Tests

- `.github/workflows/check-common-versions.yml` verwendet das eingeschränkte
  App-Token, Zustandscheck, feste Draft-Identität, validierten Body,
  Default-Branch-Drift-Prüfung und einen credential-freien Ergebnis-Job.
- `ci/checks/security/check-ci-security-contract.py` definiert ein exaktes
  Common-Version-Publisher-/Ergebnis-Profil und weist nativen Token-/Permission-/
  Scope-, Zustands-, Pfad-, SHA-, Write-Pfad- und Endzustandsdrift zurück. Seine
  Publisher-Step- und Ergebnis-Job-Prüfungen sind in begrenzte Helfer zerlegt,
  um die zwei aktuellen Sonar-Befunde zur kognitiven Komplexität ohne
  Abschwächung des Vertrags zu beheben.
- `ci/tools/check-common-versions.py` schlägt bei `unknown` fail-closed fehl
  und unterscheidet bewusst nicht aktualisierbare lokale Policy-Einträge von
  unsicheren Upstream-Auflösungsfehlern.
- `tests/ci_security/test_ci_security_contract.py` mutation-testet App-Token,
  Konfigurationsnamen, Berechtigungen, Repository-/Owner-Scope, Branch, Draft,
  Marker, Staging, direkte/Force-Pushes, SHA-Bindung, Artefaktwiederverwendung,
  Publisher-Gate, PR-Übernahme-Bypässe und führt Endzustände sowie
  zweisprachige Zusammenfassungen direkt aus.
- `tests/security_regression/test_common_versions_sonar_provenance.py` beweist,
  dass unbekannte Provenance fail-closed fehlschlägt, während nicht
  aktualisierbare lokale Policy keinen falschen Fehler erzeugt.
- `tests/security_regression/test_crs_git_ref_provenance.py` macht seinen
  lokalen Provenance-Helper importierbar, wenn der Test per vollqualifiziertem
  Modulnamen aufgerufen wird.
- `ci/tooling/security-tools.lock.yml` hält die zusätzliche Verwendung der
  bereits gepinnten App-Token-Action fest; keine Action-Version ändert sich.
- `docs/github-actions-workflow-security.md` und die deutsche Begleitdatei
  dokumentieren App-Token-Vertrag, No-Update-/Konfigurationsverhalten, festen
  Draft-Zustand und die Erwartung normaler PR-Checks.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk proxy gh run view 31254801083 --log` | 0 | Resolver bestand; Kandidatenvalidierung scheiterte mit `ModuleNotFoundError: git_provenance_test_support`; Publisher wurde übersprungen. | [Lauf #14](https://github.com/Easton97-Jens/ModSecurity-test-Framework/actions/runs/31254801083) |
| `make test-ci-security-contract` | 0 | 138 CI-Security-, Change-Record-, Evidence-, Updater- und Security-Contract-Tests bestanden, einschließlich direkter Terminal-Ergebnis-Ausführung. | Task-eigener externer Framework-Worktree |
| `make test-workflow-action-pins` | 0 | 25 Action-Pin-Regressionstests bestanden. | Derselbe Task-Worktree |
| `make test-workflow-security-contract` | 0 | 7 Workflow-Security-Contract-Tests bestanden. | Derselbe Task-Worktree |
| `make check-github-actions-workflows` | 0 | Python-Version-, Pin- und Permission-Prüfungen akzeptierten jeden eingecheckten Workflow. | Derselbe Task-Worktree |
| `make check-documentation` | 0 | Links, zweisprachige Parität, Pfadreferenzen und der Change-Record-Contract bestanden. | Derselbe Task-Worktree |
| `make lint` | 0 | Die vollständige lokale Lint- und Regressionsmatrix bestand, einschließlich Workflow-Security- und Provenance-Suites. | Derselbe Task-Worktree |
| SonarCloud-PR-#65-Analyse bei `0ba1e39d64baaa34cb9f2ae51b875609749f724e` | 0 | Quality-Gate `OK` und keine offenen Hotspots, aber zwei neue OFFENE `python:S3776`-Befunde blieben; dies ist die Ursache des aktuellen begrenzten Follow-ups, kein Erfolg der Null-Policy. | [PR-Analyse](https://sonarcloud.io/dashboard?id=Easton97-Jens_ModSecurity-test-Framework&pullRequest=65) |
| `<locked-tools>/actionlint -shellcheck=<locked-tools>/shellcheck` | 0 | Alle eingecheckten Workflows und eingebetteten Shell-Blöcke bestanden. | SHA-256-gesperrte lokale Tools |
| `<locked-tools>/zizmor --offline .github` | 0 | Keine Findings; 33 repository-konfigurierte Suppressions wurden gemeldet. | SHA-256-gesperrtes lokales Tool |
| `<locked-tools>/ruff check …` und `ruff format --check …` | 0 | Ruff-Lint und Formatprüfungen akzeptierten den relevanten CI-Security-Scope (20 Dateien). | SHA-256-gesperrtes lokales Tool |
| Fokussierter `unittest`-Updater-/NGINX-/CRS-Modulverbund | 0 | 37 Tests bestanden; die fokussierte Common-Version-Provenance-/Terminal-State-Suite bestand ebenfalls. | Derselbe Task-Worktree |
| `check-common-versions.py --check --json --timeout 10` | 2 | Korrektes fail-closed-Preflight: ein ModSecurity-v3-Release erfordert getrennte Immutable-Provenance-Review und ein neueres HAProxy-Tupel ist verfügbar; keine Datei wurde geändert. | Task-eigener externer Framework-Worktree |
| `git diff --check` | 0 | Keine Whitespace-Fehler im finalen uncommitted Review. | Derselbe Task-Worktree |

## Sicherheitsauswirkung

Dies ist eine CI-Autoritäts-Härtung und eine CI-Validierungsreparatur. Der
ursprüngliche Native-Token-Publisherpfad wird strukturell zurückgewiesen,
während der legitime Kontrollfall ein Default-Branch-Kandidat mit passender
SHA-256, sicherer App-Konfiguration, zulässigem Zustand A/B und genau einem
erlaubten geänderten Pfad bleibt. Die Alternativ-Bypass-Mutationen decken
Token-Fallback, App-Scope-/Permission-Drift, Private-Key-Namensdrift,
Branch-/PR-Hijacking, breites Staging, direkte und Force-Pushes, kurzen oder
fehlenden Digest, Resolver-Artefaktwiederverwendung und ein nicht
vertrauenswürdiges Publisher-Gate ab. Es wird kein Credentialwert festgehalten.

## Dokumentation und Runtime-Evidenz

Die englische/deutsche Workflow-Security-Paarung ist aktualisiert. Keine
Connector- oder MRTS-Runtime war erforderlich. Lauf #14 ist Hosted-
Fehlerevidenz für den Testimportdefekt, aber kein Nachweis für den App-
Publisher: Sein Publisher wurde korrekt übersprungen. Die Repository-
Metadatenprüfung bestätigte die erforderlichen App-Variablen- und
App-Secret-Namen, ohne einen der Werte zu lesen. Das Standard-CLI-OAuth-
Credential kann App-Installationsmetadaten nicht über den App-JWT-Endpunkt
belegen; Installation und effektive App-Berechtigungen bleiben daher
unverifiziert, bis ein echter Post-Merge-Publisher-Lauf das begrenzte Token
erzeugt und verwendet. Dieser Lauf muss reale Upstream-Ergebnisse statt eines
fabrizierten Kandidaten verwenden.

Ein schreibfreies Resolver-Preflight gab korrekt Exit-Code 2 statt eines
falschen No-Update-Ergebnisses zurück: ModSecurity v3 hat nun ein neueres
Release, dessen Tag und unveränderlicher Commit getrennte Provenance-Review
erfordern, und HAProxy hat ein neueres offizielles Tarball-/Checksum-Tupel.
Das ist Source-Control-Evidenz für fail-closed-Verhalten, kein App-Publisher-
End-to-End-Ergebnis und keine Autorisierung, einen der Pins in diesem PR zu
aktualisieren.

## Nicht ausgeführte Prüfungen

Die für das hash-gesperrte Pyright-Paket erforderliche repository-lokale
Node-Runtime ist nicht vorhanden (`node` und `nodejs` fehlen); Pyright bleibt
daher blockiert und wird nicht global installiert. Exact-Head-Hosted-Check-
und Sonar-Evidenz für PR #65 werden in seinem GitHub-Check-Set und in
secret-freier Task-Lifecycle-Evidenz festgehalten. Sie darf einen kontrollierten
Merge nur nach frischer Bestätigung für den dann aktuellen Head stützen;
Post-Merge-App-Publisher-Evidenz bleibt ausstehend. Keine nicht verfügbare oder
nicht ausgeführte Prüfung wird als bestanden dargestellt.

## Einschränkungen und Restrisiko

Die erforderlichen App-Konfigurationsnamen sind vorhanden, aber Installation
und effektive Berechtigungen sind noch nicht durch einen erfolgreichen
kurzlebigen Token-Mint belegt. Das normale Event-/Check-Verhalten eines vom
App-Token erzeugten Draft-PRs bleibt unbeobachtet, bis der Source-Fix-PR mit
aktueller Autorisierung gemergt ist. Das aktuelle Resolver-Preflight schlägt
für die getrennte ModSecurity-v3-Provenance-Entscheidung fail-closed fehl; es
darf nicht als No-Update dargestellt werden. Eine HAProxy-
Versionsaktualisierung muss, falls sie später verfolgt wird, über einen
separaten automatisch erzeugten, begrenzten Draft-PR erfolgen und ist keine
Änderung von `ci/lib/common.sh` in PR #65. Der Zustandscheck reduziert
Branch-/PR-Übernahme- und Default-Branch-Drift-Risiko, autorisiert aber weder
einen Branch-Protection-Bypass noch eine Änderung außerhalb von
`ci/lib/common.sh`.

## Finaler Diff- und Review-Status

Der Source-Fix-Worktree ist auf
`fix/common-version-draft-publisher-app-token` isoliert; keine Änderung von
Framework `master`, Parent, MRTS oder Gitlink ist autorisiert. Der finale
Source-Review umfasst ein sauberes `git diff --check`, exakte statische
Publisher-/Ergebnis-Profile, keinen nativen Token-Fallback, keinen `workflows`-
Write-Request, keinen direkten/Force-Push und keinen ungeprüften App-Token-
Consumer. Der frühere Source-Head
`d3321ccd0d88049a35a5be0b5f2ae0fdf530c701` bestand die frischen anwendbaren
Hosted-Gates einschließlich SonarCloud Quality Gate `OK` mit 0 offenen
Befunden und 0 offenen Hotspots; jeder spätere Dokumentations-Commit benötigt
seine eigene Exact-Head-Gate-Runde. Unter der aktuellen Nutzerautorisierung ist
ein kontrollierter Merge ohne Admin- oder Auto-Merge nur nach diesen frischen
Gates für den dann aktuellen Head zulässig. Diese Autorisierung deckt nur die
geprüfte Publisher-Härtung ab und autorisiert keine Versions- oder
Provenance-Änderung in `ci/lib/common.sh`.

Die ModSecurity-v3-Provenance-Entscheidung bleibt getrennt. Jede HAProxy-
Versionsaktualisierung erfordert, falls sie verfolgt wird, einen separaten
automatisch erzeugten Draft-PR. `FND-FRAMEWORK-0059` kann erst nach Merge und
der Source-Regression auf dem resultierenden `master` als `verified` gelten;
`FND-FRAMEWORK-0060` bleibt `fixed`, solange kein reales Publisher-Update-E2E
es verifiziert. Keines der Findings wird durch die Gates von PR #65 geschlossen.
