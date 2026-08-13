# Change Record: 20260812-01-add-atomic-common-version-provenance-resolver

**Sprache:** Deutsch | [English](20260812-01-add-atomic-common-version-provenance-resolver.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260812-01-add-atomic-common-version-provenance-resolver` |
| UTC-Datum | 2026-08-12 |
| Framework-Basisrevision | `209389022c942d83113f6be88bf31d25637352f0` |
| Issue oder Pull Request | Der Draft-[PR #76](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/76) ist offen und zielt von `agent/common-version-atomic-provenance` auf `master`. Zum Zeitpunkt der erfassten Sonar-Evidenz lösten lokaler Checkout, `origin/agent/common-version-atomic-provenance` und PR-Head alle zu `fae3b81db491944a21395de80e3c928f82077143` auf. |

## Motivation und Problemstellung

Die bisherige Common-Version-Wartungslogik benötigte eine einzige prüfbare
Quelle der Wahrheit für jede erfasste externe Komponenten-Provenance-Eingabe.
Die Änderung führt einen datengetriebenen Resolver ein, der sichere
automatische Updates von Version, URL und Digest von Provenance-Entscheidungen
mit notwendiger Prüfung und von Metadaten unterscheiden kann, die nie zu einer
Updater-Eingabe werden dürfen.

## Betroffene Komponenten und Sicherheitsgrenzen

Die reine Framework-Änderung betrifft `ci/lib/common.sh`,
`ci/tools/check-common-versions.py`, ihren Workflow und Regression-/Security-
Checks sowie die gepaarte Variablenreferenz. Die Grenze beginnt bei offiziellen
Upstream-Metadaten für Release, Listing, Prüfsumme und Git-Tag und endet bei
einem validierten atomaren Kandidaten für `ci/lib/common.sh`. Der Resolver
weist unerwartete URL-Redirects, nicht zugewiesene oder mehrfach besessene
Provenance-Variablen und unsichere Update-Zustände ab. Parent, MRTS, Gitlinks,
Connector-Runtime-Verhalten und Produktions-Deployment liegen außerhalb dieser
Änderung.

## Akzeptanzkriterien

1. Eine Komponenten-Registry deklariert Eigentümer, Resolver-Strategie,
   offizielle Quelle, Update-Policy, Prüfsummenstrategie und atomare
   Update-Gruppe jeder Provenance-Variablen.
2. Automatische Komponenten aktualisieren ihre voneinander abhängigen Werte
   für Version, URL, Asset und SHA-256 als eine validierte Gruppe.
3. CRS und ModSecurity v3 bleiben manuelle Prüfentscheidungen auf Basis
   stabiler Tag- und unveränderlicher aufgelöster Commit-Provenance.
4. Lokale oder nicht zur Beschaffung gehörende Metadaten sind explizit
   `not_applicable`.
5. Exakte Komponenten-Auswahl und Registry-Auflistung sind für CLI und
   optionale manuelle Workflow-Dispatch verfügbar.
6. Englische und deutsche Dokumentation beschreiben denselben Vertrag, ohne
   ein nicht beobachtetes Delivery-Ergebnis zu behaupten.

## Untersuchte Alternativen

- Komponenten-Resolver-Policy in unabhängigen Funktionen zu pflegen wurde
  verworfen, weil Ownership-, Kompatibilitäts- und Atomaritätsregeln driften
  könnten.
- Jede erfasste Variable automatisch erneuerbar zu behandeln wurde verworfen,
  weil geprüfte Tag/Commit-Pins und lokale Hinweise unterschiedliche
  Vertrauensgrenzen haben.
- Eine Version getrennt von abgeleiteten URLs oder Digests zu aktualisieren
  wurde verworfen, weil dies ein inkonsistentes Provenance-Tupel erzeugen kann.

## Implementierungsentscheidung

`COMPONENT_DEFINITIONS` zentralisiert die Komponentenverträge und verteilt auf
kleine strategie-spezifische Resolver. Der Resolver unterscheidet Datensätze
`automatic`, `manual_review` und `not_applicable`, erhält geprüfte Pins und
bricht bei `unknown`, `blocked` und `error` fail-closed ab. Automatische
Änderungen werden als atomare Gruppen gerendert und validiert, einschließlich
dynamischer URLs, die aus der aktualisierten Version abgeleitet werden.
`--list-components` legt exakte Registry-Namen offen; wiederholte exakte
Optionen `--component` begrenzen die Auflösung. Der geplante Workflow löst alle
Datensätze auf, sofern seine optionale `workflow_dispatch`-Eingabe `component`
nicht genau einen Datensatz auswählt.

### APR-util-Inherited-Provenance-Follow-up

Der sourcebare APR-util-Shell-Guard unterscheidet nun ein von einem früheren
Source exportiertes geprüftes Tupel von einem ungeprüften Environment-Override.
Er erfasst sowohl Präsenz als auch Pre-Assignment-Wert unter internen
`CI_APR_UTIL_*`-Namen, setzt diesen Zustand bei jedem Source zurück und
reassertet anschließend das resolver-sichtbare kanonische Tupel vor der
Expected-URL-Ableitung. Nur keine geerbten APR-util-Felder oder alle vier
exakten kanonischen Felder werden akzeptiert. Leere, partielle, geänderte,
fehlerhafte und vollständig self-consistent alternative Tupel scheitern
fail-closed mit Exit `77`, bevor der Apache-Preparer einen Download- oder
Archivbefehl erreicht. Die vier öffentlichen Provenance-Felder und die
resolver-verwaltete Literal-/Derived-Struktur bleiben unverändert; kein
`APR_UTIL_PINNED_*`, `readonly`, `eval` oder Bash-only-Verhalten wurde ergänzt.

## Geänderte Dateien und Tests

- `ci/lib/common.sh` enthält die vom Resolver verwendeten erfassten
  Provenance-Standards und den APR-util-Inherited-State-Guard.
- `tests/security_regression/test_apr_util_provenance.py` ergänzt Repeat-
  Source-, exaktes-Inherited-Child-Tuple-, Post-Source-Mutation-, coherent-
  replacement- und Fake-Tool-before-network-Regression-Coverage.
- `ci/tools/check-common-versions.py` enthält Komponenten-Registry,
  Resolver-Dispatch, atomare Kandidatenbehandlung und den CLI-Auswahlvertrag.
- `.github/workflows/check-common-versions.yml` übergibt die optionale
  manuelle Komponenten-Auswahl durch den Resolver-Workflow.
- CI-Security- und Provenance-Regression-Dateien decken den geänderten Vertrag
  ab.
- `docs/reference/variables.md` und `docs/reference/variables.de.md`
  dokumentieren Registry, Policies, Strategien offizieller Quellen, atomare
  URLs, CLI und Workflow-Auswahl.
- Dieser gepaarte Record bewahrt die Framework-eigene Entscheidung und den
  aktuellen Validierungsstatus.
- Zum Zeitpunkt der erfassten Sonar-Evidenz enthielt die veröffentlichte PR-Historie
  `e23152be008c52ecc5b5e8bcc6c7357d7a083408` (`Add atomic common-version
  provenance resolver`) und
  `581e1cb2a5f971e5a5b0d83ef2b63ce4f3923795` (`Format CI security contract
  updates`), gefolgt von
  `ba348a7c28b13edcdc253aef7389c89b8285b241` (`Resolve Sonar code smells in
  provenance resolver`) und dem damals aktuellen exakten Head
  `fae3b81db491944a21395de80e3c928f82077143` (`Reduce release URL validation
  complexity`). Die beiden letzten Commits bilden die verhaltensbewahrende
  Sonar-Remediation; ihre lokale Validierung bestand.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | ---: | --- | --- |
| `git diff --check -- docs/reference/variables.md docs/reference/variables.de.md` | 0 | Keine Whitespace-Fehler in der gepaarten Resolver-Referenzaktualisierung. | Framework-Working-Tree |
| `make check-documentation` | 0 | Dokumentationslinks, Variablendokumentation, Repository-Pfade und Change-Record-Vertrag bestanden vor dem Hinzufügen dieses Record-Paars. | Framework-Working-Tree |
| `git diff --check -- reports/audits/change-records/20260812-01-add-atomic-common-version-provenance-resolver.md reports/audits/change-records/20260812-01-add-atomic-common-version-provenance-resolver.de.md` | 0 | Keine Whitespace-Fehler im gepaarten Change Record. | Framework-Working-Tree |
| `make check-documentation` | 0 | Dokumentationslinks, Variablendokumentation, Repository-Pfade und der finale Change-Record-Vertrag bestanden mit diesem Record-Paar. | Framework-Working-Tree |
| `gh pr view 76 --json number,url,state,isDraft,headRefName,headRefOid,baseRefName,commits,reviewDecision,mergeStateStatus` | 0 | Draft-PR #76 auf `agent/common-version-atomic-provenance`, Ziel `master`, mit damals aktuellem PR-Head `fae3b81db491944a21395de80e3c928f82077143` und den vier oben genannten veröffentlichten Commits beobachtet. | [PR #76](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/76) |
| Lokale Suiten `test_common_versions_sonar_provenance` + `test_common_version_atomic_provenance` | 0 | 44 verhaltensbewahrende Sonar-Remediation-Tests bestanden in `749.688s`. | Framework-Working-Tree |
| Direkte Suite `test_common_version_atomic_provenance` | 0 | 15 atomare Provenance-Tests bestanden. | Framework-Working-Tree |
| `make test-ci-security-contract` | 0 | 173 CI-Security-Contract-Tests bestanden in `54.902s`. | Framework-Working-Tree |
| Lokale `py_compile`-Validierung | 0 | Geänderter Python-Validierungscode wurde erfolgreich kompiliert. | Framework-Working-Tree |
| `make check-documentation` | 0 | Dokumentationsvalidierung bestand nach der lokalen Sonar-Remediation-Validierung. | Framework-Working-Tree |
| `git diff --check` | 0 | Der lokale Remediation-Diff hatte keine Whitespace-Fehler. | Framework-Working-Tree |
| Exact-Head-`SonarCloud Code Analysis` für PR #76 | success | Abgeschlossen um `2026-08-12T20:31:29Z`. | [PR-#76-SonarCloud-Analyse](https://sonarcloud.io/dashboard?id=Easton97-Jens_ModSecurity-test-Framework&pullRequest=76) |
| SonarQube-Cloud-Bot-Kommentar zu PR #76 | beobachtet | Um `2026-08-12T20:31:32Z` meldete er Quality Gate passed, `0 New issues`, `0 Accepted issues` und `0 Security Hotspots`. | [PR-#76-Kommentar](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/76#issuecomment-5272463046) |
| SonarQube-Cloud-API-Issue-Suche für PR #76 | 0 | Die begrenzte PR-Abfrage lieferte insgesamt `0`; dies behauptet nichts über nicht zugehörige Projekt- oder künftige Head-Issues. | PR-#76-Exact-Head-Evidenz |
| `sh -n ci/lib/common.sh ci/provisioning/prepare-apache-build.sh` | 0 | Aktualisierter sourcebarer Guard und Apache-Preparer besitzen gültige Shell-Syntax. | Task-eigene lokale Validierungswurzel |
| `python3 -m unittest tests.security_regression.test_apr_util_provenance -v` | 0 | 13 APR-util-Inheritance-/Provenance-Tests bestanden in `1.755s`. | Task-eigene lokale Validierungswurzel |
| `python3 -m py_compile ci/tools/check-common-versions.py` | 0 | Common-Version-Checker kompiliert. | Task-eigene lokale Validierungswurzel |
| Atomare, Common-Version-Provenance-, NGINX- und PCRE2-fokussierte Suiten | 0 | 15 atomare, 29 Common-Version-, 4 NGINX- und 3 PCRE2-Tests bestanden; die Common-Version-Suite endete in `735.288s`. | Task-eigene lokale Validierungswurzel |
| `make test-ci-security-contract` | 0 | 173 CI-Security-Tests bestanden in `53.682s`. | Task-eigene lokale Validierungswurzel |
| `make check-documentation` | 0 | Dokumentation und Change-Record-Vertrag bestanden vor diesem Follow-up-Record-Edit. | Task-eigene lokale Validierungswurzel |
| `shellcheck -x ci/lib/common.sh ci/checks/catalog/check-common-helpers.sh` | 0 | Kein ShellCheck-Finding. | Task-eigene lokale Validierungswurzel |
| `make lint` | 0 | Finales vollständiges lokales Aggregat bestand nach dem initialen APR-util-Record-Edit, einschließlich seiner Dokumentations- und `git diff --check`-Stufen. | Task-eigene lokale Validierungswurzel |

## Sicherheitsauswirkung

Dies betrifft die Provenance- und CI-Wartungsgrenze. Es stärkt die Abbildung
von offiziellen Metadaten zu Kandidatenwerten durch zentralisierte Ownership,
Erzwingung atomarer Gruppen und Beibehaltung manueller Prüfung für
unveränderliche Git-Provenance. Das APR-util-Follow-up härtet Source-/Child-
Source-Tuple-Bindung ohne Lockerung von HTTPS-, Digest-, Redirect- oder Archiv-
Controls. Eine hermetische Preparer-Fixture bestätigt, dass ungültiger
Inherited- oder Post-Source-Zustand vor Network-/Archivtools stoppt. Keine
Connector-Runtime-Behauptung oder Deployment-Aktion wurde ausgeführt.

## Dokumentation und Runtime-Evidenz

Die gepaarte Variablenreferenz dokumentiert den neuen Resolver-Vertrag auf
Englisch und Deutsch. Draft-PR #76 sowie sein damals veröffentlichter
Branch/Head wurden beobachtet. Keine Host-Runtime, kein Connector-Lifecycle,
kein Merge, keine Parent-Aktion, MRTS-Aktion oder Gitlink-Update wurde
beobachtet oder als Evidenz gesammelt. Eine verhaltensbewahrende Remediation
für einen Sonar-Code-Smell hat die oben erfasste lokale Validierung bestanden.
Der Exact-Head-SonarCloud-Check war um `2026-08-12T20:31:29Z` erfolgreich; der
nachfolgende Bot-Kommentar und die begrenzte API-Abfrage meldeten die oben
erfassten Null-Issue-Fakten. Diese Sonar-Fakten schließen die noch laufende
Hosted-CI für den aktuellen Head nicht ab.

Die APR-util-Guard-Implementierung wurde als
`b3dc9aeda0fda59aae65e0c54785e6b9500d025b` auf demselben ausgewählten
Draft-PR-#76-Branch committed und gepusht. Diese Traceability-Abgleichung ist
ein separates, ausschließlich dokumentarisches Follow-up; ihr späterer exakter
PR-Head, Hosted-CI, Sonar, Review, Branch Protection und jede
Resulting-Master-Evidence bleiben getrennte Beobachtungen und werden hier nicht
behauptet.

## Nicht ausgeführte Prüfungen

- Zusätzliche fokussierte Resolver-, CI-Security- und Regressionstests über
  die oben erfassten bestandenen Suiten hinaus wurden vom früheren reinen
  Record-Subtask nicht ausgeführt; der APR-util-Implementierungs-Owner führte
  anschließend die oben gelisteten fokussierten Suiten aus. Das finale volle
  lokale `make lint`-Aggregat endete anschließend mit Exit `0`, einschließlich
  seiner Dokumentations- und `git diff --check`-Stufen. Es wird hier keine
  lokale Testlücke behauptet; Hosted-Exact-Head-Evidenz bleibt getrennt.
- Zum Beobachtungszeitpunkt hat die Hosted-CI für den aktuellen Head noch
  laufende Checks. Der frühere OSV-Versuch auf
  `ba348a7c28b13edcdc253aef7389c89b8285b241` traf beim Tool-Download auf einen
  externen HTTP 503; er ist keine Evidenz für
  `fae3b81db491944a21395de80e3c928f82077143`. Der OSV-Status für den finalen
  Head, verbleibende CI-Checks, Review und Branch-Protection-Disposition
  bleiben getrennt ausstehend.

## Einschränkungen und Restrisiko

Upstream-Release- und Prüfsummendaten sind zeitvariabel. Der lokale Vertrag des
Resolvers ersetzt keinen künftigen geprüften Kandidaten oder eine Hosted-
Validierung. Manuelle CRS- und ModSecurity-v3-Provenance-Entscheidungen bleiben
absichtlich Grenzen menschlicher Prüfung. Dieser Record belegt keine
Connector-Kompatibilität oder Runtime-Reife.

## Finaler Diff- und Review-Status

Dieser Record ist Teil der oben beschriebenen veröffentlichten PR-#76-
Historie. Zum Zeitpunkt der erfassten Sonar-Evidenz lösten lokaler Branch,
sein `origin`-Gegenstück und der PR-Head alle zu
`fae3b81db491944a21395de80e3c928f82077143` auf. Exact-Head-Sonar-Evidenz
bestand mit den oben genannten begrenzten Null-Issue-Fakten, doch Hosted-CI
lief noch; OSV-Status für den finalen Head, verbleibende CI, Review,
Branch-Protection und Merge-Status stehen aus. Es werden kein Merge, keine
Parent-Änderung, MRTS-Änderung oder Gitlink-Update behauptet.

Die APR-util-Guard-Implementierung ist als
`b3dc9aeda0fda59aae65e0c54785e6b9500d025b` auf demselben ausgewählten
PR-Branch committed und gepusht. Diese ausschließlich dokumentarische
Abgleichung behauptet den nachfolgenden exakten PR-Head absichtlich nicht vor
ihrem eigenen normalen Follow-up-Commit und Push.
