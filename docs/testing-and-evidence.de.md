# Testing und Evidence

**Sprache:** [English](testing-and-evidence.md) | Deutsch

Diese Anleitung definiert den Framework-Testworkflow und die Grenze zwischen
einem Testergebnis, einem generierten Bericht und hochstufbarer
Connector-Evidence. Sie behauptet keine Connector-Unterstützung, die nicht
über den einschlägigen Host-Pfad beobachtet wurde.

## Testebenen

| Ebene | Zweck | Evidence-Grenze |
|---|---|---|
| Statische Checks | Syntax, Schemata, Links, Variablen und lokale Verträge | Kein Runtime-Unterstützungsanspruch |
| Katalogchecks | Fallauswahl und No-CRS-Schemavalidierung | Kein Host-Ausführungsanspruch |
| Starter-Checks | Build- oder Self-Test-Voraussetzungen | Niemals Connector-Runtime-PASS |
| Runtime-Smoke | Echter Host-Request durch den Connector | Nur beobachtete Host-Evidence |
| Generierte Berichte | Reproduzierbare Darstellung aktueller Eingaben | Reporting, keine Promotion |

`PASS` und `FAIL` beschreiben beobachtete Ergebnisse. `BLOCKED` beschreibt
eine fehlende Umgebung, Abhängigkeit, Harness oder Runtime-Voraussetzung.
`NOT_EXECUTABLE` bedeutet, dass ein Fall strukturell nicht auf diesen Connector
oder Run-Modus anwendbar ist. Keiner dieser Zustände ist ein PASS.

## Evidenzgrenze für CI-Security

Das [CI-Security-Tooling](security/ci-security-tooling.de.md) validiert
Workflow-Provenienz, Berechtigungen, statische Quellqualität,
Abhängigkeitsmetadaten und Grenzen der Scanner-Ausgabe. Ein lokaler PASS oder
ein GitHub-Actions-Ergebnis ist nur statische CI-Evidenz: Es belegt weder
Connector-Runtime-Verhalten noch Protocol-Handling, Lifecycle-Promotion oder
einen Host-Smoke. Das SonarQube-Cloud-Quality-Gate bleibt separat beobachtete
externe Evidenz für den exakten Pull-Request-Head.

## Common-Structure-CI-Vertrag

Der Workflow `test-common` entdeckt den gemeinsamen YAML-Bestand dynamisch. Er
verlangt einen nichtleeren Bestand `tests/cases/**/*.yaml` und eine nichtleere
Apache-Auswahl mit Scope `common` aus `case_cli.py list-cases`, bevor er jeden
ausgewählten Fall materialisiert und prüft. Er behandelt bewusst keine feste
Gesamtzahl von YAML-Dateien als Vertrag: Fall-YAML und Runner-Discovery bleiben
bei der Weiterentwicklung des Katalogs die Quellen der Wahrheit.

Nur-Katalog-Fälle, deren Metadaten sie vom Standard-Runtime-Pfad ausschließen,
werden vor der Runtime-spezifischen Schemavalidierung gefiltert. Ihre eigenen
Katalog- oder statischen Checks bleiben für ihre Verträge zuständig.

`make test-workflow-contract` ist der fokussierte lokale Regressionstest für
diesen Workflow-Vertrag. Der Workflow selbst bleibt die Ende-zu-Ende-Kontrolle,
weil er Discovery, Materialisierung, Fixture-Erzeugung und Status-Assertions
mit dem aktuellen Katalog ausführt.

## Empfohlener Workflow

Führe Checks aus dem Framework-Checkout oder über das Connector-Repository mit
expliziten Integrationspfaden aus:

```sh
make setup-dev
make lint
make check-no-crs-catalog
make check-documentation
make quick-check
make check-test-matrix
```

Verwende einen beschreibbaren Build- und temporären Ort außerhalb von Git. Die
zentrale [Variablen- und Platzhalterreferenz](reference/variables.de.md)
definiert `FRAMEWORK_ROOT`, `CONNECTOR_ROOT`, `BUILD_ROOT`, `SOURCE_ROOT`,
`TMP_ROOT`, `LOG_ROOT` und `EVIDENCE_ROOT` einschließlich Ownership- und
Sicherheitsregeln.

Vollständige Connector-Validierung ist explizit:

```sh
make smoke-all
make runtime-matrix
make runtime-matrix-all
make test-no-crs
make test-with-crs
```

Schnelle Checks sind nützliches Feedback, ersetzen aber keinen echten
Connector-Smoke. Ein erfolgreicher Source-Build allein ist kein Lifecycle-,
Response-Body- oder Produktionsreife-Claim.

## Vertrag der Protokoll-Targets

Die öffentlichen Targets `make protocol-client`,
`make check-protocol-evidence` und
`make check-transport-hardening-evidence` behalten ihre kompatiblen Namen mit
Bindestrichen. Ihre Standard-Tools sind jeweils
`ci/checks/protocol/protocol_client.py`,
`ci/checks/protocol/check_protocol_evidence.py` und
`ci/checks/evidence/check_transport_hardening_evidence.py`.

`protocol-client` beendet sich mit `2`, wenn `PROTOCOL_URL` fehlt (und strikte
Evidence benötigt zusätzlich `PROTOCOL_FOLLOWUP_URL`).
`check-protocol-evidence` beendet sich mit `2`, wenn `PROTOCOL_ARTIFACT_DIR`
kein Verzeichnis ist, und `check-transport-hardening-evidence` beendet sich
mit `2`, wenn `CONNECTOR` fehlt. Nach diesen Guards meldet der vorhandene
Runner oder Checker sein eigenes Evidence-Ergebnis.
`make test-makefile-contract`, das auch von `make lint` ausgeführt wird,
verlangt statisch, dass jedes vom Makefile referenzierte lokale Python- oder
Shell-Skript existiert.

Dieser Vertrag beweist nur die Auflösung von Target zu Tool. H1-, H2- und
H3-Ergebnisse benötigen weiterhin die jeweiligen Client-, Host- und
Artefaktvoraussetzungen und werden getrennt als Runtime-Evidence berichtet.

## CRS-Quellherkunftsvertrag

`make test-crs-provenance-contract`, das ebenfalls Bestandteil von `make lint`
ist, führt die echte CRS-Provisionierungsgrenze mit einem temporären
Fake-Git-Programm aus und prüft die Update-Entscheidung mit einem Fake-GitHub-
Release-Client. Es verifiziert, dass mutable Tags, Branches, Ref-Namespaces,
kurze Hashes und ein nicht zugehöriger vollständiger Hash vor einer Git-Nutzung
abgelehnt werden; dass der geprüfte vollständige Commit nur einen frischen
Checkout bereitstellt und ein bereits vorhandener Source-Pfad vor der Git-
Nutzung abgelehnt wird; dass der exakte geprüfte Release-Tag geladen wird und
zum selben Commit aufgelöst werden muss; und dass ein fehlender, verschobener,
gefetchter, aufgelöster oder finaler `HEAD`-Mismatch vor der Submodul-
Verarbeitung stoppt. Ein neueres Upstream-Tag wird als `unknown` ohne
automatische Änderung gemeldet: Die Änderung von Release-Tag und
unveränderlichem Commit bleibt eine geprüfte Provenance-Änderung. Der Test
benötigt weder Netzwerk noch Connector-Runtime und beweist nur die
Provisionierungs-Identitätskontrolle, keinen CRS-Runtime-Support-Claim. Die
legitime Kontrolle akzeptiert ein fehlendes Manifest und die exakte Root-
Empty-Blob `.gitmodules` `e69de29bb2d1d6434b8b29ae775ad8c2e48c5391` nur nach
Tree-, Index-, Worktree-, Gitlink-, lokaler Konfigurations- und Registry-
Prüfung. Sie weist nichtleere, falsche Mode-, verlinkte, spezielle,
abweichende, verschachtelte oder Gitlink-haltige Zustände ohne Aufruf von
`git submodule` ab.
Der gleiche Verifier läuft in `prepare-crs.sh` unmittelbar bevor es Source-
Templates, Rules oder Plugins liest oder Runtime-Dateien schreibt. Daher wird
eine Ersetzung nach erfolgreichem Fetch vor dem Source-Verbrauch abgewiesen;
dies bleibt ein Ergebnis der Provisionierungsgrenze und keine Connector-
Runtime-Evidenz.

## ModSecurity-v3-Quellherkunftsvertrag

`make test-modsecurity-v3-provenance-contract`, ebenfalls von `make lint`
ausgeführt, führt die V3-Fetch- und Direct-Build-Grenze dort mit einem
temporären Fake-Git-Programm aus, wo die Topologieentscheidung kontrollierten
Input benötigt, und ergänzt das um Real-Git-Fixtures für frische Roots. Der
Test verifiziert, dass mutable Refs und abweichende nichtleere Legacy-Aliase
abgewiesen werden, während leere Aliase zu geprüften Metadaten normalisieren;
außerdem weist er einen fremden Origin, abweichende
gefetchte/aufgelöste/ausgecheckte Commits und vorhandene Fetch-Pfade sowie
jedes fehlende, zusätzliche, Origin- oder Commit-abweichende, verlinkte,
ausbrechende, schmutzige oder nicht normale Index-Mitglied der freigegebenen
rekursiven Topologie ab. Er beweist, dass Apache, NGINX und der eigenständige
V3-Builder einen vorhandenen nicht freigegebenen Checkout vor Copy- oder
Build-Kommandos stoppen und dass der eigenständige Build-Pfad den vollständigen
Guard vor dem Source-Copy erreicht. Die legitime Fake-Kontrolle verwendet den
exakten freigegebenen Root und Graphen mit acht Kindern. Real-Git-Kontrollen
beweisen, dass ein früheres Fake-Git aus `PATH` ignoriert wird, ein verlinkter
Fresh-Root-Parent vor Git abgewiesen wird, `core.worktree` Checkout-Schreibungen
nicht umleiten kann, ein externer Attributes-/Smudge-Filter nicht läuft und
eine lokale benutzerdefinierte `submodule.*.update`-Einstellung vor der
Rekursion entfernt wird. Der Vertrag hat keinen Netzwerkzugriff, akzeptiert
keine generischen Submodule und behauptet keinen Connector-Runtime-Support.

## No-CRS- und Full-Lifecycle-Evidence

Die kanonische No-CRS-Implementierung ist
`ci/checks/catalog/no_crs_baseline.py`. Ihre Operationen `select`, `init`,
`finalize`, `validate` und `summarize` halten Auswahl, kanonische Artefakte
und Validierung getrennt.

Der Evidence-Pfad zeichnet nur geprüfte, normalisierte Metadaten auf. Er lehnt
unbegrenzte Request- oder Response-Payload-Felder ab und leitet keinen PASS aus
einem Exit-Code ab. Capability-Deklarationen und generierte Berichte ersetzen
kein beobachtetes Ergebnis. P1–P4, Phase-4-Safe-Behandlung, First-Byte-Timing
und No-Full-Response-Buffering-Assertions unterliegen ihren expliziten
Validator-Eingaben und der Promotion-Policy.

`RESPONSE_BODY` ist absichtlich nicht verifiziert und nicht hochgestuft, bis
die erforderliche stabile Connector-Evidence vorliegt. Eine Pass-Through-Response,
ein Late-Intervention-Log, eine leere Antwort oder ein quellabgeleiteter
Upstream-Test ist für sich kein Response-Body-Blocking-Beweis.

## Fünf-Connector-With-CRS-/No-MRTS-Evidenzvertrag

`ci/checks/catalog/five_connectors_with_crs_no_mrts.py` definiert das separate,
fail-closed Profil `five-connectors-with-crs-no-mrts`. Seine geschlossene
Inventarliste besteht exakt und in dieser Reihenfolge aus Apache, HAProxy,
Envoy, Traefik und lighttpd. NGINX ist nur von diesem Profil ausgeschlossen;
es bleibt Teil der allgemeinen Sechs-Connector-Grenze und ihrer übrigen
Bewertungspflichten.

Die kanonische Fixture ist
`tests/cases/security/crs/crs_sqli_anomaly_block.yaml`. Sie bindet die
Allow-Kontrolle (`200`) und die SQL-Injection-Blockierung (`403`, Intervention
`deny`) an die kanonische OWASP-CRS-Regel `942270`, mit dem Tupel aus
`CRS_GIT_REF` und `CRS_APPROVED_COMMIT` in `ci/lib/common.sh` und dem
gepinnten Digest von `rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf`. Die
Fixture definiert keine lokale Ersatzregel. Ihre frische Source muss den
kanonischen Tag-Ref enthalten und dieser Tag muss zu `CRS_APPROVED_COMMIT`
aufgelöst werden.

| Connector | Geschlossene Adapteridentität | Vertragsmodus | Akzeptierte Raw-Evidenz |
| --- | --- | --- | --- |
| Apache | `apache-native-httpd-module` | `native-httpd-module` | Audit |
| HAProxy | `haproxy-native-htx-filter` | `native-htx-filter` | Event |
| Envoy | `envoy-ext-proc-service` | `ext_proc` | Event |
| Traefik | `traefik-native-middleware` | `native-traefik-middleware` | Event |
| lighttpd | `lighttpd-patched-native-module` | `patched-native-lighttpd` | Audit oder Event |

Dies sind geschlossene Evidenzidentitäten. Die aufgeführten Framework-Smoke-
Entrypoints sind als `compatibility-only` markiert und gehören zum Parent-
Hostvertrag; sie dürfen daher nicht als native Hostausführung umbenannt oder
zur Promotion dieses Profils verwendet werden.

Das Catalog-Tool hat vier getrennte Operationen:

```sh
python ci/checks/catalog/five_connectors_with_crs_no_mrts.py profile
python ci/checks/catalog/five_connectors_with_crs_no_mrts.py verify-fixture --source-root <fresh-source-root>
python ci/checks/catalog/five_connectors_with_crs_no_mrts.py validate --evidence-root <private-root> --source-root <fresh-source-root> --connector <fixed-connector> --run-id <id>
python ci/checks/catalog/five_connectors_with_crs_no_mrts.py aggregate --evidence-root <private-root> --source-root <fresh-source-root> --run-id <id>
```

`validate` akzeptiert nur ein Mitglied der geschlossenen Liste sowie
hash-adressierte, vom Host bereitgestellte Raw-Evidenz und nicht mutierend
normalisierte Evidenz. Es verlangt beide Korrelationsidentitäten, die gepinnte
CRS-Identität, eine Allow-Kontrolle, das beobachtete `942270`-`deny`-Ergebnis,
die geschlossenen No-MRTS-Felder und abgeschlossenen Cleanup. `aggregate`
akzeptiert exakt ein validiertes Same-Run-Bundle für jeden der fünf Connectors
und weist ein partielles, doppeltes oder NGINX enthaltendes Inventar zurück.
Die Evidenzwurzel muss privat und außerhalb des Checkouts liegen; Ergebniswege
werden nie überschrieben.

Die vier Raw-Eingaben haben feste, Run-gebundene Orte für Hostkonfiguration,
Allow-Request, Block-Audit und Cleanup. Sie werden als strenge Key/Value-
Records geparst und per Hash an das normalisierte Event gebunden. `validate`
und `aggregate` leiten die Framework-Revision aus einem sauberen
Verifier-Checkout ab, statt ein vom Aufrufer geliefertes Commit-Argument
anzunehmen. Ihre erfolgreichen Ausgaben sind `CONTRACT_VALIDATED` mit
`host_runtime_status: UNATTESTED`, niemals ein Connector-Host-`PASS`.

Die fokussierte lokale Regressionprüfung prüft Fixtures, Schemas,
Closed-Set-Zurückweisung, Provenance-Bindung, Receipt-Validierung und negative
Fälle. Weder diese Prüfung noch ein Catalog-Befehl startet einen Connector-Host,
beweist einen Runtime-Erfolg von fünf Hosts, Produktionsreife oder einen realen
MRTS-Prozesszustand. Ein späterer Connector-eigener Lauf muss eigene Host- und
Lifecycle-Evidenz liefern, bevor eine Runtime-Aussage möglich ist.

## Fallvarianten und Imports

Die Variante `no-crs` materialisiert nur lokale Regeln. Die Variante `with-crs`
lädt die konfigurierte Core Rule Set vor lokalen Fallregeln. Optionale
MRTS-Eingaben verwenden `MODSECURITY_MRTS_VARIANT` und hängen generierte
Fallwurzeln nur für den gewählten MRTS-Run an. Feature-Demo-Material bleibt
explizites Opt-in und stuft ein Ergebnis nicht hoch, nur weil es in einem
Bericht vorkommt.

[Katalog und Fälle](catalog-and-cases.de.md) beschreibt Schema, Provenienz,
Status- und Capability-Regeln.

## Generierte Berichte

Der Report-Generator besitzt die generierten Ausgaben unter
`testing/generated/` sowie die Framework-Root-Coverage-Zusammenfassung. Ändere
keine generierte Datei manuell. Aktualisieren über:

```sh
make refresh-framework-reports
make check-test-matrix
```

Der aktuelle Einstiegsbericht ist die
[Testabdeckungsübersicht](testing/test-coverage-overview.de.md). Die
detaillierte [Fallmatrix](testing/generated/coverage/case-matrix.generated.de.md)
und [Runtime-Matrix](testing/generated/runtime/runtime-matrix.generated.de.md)
bewahren die reproduzierbaren Details, die ältere manuelle Matrizen duplizierten.

## Privacy und Sicherheit

Tests, Normalizer und Report-Schreiber müssen Request- und Response-Payloads
aus kanonischen Event- und Decision-Metadaten heraushalten. Logs dürfen
geprüfte Hashes, Größen, Trunkierungsinformationen, Identifikatoren, Phase,
Status und Host-Version-Metadaten tragen, soweit das Schema es zulässt.
Redaktion und Control-Character-Sicherheit sind erforderlich, bevor Evidence
hochgestuft wird.

Hash-Chain-Daten sind nur für Smoke-Tamper-Detection nützlich. Dauerhafter
Manipulationsschutz erfordert Connector-eigene Schlüsselbehandlung,
Signaturen oder HMACs sowie geeignete Storage-Kontrollen.

## Historischer Kontext

Frühere Testanleitungen, Import-Maps, Response-Body-Untersuchungen und
PR-bezogene Pläne wurden hier zusammengeführt. Git bewahrt ihre detaillierten
historischen Beobachtungen; aktuelle Claims stammen aus dem ausführbaren
Katalog und aktueller generierter Evidence.
