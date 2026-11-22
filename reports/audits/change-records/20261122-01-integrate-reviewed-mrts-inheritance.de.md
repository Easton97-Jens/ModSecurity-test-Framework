# Change Record: geprüfte MRTS-Vererbung integrieren

**Sprache:** [English](20261122-01-integrate-reviewed-mrts-inheritance.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261122-01-integrate-reviewed-mrts-inheritance |
| UTC-Datum | 2026-11-22 |
| Framework-Basisrevision | `e1964415efcd3cda11614ce13b7d34331ee0cf06` |
| Issue oder Pull Request | Externe Abhängigkeit: [MRTS #7](https://github.com/Easton97-Jens/MRTS/pull/7); diese Framework-Folge-PR wurde noch nicht erstellt. |

## Motivation und Problemstellung

Die gesondert geprüfte MRTS-Vererbungsänderung wird über ihren tatsächlichen offiziellen Main-Mergecommit übernommen. Das Framework pinnt bisher `ee2174431c4edf97e66afe32558ce8454deb2397`; ausgewählter Nachfolger ist `488e75388d917615feecab91650c3278b9c78b1e`. Der geprüfte PR-Kopf ersetzt nicht das tatsächliche Squash-Ergebnis.

## Betroffene Komponenten und Sicherheitsgrenzen

Im Framework ändern sich ausschließlich `tools/MRTS` und dieses englisch/deutsche Change-Record-Paar. MRTS und Parent bleiben unabhängig verantwortete Repositories. Framework-Produkt, Testquellen, Workflows, Inventarauswahl und Validierungsregeln werden nicht geändert. Die spätere Parent-Pinfolge ist ein eigener Integrationsschritt.

## Akzeptanzkriterien

Erforderlich sind der offiziell gemergte MRTS-Commit, Vorwärtsabstammung vom bisherigen Pin, ein sauber materialisierter verschachtelter Checkout und zutreffende Reviewnachweise. Die bisherigen 100 Kernfälle, 80 Ausführungsselektoren und 1144 getrennten Offlineausnahmen bleiben erhalten. Registrierte Quellbindungen, Spezialistenarchiv, aktives Inventar und geltende Dokumentationsverträge werden geprüft. Vor dem gesondert freigegebenen regulären Merge müssen frische Prüfungen des exakten Framework-PR-Kopfs vorliegen.

## Untersuchte Alternativen

Der alte Pin würde die geprüfte Vererbungsänderung nicht übernehmen. Integritätswerte ohne Lektüre ihrer historischen und aktuellen Policyquellen zu aktualisieren, wäre kein semantisches Review. Der eingeschränkte automatische Publisher erlaubt nur ein Gitlink-Update; er wird nicht zur Veröffentlichung des zusätzlichen Change-Record-Paars verwendet.

## Implementierungsentscheidung

Root hat den tatsächlichen MRTS-#7-Squashmerge ausgewählt, dessen Baumgleichheit zum geprüften Baum sowie den bisherigen Pin als einzigen Parent geprüft, den sauberen Detached-Checkout materialisiert und den Framework-Gitlink gestaged. Der native Abstammungsprüfer akzeptiert diesen Vorwärtsschritt. Validatoren, Gates und Quellautoritätskontrollen bleiben verbindlich.

Die externe MRTS-Änderung aktualisiert genau zwei geerbte Parent-Bindungen. Die Architekturpolicy entfernt einen beispielhaften Leselisteneintrag und erhält Quellautorität sowie Repositorybesitz. Die Befehlspolicy unterscheidet installierte automatische Secrets-Hooks von agentseitigen Shellbefehlen; für Agentbefehle bleiben RTK und kanonischer Sonarstarter erforderlich. Das vollständige historische Policybyte- und Semantikreview ist getrennt dokumentiert; Prüfsummengleichheit wurde nicht als Sicherheitsbeweis behandelt.

## Geänderte Dateien und Tests

- `tools/MRTS`: bisheriger Pin auf den oben genannten tatsächlichen Mergecommit.
- Dieses Change-Record-Paar.

Keine Tests werden ergänzt oder geändert. Bestehende Abstammungstests akzeptieren gleiche und nachfolgende Commits und weisen rückwärts gerichtete, divergente, fehlende, nicht als Commit vorliegende, fehlerhafte und durch Replacement-Objekte manipulierte Eingaben zurück. Sechs ausgewählte Workflowvertragsmethoden erhalten die drei Abstammungskontrollen, aufgelöste Identitäten und Publishergrenzen.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk bypass bash ci/tools/verify-mrts-update-lineage.sh tools/MRTS ee2174431c4edf97e66afe32558ce8454deb2397 488e75388d917615feecab91650c3278b9c78b1e` | 0 | Roots aufgezeichneter nativer Aufruf verwendete die gleichwertigen expliziten absoluten Prüfer- und Repositorypfade; Vorwärtsabstammung akzeptiert. | `20261122-readiness-continuation/framework-mrts-pin-commands.json` |
| Framework-Python `-B -m unittest tests.ci_security.test_mrts_update_lineage` plus sechs ausgewählte `CiSecurityContractTest`-Methoden | 0 | Roots gezielte Vorprüfung bestanden; genaue Selektoren und Kontext stehen im Receipt. | `20261122-readiness-continuation/framework-prechecks/receipt.json` |
| Framework-Python `-B ci/checks/security/check-ci-security-contract.py` | 0 | Bestehender nativer Workflow-Sicherheitsvertrag in Roots Vorprüfung bestanden. | `20261122-readiness-continuation/framework-prechecks/receipt.json` |
| Framework-Python: `update-inventory-bindings.py --check` und `update-test-archive.py --check` | 0 / 0 | Registrierte Quellbindungen und erhaltenes Spezialistenarchiv stimmen überein; kein Writer und keine Regeneration verwendet. | `20261122-readiness-continuation/framework-pin-validation/inventory-receipt.json` |
| Framework-Python: `run-active-tests.py --check` | 0 | Explizites `CONNECTOR_TEST_PROFILE=parent` und isolierter Framework-/Parent-/Revisions-/Ausgabekontext; Zähler blieben 100/80/1144. | `20261122-readiness-continuation/framework-pin-validation/active-context-complete.receipt.json` |
| Framework-`make check-doc-links check-bilingual-docs check-repository-path-references check-change-records` mit explizitem Framework-Python | 0 | Vier native Ziele nach Aufnahme des neuen Paars in die Suche nach versionierten Dateien bestanden; beide aktuellen Quelldateien wurden erfasst. | `20261122-readiness-continuation/framework-pin-validation/docs-tracked.receipt.json` |

## Sicherheitsauswirkung

Keine Produktsicherheitsremediation. Die Änderung übernimmt geprüfte Governancebindungen und erhält Isolation, Credentialbehandlung, Abstammungsprüfung und reguläre Delivery-Gates. Kein Sicherheitsbefund wird dispositioniert und keine Laufzeitsicherheit abgeleitet.

## Dokumentation und Runtime-Evidenz

Dieses gepflegte englisch/deutsche Paar dokumentiert die Framework-Integrationsentscheidung. Externes MRTS-Main am ausgewählten Commit hat vier erfolgreiche Hosted-Checks und zwei erfolgreiche Workflows; der vollständige revisionsgebundene Sonarreadback meldet Gate OK, alle fünf Bedingungen OK, Gesamt-/Neucodebewertungen A/A/A sowie null ungelöste Befunde, Neucodebefunde und Hotspots. Der gehostete CPython-3.14.6-Governanceworkflow validiert ein isoliertes Policyfixture; er ist kein tatsächlicher lokaler Parent-/Framework-/MRTS-Vererbungslauf.

Roots Kandidaten-Policykomposition prüft 27 Parenteinträge, 21 Frameworkbindungen und 12 MRTSbindungen ausschließlich auf Manifestebene. Diese Pinintegration hat keine Host-, Protokoll-, Lifecycle-, Volltestkampagne oder neue Laufzeitevidenz erzeugt.

## Nicht ausgeführte Prüfungen

Der erste aktive Inventaraufruf ließ das verpflichtende explizite Profil aus und endete vor der Ausführung mit Exit 2; der korrigierte Aufruf bestand ohne Änderung einer Quellkontrolle. Beide Versuche bleiben in den privaten Nachweisen erhalten.

Die vorgesehene lokale MRTS-CPython-3.14.6-Umgebung fehlt; kein Ersatzinterpreter wird als natives MRTS-Testergebnis ausgegeben. Vollständige Produkt-/Laufzeitkampagnen liegen außerhalb dieser Pinänderung. Frische Hosted-Checks dieser Framework-PR sind noch nicht lesbar, da die PR noch nicht erstellt ist.

## Einschränkungen und Restrisiko

Gehostete MRTS-Fixturegovernance, lokale Manifestkomposition und Framework-Prüfungen belegen unterschiedliche Ebenen. Die aktuell beobachtete Framework-Basis hat einen fehlgeschlagenen Current-Revision-Advisory-Job bei der Abhängigkeitsinstallation; dessen Status wird weder verborgen noch zu einem erfolgreichen Scorecard-Lauf umgedeutet. Neue Prüfungen des exakten Framework-Kopfs und gesondert geprüfte Parent-Pinübernahme bleiben erforderlich. Bestehende Laufzeitberichte erhalten keine neue Revisionszuordnung.

## Finaler Diff- und Review-Status

Der geprüfte Framework-Diff besteht aus dem vorwärts aktualisierten `tools/MRTS`-Gitlink und diesem Dokumentationspaar. Produktcode, CI, Testquellen, aktive Fallauswahl, registrierte Quellbindungen und Spezialistenarchiv bleiben unverändert. Bestehende Abstammungs-/Sicherheitsvorprüfungen sowie Quellbindungs-, Archiv-, aktive Inventar- und vier Dokumentationsprüfungen mit erfassten neuen Quelldateien bestanden. Das Inventar enthält weiterhin 100 Kernfälle, 80 Ausführungsselektoren und 1144 getrennte Offlineausnahmen. Das Record-Paar erfüllt alle 13 Templateabschnitte; Whitespace- und ausgewähltes Wholefile-Secretsreview der eigenen Dateien begleiten die Übergabe. Frische CI des veröffentlichten Kopfs und die getrennte Parent-Pinintegration stehen aus; ein Framework-Commit- oder Mergeergebnis wird hier nicht behauptet.
