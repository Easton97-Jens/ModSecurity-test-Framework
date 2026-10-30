# Test-Ownership und Framework-Schnittstelle

**Sprache:** [English](connector-test-suite.md) | Deutsch

Das Framework besitzt die vollständige Testimplementierung: Common- und
Connector-Unit-, Native-, Compile-, Integrations-, Regressions- und E2E-Tests;
Fixtures und Fehlermodule; Testadapter; Auswahl und Inventare; Provisionierung,
Orchestrierung, Erfassung, Korrelation, Validierung und Report-Generatoren.
Das schließt Tests der Connector-Makefiles, Workflows und Repository-Verträge ein.

Der Connector besitzt produktiven Common- und Connector-Code, produktive
Module, Services und Response-Companions, Produktkonfiguration,
Build-Abhängigkeiten, Installation, Packaging und Deployment. Make-Targets und
kleine CI-Einstiege rufen das gepinnte Framework auf. Produktbinärdateien laden
das Framework nicht. Produktive Envoy-Launcher liegen in
`connectors/envoy/scripts/`; produktive Regeln verlangen eine explizite Regeldatei.

Die einseitige Abhängigkeit bleibt Connector → Framework. Das Framework erhält
kein Connector-Submodul. Das MRTS-Werkzeug bleibt gepinnt und schreibgeschützt;
Framework-Paket-/Importkorrekturen haben eine getrennte Followup-Zuständigkeit.

## Quellen- und Auswahlverträge

`TEST_ROOT` wählt den Framework-Checkout. `CONNECTOR_ROOT` wählt den
Produkt-Checkout; `CONNECTOR_REVISION` muss dessen exaktem Git-HEAD entsprechen.
`CONNECTOR_TEST_PROFILE` benennt das Profil.
`CONNECTOR_TEST_OUTPUT_ROOT` muss bereits außerhalb beider Checkouts existieren
und vertrauenswürdige Vorfahren ohne Symlinks besitzen. Connector-Tests lehnen
fehlende oder ungültige Produktangaben ab. Reine Framework-Selbsttests benötigen
keinen Connector-Checkout.

`connector_suite/config/testing/active-cases.json` im Framework ist die
Auswahlautorität. Die Migration erhält die Basis von **100 Standardfällen in
80 Ausführungen** sowie **1.893 On-demand-Fällen in 839 Ausführungen**.
Neue Migrationsregressionen sind ausdrücklich On-demand und werden getrennt von
diesen Basiszahlen geführt. Mehr als 100 Standardfälle werden vor der
Ausführung abgelehnt; die Auswahl wird niemals abgeschnitten. Definitionen,
ausgewählte Fälle, Ausführungen und beobachtete Läufe sind unterschiedliche
Größen. Eine Wiederholung ist ein weiterer Versuch, kein zusätzlicher
eindeutiger Fall. Der Umzug aktiviert keine archivierte Kampagne.

Das finale kanonische Inventar enthält
**100 Standardfälle / 80 Ausführungen**, **2250 On-demand-Fälle / 1029
Ausführungen**, **463 feste Framework-Testquellbindungen** und **232
Produktquellsnapshots**. Sein kompaktes JSON umfasst **2091364 Bytes** und liegt
unter der unveränderten Zulassungsgrenze von **2 MiB**. Dies sind Auswahl-/
Quellmengen, keine Zahlen ausgeführter oder bestandener Fälle. Die Erweiterung
fügt 42 explizite On-demand-Methoden hinzu: 28 Clean-Pair-Methoden (darunter ein
noch ausstehender tatsächlicher Lauf) und 14 MRTS-Paket-Methoden; die ursprüngliche
Baseline mit 1993 Fällen bleibt unverändert.

Die 120 neuen fokussierten Methoden bestanden ohne Skips, einschließlich der
Ergebnisintegritäts-Teilmenge mit 56 Methoden / 131 expandierten Varianten und
der geschlossenen Pfadregel-Teilmenge mit 9 Methoden / 32 expandierten Varianten.
Getrennt davon bestanden 136 fokussierte Portabilitätsmethoden, 330 native
Framework-CI-Methoden, 30 öffentliche API-Methoden und 3 Makefile-Methoden.
Das vollständige native Framework-Dokumentations-Target bestand.

Sieben reparierte Standardfall-IDs bestanden über den öffentlichen Runner. Die
tatsächliche öffentliche CLI-Kontrolle fremder UID/GID bestand beide Teilfälle
in ausdrücklich autorisierter isolierter Ausführung. Alle neun Go-Ausführungen
bestanden. Siebzehn native Ausführungen bleiben blockiert: Bei 13 fehlen
validierte Hostvoraussetzungen, bei 4 sind Scannerfixture-Voraussetzungen
verifiziert. Der pinabhängige Standard-Sonar-Check wartet auf den finalen
Connector-Pin. Ein künftiger Gesamt-PASS der Standardläufe wird nicht behauptet.

Schema 4 trennt feste Framework-Testquellprüfsummen von
`connector_source_paths`. Produkteingaben werden aus der explizit ausgewählten
Revision erfasst, im Beleg aufgeführt und vor sowie nach der Ausführung erneut
geprüft. Collector-Änderungen verlangen weiterhin eine geprüfte feste
Prüfsumme. Schema-1/2/3-Testfixtures behalten ihre strengen Prüfsummenregeln.
Produkt-Updater verändern das unabhängige Framework-Inventar nicht.

`connector_suite/source-map.json`, `migration-baseline.json` und `test-map.tsv`
halten bisherige Quell-IDs, Prüfzwecke, Selektoren, Aufrufer und neue
Framework-Pfade fest. Die Python-Namensräume heißen
`modsecurity_connector_tests`, `modsecurity_connector_ci` und
`connector_suite.adapters`. Go-Tests behalten Paketinternazugriff über externe
Overlays; Produktbäume werden dafür nicht verändert. Native
Test-Übersetzungseinheiten gehören zu `connector_native_tests/`.

Der Migrationsmap-Generator erzeugt jetzt Schema 3 mit einer `prerequisites`-
Referenz je Test-ID auf einen Ausführungskatalog. Die TSV erhält ihre
ursprünglichen sieben Spalten und ergänzt maschinelle Voraussetzungen sowie
lesbare Spalten für Tool, SDK, Host, Profil, Privilegien, Abhängigkeiten, Checkout
und externe Ausgabe. Tatsächliche Quellrouten von Parent-Root-/Komponenten-Make,
Framework-Make und `connector.mk`, CI/Actions, Python-Discovery, nativen C/C++-,
Go- und Framework-Selbsttests werden festgehalten. Discovery-Kandidaten oder
gebundene Quellen belegen keine automatische Auswahl oder beobachtete Ausführung.
SDK-/Tool-/Host-/Privilegiendeklarationen behalten Quellstellen und bedingten oder
ungeklärten Status; Verfügbarkeit wird nicht abgeleitet. Fallprofilmetadaten
bleiben vom Laufzeitparameter `--profile` getrennt.

Dasselbe Artefakt ordnet fünf stabile Anforderungs-IDs der aktuellen
Dateizuständigkeit zu: `migration.test-ownership`,
`migration.shared-test-mechanics`, `migration.mrts-separate-packet`,
`migration.connector-thin-integration` und `migration.clean-pair-integration`.
Das MRTS-Paket gehört zu einem separaten Framework-Followup-Worktree/PR;
`tools/MRTS` bleibt gepinnt und schreibgeschützt. Guards für verschachtelte
Definitionen und Validierungsquellen, Regressionserhalt und Framework-Integration
werden getrennt vom Werkzeugrepository nachverfolgt. Generierte Archiv- und Map-Ausgaben
stimmen mit ihren eingefrorenen Quelleingaben überein: Beide Generatorläufe mit
`--check` bestanden und erhielten alle 1993 ursprünglichen Fall-IDs. Die obigen
kanonischen Inventarzahlen beschreiben Auswahl, keine erfolgreiche Ausführung.

## Aufruf

Dies ist eine Quellcheckout-Schnittstelle. Ihre Verfügbarkeit behauptet nicht,
dass alle migrierten Module im installierbaren Framework-Paket enthalten sind.
Python startet mit `-P` und `PYTHONSAFEPATH=1`; nur Framework-Root und
`connector_suite/` gehören in `PYTHONPATH`. Produktquellen werden über begrenzte,
explizite Schnittstellen geladen.

Im Connector-Checkout muss das gepinnte Framework ausdrücklich ausgewählt
werden, wenn die Umgebung noch Pfade eines anderen Worktrees exportiert:

```sh
FRAMEWORK_ROOT="$PWD/modules/ModSecurity-test-Framework" \
CONNECTOR_TEST_OUTPUT_ROOT="$EXTERNAL_OUTPUT" \
PYTHON="$FRAMEWORK_PYTHON" make check-active-inventory
```

Der öffentliche Adapter für Quell-Checkouts unterstützt auch getrennte Checkouts:

```sh
PYTHONSAFEPATH=1 PYTHONPATH="$FRAMEWORK_ROOT:$FRAMEWORK_ROOT/connector_suite" \
"$FRAMEWORK_PYTHON" -P -m modsecurity_test_framework.connector \
  --connector-root "$CONNECTOR_ROOT" --connector-revision "$CONNECTOR_REVISION" \
  --test-root "$FRAMEWORK_ROOT" --profile h1 \
  --output-root "$EXTERNAL_OUTPUT" --group inventory --check
```

Ohne `--check` wird die ausgewählte Standardgruppe ausgeführt. Weitere
Inventarfälle verlangen `--on-demand` und einen expliziten Gruppen-, Fall- oder
Ausführungsselektor. Benannte Spezialisteneinstiege verlangen zusätzlich
`ON_DEMAND_TESTS=1`. Dieses Flag autorisiert keine breite historische Kampagne.

## Ergebnisintegrität und hostspezifische Verträge

Live-Nachweise binden Lauf, Fall, Request und Quellrevision; Hostnachweise
verlangen zusätzlich eine eindeutige Hosttransaktion. Ein Request-Beleg begrenzt
das erfasste Logintervall; fremde oder mehrdeutige Transaktionen dürfen den Fall
nicht anreichern. Ein abgeschlossener Request mit gültigem abgeschlossenem Beleg
kann eine typisierte reine Clientbeobachtung `request_bound` mit
`transaction_id: null` und `promotion_allowed: false` liefern. Dies dokumentiert
die Clientantwort, ohne eine Hosttransaktion zu erfinden oder eine Hostfähigkeit
zur Promotion freizugeben. Beobachteter Clientstatus und Interventionsstatus
bleiben getrennt. Schreibfehler, fehlende Pflichtzeilen und leere vorgeschriebene
Ergebnismengen lassen den Lauf scheitern. Ausgeführter Envoy-Traffic bleibt bei
Assertion-Fehlern sichtbar, auch vor dem ersten Katalogfall, ohne einen Fall-PASS
zu erfinden.

Apache führt doppelte Header zusammen, bevor der Adapter sie beobachtet. Der
explizite Regelmaterialisierer `apache-native` erhält den ursprünglichen
Wire-Fall, HTTP 200, Regel `1100504` und ihre Audit-Assertion und dokumentiert die
Anpassung. Historische artefaktgebundene Overrides werden nicht abgeschwächt.

Die beiden intern injizierten NGINX-Zeigerfehler verlangen HTTP 500,
`phase1_error`, `MSCONN_EVENT_CONNECTOR_ERROR` und `reason=connector_error`.
Fehlerhafte Clienteingaben behalten HTTP 400 und ihren eigenen
Protocol-Error-Typ. Damit werden veraltete Testerwartungen korrigiert; die
Fail-closed-Schutzwirkung des Produkts bleibt erhalten.

Geschützte Broker authentifizieren die geschützte Parent-Basis und deren
exakten Framework-Gitlink, bevor sie privilegierten Testcode auswählen.
Framework-Inhalte des Kandidaten sind kein vertrauenswürdiger Code.
Vom Gate verlangte Parent-Pfade bleiben kleine authentifizierte Einstiege;
Gate-Protokoll und Hostberechtigungen bleiben erhalten. Fehlende Voraussetzungen
des geschützten Hosts bleiben Blocker.

Der jüngste begrenzte Ergebnisintegritätslauf bestand 56 Methoden / 131
expandierte Varianten. Drei tatsächliche Apache-H1-Kontrollen bestanden mit
HTTP 200 / 403 / 200 (Allow, Deny, Duplikatheader). Die Allow-Kontrolle verwendete
die oben beschriebene reine Clientbeobachtung `request_bound`; sie belegt keine
Hostfähigkeit. Der NGINX-H1-Versuch war mit Exit 77 blockiert, weil die benötigte
vorhandene Laufzeitumgebung fehlte; dies ist kein bestandener Hostlauf. Diese
Beobachtungen qualifizieren weder einen vollständigen H1-Lifecycle noch ein
installiertes geschütztes Host-Gate.

Der vorgelagerte [Framework-PR #139](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/139)
und [Connector-PR #432](https://github.com/Easton97-Jens/ModSecurity-conector/pull/432)
sind bereits gemergt. Der Task übernahm die Framework-Upstream-Basis
`1d1e73fb069598e0f0f809d0bf16b5e59047ff88`; Taskänderungen und Backups blieben
durch Dreiwegeabgleich erhalten. Diese Upstream-Integration ist von der Lieferung
der Migrations- und MRTS-bezogenen Framework-Pakete getrennt.

## Integration und Nachweise

Die Clean-Pair-CLI prüft eine committete Connector-Revision standardmäßig gegen
ihren eingetragenen Framework-Gitlink. Beide Quellrepositories müssen die
gewählten Gitobjekte enthalten. Sie erzeugt daraus saubere lokale Checkouts,
prüft erforderliche Einstiege und Schnittstellen, ruft das tatsächliche
Parent-Make-Target `test-framework-integration-probe` auf und validiert das exakte
zugelassene Ergebnis des Common-Headertests. Die Prüfung verlangt vorhandenes Git,
Make, kompatibles Python und `cc` sowie vorhandenen privaten externen
Ausgabespeicher. Uncommittete Quelländerungen werden nicht in das Paar kopiert.
Quellverdrahtung und Unit-Kontrollen ersetzen keinen erfolgreichen echten
Paarbeleg; dieser positive Lauf steht hier noch aus.

```sh
PYTHONSAFEPATH=1 PYTHONPATH="$FRAMEWORK_ROOT:$FRAMEWORK_ROOT/connector_suite" \
"$FRAMEWORK_PYTHON" -P -m modsecurity_test_framework.connector_integration \
  --connector-source "$CONNECTOR_ROOT" --framework-source "$FRAMEWORK_ROOT" \
  --connector-revision "$CONNECTOR_REVISION" --output-root "$EXTERNAL_OUTPUT" \
  --python "$FRAMEWORK_PYTHON" --profile h1
```

Eine getrennt ausgewählte Entwicklungsrevision verwendet die folgende explizite
Option. Ihr Beleg enthält `mode: development` und `standard_combination: false`;
sie bleibt von der Prüfung der Standardkombination mit eingetragenem Pin getrennt.

```sh
PYTHONSAFEPATH=1 PYTHONPATH="$FRAMEWORK_ROOT:$FRAMEWORK_ROOT/connector_suite" \
"$FRAMEWORK_PYTHON" -P -m modsecurity_test_framework.connector_integration \
  --connector-source "$CONNECTOR_ROOT" --framework-source "$FRAMEWORK_ROOT" \
  --connector-revision "$CONNECTOR_REVISION" --output-root "$EXTERNAL_OUTPUT" \
  --python "$FRAMEWORK_PYTHON" --profile h1 \
  --development-framework-revision "$(git -C "$FRAMEWORK_ROOT" rev-parse HEAD)"
```

Ein erfolgreicher Prüflauf belegt das Repository-Schnittstellenverhalten für den tatsächlichen
Common-Fall. Gehostetes H1 und installierte Gates verlangen eigene Nachweise.

Framework-Änderungen werden zuerst geliefert und ihr exakter Commit remote
bereitgestellt. Der abhängige Connector-PR aktualisiert Gitlink und vollständige
CI-SHA-Referenzen auf diesen Commit. Der Framework-PR muss vor dem Connector-PR
integriert werden; keines der Repositories wird automatisch gemergt. HTTP/2,
HTTP/3, Coverage und vollständige Abhängigkeitsprüfung bleiben bis
auf erforderliche Pfad- und Aufruferanpassungen außerhalb dieser Migration.

Die zweisprachigen Change Records unterscheiden ausgeführte Prüfungen, Fehler,
Blocker und nicht ausgeführte Prüfungen. Statische Checks, native
Primitivtests oder Produktbuilds belegen keinen gehosteten H1-Lifecycle und keine
Promotion des aktuellen HEAD.
