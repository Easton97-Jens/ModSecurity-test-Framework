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

Das registrierte kanonische Schema-5-Inventar enthält **100 Standardfälle /
80 Ausführungen**, **2443 On-demand-Fälle / 1107 Ausführungen**, **515 feste
Framework-Testquellbindungen** und **235 Produktquellsnapshots**. Der Katalog
deklariert **1187 Ausführungsdefinitionen / 2543 Fälle**; dies sind Auswahlmengen,
keine Zahlen ausgeführter oder bestandener Fälle. Das kompakte JSON umfasst **1112077 Bytes**; die expandierten UTF-8-Quellpfade
belegen **1086696 Bytes**. Beide liegen unter der unveränderten Grenze von
**2097152 Bytes (2 MiB)**. Alle bisherigen Bindungsidentitäten bleiben erhalten;
alle 750 geordneten Quellpooleinträge werden genutzt. Die ursprünglichen 1993
Falldictionaries und Standard-IDs bleiben unverändert. Die Zulassung prüft die
Grenze expandierter UTF-8-Quellpfade weiterhin vor der Materialisierung.

Die Erweiterung enthält nun **120 explizite On-demand-Methoden**, einschließlich
37 neuer Methoden / 79 Fälle in N28: 5 Methoden zur Argumentzulassung / 15 Fälle,
2 native Fixturemethoden / 6 Fälle, 12 Go-Capture-Methoden / 31 Fälle und
18 Archivsnapshot-Methoden / 27 Fälle. Jede neue Methode besitzt eine eigene
registrierte Auswahl und explizite Varianten. Alle 37 tatsächlichen Quell-/
Effekttraces bestanden mit vor Imports aktiven Guards: 35 reine Methoden hatten
null Effekte; die 2 nativen Methoden nutzen die explizite Prozessgrenze.
Es gibt 111 reine Erweiterungskontrollen und 157 Zeilen mit Prozessausführung
über 13 explizit erlaubte Module. Die Standardauswahl bleibt auf 100 begrenzt.
Der tatsächliche öffentliche Runner bestand alle 37 neuen Methoden / 79 Fälle
in 166.939 Sekunden; 2 verpflichtende Kontrollen ohne CLI-Opt-in bestanden auch
mit `ON_DEMAND_TESTS=1`. Die öffentliche Zulassung bestand in 6.06 Sekunden.
Finale Quellbindungen und alle sechs Generatoroperationen bestanden nach den
späteren Importreparaturen; die frische finale Zulassung bestand in 5.327 Sekunden.
Commit/Push des Paars und gehostete CI-/Sonar-Prüfung für exakt diesen Stand
stehen noch aus.

Die fünf neuen Quellbindungen folgen beobachteten kanonischen Lese-Closures.
Zwei bestehende NGINX-Zeilen ergänzen außerdem den tatsächlichen sofortigen
P3-Runner-Import in ihrer Closure. Dies ändert die Quellerfassung, ohne
unabhängige Fälle hinzuzufügen oder zu verstecken. Kein Archiv wird automatisch
ausgewählt und kein Standardfall ergänzt.
Das neue native Fixturemodul verwendet den bereits unterstützten vollständigen
Framework-Prefix für Quellbindungen. Die historische Source-Map bleibt bytegleich
zu `cb129a45`; es entsteht kein erfundener früherer Produktpfad. Eine neue, noch
unveröffentlichte Fall-ID wurde deterministisch auf die unveränderte Grenze von
128 Zeichen gekürzt; ursprüngliche und Standard-IDs bleiben erhalten.

Die früheren 120 fokussierten Methoden bestanden ohne Skips, einschließlich der
Ergebnisintegritäts-Teilmenge mit 56 Methoden / 131 expandierten Varianten und
der geschlossenen Pfadregel-Teilmenge mit 9 Methoden / 32 expandierten Varianten.
Frühere begrenzte Läufe bestanden 136 fokussierte Portabilitätsmethoden,
30 öffentliche API-Methoden und 3 Makefile-Methoden. Die frühere lokale native
Framework-CI bestand 330 Tests in 163.868 Sekunden; die exakten Workflow-Ruff-
Lint-/Formatprüfungen bestanden alle 38 Dateien in 0.104 Sekunden, und 19 Sonar-
Vertragsmethoden bestanden in 4.836 Sekunden. Diese lokalen Ergebnisse belegen
keine gehosteten Gates des aktuellen Heads.
Das vollständige native Framework-Dokumentations-Target bestand.

Sieben reparierte Standardfall-IDs bestanden über den öffentlichen Runner. Die
tatsächliche öffentliche CLI-Kontrolle fremder UID/GID bestand beide Teilfälle
in ausdrücklich autorisierter isolierter Ausführung. Alle neun Go-Ausführungen
bestanden. Das Ledger der neuesten Beobachtungen enthält 67 bestandene und
13 blockierte Standardausführungen für 74 bestandene und 26 blockierte eindeutige
Fälle. Die vier Scannerfixtures und der pinabhängige Sonar-Check bestanden bei
gezielten Wiederholungen; die 13 Host-/Profilvoraussetzungen bleiben blockiert.
Diese Beobachtungen umfassen mehrere Quellrevisionen und bilden keinen
vollständigen Standardlauf auf einem künftigen finalen Paar.

Die authentifizierte Parent-Bridge stellt die eigenständige CLI `connector-context`
über `ci/run-trusted-framework.py --tool connector-context` bereit. Sie ersetzt
22 lokale Context-Action-Aufrufe in 9 Workflows und erhält Authentifizierungs-
und Privilegienguards. Vier neu registrierte geschützte reine Methoden decken
15 expandierte Fälle ab; die Quellclosure folgt tatsächlichen Imports und
öffentlichen Einstiegen. Dies ergänzt weder Standardfälle noch einen globalen
Produkt-Importpfad.

Die aktuelle Arbeitsfassung der Bridge delegiert die rohe Gitobjektidentität an
das feste unprivilegierte `git hash-object --no-filters`; beim lokalen Git-Build
wurde SHA1_DC nachgewiesen. Dies belegt weder den kryptografischen Build aller
Hosts noch eine SHA-256-Gitidentität. Unveränderliche Byteprüfungen behalten
SHA-256. Ein versiegeltes eigenes JSON-memfd transportiert Quelldateinamen und
exakte argv; der feste Interpreterbefehl enthält nur eigene Deskriptoren.
Exaktes main-/Exitstatus-Verhalten, UID-Guards und die Cells-API bleiben erhalten.
Zwei separat registrierte Prozessmethoden decken sechs exakte argv-Rundläufe und
acht benannte ungültige Deskriptor-/Envelope-Fälle ab. Produkt-Komponenten-
Basisnamenguard und Spezialisierung toter Zweige erhalten Authentifizierungsweg
und Digestprüfungen. Updater-CLI-Bootstraps nutzen ein festes gemeinsames Register
mit acht Kompatibilitätsexporten, der Workflow-Updater eine Framework-Pfadkonstante.
ASCII-JSON-Escaping erhält gültige POSIX-Argumente mit Surrogate-Escapes;
der sechste argv-Fall ist separat registriert. Collector-Metadaten verwenden
exakte Bindungspaare getrennt von Nutzargumenten; eine neue reine Methode
deklariert fünf Fälle, ohne einen Snapshot-Helfer hinzuzufügen.

Der erneuerte echte native Capture kompilierte alle 81 Übersetzungseinheiten in
39.790 Sekunden mit tatsächlichen SDK-`ALL_INCS` und zugeordneten Header-
Eingaben ohne Quell- oder SDK-/Header-Drift. Acht SDK-Zulassungskontrollen vor dem Recipe-Import
und 19 native Sonar-Vertragsmethoden bestanden; die ASTs der ursprünglichen
18 Methoden bleiben exakt erhalten. Vier neue feste Quellbindungen haben
präzise physische Framework-Eigentümer. Die Closure erhält acht beobachtete,
zwei semantische und zwei öffentliche Einstiegsabhängigkeiten; Quellbindungen
wurden nicht global ausgedünnt. Die frische kanonische Security-Prüfung bestand
69 Methoden / 257 beobachtete Teilfälle in 10.939 Sekunden ohne Skips oder
Quelldrift gegen Bridge-Arbeitsfassung mit SHA-256
`1ef4d6fb021605f52c63fef3bf522a325736ceb40457d48c94c091b1e3efc5eb`.
Dies umfasst den separat registrierten sechsten argv-Fall mit Surrogate-Escapes.
Die Quality-Folgekorrekturen betreffen 66 Quelldateien. Sie ersetzen 23
S1192-Literale in 13 Dateien durch Konstanten, mit Gleichwertigkeitsprüfungen
für 440 Funktionen. Bei 24 ungenutzten Parameterplätzen in 23 Dateien änderten
sich nur Deklarationen; 165 betroffene Methoden haben bestandene Beobachtungen
über begrenzte Läufe. Das breitere Ruff-Ergebnis behält unverändert seine 203
Baseline-Befunde: Für diese Dateien wird kein vollständiger Lint-PASS behauptet.
Sechs API-Komplexitätsrefactorings erhalten Guards und Signaturen; 1322
differenzielle Pfade und 94 Methoden / 286 Teilfälle bestanden. Sieben Go-Helfer-
Extraktionen in fünf Dateien erhalten nach Helfer-Inlining alle 210 ursprünglichen
Funktions-ASTs und 112 Testdefinitionen; Normal-/Race-Läufe behalten exakt 205
terminale Test-/Teiltestidentitäten, alle bestanden ohne Skips. Die 17 YAML-Guards
und actionlint-/zizmor-Verträge bleiben erhalten. Der ungültige Callee-Default
wurde später bei erhaltener exakter Dispatch-/Call-Schnittstelle entfernt. Alle 41 Trusted-/Lighttpd-Methoden / 185 Teilfälle
bestanden unter Erhalt von 40 alten Methoden und 114 Assertions. Die Ausgabeprüfung
bestand 39 Methoden und 13 Dateisystemprüfungen. HAProxy-Zuständigkeitsprüfungen
bestanden 39 Methoden unter Erhalt von 25 bestehenden Methoden und allen Assertions.
Ein begrenzter unabhängiger Review bestand 157 Methoden in 5.016 Sekunden ohne
Findings. Zwei C-Fixture-Verfeinerungen bestanden drei vorhandene Lebensdauer-/
Mutationsmethoden in 51.935 Sekunden; alte/neue UTF-8-Smoke-Eingaben kompilierten
und erzeugten bytegleiches stdout. Die tatsächliche native Evaluator-Übersetzungs-
einheit und 59 kanonische Lighttpd-Ergebnisse behalten Parität zu 40 alten
Verträgen. Dies sind lokale Nachweise für die Quality-Folgekorrekturen. Der erneuerte
native Lauf bestand 330 Tests in 162.202 Sekunden (äußerer Aufruf: 165.353 Sekunden),
die exakten 38-Dateien-Workflow-Ruff-Lint-/Formatprüfungen bestanden und 19 Sonar-
Vertragsmethoden bestanden in 4.847 Sekunden. Die Prüfung indizierter Inventare
bestand 61 Methoden / 21 Teilfälle in 18.843 Sekunden sowie zwei tatsächliche
geschützte Kindprozesskontrollen; die frische Zulassung erfasste alle 1149
Ausführungsdefinitionen / 2461 Fälle, nicht die Ausführung dieses Gesamtkatalogs.
Alle 20 neuen öffentlichen Methoden / 47 expandierten Fälle und 20 impliziten
Auswahlablehnungen bestanden ohne Skips über die ersten 16 erfolgreichen und
vier fortgesetzten Selektoren. Der Koordinator hatte für diese vier Fixtures
zunächst das bestehende Opt-in `ON_DEMAND_TESTS=1` ausgelassen; die strenge
Skipprüfung lehnte diesen Versuch korrekt ab. Ihre korrigierten CLI-Aufrufe
erhalten sowohl `--on-demand` als auch `ON_DEMAND_TESTS=1`; Umgebungs-Opt-in allein
wurde weiterhin mit Exit 2 abgelehnt. Dafür änderten sich weder Quellen noch Tests
oder Gates. Dies sind quellgebundene Belege der Arbeits-Folgekorrekturen:
Die Framework-Revisionsumgebung des Kindes war ungesetzt, statt eine Abnahme
eines künftigen committeten Paars vorzutäuschen. Unabhängiger Review von sieben
Quellschnittstellen fand innerhalb dieses begrenzten Umfangs keinen validierten
neu eingeführten Befund. Neue Commit-Paar- und Hosted-Head-Abnahme bleiben nötig.

Die CI-Triage identifizierte drei getrennte Migrationsursachen: An der zweiten
`sudo`-/`env -i`-Grenze verliert NGINX die vertrauenswürdige Run-ID; Envoy CRS
übergibt `run_id` doppelt; Lesezugriff und Fingerprint des verschobenen
Importstatus wählen noch einen alten Produktpfad. Die erforderlichen Korrekturen
erhalten die vertrauenswürdige Run-ID über die zweite Grenze, entfernen das
Duplikat bei unverändert strengem Parser und wählen für beide Importstatus-
Operationen den ausgewählten Framework-Eigentümer. Die begrenzte Harness-Prüfung
bestand 42 Methoden in 9.615 Sekunden (14 NGINX, 28 Envoy): Die geschlossene
zweite Grenze erhält die ID und lehnt fehlerhafte Eingaben ab; alle drei echten
Envoy-Summary-Blöcke enthalten eine ID, injizierte Duplikate und abweichende IDs
werden fail-closed abgelehnt. Siebzehn vorhandene native Generatormethoden
bestanden in 0.138 Sekunden. Das tatsächliche ausgewählte Framework-Manifest
meldet 80 `former_xfail`- und 10 `mapped_only`-Einträge; Lese- und Fingerprint-
SHA-256 stimmen überein. Private Framework-/Produkt-Decoy-Kontrollen und der
bestehende `framework:`-Resolver bestanden. Dies sind lokale Grenz- und Generator-
nachweise ohne Live-Host-Lauf. Das veröffentlichte Recorded-Paar `70ce`/`8ce` und die separate DEV-Probe
bestanden; der ältere `e77`/`4391`-Beleg bleibt historisch gültig. Das frühere Source-Owner-Korrekturpaket mit 13 Dateien belegte diese lokalen Prüfungen:
Start-/Remaining-/HAP-C- sowie Common-SDK-/Security-Prüfungen wählen die echten
Framework-Make-/Quelleigentümer. Tatsächliche Common-Helfer-C/C++-Kompilierung
erhält die drei Test-Heredocs und 679 Assertions sowie zwei Framework-Ergebnis-
helfer; zwei HAProxy-Standards-Helfer kompilieren als C17. Framework-Make stellt
Shell-/Python-Lint über verschobene Pfade und Manifest wieder her und exportiert
die ausgewählte Framework-Revision. Der C++-Collector lässt nur den exakten
getrackten regulären revisionsgebundenen Framework-Evaluator zu; acht vorhandene
Methoden, tatsächlicher Bear-C++-Capture und öffentliches Parent-Make bestanden.
NGINX-Request-Window-/Case-Info-Verarbeitung bindet die zugelassene Logs-Wurzel
und unterstützt deren Geschwisterlayout: 62 vorhandene Methoden bestanden in
30.853 Sekunden bei unveränderten strengen Lesern. Die spätere gehostete
Triage auf `70ce` / `8ce` fand zwei andere Ursachen: actionlint lehnt das
überflüssige `default: false` des verpflichtenden wiederverwendbaren Lighttpd-
Inputs `on_demand` ab; rekursives HAProxy-Make löst einen relativen Pythonpfad im
Komponentenverzeichnis auf. Der Callee lässt diesen Default nun weg; der exakte
Parent-Dispatch-Default bleibt false, mit expliziter gleichnamiger Weitergabe,
verpflichtenden booleschen Typen sowie unveränderten Berechtigungs-, Pin- und
Triggerprüfungen. Acht benannte ungültige Schnittstellen werden abgelehnt. Das
quotierte vorhandene `FRAMEWORK_PYTHON` korrigiert die rekursive Grenze: Derselbe
gewählte relative Interpreter reproduzierte zuvor Error 127; danach bestand das
tatsächliche Parent-HTX-Target. Alle 22 Framework-Workflows bestanden actionlint/
ShellCheck. Erneuerte native-/Sonar-Vertragsprüfungen und die 20 öffentlichen
Selektoren bestanden wie oben begrenzt belegt.

Die erneuerte Capability-Erfassung prüft den ausgewählten Quelleigentümer:
zugeordnete Pfade liegen im Framework, nicht zugeordnete produktive Pfade im
Produkt; ein fehlendes zugeordnetes Ziel weist einen Produkt-Köder zurück.
Alle 18 Modulmethoden bestanden, einschließlich der drei benannten Varianten
der neuen Methode; die öffentliche Collector-Prüfung bestand für 6 Connectors /
60 Capability-Einträge. Dies prüft Quellverträge und belegt keine Laufzeit-
Hostfähigkeit. Erneute tatsächliche C17-Compilerläufe für Apache, NGINX und
HAProxy bestanden; der NGINX-/HAProxy-Lauf dauerte mit geprüften gecachten
Header-Eingaben 8.615 Sekunden. Die früheren fünf Source-Owner-Orakel belegten
Verdrahtung, keine vollständige Kompilierung. Die neue öffentliche Capability-
Methode bestand separat ihre 3 Varianten und 1 implizite Auswahlablehnung.
Die bisherigen 20 Methoden / 47 Varianten und 20 Ablehnungen behalten ihre eigenen
quellgebundenen Belege; ein gemeinsamer Lauf mit 21 Methoden wird nicht behauptet.
Die gehostete N28-Abnahme bleibt ausstehend; die historische `8ce`-Analyse hat
weiterhin Gate `ERROR` mit 120 OPEN-Issues.

Ein tatsächlicher Parent-Aufruf `make quick-check` bestand mit Exit 0 in
576.252 Sekunden innerhalb seiner 600-Sekunden-Grenze. Er erreichte das gesamte
vorausgesetzte Lint, das kanonische Installed-actionlint-Modul, den Lint-Diffcheck,
die Python-Kompilierung der Framework-Normalizer/-Runner-/CI-Quellen und den
abschließenden Quick-check-Diffcheck. Alle 510 Quellbindungen blieben ohne Drift
unverändert. Das Log enthält 79 bestandene Ausführungsquittungen für 18 eindeutige
Ausführungs-IDs; dies ist keine Hostqualifikation von 80 Ausführungen. Der frühere
Timeout des kombinierten Target-Aufrufs folgte aus der Aufrufannahme des
Koordinators: Parents `%`-Dispatcher startet für jedes angeforderte Target ein
eigenes Submake. Dieser Timeout war kein Quellfehler und keine Guard-Ausnahme.
Die beiden Make-Korrekturen erhalten die quotierte Weitergabe des relativen
Framework-Python und rufen Installed-Workflow-Lint über
`-m modsecurity_connector_ci.tools.lint_installed_workflows` auf; 11 fokussierte
Tests und die tatsächliche CLI bestanden. Dies belegt die lokale `70ce`/`8ce`-
Folgekorrektur, keine Abnahme eines künftigen committeten Paars oder Hosted-Heads.

Drei C++-Jobs und der native HAProxy-/Runtime-Pfad trafen auf ein nicht
erreichbares Netzwerk. Runtime hatte bereits drei Versuche; zusätzliche
Runtime-Wiederholungen werden nicht eingeführt. Native Beschaffung nutzt einen
gemeinsamen Transport mit höchstens drei Versuchen nur bei vorübergehenden
Fehlern: HTTPS/TLS und Digests bleiben verpflichtend, dauerhafte Fehler werden
nicht wiederholt und vorhandene Ziele nicht überschrieben. Tatsächliche
Prüfsummenparität gepinnter Cachearchive bestand, einschließlich des direkten
verifizierten Cachepfads ohne Netzwerk; dies belegt keine gehostete
Netzwerkerholung. Der beobachtete Apache-Job nutzte die Merge-Revision `054c`,
nicht den wörtlichen Parent-Stand `70ce`.

Vier Traefik-Source-Owner-Reparaturen erhalten alle 62 Testmethoden-ASTs; die
beiden eigenständigen Module erhalten ihre vollständigen ursprünglichen ASTs
abgesehen von wiederhergestellten Imports. Tatsächliche begrenzte native/
Dateitests (9) und private Exporttests (52) bestanden. Fünf weitere Komplexitäts-
zerlegungen bestanden dieselben 119 bestehenden Methoden vor und nach der
Änderung bei erhaltenen Guards und Assertions. Native Gitobjekt-Authentifizierung
bestand 28 Methoden in 144.687 Sekunden, 16 benannte Probes und eine Offline-
Importgrenzprüfung mit dem exakt geprüften lokalen SHA1_DC-Backend. Dies sind
begrenzte lokale/Quellnachweise, keine öffentliche Hostqualifizierung. Frischer
Standardlauf, nächstes committetes Paar und gehostete New-Head-Abnahme bleiben
getrennt nachzuweisen.

Der Umzug von 1295 Quellpfaden ist von Deduplizierung zu unterscheiden. Die
begrenzte Loader-Konsolidierung ersetzte 326 Blöcke und entfernte netto 1067
Loader-Zeilen; 29 neue gemeinsame Loader-Zeilen sind separat erfasst. Dies sind
Loader-Metriken, keine Behauptung über die gesamte Codeverkleinerung.

Schema 4 führte getrennte feste Framework-Testquellprüfsummen und
`connector_source_paths` ein. Schema 5 erhält diese geordneten Pools und speichert
`sources` jeder Ausführung als Ganzzahlindizes in den Pool aus zunächst festen
Framework-, danach Produktpfaden. Dies ersetzt wiederholte Pfade, nachdem das
frühere JSON sein Budget beinahe ausgeschöpft hatte; Abhängigkeiten oder Auswahl
werden nicht entfernt. Schemas 1–4 bleiben kompatibel. Boolesche, unbekannte,
doppelte und ungenutzte Referenzen werden abgelehnt. Sowohl rohe JSON-Eingabe als
auch expandierte UTF-8-Quellpfadbytes sind auf 2097152 Bytes begrenzt; die
Expansionsgrenze wird vor Materialisierung oder Quelllesezugriffen geprüft. Die
Grenze von 100 Standardfällen bleibt unverändert. Pflege erhält Indexreihenfolge
und atomare Aktualisierung. Produkteingaben werden aus der explizit gewählten
Revision erfasst, im Beleg aufgeführt und vor/nach Ausführung erneut geprüft.
Collector-Änderungen verlangen weiterhin eine geprüfte feste Prüfsumme;
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
werden getrennt vom Werkzeugrepository nachverfolgt. Archiv- und Map-Ausgaben
wurden zum dokumentierten Quellenfreeze in dieser Reihenfolge regeneriert; beide Generatorläufe mit
`--check` bestanden und erhielten alle 1993 ursprünglichen Fall-IDs. Auch der
Bindungs-`--check` und die öffentliche CLI-Inventarzulassung bestanden bei diesem
Freeze. Die jüngste Quellclosure-Registrierung der vier Kontextmethoden ist ein
getrennter Quellbeleg. Die obigen
kanonischen Inventarzahlen beschreiben Auswahl, keine erfolgreiche Ausführung.


Die aktuelle Integration übernimmt außerdem Connector-Master `ee134` aus
[Connector-PR #433](https://github.com/Easton97-Jens/ModSecurity-conector/pull/433)
über den regulären Merge `8c7e8c44`. Alle 1993 Baseline-Fallobjekte des aktuellen
Masters stimmen exakt mit ihren Framework-Gegenstücken überein. Ursprüngliche
unveränderliche Baseline-Identitäten bleiben von dieser späteren Integration getrennt.

Die separat veröffentlichte MRTS-Paketkorrektur `197df49` bestand 99 Methoden in
73.152 Sekunden; unabhängige Definitionsdurchläufe und Prüfungen der
Dateideskriptorparität bestanden. Dies ändert Framework-Paketierung und Guards;
`tools/MRTS` bleibt gepinnt und schreibgeschützt. Der neueste native Framework-CI-
Lauf bestand 339 Methoden in 162.706 Sekunden. Tatsächliche begrenzte Läufe
bestanden außerdem 54 Common-Kontrollen, 29 portable Kontrollen, 23 CRS-Kontrollen
und 13 Launcher-Kontrollen. Dies sind getrennte Suiten; ihre Anzahlen erhöhen
nicht die eindeutigen Inventarfallzahlen.

Für alle nativen Framework-Lint-Rezeptschritte liegen bestandene Beobachtungen
aus dem erhaltenen Gesamtlauf und fokussierten Reparaturen/Fortsetzungen vor.
Der ursprüngliche einzelne Gesamtlauf bleibt mit Exit 2 dokumentiert; dies ist
kein einzelner vollständig grüner Lint-Lauf. Getrennt davon bestanden 66
Sicherheitsmethoden / 238 Teilfälle ohne Skips. Korrekturen an Runtime-Root-
Ownership, fehlenden Run-IDs und Namespaces haben einen begrenzten PASS mit 34
HAProxy-/Lighttpd-Kontrollen. Die frische Envoy-Suite bestand alle 28 ursprünglichen Methoden in 9.446 Sekunden;
alle Methoden-IDs und Assertion-Anzahlen bleiben erhalten. Nach der minimalen
Produkt-Rezept-Fallback-Korrektur bestanden vier tatsächliche `make -n`-Kontrollen:
Standard, `MS`-Fallback, explizite `RULES`-Priorität und widersprüchliche
`RULES`/`MS` beim Companion. Das Productstatus-
Change-Record-Paar besteht nun die tatsächliche strukturelle Parent-Prüfung des
ganzen Archivs; diese belegt keine Runtime- oder CI-Aussagen.

Die minimale NGINX-Configure-Probe bestand mit vorhandenen checksum-verifizierten
Archiven; die SDK-Korrektur nutzt das tatsächliche `BUILD_ROOT`-SDK mit expliziten
Include-/Library-Pfaden. C-Family-Bytegleichheit beschreibt diese frühere reine
SDK-Phase. Anfängliche Byte-Erhalt-Aussagen einschließlich der 35 Go-Dateien
betreffen den ersten Transfer; spätere explizite C-/Go-Verfeinerungen nutzen die
oben genannten semantischen Nachweise. 11 bestehende Kontexttests und vier negative CLI-Kontrollen bestanden
ebenfalls. Configure-Erfolg belegt diese Build-/Konfigurationsschicht, keinen
Laufzeit-Lifecycle. Die tatsächliche C-Family-Erfassung wurde nach der Zerlegung zweimal abgeschlossen:
81 Übersetzungseinheiten erzeugten 81 eindeutige Objekte; beide Läufe bestanden
in 38.241 beziehungsweise 37.935 Sekunden. Dies sind Übersetzungseinheiten und
Objekte, keine Testmethoden oder zusätzlich ausgewählten Fall-IDs. Die exakte Standardverteilung beträgt 76 C17-, 4 C++17- und 1 ursprüngliche
Smoke-C99-Übersetzungseinheit. Jeder Compileraufruf behält `-Wall -Wextra -Werror`
ohne `-Wno`-Option; der ursprüngliche Smoke-Standard bleibt unverändert. Generierte HAProxy-/Lighttpd-Includes nutzen dieselben gepflegten
ursprünglichen Übersetzungseinheiten und exakten Produktextraktionen in tatsächlichen
Tests und Erfassung. Alle 28 bestehenden Builder-Testmethoden-ASTs und nativen
Funktionskörper bleiben erhalten; fünf frühere Kommentarmarker enthalten nun echte
Includes. Auch die finale Erfassung mit exakten Quellhashes nach AST-identischer
Formatierung und Zulassungsreparatur bestand alle 81 Einheiten in 36.126 Sekunden.
Die unabhängige Prüfung bestand acht Tests und prüfte alle 81 Objekte.

Die Produktanalyse-Eingabe des Sonar-Workflows muss den kompatiblen veröffentlichten
Migrationscommit `cfd5e49cada3fc793ef50993147e3796a0907443` verwenden. Der Stand
`ee134` vor der Migration enthält doppelte Testhelfer und eignet sich nicht für
diese gemeinsame Analyse. Die Auswahl nutzt weder ein Produktsubmodul noch einen
umgekehrten Framework-Pin. Die unabhängige Prüfung von NGINX-Wrapper und Secret-
Verdrahtung bestand sechs Tests. Der neue fokussierte Lauf bestand alle
36 Methoden in 246.637 Sekunden. Sechs Module mit Namespace-Reparaturen erhalten
71 bestehende Methoden und alle 234 Assertion-ASTs. Ihre neuesten Ergebnisse je
Methode sind 71 PASS: Das Worker-Modul hatte zunächst sechs Sandbox-UID-Mapping-
Skips und bestand anschließend außerhalb der Linux-Sandbox alle 21 Methoden
in 20.519 Sekunden mit unveränderten Guards, einschließlich der sechs tatsächlichen
Root/nobody-Deskriptorfälle. Diese Beobachtungen sind kein gemeinsamer Final-Head-
Suitenlauf und führen keine Fall-IDs ein. Das genannte committete Paar bestand
separat; nach den nächsten Pins bleiben erneute Paarabnahme und gehostete Gates
für Framework-PR #142 / Connector-PR #434 erforderlich. Die historische Sonar-Analyse von Connector
`e77c833eef4b23e1252dbcd4c6507ded0b7e2064` bestand alle fünf Gate-Bedingungen mit
2.0% Duplikation, null ungelösten Issues und null TO_REVIEW-Hotspots. Dies ist
kein Sonar-PASS für Parent `70ce`: Die letzte Rücklesung analysierte weiterhin
`e77`. Das historische Framework `4391` hatte zunächst 280 Issues und nach acht
nutzerautorisierten einzeln belegten Fehlalarmen 272. Die historische Framework-
Analyse von `8ce35c1108d753986b11cb011d24fc99f262f112` um 16:46:21 UTC hatte
Zuverlässigkeit A, Wartbarkeit A, 0.0% Duplikation und keine Hotspots, aber Security
E und Gate `ERROR`; ihr erstes vollständiges Issue-Inventar enthielt 178 ungelöste
Findings. Diese Anfangszahl ist kein aktueller Restbestand. Nutzerautorisierte
issuespezifische Kommentare und Serverrücklesungen bestätigen getrennt die
bisherigen acht, 24 nativen, 16 Python- und weiteren 16 nativen Vertrags-
Fehlalarmdispositionen. Zwei weitere Lifecycle-Modellfehler erhöhen die einzeln
belegte Gesamtzahl auf 66. Die zusätzlichen 16 nativen Vertragsdispositionen
betreffen vier Controller- und zwölf ABI-Modellfehler; elf tatsächliche C17-
Typ-Probes bestanden mit drei positiven und acht Const-Inkompatibilitätskontrollen.
Die vollständige Serverrücklesung um 18:38:27 UTC für die `8ce`-Analyse vom
16:46:21 UTC zeigt 120 OPEN-Issues und null Hotspots; Gate `ERROR` und Security E
bleiben bei Zuverlässigkeit A, Wartbarkeit A und 0.0% Duplikation. Die zwei neuen
individuellen Rücklesungen betreffen `_7KT`s schreibgeschützte Post-Link-
`TMPDIR`-Provenienz, keine Zulassung vor Compiler-Ausführung, und `_7MD`s
synchronen `re.subn`-Callback. Alle 10 CLI-Autoritätsfragen bleiben offen; diese
Dispositionen lassen keine Compilerargumente oder Werkzeuge zu. Die optionale Coverage-Bedingung meldet OK,
ohne damit eine neue Coverage-Menge zu belegen. Python `_7Lu` und alle anderen
unsicheren Findings bleiben offen; es gibt weder pauschale Disposition noch
Risikoakzeptanz oder Regeländerung. Sonar-Kategorien sind keine unabhängig
validierten Exploits. Beide Migrations-PRs bleiben Draft und ungemergt; das nächste
committete Paar und tatsächliche Analysen/Gates des neuen Heads bleiben erforderlich.

Gitleaks-Baseline-Beobachtungen und geprüfte Fehlalarmklassifikation sind
getrennt. Die aktuelle Konfiguration enthält zwei `generic-api-key`-Allowlists,
die jeweils zugleich den exakten öffentlichen SHA und seinen geprüften Pfad
verlangen (AND-Verknüpfung). Der Rohbeleg mit 70 öffentlichen Hash-Fehlalarmen
und acht positive/negative Kontrollen bleiben erhalten. Frühere Baseline-Scans
ohne Unterdrückungen bedeuten nicht, dass die aktuelle Konfiguration keine
Allowlists enthält. Die tatsächliche Remote-CI-Prüfung dieser Konfiguration steht
noch aus; Zugangsdaten oder Kundennutzdaten sind in versionierten Belegen unzulässig.

Der Entwicklungsversuch mit Connector `8c7e8c44` und Framework-Komposition `1aef2`
wurde wegen einer veralteten MRTS-Paketquellbindung korrekt abgelehnt. Er bleibt ein
abgelehnter Versuch. Die finale Quellbindungsaktualisierung sowie spätere Proben
des committeten und des expliziten Entwicklungspaars bestanden separat. Das frühere eingetragene
Paar `cfd5e49` / `e52d7d4` und seine drei beobachteten Apache-Kontrollen behalten
nur ihren ausdrücklich dokumentierten Geltungsbereich.


Die separat ausgewählte reine Backend-Isolationsregression lautet
`offline.migration.prepared-backend-imports-are-isolated-and-reject-tampering`
(`DiagnosticTests.test_prepared_backend_imports_are_isolated_and_reject_tampering`).
Sie bestand über den bestehenden Offline-Hook eine Methode mit fünf Teilfällen
und ohne Skips. Der AST der ursprünglichen Methode für deklarierte Fälle wurde
exakt wiederhergestellt; die neue Logik erhält fünf eigene On-demand-Fall-IDs
und erweitert keine alte ausgewählte Schleife.

Die NGINX-Produktkorrektur der Beobachtbarkeit in Commit `1c1` erfasst nur einen
bekannten Requestfehlerstatus 400..599, andernfalls null, vor dem unveränderten
Timeout-504-Override. Nicht beobachtbarer Transport, sichtbarer Status null und
leere tatsächliche Aktion bleiben erhalten. Echter extrahierter Producer und
exakte Consumer bestanden nach sechs roten Statusvarianten 28 Methoden/
156 expandierte Teilfälle; die 26 bestehenden Bundle-Methoden bestanden ebenfalls.
Interne Pointerfehler verlangen kanonisch `connector_error`,
`MSCONN_EVENT_CONNECTOR_ERROR`, typisiertes `request_headers` und HTTP500;
fehlerhaftes Client-Framing bleibt HTTP400/Protokollfehler. Drei neueste
tatsächliche H1-Treiber bestanden nach einem 198.789-Sekunden-Build auf Produkt
`1c1`. Die zusätzliche Artefaktleserreparatur für bestehende Helfer erlaubt nun das
strenge Wiederöffnen beider frischen Fehlerbundles mit anschließender Projektion
und Vertragsableitung. Der unten beschriebene ausgewählte Entwicklungsnachweis
belegt weder einen vollständigen Lifecycle noch ein Gate des finalen committeten Paars.

Die aktuelle Merge-Freigabe des Nutzers gilt nur bei sauberer Sonar-Analyse,
keinen neuen offenen Findings und bestandenen Pflicht-Gates. Ein Cloud-Gate des
aktuellen Heads oder ein Migrationsmerge wird hier nicht behauptet.


Der zweite explizit ausgewählte reine Guard,
`NativeBundleRouterTests.test_worker_self_maps_require_exact_helper_and_paired_ledger`,
bestand eine Methode mit sieben Teilfällen und ohne Skips. Die beiden neuen
reinen Selektoren deklarieren somit fünf beziehungsweise sieben Teilfälle
getrennt. Beide bestanden über die öffentliche CLI ohne Skips; die Auswahl
jedes Selektors ohne `--on-demand` wurde mit Exit 2 abgelehnt. Nur das redundante Präfix `Migration regression: ` wurde aus 360
Prüfzwecken neuer Fälle entfernt, um die Inventargrenze von 2 MiB einzuhalten;
alle 1993 ursprünglichen Baseline-Falldictionaries bleiben unverändert.

Frische echte NGINX-H1-Nachweise bestehen nun die ausgewählte vollständige
Prüfkette: Baseline HTTP 200, beide internen Pointerfehler HTTP 500, identische
34-Quellen-Hashmengen vor dem Start/im Envelope/nach der Ausführung sowie den
öffentlichen strengen Bundle-Reader, die Projektion und Vertragsableitung. Beide
Fehlerbelege behalten `layer_verified=true`, `errors=[]`, kanonisches
`connector_error`, typisiertes `request_headers` und ganzzahliges HTTP 500. Der
Beleg nutzt Produkt `1c1c71459ce13fc4e2741dd6c30e671cfcbe55a0` und explizite
Framework-Entwicklungsquellen `1aef2c2268aeb38425aec1da7661baf6c449de25`; der
eingetragene Framework-Gitlink bleibt `e52d7d44c81e997a296b7ffdfb33f12bf85455b9`.
Dies ist Entwicklungs-Evidence für drei ausgewählte Fälle, keine Abnahme des
finalen committeten Paars oder aller 42 nativen Fälle. Erhaltene rohe Ergebniszeilen
bleiben `NOT_EXECUTED`; Schichtbelege erfinden keine kanonische Ergebnis-Promotion.
Die 13 blockierten Standardausführungen mit ihren 26 Fällen bleiben im getrennten
Standardledger unverändert.

Das MRTS-Followup [Framework-PR #141](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/141)
wurde unter der bedingten Nutzerfreigabe gemergt: Der exakte Head `197df49` wurde
als `f5a0940c56edbb94d55d309636ce3d6f501e31a2` gesquasht. Alle 16 Actions-Checks
waren terminal (13 erfolgreich, 3 beabsichtigte beratende Skips); Sonar bestand
für diesen Head alle fünf Bedingungen bei null OPEN/CONFIRMED-Issues und null
TO_REVIEW-Hotspots. Der gemergte Master hat 9 terminale Checks: 8 erfolgreich
und einen bestehenden eventabhängigen Skip. Der veröffentlichte reguläre Framework-Master-Merge
`5a827f3db670588febebd29fa6115142da198c6f` erhielt den geprüften Tree `8037cff4`.
Dies belegt weder das Current-Head-Gate des Migrations-PRs noch die Abnahme nach
späteren Pinänderungen.

Frühere begrenzte Prüfungen bestanden außerdem 18 Sonar-Vertragsmethoden
in 4.966 Sekunden und 39 pinabhängige Methoden / 56 expandierte Varianten.
Formatierung zweier bestehender CI-Testdateien erhielt deren ASTs; alle 38 Ruff-
Dateien bestanden. Lokales Pyright bleibt wegen fehlendem Node blockiert, ohne
Installation; sein gehostetes Typ-Gate bleibt erforderlich. Der Cleanup privater Kandidatenausgaben wurde mit einem exakten privaten
externen temporären Root und `CONNECTOR_TEST_OUTPUT_ROOT` im Kindprozess
korrigiert; bestehende Assertions und öffentliche Evidence bleiben erhalten.
Der Postpatch-Lauf bestand 50 Methoden / 160 Teilfälle bei einem veralteten
Quellbindungsfehler; nach Bindungsaktualisierung bestand die verbleibende
Integrationsmethode in 31.859 Sekunden ohne Skips. Damit liegen bestandene
Beobachtungen aller 51 Methoden / 160 Teilfälle über diese Läufe vor, kein
einzelner vollständig grüner Lauf.

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
Hostfähigkeit. Ein früherer NGINX-H1-Versuch war mit Exit 77 blockiert, weil die benötigte
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
Das committete saubere Paar Connector
`70cefa5706b1a8339046f3f3d1f77ea9493f3cd0` / Framework
`8ce35c1108d753986b11cb011d24fc99f262f112` bestand in 125.528 Sekunden im Recorded-
Pin-Modus mit `standard_combination=true`, beiden Checkouts sauber vor/nach dem
Lauf und bestandenem tatsächlichem Parent-Make → Common-C1-Test.

Ein getrennter expliziter DEV-Lauf bestand mit demselben Connector und gewähltem
Framework `e52d7d44c81e997a296b7ffdfb33f12bf85455b9`, eingetragenem Gitlink
`8ce35c1`, in 123.950 Sekunden mit `mode=development` und
`standard_combination=false`. Nur der erwartete Connector-Gitlink wich vor/nach
dem Lauf ab; Framework blieb sauber. Die echte UID-1001-Bridge stellte 11 Exporte
bereit, erhielt privaten Ausgabemodus 0700 und lehnte den falschen Pin mit Exit
77 ab. Alle 90 Updater-Methoden / 216 Teilfälle bestanden ohne Skips über Läufe
mit 39 Methoden (90.988 Sekunden) und 51 Methoden (77.711 Sekunden). Diese Belege
gelten für genau dieses veröffentlichte Paar vor den neuesten Schnittstellen-,
Transport- und Indexinventaränderungen. Sie nehmen das nächste committete Paar
nicht ab. Frühere Recorded-/DEV-Belege für `e77` / `4391` (126.317 / 123.559
Sekunden), der abgelehnte veraltete DEV-Versuch und Apache H1 auf `cfd5e49` /
`e52d7d4` (28.625 Sekunden) behalten ihren historischen Umfang. Abnahme nach den
nächsten Pins und aktuelle gehostete Gates für Framework #142 / Connector #434
bleiben erforderlich. Belege bleiben in privatem externem Speicher; versionierte
Belege enthalten keine Kundennutzdaten oder Zugangsdaten.

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
integriert werden; Merge bleibt an die bedingte Nutzerfreigabe und alle Pflicht-Gates gebunden. HTTP/2,
HTTP/3, Coverage und vollständige Abhängigkeitsprüfung bleiben bis
auf erforderliche Pfad- und Aufruferanpassungen außerhalb dieser Migration.

Die zweisprachigen Change Records unterscheiden ausgeführte Prüfungen, Fehler,
Blocker und nicht ausgeführte Prüfungen. Statische Checks, native
Primitivtests oder Produktbuilds belegen keinen gehosteten H1-Lifecycle und keine
Promotion des aktuellen HEAD.

## N28-Quelländerungen und aktuelle Nachweisgrenzen

N28 extrahiert begrenzte Helfer für Migrationsmap-Erzeugung, Inventarzulassung,
Wartung, native Erfassung, Beobachtungen und Ergebnisprojektion; bestehende
Selektoren und Assertions bleiben erhalten. Die Argumentzulassung verhindert,
dass Make-aktive Interpreterpfade sowie Archiv-Responsefile-/Optionsoperanden
ihre nachgelagerten Parser erreichen. Bestehende benutzerdefinierte
Unicode-Interpreterpfade bleiben unterstützt.

Das private native Eventfixture hält zugelassene Verzeichnisdeskriptoren und
räumt relativ zu seiner geöffneten Wurzel auf. Seine 2 explizit prozessausführenden
Methoden / 6 Fälle bestanden tatsächlich mit strengem C17 und Deskriptordelta
null. Der reparierte Zweig für root-eigene Eltern-/Leafpfade nutzt vor dem
Identitätswechsel einen gehaltenen Arbeitsverzeichnisdeskriptor und feste
relative Eventpfade. Der vollständige Zweig für UID 65534 war lokal
**NOT_EXECUTED**, weil erforderliche UID-Abbildungen/Berechtigungen fehlten.
Statische Prüfung und Pfadkontrollen mit aktueller Identität ersetzen diesen
Zweig nicht. Die Prozessmodul-Allowlist wächst explizit von 12 auf 13.

Go-Capture lässt private Quell-/Ausgabewurzeln vor dem Compileraufruf zu, lehnt
Responsefiles sowie mehrdeutige/überschreibende Ausgabeargumente ab und hält Bytes
über eigene Deskriptoren. Die Deskriptorverantwortung bleibt auch bei Fehlern der
Stream-Wrapper-Konstruktion erhalten. Die Fehlerbehandlung löscht keinen
ersetzten Namensraumeintrag; private unvollständige Artefakte können zur
expliziten Prüfung zurückbleiben. Konsumenten müssen zusätzlich zur
Artefaktintegrität einen erfolgreichen Producerstatus verlangen. Die 12 neuen
Methoden / 31 Fälle decken dieses begrenzte Verhalten ab. Die separate Frage
`_7KV` zur Berechtigung der Werkzeugauswahl bleibt OPEN; diese Datenpfadreparatur
autorisiert keine beliebige Compilerauswahl.

Beide NGINX-Fixtureaufrufer öffnen die Quelle nun über einen vertrauenswürdigen
Nofollow-Vorfahren-FD-Walk, kopieren höchstens **67108864 Bytes (64 MiB)** in einen
privaten `BytesIO`, hashen die kopierten Bytes und extrahieren dasselbe Objekt.
Ein Austausch des Quellpfadnamens nach dem Hashen kann die extrahierten Bytes
nicht ändern. Das tatsächlich gepinnte Archiv `nginx-1.31.6` umfasst
**1373124 Bytes**. Die komprimierte Eingabegrenze ist neu; sie begrenzt den
Archivinhalt, nicht den gesamten RAM oder extrahierte/unkomprimierte Daten.
Python-Puffer-/Kopieroverhead kommt hinzu. Es entsteht keine neue Anforderung
an `O_TMPFILE` oder Dateisystemunterstützung. Bestehende Prüfungen für Memberzahl,
Traversal, Links und Geräte bleiben erhalten. Eine fehlgeschlagene
Archivzulassung kann die deterministische Taskwurzel zurücklassen; ein erneuter
Versuch mit derselben Wurzel scheitert geschlossen. Unsichere automatische
Bereinigung wird nicht ergänzt. Die 18 neuen Methoden / 27 Fälle führen kein
nicht vertrauenswürdiges Fixture-`configure`-Skript aus.

Sechs bestehende Collectortests benötigten ebenfalls Migrationsabgleich. Vier
synthetische Quellzeilen ließen die bereits im Event vorhandene Transaktions-ID
aus; der unveränderte Collector lehnte das Ausleihen dieser Events korrekt ab.
Die Fixtures enthalten nun die jeweils passenden IDs. Zwei weitere Tests prüfen
den Framework-eigenen Artifact-Stager-Pfad und lesen die ausgewählte
`connector_suite/connector.mk` für die bestehenden Protocol-Client-Assertions.
Alle 44 Methoden, 190 Assertions und 3 Subtest-Aufrufstellen bleiben erhalten.
Kopierte Fixturesnapshots wechselten sechs RED-Ergebnisse zu sechs GREEN-
Ergebnissen. Die frische kanonische Ausführung bestand nun die reparierten sechs
und zwei bestehende Transaktionsisolationstests ohne Skips. Die ersten fünf
Reparaturen und beide Isolationstests bestanden reine Guards mit null Effekten;
die Script-Ablehnungsmethode bestand ihre explizite Prozessgrenze mit einem
Effekt und ohne Quellschreibzugriffe. Ihr früherer irrtümlicher Aufruf mit reinem
Guard scheiterte korrekt und bleibt dokumentiert; die Methode wird nicht als
rein bezeichnet. Keine Provenienz-, Runtime- oder Audit-/Scrubbing-Prüfung wurde
abgeschwächt.

Die aktuellen direkten Läufe bestehender Verträge bestanden 112 Inventar-/
Wartungsmethoden / 80 Subcases und 75 Workflow-/Native-Vertragsmethoden /
163 Subcases. Die separate Result-Runner-Gruppe hatte vor der Fixturereparatur
sechs reproduzierte bestehende Fehler und drei Skips wegen der Voraussetzung
eines sauberen Frameworks im geänderten Worktree. Diese Skips sind kein PASS;
ein PASS der gesamten Gruppe oder einer vollständigen On-demand-Kampagne wird
nicht behauptet. Separat bestand der öffentliche Runner die 37 neuen Methoden /
79 Fälle in 166.939 Sekunden. Die 2 Kontrollen ohne CLI-Opt-in bestanden sogar
mit `ON_DEMAND_TESTS=1`; die 2 bestehenden NGINX-Auswahlen mit sofortigem Import
bestanden in 15.578 Sekunden. Die Zulassung bestand in 6.06 Sekunden. Diese
Belege binden Inventar
`34f3e84ab90e69de85f0b9e042bebc965fde0f34af496f471c74bcde37583ea5` vor zwei
späteren unabhängigen Produktimport-Reparaturen. Die exakte Rekonstruktion gegen
das finale Inventar
`dc5980db497faa5ba6885f71552a8555c7bcd96f1ec759a0c4c786e76aec308e` beweist:
Nur ein alter Revisionstest-Quellhash änderte sich außerhalb aller 37 ausgewählten
Closures; jedes ausgewählte Quell-/Fallfeld ist identisch. Aus dieser unabhängigen
Hashaktualisierung wird weder eine Wiederholung der 37 Methoden abgeleitet noch
eine solche erforderlich. Kein früherer Skip der breiteren Suite wird in PASS
umgedeutet.

Der tatsächliche kanonische Go/CGo-Native-Producer bestand offline in
146.568 Sekunden mit 84 Übersetzungseinheiten: 62 Produkteinheiten und
22 Kontexteinheiten sowie 73 Produktheadern. Die erfassten Eingabehashes blieben
stabil. Der 32-Byte-FIPS-Übergang und Build-ID-Replay entsprachen dem finalen
Artefakt; dies ist keine FIPS-Zertifizierung. Die Validierung verzeichnet explizit
`development_only=true` und `import_eligible=false`. Das native Programm wurde
nicht gestartet; daraus folgt kein Host-Runtime- oder gehosteter Sonar-PASS.
Nach den gewählten Produktimport- und Legacy-/Migriert-Verifier-Markerreparaturen
bestanden alle 11 alten Go-Versionsmethoden / 25 Subcases und 4 alten
Capture-/FIPS-Methoden ohne Skips. Die 5 aktiven Go-Versionszeilen haben keine
Closure-Lücken. Die aktuelle kanonische native CI bestand 330 Tests in
170.503 Sekunden. Die exakte Workflow-Auswahl für Ruff-Lint/-Format mit 38 Dateien
bestand in 0.324 Sekunden; 19 Sonar-Vertragsmethoden bestanden in 5.139 Sekunden.
Die tatsächliche Kompilierung aller 81 ausgewählten Übersetzungseinheiten
bestand in 40.57 Sekunden, einschließlich erzeugter Objektdateien für alle
4 geänderten Framework-C-Fixtures unter C17 mit `-Wall -Wextra -Werror`.
Dieser Lauf verwendet die unveränderliche Produkteingabe
`cfd5e49cada3fc793ef50993147e3796a0907443`, statt den gesamten aktuellen
Produktbaum. Der Vergleich von 223 Produkteingaben fand eine Abweichung: die
zwei bestehenden Statuszeilen in
`connectors/nginx/src/ngx_http_modsecurity_access.c`. Diese aktuelle
Übersetzungseinheit bestand separat strenges C17 mit `-Wall -Wextra -Werror` in
0.559 Sekunden und erneut in 0.666 Sekunden nach dem Snapshot aller 349
tatsächlichen Eingaben. Der wiederholte Objekt-SHA ist identisch. Ihre 348 Header
blieben hashstabil: 6 aktuelle Produktheader identisch zur unveränderlichen
Eingabe, 24 unveränderliche Produktheader, 93 gecachte SDK-/NGINX-Header und
225 Systemheader bei null Kontextabweichungen. Dieser separate Nachweis für die
aktuelle Einheit benennt den ursprünglichen Lauf mit 81 Einheiten nicht um.

Die zwei reinen Importkorrekturen bestanden außerdem 19 bestehende
Revisionsmethoden / 51 Subcases ohne Skips sowie Report-CLI-`--help` und
Importprüfungen. Alle 25 beziehungsweise 112 ursprünglichen Funktions-ASTs der
jeweiligen Module bleiben exakt; kein Report wurde generiert. Keine aktive
Zeile ist betroffen; der eine indirekt gebundene Testhash wurde aktualisiert.
Die 37 öffentlichen Quell-Closures bleiben durch diese unabhängigen Korrekturen
unverändert. Alle sechs finalen Generatoroperationen bestanden nach dieser
Aktualisierung; die frische vollständige Zulassung bestand in 5.327 Sekunden.
Staging/Gitleaks, Commit/Push des Paars und gehostete CI-/Sonar-Prüfung für exakt
diesen Stand stehen aus. Diese lokalen
Ergebnisse belegen weder gehostete Gates für exakt den aktuellen Head noch
Mergefähigkeit.

Das veröffentlichte Paar Connector `1f213858ae059d77a84a4bf500b9e90f025e15fe`
und Framework `cb129a45ccfd033fa5aafd08ca0dc7d9ec731e49` hat getrennte reale
Abnahmen für Recorded-Pins (151.690 Sekunden) und expliziten DEV-Modus
(151.493 Sekunden). Der Recorded-Lauf nutzte saubere Klone mit
`standard_combination=true`; DEV wählte Framework
`8ce35c1108d753986b11cb011d24fc99f262f112`, verzeichnete
`standard_combination=false` und behielt nur die erwartete Gitlink-Abweichung.
Die tatsächlich versiegelte UID-1001-Bridge bestand mit 11 Exports/privatem Modus
0700; Wrong-Pin-Kontrollen lieferten 77 ohne Exports. Alle 90 Updatermethoden /
216 Subcases bestanden. Diese Nachweise gelten für dieses veröffentlichte Paar,
nicht für den unveröffentlichten N28-Folgecommit oder einen finalen Host-Lifecycle.

Die neueste vollständige Framework-Sonar-Analyse um `2026-10-30T19:04:35Z`
analysiert `cb129a45ccfd033fa5aafd08ca0dc7d9ec731e49`. Das letzte vollständige
Issue-Inventar, gelesen um `2026-10-30T19:35:24Z`, enthielt **115 OPEN-Issues**,
Gate **ERROR** und **0 TO_REVIEW-Hotspots** vor der jüngsten Einzeleinstufung.
Eine neue vollständige Issue-Zahl nach dieser Einstufung wird nicht behauptet.
Parent `1f213858` hat weiterhin die veraltete Analyse von `e77c833`. Die
dokumentierten einzelnen False-Positive-Einstufungen summieren sich nun auf
**67**, einschließlich des nativen Git-Objektidentitäts-Sinks mit festen
Argumenten und vollständiger Kommentar-/Statusrücklesung. Sieben weitere Fragen
zur Werkzeugautorität bleiben OPEN. Ungeklärte Findings bleiben offen; keine
Regel und kein Quality Gate wird abgeschwächt. N28 besitzt
noch keinen veröffentlichten neuen Head und kein gehostetes Gate für exakt
diesen Stand. Framework-PR #142 und Connector-PR #434 bleiben Draft und
ungemergt. Die bedingte Master-Integration setzt sauberes Sonar für den exakten
aktuellen Head, keine neuen offenen Findings und sämtliche erforderlichen
CI-/Review-Bedingungen voraus; Mergefähigkeit wird nicht behauptet.
