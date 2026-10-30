# Change Record: CR-20261030-test-ownership-migration

**Sprache:** [English](CR-20261030-test-ownership-migration.md) | Deutsch

## Identität

| Field | Value |
| --- | --- |
| Change-ID | CR-20261030-test-ownership-migration |
| Datum (UTC) | 2026-10-30 |
| Basis-Revision | `3a4f2281568139d94fda6b51dc2e07bb8fc06c67` |

## Motivation und Problemstellung

Sämtliche Connector-Tests und Testinfrastruktur müssen ins unabhängige
Framework wechseln. Connector behält produktiven Code/Build/Delivery und kleine
gepinnte Integrationsaufrufe. Getrennte Worktrees erhalten die Originalcheckouts.

## Betroffene Komponenten und Sicherheitsgrenzen

Explizite `TEST_ROOT` und `CONNECTOR_ROOT` trennen Testmechanik und geprüftes
Produkt. Schema 4 bindet Framework-Quellhashes fest und Produktquellsnapshots an
die ausgewählte exakte Revision. Begrenzte Produktquellimporte ersetzen einen
globalen Connector-Importpfad. Geschützte Ausführung authentifiziert geschützte
Parent-Gitobjektkette und gepinnte Framework-Quelle vor der Codeauswahl.
Erforderliche Gates, Hostisolation und Quellauthentizität dürfen nicht umgangen
werden. Kundenpayloads und Zugangsdaten gehören nicht in versionierte Evidence.

Der vorgelagerte [Framework-PR #139](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/139)
und [Connector-PR #432](https://github.com/Easton97-Jens/ModSecurity-conector/pull/432)
sind bereits gemergt. Der Task übernahm die Framework-Upstream-Basis
`1d1e73fb069598e0f0f809d0bf16b5e59047ff88`; Taskänderungen und Backups blieben
durch Dreiwegeabgleich erhalten. Diese Upstream-Integration ist von der Lieferung
der Migrations- und MRTS-bezogenen Framework-Pakete getrennt.

## Akzeptanzkriterien

Die erhaltene Auswahlbasis umfasst 100 Standardfälle / 80 Ausführungen und
1893 On-demand-Fälle / 839 Ausführungen. Neue Migrationsregressionen bleiben auf
Abruf; die Standardgrenze bleibt 100. Testidentitäten, Assertions und Zählung
unterschiedlicher Fälle müssen erhalten bleiben. Produkt-Builds dürfen keine
Framework-Laufzeitabhängigkeit erhalten. Framework-Delivery geht dem abhängigen
Connector-Pin voraus; die aktuelle Nutzerfreigabe erlaubt Merge nur bei sauberer
Sonar-Analyse, keinen neuen offenen Findings und bestandenen Pflicht-Gates.

## Untersuchte Alternativen

Connectorspezifische Tests im Parent oder ein umgekehrtes Connector-Submodul
würden die unerwünschte geteilte Ownership erhalten. Globale Produktimportpfade
erlauben Kandidatendateien, vertrauenswürdige Module zu überdecken. Explizite
Quellcheckout-Schnittstellen, Quelldomänenzulassung und externe Overlays vermeiden
diese Varianten.

## Implementierungsentscheidung

Framework besitzt migriertes `connector_suite/`, `connector_native_tests/`,
gemeinsame öffentliche Adapter-/Quellschnittstellen, Ergebniskorrelation und
exakt gepinnte CI-Actions. Das Mapping erhält logische Quellidentitäten bei
eindeutigen physischen Paketnamespaces. Produktcode ist expliziter revisionsgebundener
Input, keine Framework-Laufzeitabhängigkeit und kein Submodul.

Die genannten nativen/Komponentenergebnisse belegen weder Host-Requestverkehr
noch Produkt-Promotion. Apache-Duplikatheader werden explizit an beobachtete
zusammengeführte Werte angepasst; HTTP 200, Regel `1100504` und Auditassertions
bleiben erhalten. NGINX-Tests interner Pointerfehler verlangen HTTP 500 /
`phase1_error` / `MSCONN_EVENT_CONNECTOR_ERROR` / `reason=connector_error`;
fehlerhafte Clienteingabe behält HTTP 400. Dies korrigiert veraltete Testverträge
ohne Abschwächung des Produkts.

## Geänderte Dateien und Tests

`connector_suite/` enthält migrierte Tests, Adapter, Fixtures, Inventar,
Provisionierung, Evidence-/Reporttools und Pfad-/Fallmaps. `connector_native_tests/`
enthält extrahierte native Programme und ihr Quellmanifest.
`modsecurity_test_framework/`, `tests/runners/`, `tests/normalizers/`, `ci/`,
`.github/actions/` und `.github/workflows/` integrieren explizite Roots, sichere
Importe, Korrelation und authentifizierte Orchestrierung. Neue Regressionen bleiben
auf Abruf.

Dokumentationspaare: `docs/connector-test-suite`, `docs/connector-integration`,
`connector_suite/modsecurity_connector_ci/README`,
`connector_suite/modsecurity_connector_tests/README` und dieser Record
(`.md` / `.de.md`). Der finale Git-Diff ist die vollständige Dateiliste.

Die angeforderten Arbeiten sind wie folgt zugeordnet; offene Validierung und
Delivery werden ausdrücklich ausgewiesen und nicht aus dem Dateiumzug abgeleitet.

| Angeforderter Bereich | Umsetzung oder Abgrenzung |
| --- | --- |
| Basis und Zuordnung | Quell-/Fallmaps erhalten ursprüngliche Identitäten, Prüfzwecke, Selektoren und alte Aufrufer neben aktuellen Framework-Pfaden und öffentlichen Aufrufern; Verfügbarkeit bleibt von Auswahl und Ausführung getrennt. |
| Vollständige Test-Ownership | Testimplementierungen, Fixtures, Orchestrierung, Provisionierung, Collectors und Reports wechselten ins Framework; produktiver Code/Build/Delivery bleiben im Connector mit kleinen gepinnten Einstiegen und zwei authentifizierten Broker-Shims. |
| Repository-Schnittstelle | Explizite Roots, Revision, Profil und externe Ausgabe; öffentliche eindeutige Python-Namensräume und begrenzte Importe; einseitige Abhängigkeit Connector → Framework und unveränderte geschützte Vertrauensgrenzen. |
| Auswertungsfehler | Requestlokale Identität lehnt fremde/mehrdeutige Anreicherung ab; Envoy erhält ausgeführten Traffic nach Assertion-Fehlern; Pflichtschreibfehler und leere vorgeschriebene Ergebnismengen scheitern; Wiederholungen erhöhen die Zahl eindeutiger Fälle nicht. |
| Laufzeitabweichungen | Zusammengeführte Apache-Duplikatheader verlangen explizite native Regelanpassung unter Erhalt von Regel `1100504` und Auditassertion; injizierte interne NGINX-Fehler verlangen HTTP 500 und Connector-Error-Semantik, fehlerhafte Clienteingabe behält HTTP 400. Tatsächliche Apache-Kontrollen und drei ausgewählte NGINX-Entwicklungs-H1-Fälle bestanden; finale Paarabnahme und vollständige Lifecycle-Qualifikation bleiben getrennt. |
| Parallele Themen | HTTP/2, HTTP/3, Coverage und vollständige Abhängigkeitsprüfung bleiben außer erforderlichen Pfad-/Aufruferanpassungen außerhalb des Umfangs. MRTS-Paket-/Importkorrekturen gehören zum separaten Framework-Followup-Paket und gemeinsamen Integrationscheck. |
| Gemeinsame Mechanik und Codeumfang | Native Extraktion ist Verschiebung; Loader-Konsolidierung entfernt Caller-Implementierung bei zusätzlichem gemeinsamem Helfercode. Daraus werden weder eine gleich große Gesamtreduktion noch vollständige mechanische Gleichwertigkeit abgeleitet. |
| Validierung und Delivery | Neueste Standardbeobachtungen: 67 bestandene / 13 blockierte Ausführungen, 74 bestandene / 26 blockierte Fälle über dokumentierte Revisionen. Das eingetragene Paar e77/4391 und die explizite DEV-Probe bestanden vor den uncommitteten Source-Owner-Korrekturen; frühere begrenzte Apache-Nachweise bleiben erhalten. Paarabnahme nach nächsten Pins, installiertes Gate und gehostete Final-Head-Gates bleiben offen. Merge bleibt an die aktuelle Nutzerfreigabe und alle Pflicht-Gates gebunden. |
| Erweiterungsklassifikation und Datenschutz | Eine geschlossene geprüfte Menge mit Prozessausführung nutzt migration-integration; reine Kontrollen behalten Offline-Audit, ursprüngliche Baseline-Gruppen und Guard-ASTs bleiben erhalten. Private externe Ausgabe und Ausschluss von Kundennutzdaten/Zugangsdaten bleiben erforderlich. |

## Befehle und Ergebnisse

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

Der frische native Capture kompilierte alle 81 Übersetzungseinheiten in
35.853 Sekunden mit tatsächlichen SDK-`ALL_INCS` und zugeordneten Header-
Eingaben ohne Drift. Acht SDK-Zulassungskontrollen vor dem Recipe-Import
und 19 native Sonar-Vertragsmethoden bestanden; die ASTs der ursprünglichen
18 Methoden bleiben exakt erhalten. Vier neue feste Quellbindungen haben
präzise physische Framework-Eigentümer. Die Closure erhält acht beobachtete,
zwei semantische und zwei öffentliche Einstiegsabhängigkeiten; Quellbindungen
wurden nicht global ausgedünnt. Die frische kanonische Security-Prüfung bestand
69 Methoden / 257 beobachtete Teilfälle in 10.939 Sekunden ohne Skips oder
Quelldrift gegen Bridge-Arbeitsfassung mit SHA-256
`1ef4d6fb021605f52c63fef3bf522a325736ceb40457d48c94c091b1e3efc5eb`.
Dies umfasst den separat registrierten sechsten argv-Fall mit Surrogate-Escapes.
Finale öffentliche Selektorwiederholungen stehen noch aus.

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
nachweise ohne Live-Host-Lauf. Das veröffentlichte Paar `e77`/`4391` bestand
getrennt. Ein neues Source-Owner-Korrekturpaket mit 13 Dateien ist uncommittet:
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
30.853 Sekunden bei unveränderten strengen Lesern. Die aktuelle gehostete CI
hat 12 bekannte Fehler durch alte Make-Orakel und den NGINX-Wurzelpfad. Die
öffentliche Parent-/Framework-Source-Owner-Abnahme nach Binding-Refresh steht
aus; für das neue Harness wird kein Live-Host-PASS und kein frischer kompletter
Standardlauf behauptet.

Der Umzug von 1295 Quellpfaden ist von Deduplizierung zu unterscheiden. Die
begrenzte Loader-Konsolidierung ersetzte 326 Blöcke und entfernte netto 1067
Loader-Zeilen; 29 neue gemeinsame Loader-Zeilen sind separat erfasst. Dies sind
Loader-Metriken, keine Behauptung über die gesamte Codeverkleinerung.

Das finale kanonische Inventar enthält
**100 Standardfälle / 80 Ausführungen**, **2307 On-demand-Fälle / 1042
Ausführungen**, **492 feste Framework-Testquellbindungen** und **234
Produktquellsnapshots**. Sein kompaktes JSON umfasst **2085028 Bytes** und liegt
unter der unveränderten Zulassungsgrenze von **2 MiB**. Dies sind Auswahl-/
Quellmengen, keine Zahlen ausgeführter oder bestandener Fälle. Die Erweiterung
fügt 55 explizite On-demand-Methoden hinzu: 28 Clean-Pair-Methoden, 14 MRTS-Paket-
Methoden, 3 Klassifikationsguards, 2 Prepared-/Backend-Helfermethoden, 4 Kontext-
methoden, 2 Methoden für versiegelte Aufrufe sowie je eine Collector- und SDK-Methode; die ursprüngliche Baseline mit 1993 Fällen
bleibt unverändert. Eine geschlossene geprüfte Menge von 155 neuen Zeilen mit
Prozessausführung nutzt in 12 Modulen die Gruppe `migration-integration` mit
aus dem Target abgeleiteten ID-Hashes; 48 reine Kontrollen behalten die Offline-
Audit-Gruppe. Die Gruppenzuordnungen der ursprünglichen 1993 Fälle und die ASTs
der Guardfunktionen bleiben unverändert; die ursprünglichen 40 reinen Kontrollen, beide reinen Helfermethoden und vier geschützte Kontextmethoden bestanden.

Die 120 neuen fokussierten Methoden bestanden ohne Skips, einschließlich der
Ergebnisintegritäts-Teilmenge mit 56 Methoden / 131 expandierten Varianten und
der geschlossenen Pfadregel-Teilmenge mit 9 Methoden / 32 expandierten Varianten.
Frühere begrenzte Läufe bestanden 136 fokussierte Portabilitätsmethoden,
30 öffentliche API-Methoden und 3 Makefile-Methoden. Die aktuelle lokale native
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

Vorhandene Task-Evidence verzeichnet 56 Ergebnisintegritätsmethoden / 131
expandierte Varianten ohne Fehler, Errors oder Skips unter Python `-P`,
`PYTHONSAFEPATH=1` und Framework-exklusivem `PYTHONPATH`. Quellisolation hat 3
bestandene Methoden, Quelldomänenzulassung 4. Sechs extrahierte native Suites
bestanden; der SPOP-Spezialist behält einen gegen Original und Migration
reproduzierten Fehler. Dieser native Fehler wird nicht als PASS gemeldet.
Dies sind Tasklauf-Ergebnisse, kein Final-Head-Wiederholungslauf und keine
gehostete H1-Qualifikation.

Der Quellerhalt-Audit prüfte 5886 Python-Testmethodendefinitionen der Basis,
einschließlich der vier vorgelagerten MRTS-Methoden, und fand zu diesem Zeitpunkt
keine fehlenden Methoden oder geringeren `self.assert*`-Zahlen. Dieser syntaktische Audit belegt keine semantische
Gleichwertigkeit. Native Extraktion erhielt laut Quellmanifest 69 Funktionen /
2011 Zeilen bytegleich. Loader-Konsolidierung ersetzte 326 wiederholte Blöcke und
entfernte 1067 Caller-Zeilen; der gemeinsame Helfer benötigt zusätzlichen Code,
daher wird keine gleich große Gesamtreduktion behauptet.

Ein frischer begrenzter unabhängiger Quellvertrauensreview fand keine Findings
und bestand 53 Methoden (20 Trusted-Bridge, 3 Python-Isolation, 30 NGINX-Verträge)
ohne Skips/Errors gegen Connector-Revision
`ec18f9e92286379a2410e917f76e6a5502675804`. Dies ist weder vollständiger
Securityscan noch privilegierter Hostlauf oder Qualifikation mit installiertem Gate.

Dokumentationsvalidierung wurde tatsächlich über RTK ausgeführt: Eine begrenzte
Python-Prüfung relativer Links, Überschriften und Codeblöcke bestand für alle
22 zugewiesenen Markdown-Dateien (11 EN/DE-Paare, keine defekten relativen Links,
gleiche Überschriftenzahlen und eingefasste Befehle).
`rtk bypass git diff --check -- <owned-document-paths>` bestand in beiden
Taskrepositories. Der native Framework-Checker
`ci/checks/documentation/check-change-records.py --root <framework-root>` bestand.
Die unveränderte ursprüngliche Parent-Creator-/Checker-API, aus dem Originalcheckout
mit explizitem Taskroot-Ausgabe-/Prüfumfang geladen, erzeugte und validierte das
Parent-Archiv, weil dem Creator während der Migration sein alter Checkerpfad
fehlte. Keine Datei des Originalcheckouts wurde geändert. Diese begrenzte Prüfung
ersetzt weder vollständige Repository-Make-Targets für Zweisprachigkeit/Links
noch Faktenreview. Die unveränderten Parent-`ordinary_pair_errors`-Prüfungen bestanden für
alle zehn zugehörigen Paare außerhalb des getrennten Framework-Recordschemas.

Finale Dokumentationsaktualisierung: Alle acht Migrationsguide-/Recorddateien
bestanden Prüfungen relativer Links, EN/DE-Struktur, eingefasster Befehle und
technischer Literale; beide Recordverträge und begrenztes `git diff --check`
bestanden. Die obigen eingefrorenen Inventarsummen beschreiben Auswahl und
Quellzulassung und behaupten keine Ausführung.

Die finale Leserlinkkorrektur richtete 40 Links in 32 Connector-Markdown-Dateien
anhand der exakten Migrationsquellmap neu aus, ohne historische Prosa zu ändern.
Explizite Linkprüfungen mit Connector- und Framework-Root bestanden. Die
vollständige Connector-Zweisprachigkeitsprüfung und die Framework-Variablen-/
Zweisprachigkeitsprüfung bestanden nach Ergänzung der sieben neuen
Schnittstellenvariablen in der zentralen Referenz beider Sprachen. Die finale native Framework-Repository-Pfadreferenzprüfung bestand für
2134 Dateien ohne veraltete Pfade. Für zwei exakte historische JSON-Byteidentitäten
und zwei exakte Negativfixture-Zeilen gilt eine geschlossene provenancegebundene
Regel; geänderte Bytes, veraltete Guards und zusätzliche aktive Pfade bleiben
Fehler. Ihre neun fokussierten Methoden / 32 expandierten Varianten bestanden
ohne Skips und lassen keine neuen Standardfälle zu. Das vollständige native
Framework-Dokumentations-Make-Target bestand Link-, Variablen-/Zweisprachigkeits-,
Repository-Pfad- und Change-Record-Prüfungen. Historische Evidence und
Negativinput-Bytes blieben erhalten.

Der vollständige Capture-Registry-Spezialistenlauf mit 58 Methoden verzeichnete
54 bestandene Methoden und vier Nicht-PASS-Ergebnisse (3 Failures / 1 Error)
aufgrund der vorbestehenden SDK-Hashabweichung. Der Hashvertrag bleibt erhalten: Das geprüfte Manifest erwartet
`89ff282b7287ab30a4194bc06c04835f104b8037442e89b35a68fd1253dcfcfc`, während
sowohl die ursprünglichen Connector-Bytes aus
`ec18f9e92286379a2410e917f76e6a5502675804` als auch die bytegleiche migrierte
Eingabe den Hash
`a220539856ea8164302f7b427fe72c829f035541387aebce620aebae0fa1310e` haben.
Kein Registry-Hash oder historisches Objekt wurde abgeschwächt oder umgeschrieben.
Eine getrennte breitere Spezialistenkontrolle lehnt das Laden eines externen
erfassten Controllers aus einer nicht ausgewählten Quelle fail-closed ab; diese
Ablehnung bleibt eine Nicht-PASS-Positivkontrolle. Diese Ergebnisse sind von den
136 bestandenen Portabilitätsmethoden getrennt.

Prüfsummenverifiziertes Ruff `0.16.10` wurde als freigegebenes isoliertes natives
CI-Tool bezogen. Der tatsächliche native CI-Lintcheck bestand. Die Formatierung
von sieben Dateien erhielt deren ASTs; die neueste vollständige Ruff-Nachprüfung
mit 38 Dateien bestand.

## Sicherheitsauswirkung

Explizite `TEST_ROOT` und `CONNECTOR_ROOT` trennen Testmechanik und geprüftes
Produkt. Schema 4 bindet Framework-Quellhashes fest und Produktquellsnapshots an
die ausgewählte exakte Revision. Begrenzte Produktquellimporte ersetzen einen
globalen Connector-Importpfad. Geschützte Ausführung authentifiziert geschützte
Parent-Gitobjektkette und gepinnte Framework-Quelle vor der Codeauswahl.
Erforderliche Gates, Hostisolation und Quellauthentizität dürfen nicht umgangen
werden. Kundenpayloads und Zugangsdaten gehören nicht in versionierte Evidence.

## Dokumentation und Runtime-Evidenz

Der jüngste begrenzte Ergebnisintegritätslauf bestand 56 Methoden / 131
expandierte Varianten. Drei tatsächliche Apache-H1-Kontrollen bestanden mit
HTTP 200 / 403 / 200 (Allow, Deny, Duplikatheader). Die Allow-Kontrolle verwendete
eine reine Clientbeobachtung `request_bound`; sie belegt keine
Hostfähigkeit. Ein früherer NGINX-H1-Versuch war mit Exit 77 blockiert, weil die benötigte
vorhandene Laufzeitumgebung fehlte; dies ist kein bestandener Hostlauf. Diese
Beobachtungen qualifizieren weder einen vollständigen H1-Lifecycle noch ein
installiertes geschütztes Host-Gate.

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

Die genannten nativen/Komponentenergebnisse belegen weder Host-Requestverkehr
noch Produkt-Promotion. Apache-Duplikatheader werden explizit an beobachtete
zusammengeführte Werte angepasst; HTTP 200, Regel `1100504` und Auditassertions
bleiben erhalten. NGINX-Tests interner Pointerfehler verlangen HTTP 500 /
`phase1_error` / `MSCONN_EVENT_CONNECTOR_ERROR` / `reason=connector_error`;
fehlerhafte Clienteingabe behält HTTP 400. Dies korrigiert veraltete Testverträge
ohne Abschwächung des Produkts.

## Nicht ausgeführte Prüfungen

Ein früherer NGINX-H1-Versuch war mit Exit 77 blockiert, weil die benötigte vorhandene
Laufzeitumgebung fehlte; weder ein NGINX-Host-PASS noch ein Nachweis mit
installiertem geschütztem Host-Gate ist hier dokumentiert. Current-Head-CI,
finaler Gesamtdiffreview, finale Quellmap-/Inventarregenerierung und abhängige
PR-Delivery benötigen getrennte beobachtete Ergebnisse. HTTP/2, HTTP/3,
Coverage-Featurearbeit und vollständiger Abhängigkeitsaudit liegen
außer notwendigen Pfadanpassungen außerhalb des Umfangs. Der öffentliche Adapter
ist eine Quellcheckout-Schnittstelle; installierbare Paketinhalte sind ein
getrennter Vertrag. MRTS bleibt schreibgeschützt. Kein Migrationsmerge wird behauptet.

## Einschränkungen und Restrisiko

Ein früherer NGINX-H1-Versuch war mit Exit 77 blockiert, weil die benötigte vorhandene
Laufzeitumgebung fehlte; weder ein NGINX-Host-PASS noch ein Nachweis mit
installiertem geschütztem Host-Gate ist hier dokumentiert. Current-Head-CI,
finaler Gesamtdiffreview, finale Quellmap-/Inventarregenerierung und abhängige
PR-Delivery benötigen getrennte beobachtete Ergebnisse. HTTP/2, HTTP/3,
Coverage-Featurearbeit und vollständiger Abhängigkeitsaudit liegen
außer notwendigen Pfadanpassungen außerhalb des Umfangs. Der öffentliche Adapter
ist eine Quellcheckout-Schnittstelle; installierbare Paketinhalte sind ein
getrennter Vertrag. MRTS bleibt schreibgeschützt. Kein Migrationsmerge wird behauptet.

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

Die Clean-Pair-CLI prüft eine committete Connector-Revision standardmäßig gegen
ihren eingetragenen Framework-Gitlink. Beide Quellrepositories müssen die
gewählten Gitobjekte enthalten. Sie erzeugt daraus saubere lokale Checkouts,
prüft erforderliche Einstiege und Schnittstellen, ruft das tatsächliche
Parent-Make-Target `test-framework-integration-probe` auf und validiert das exakte
zugelassene Ergebnis des Common-Headertests. Die Prüfung verlangt vorhandenes Git,
Make, kompatibles Python und `cc` sowie vorhandenen privaten externen
Ausgabespeicher. Uncommittete Quelländerungen werden nicht in das Paar kopiert.
Das committete saubere Paar Connector `e77c833eef4b23e1252dbcd4c6507ded0b7e2064` /
Framework `4391a424f34ea9c7b7ed09fd1df72a38a23cb909` bestand in 126.317 Sekunden im Recorded-Pin-Modus
mit `standard_combination=true`, beiden Checkouts sauber vor/nach dem Lauf und
einem bestandenen tatsächlichen Parent-Make → Common-C1-Test.

Ein getrennter expliziter DEV-Lauf bestand mit demselben Connector und ausgewähltem
Framework `e52d7d44c81e997a296b7ffdfb33f12bf85455b9`, eingetragenem Gitlink
`4391a42`, in 123.559 Sekunden mit `mode=development` und `standard_combination=false`. Vor/nach dem Lauf
wich nur der erwartete Connector-Gitlink ab; Framework blieb sauber. Die echte
UID-1001-Bridge stellte 11 Exporte bereit, das private Ausgabeverzeichnis behielt
Modus 0700 und die Wrong-Pin-Kontrolle lehnte mit Exit 77 ab. Alle 90 Updater-
Methoden / 216 Teilfälle bestanden ohne Skips über den 39-Methoden-Lauf
(93.183 Sekunden) und den 51-Methoden-Lauf (77.813 Sekunden). Diese Paarnachweise
gehen den uncommitteten Source-Owner-Korrekturen voraus; die Abnahme des nächsten
committeten Paars muss erneuert werden. Der frühere
veraltete DEV-Versuch bleibt abgelehnt. Frühere Apache-H1-Kontrollen auf
`cfd5e49` / `e52d7d4` behalten ihren begrenzten 28.625-Sekunden-Beleg. Nach den
nächsten Pins bleiben erneute Abnahme und aktuelle gehostete Gates für Framework
#142 / Connector #434 erforderlich. Nachweise bleiben in privatem externem
Ausgabespeicher; versionierte Belege dürfen keine Kundennutzdaten oder Zugangsdaten enthalten.

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
Include-/Library-Pfaden. Die C-Family-Quellbytes bleiben identisch; dafür wird
keine erneute Erfassung der 81 Einheiten behauptet. 11 bestehende Kontexttests und vier negative CLI-Kontrollen bestanden
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
für Framework-PR #142 / Connector-PR #434 erforderlich. Die vollständige Exact-Head-Sonar-Analyse von Connector
`e77c833eef4b23e1252dbcd4c6507ded0b7e2064` bestand alle fünf Gate-Bedingungen:
2.0% Duplikation, null ungelöste Issues und null TO_REVIEW-Hotspots. Die erste
vollständige Framework-Analyse von `4391a424f34ea9c7b7ed09fd1df72a38a23cb909`
verfehlte ihr Gate mit Zuverlässigkeit B und Security E: 280 ungelöste Issues
(86 von Sonar klassifizierte Schwachstellen, 193 Code-Smells, ein Bug), null
Hotspots und 0.0% Duplikation. Diese Kategorien sind keine unabhängig validierten
Exploits. Beide Issue-Inventare sind vollständig. Das uncommittete Source-Owner-Paket hat
keine erneuerte gehostete Abnahme. Framework hat kein sauberes Quality Gate und ist nicht mergebereit;
keiner der Migrations-PRs ist gemergt.

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

## Finaler Diff- und Review-Status

Die Migrationslieferung nutzt getrennte Task-Worktrees und veröffentlichte
Framework-PR #142 / Connector-PR #434. Genanntes committetes Paar und explizite
DEV-Probe bestanden; nächste Pins, erneute Paarabnahme und gehostete Current-Head-
Prüfungen bleiben offen. Der Cleanup privater Kandidatenausgaben hat nun die
oben getrennt dokumentierten bestandenen Beobachtungen. Ruff bestand lokal;
Pyright benötigt sein gehostetes Gate. Ein Migrationsmerge wird nicht behauptet.
