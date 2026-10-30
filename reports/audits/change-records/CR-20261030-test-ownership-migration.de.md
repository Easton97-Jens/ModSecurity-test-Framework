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
Connector-Pin voraus; Merge oder Master-Push sind nicht freigegeben.

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
| Laufzeitabweichungen | Zusammengeführte Apache-Duplikatheader verlangen explizite native Regelanpassung unter Erhalt von Regel `1100504` und Auditassertion; injizierte interne NGINX-Fehler verlangen HTTP 500 und Connector-Error-Semantik, fehlerhafte Clienteingabe behält HTTP 400. Tatsächliche Apache-Kontrollen bestanden; NGINX-Hostvalidierung ist blockiert. |
| Parallele Themen | HTTP/2, HTTP/3, Coverage und vollständige Abhängigkeitsprüfung bleiben außer erforderlichen Pfad-/Aufruferanpassungen außerhalb des Umfangs. MRTS-Paket-/Importkorrekturen gehören zum separaten Framework-Followup-Paket und gemeinsamen Integrationscheck. |
| Gemeinsame Mechanik und Codeumfang | Native Extraktion ist Verschiebung; Loader-Konsolidierung entfernt Caller-Implementierung bei zusätzlichem gemeinsamem Helfercode. Daraus werden weder eine gleich große Gesamtreduktion noch vollständige mechanische Gleichwertigkeit abgeleitet. |
| Validierung und Delivery | Fokussierte Prüfungen und begrenzte Apache-Beobachtungen werden getrennt von offenen Standardlaufergebnissen, installiertem Gate-Nachweis, Final-Head-CI und abhängiger PR-Delivery dokumentiert. Framework-Integration erfolgt vor Connector-Pinintegration; kein Merge ist freigegeben. |

## Befehle und Ergebnisse

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
von sieben Dateien erhielt deren ASTs; die finale Formatierungsnachprüfung steht
noch aus.

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
Hostfähigkeit. Der NGINX-H1-Versuch war mit Exit 77 blockiert, weil die benötigte
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

Der NGINX-H1-Versuch war mit Exit 77 blockiert, weil die benötigte vorhandene
Laufzeitumgebung fehlte; weder ein NGINX-Host-PASS noch ein Nachweis mit
installiertem geschütztem Host-Gate ist hier dokumentiert. Current-Head-CI,
finaler Gesamtdiffreview, finale Quellmap-/Inventarregenerierung und abhängige
PR-Delivery benötigen getrennte beobachtete Ergebnisse. HTTP/2, HTTP/3,
Coverage-Featurearbeit und vollständiger Abhängigkeitsaudit liegen
außer notwendigen Pfadanpassungen außerhalb des Umfangs. Der öffentliche Adapter
ist eine Quellcheckout-Schnittstelle; installierbare Paketinhalte sind ein
getrennter Vertrag. MRTS bleibt schreibgeschützt. Kein Migrationsmerge wird behauptet.

## Einschränkungen und Restrisiko

Der NGINX-H1-Versuch war mit Exit 77 blockiert, weil die benötigte vorhandene
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
werden getrennt vom Werkzeugrepository nachverfolgt. Generierte Archiv- und Map-Ausgaben
stimmen mit ihren eingefrorenen Quelleingaben überein: Beide Generatorläufe mit
`--check` bestanden und erhielten alle 1993 ursprünglichen Fall-IDs. Die obigen
kanonischen Inventarzahlen beschreiben Auswahl, keine erfolgreiche Ausführung.

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

## Finaler Diff- und Review-Status

Migrationsimplementierung und Dokumentation sind in getrennten Taskworktrees
vorbereitet. Finaler Connector-Pin, pinabhängige Prüfungen, finale
Formatierungsnachprüfung und Remote-Delivery der Migrations-PRs stehen noch aus.
Current-Head-CI-, Quality-Gate- und Migrationsmergeergebnisse werden nicht behauptet.
