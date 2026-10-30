# MRTS-Vorbereitung und Übergabe

**Sprache:** Deutsch | [English](mrts-preparation.md)

Das Framework steuert Korpusauswahl, Generierung, Import, Schemavalidierung,
Regel-Load-Datei und Runner-Übergabe. Das gepinnte Repository `tools/MRTS` dient
als schreibgeschützter Generator von Regeln und FTW-Definitionen. Connector-Owner
steuern Hostports, Prozesse, Cleanup und Laufzeitevidence.

## Paketschnittstelle

Verwende den Framework-eigenen Interpreter mit seiner deklarierten
PyYAML-Abhängigkeit. Der Generator benötigt PyYAML; diese Schnittstelle startet
keine MRTS-Hoststeuerung und installiert keine MRTS-Abhängigkeiten. Übergib
absolute, ausdrückliche Repository- und Ausgabepfade:

```sh
"$PYTHON" "$FRAMEWORK_ROOT/ci/provisioning/mrts-package.py" prepare \
  --framework-root "$FRAMEWORK_ROOT" --mrts-root "$MRTS_ROOT" \
  --connector-root "$CONNECTOR_ROOT" --build-root "$BUILD_ROOT" \
  --package-root "$BUILD_ROOT/mrts/package" --include-feature-demo 0
```

`BUILD_ROOT` muss ein dediziertes erlaubtes externes Laufzeitverzeichnis sein.
Paketziele müssen neue Unterverzeichnisse von `BUILD_ROOT/mrts` sein;
Quellcheckouts, Traversal und symlinkhaltige Ziele werden abgewiesen. Die
Ausgabe entsteht in einem privaten Staging-Verzeichnis und wird erst nach
erfolgreicher Prüfung aller gewählten Korpora durch eine Verzeichnisumbenennung
veröffentlicht. Ein vorhandenes Ziel wird abgewiesen; Neugenerierung benötigt
ein neues Ziel. Ein Fehler erhält ein früheres Paket, wählt oder verwendet es
aber nicht. Erfolgreiche Befehle geben den resultierenden Root auf stdout und
Vorbereitungsdiagnosen auf stderr aus.

Paketvorbereitung und Ergebnisverarbeitung verwenden gemeinsam die Prüfungen
für externe Roots in `ci/lib/mrts_path_safety.py`. Wähle den Laufzeitroot
unabhängig von eingehenden Definitions-, Ergebnis- und Manifestpfaden. Er muss
vom ausführenden Framework-Checkout und konfigurierten Quellcheckouts sowie
deren übergeordneten Verzeichnissen getrennt sein; Systemverzeichnisse und das
allgemeine temporäre Verzeichnis werden abgewiesen. Das nächste vorhandene
Verzeichnis muss dem aktuellen Benutzer gehören und darf keine Gruppen- oder
öffentlichen Schreibrechte gewähren. Übergeordnete Verzeichnisse müssen dem
aktuellen Benutzer oder root gehören; ein gemeinsam schreibbares
übergeordnetes Verzeichnis benötigt Sticky-Bit-Schutz. Wenn `CODEX_TEMP_ROOT`
oder `RUNNER_TEMP` konfiguriert ist, muss der Laufzeitroot ein echtes
Unterverzeichnis mindestens eines dieser Roots sein. Traversal und
Symlinkkomponenten werden vor der Pfadauflösung abgewiesen.

`--framework-root` muss dem Checkout des ausführenden Paketskripts entsprechen.
Die Vorbereitung ruft ausschließlich dessen feste Generator-, Importer- und
Load-Writer-Einstiege mit geprüften absoluten Operanden auf. Shell und Git
werden aus System-Suchverzeichnissen gewählt; der Importer verwendet den
aktuellen Python-Interpreter. Ausführbare Programme müssen reguläre,
ausführbare Dateien sein, dem aktuellen Benutzer oder root gehören und dürfen
keine Gruppen- oder öffentlichen Schreibrechte gewähren. Vom Aufrufer gesetzte
`PATH`-Einträge wählen diese Shell- und Git-Programme nicht aus.

Der Definition-Guard startet den vertrauenswürdigen Generator in einem isolierten
Python-Kindprozess mit explizit unterdrücktem Bytecode (`-I -B`). Ein fester
Bootstrap lässt ausschließlich das aufgelöste Generatorverzeichnis für
benachbarte MRTS-Imports zu, erhält Generatorargumente und führt ihn mit
`runpy` aus. Geerbtes `PYTHONSAFEPATH=1` funktioniert damit ohne eingehende
Python-Pfade zuzulassen, den Elterninterpreter zu verändern oder Bytecode im
gepinnten MRTS-Checkout zu schreiben.

`--upstream-definitions DIR` und `--feature-demo-definitions DIR` wählen
ausdrückliche Definitionsverzeichnisse statt der gepinnten Vorgaben. Nur
gewählte Korpora werden gelesen. Mit `--include-feature-demo 0` entfallen
Demo-Generierung und -Import; das Manifest vermerkt `feature-demo: disabled`.
Mit Wert `1` müssen beide Korpora generiert, importiert und validiert werden;
Regel-ID-Kollisionen zwischen Korpora sind fatal. Die gepinnte Demo enthält
derzeit überlappende IDs, daher kann ihre Aktivierung sichtbar fehlschlagen.
Deaktivierte Demo-Fälle werden in diesem Pfad nicht als ausführbare
Referenzfälle geführt.

Definitionsverzeichnisse müssen flach sein. Sowohl die Paketauswahl als auch
der direkte Generator-Guard weisen Unterverzeichnisse ab, etwa `base.yaml`
neben `extra/additional.yaml`, bevor ein Teilkorpus generiert wird. Eine nach
der Vorbereitung ergänzte verschachtelte Definition verhindert ebenfalls
Prüfung und Materialisierung. Verschiebe Definitionen vor der Paketvorbereitung
in ein geprüftes flaches Verzeichnis.

Das Paket enthält `upstream-config-tests/` und bei Auswahl `feature-demo/`,
jeweils mit `rules/`, `ftw/`, `framework-cases/` und `mrts.load`. Private
Definitionssnapshots liegen unter `definitions/`. Generator-Wrapper und
Definition-Guard prüfen diese Snapshots vor dem MRTS-Aufruf. Der vorhandene
Importer bleibt die einzige FTW-zu-Framework-Konvertierung. Er erhält
Stringtypen über YAML hinweg, einschließlich Headername `"2"`, wiederholter
Header und ihrer Reihenfolge; strenge Header-/Kontrollzeichenprüfungen bleiben
bestehen. Auch ein direkter Import stellt den vollständigen Fallkatalog zunächst
privat bereit, bevor er einen älteren ersetzt.

## Prüfung und private Ausführung

Verwende denselben Befehl mit `verify`, um ein Paket wiederzuverwenden.
`manifest.json` bindet Framework-, MRTS- und Connector-Revisionen, relevante
Framework-Quelldigests, Python-/PyYAML-Versionen, Korpusauswahl, vollständige
Definitionsauswahl mit Hashes, Artefakthashes, eindeutige Fall-IDs sowie Import-
und Validierungsstatus. Der ausgecheckte MRTS-Stand muss dem Framework-Gitlink
entsprechen und sein Arbeitsbaum sauber sein. Geänderte, neue oder entfernte
Definitionen, veränderte Artefakte, abweichende Quellenidentitäten oder eine
andere Demo-Auswahl erfordern neue Vorbereitung.
`MODSECURITY_MRTS_PREPARED=1` allein genügt nicht: Shell-Verbraucher benötigen
auch `MRTS_PACKAGE_ROOT` und prüfen das Manifest.

Die Quellenbindung umfasst die Pfad-Guards (`mrts_path_safety.py` und
`runtime_path_safety.py`), Shell-Provisionierungsbibliotheken und Einstiegspunkte,
Definition-Guard, Importer, Klassifizierungen und `runner_core.py`. Sie bindet
auch die transitiven Framework-Imports des Runners: `adapter_interface.py`,
`case_roots.py`, `msconnector_models.py` und `generated_report_utils.py`.
Das Manifest bindet zusätzlich jede Python-Datei im festen Framework-eigenen
öffentlichen Namensraum `modsecurity_test_framework/`, einschließlich Paketaliasen
und Kontext-/Ergebnishelfern. Bei Wiederverwendung wird die vollständige
ermittelte Pfad-/Digest-Zuordnung verglichen: Neue, entfernte oder geänderte
Quellen invalidieren sie. Durchlauf und Lesen weisen Symlinks ab und begrenzen
Dateizahl, Tiefe und Bytes; eingehende Umgebungspfade erweitern den Quellumfang
nicht. Schon eine Änderung an nur einer gebundenen Datei verhindert die
Wiederverwendung, auch bei unverändertem Git-HEAD. Pakete mit der älteren, kleineren Quellenliste
müssen neu vorbereitet werden.

Erzeuge für jeden Connectorlauf eine eigene private Kopie:

```sh
"$PYTHON" "$FRAMEWORK_ROOT/ci/provisioning/mrts-package.py" materialize \
  --framework-root "$FRAMEWORK_ROOT" --mrts-root "$MRTS_ROOT" \
  --connector-root "$CONNECTOR_ROOT" --build-root "$BUILD_ROOT" \
  --package-root "$BUILD_ROOT/mrts/package" --include-feature-demo 0 \
  --output-root "$BUILD_ROOT/run-apache/package" --port 18080
```

Bei eigenen Definitionsverzeichnissen müssen dieselben Optionen auch bei
`verify` und `materialize` angegeben werden. Das Ziel muss fehlen, innerhalb
von `BUILD_ROOT` und getrennt vom vorbereiteten Paket liegen. Materialisierung
prüft das Paket, kopiert es, passt ausschließlich private FTW-Eingabeports und
generierte Pfadreferenzen an, validiert die importierten Fälle und veröffentlicht
die Kopie atomar. `materialization.json` vermerkt Quellmanifesthash, Port und
private Artefakthashes. Das gemeinsame Paket bleibt unverändert. Diese Datei
beschreibt eine vorbereitete Kopie und kein Hosttestergebnis. Vertrauenswürdige
Operatoren derselben UID können Dateien ändern; dies sind Integritätsprüfungen
und private Vorbereitung, keine Prozessisolation und kein signiertes
Artefaktsystem.

`ci/lib/mrts-common.sh` verwendet diese Schnittstelle für
`prepare_mrts_runtime_variant`. Jede Shell/jeder Connector erhält eine eigene
Kopie und ergänzt deren importierte Fallverzeichnisse und Load-Dateien für den
Runner. Vorhandene optionale Präambeln bleiben in getrennt benannten kombinierten
Load-Dateien erhalten. Die Make-Einstiege `mrts-generate`, `mrts-import`,
`mrts-load` und `mrts-ftw` verwenden denselben Vorbereitungspfad. Der erste und
dritte geben Paketroot beziehungsweise Upstream-Load-Dateipfad aus. Vorbereitung
kann mehr Fälle erzeugen als eine konkrete Testauswahl ausführt; sie erweitert
das aktive Standardtestinventar nicht.

## Ergebnisintegrität

`ci/lib/mrts_results.py` wird vom nativen Job-Writer und Berichtsverbraucher
gemeinsam verwendet. Es ordnet go-ftw-JSON-Ergebnis-IDs den ausgewählten privaten
FTW-Fällen zu und trennt Auswahl, versucht/ausgeführt, PASS, FAIL, SKIP,
ignorierte, erzwungene und fehlende Ergebnisse. Doppelte/widersprüchliche IDs,
erzwungene Ergebnisse, leere Pflichtauswahlen, fehlende Resultate und
Writerfehler verhindern Laufzeit-PASS. Aggregierte Versuchszahlen erzeugen keine
fehlenden PASS-Beobachtungen. Berichte prüfen die strukturierte Quelle erneut,
statt einem gespeicherten Job-PASS zu vertrauen. Historischer Text ohne an die
Auswahl gebundene Beobachtungen bleibt unvollständig. Ein gültiges vorbereitetes
Manifest ist keine Host-Laufzeitevidence.

Beim eigenständigen CLI-Aufruf des Ergebnis-Writers muss der für den Lauf
gewählte vertrauenswürdige `BUILD_ROOT` ausdrücklich exportiert werden
(`export BUILD_ROOT`). Die Ergebnis-CLI besitzt kein Build-Root-Argument und
leitet ihre Berechtigung nicht aus einem übergebenen Ergebnis-, FTW-Verzeichnis-
oder Ausgabepfad ab. Alle Ergebniseingaben und -ziele müssen Unterpfade dieses
geprüften Roots sein; ihre Verzeichnisse müssen dem aktuellen Benutzer gehören,
dürfen keine Gruppen- oder öffentlichen Schreibrechte gewähren und keine
Traversal- oder Symlinkkomponenten enthalten. Ein fehlender `BUILD_ROOT` oder
ungültiger Pfad lässt den Writer fehlschlagen. Die Paket-CLI erhält weiterhin
das oben gezeigte ausdrückliche Argument `--build-root`.

Die eigenständige Ergebnis-CLI und der gemeinsame MRTS-Pfad-Guard laden ihre
tatsächlichen Pfadfunktionen mit `runpy` aus festen benachbarten Framework-Dateien.
Sie funktionieren mit `PYTHONSAFEPATH=1`, ohne auf die Suche im Skriptverzeichnis
angewiesen zu sein, globale Modulsuchpfade zu ändern, Modulaliase hinzuzufügen
oder einen Connector-Checkout heranzuziehen.

## Integrationsreihenfolge und Umfang

Parent-PR #432 ist bereits gemergt. Framework-PR #139 wird getrennt fortgesetzt;
die folgende Reihenfolge beschreibt den ursprünglichen Abhängigkeitsplan. Ein
Framework-Pin-Update bleibt eine separate Aktion nach dem Framework-Merge.

Liefere zuerst die Framework-Änderungen. Prüfe danach die getrennten
Connector-Aufrufer- und Ergebnisänderungen gegen diese Schnittstelle. Nach einem
separat autorisierten Framework-Merge wird der Parent-Framework-Gitlink in einem
ausdrücklichen Pin-Update-Auftrag auf die geprüfte Merge-Revision gesetzt;
anschließend wird die abhängige Connector-Änderung integriert. Weder Vorbereitung
noch diese Quelländerungen aktualisieren `tools/MRTS` oder dessen Pin. Ein
direkter Default-Branch-Push oder automatischer Merge ist nicht erforderlich.

Der allgemeine Testumzug ins Framework bleibt getrennt. Berührungspunkte sind
allein diese Framework-eigenen MRTS-Helper-/Importer-/Berichtsschnittstellen und
der native Parent-Aufrufer. HTTP/2, HTTP/3, Coverage und historische
Gesamtmatrizen bleiben außerhalb dieser Änderung. Ein echter H1-Nachweis muss
eine gewählte Definition, generierte Regel, importierten Fall, tatsächlich
geladenen Connector und beobachtetes Ergebnis separat an einen validierten
Bericht binden; Generierung und Schemaprüfung allein liefern diesen Nachweis
nicht.
