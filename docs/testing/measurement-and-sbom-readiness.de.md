# Laufbereitschaft für Messung und Komponenten-SBOM

**Sprache:** [English](measurement-and-sbom-readiness.md) | Deutsch

Ausgegebenes `$schema` erhält den kanonischen HTTP-Identifier aus `$id` des
offiziellen CycloneDX1.6-Schemas. Er identifiziert das Schema; der Exporter ruft
es nicht ab. Mit vertrauenswürdigen lokalen Schemabytes und verweigertem externem
Nachladen validieren oder in einem getrennten Verbraucher unabhängig geprüften
HTTPS-Bezug verwenden. Ein Identifierwechsel ist eine Interoperabilitätsentscheidung,
keine HTTP-Reparatur.

Dies bereitet eine später ausdrücklich ausgewählte Abnahme vor. Es führt weder
die Abnahme aus noch qualifiziert es Connectoren/Protokolle. Die 100 Standardfälle
bleiben unverändert. Historische gezielte Messungen behalten ihren Quellbezug.

## Voraussetzungen des endgültigen Commitpaars

Saubere eingecheckte Parent-/Framework-Checkouts und ihre exakten HEADs auswählen;
den vorgesehenen Parent-Gitlink separat prüfen. Framework kann bewusst vor einer
gesondert freigegebenen Pinaktualisierung geprüft werden; dann das tatsächliche
Paar angeben. `CONNECTOR_REVISION` muss dem Parent-HEAD entsprechen. Den
konfigurierten Framework-Interpreter und dessen Importwurzeln verwenden; keine
stillschweigende Parent-Venv verwenden. Kanonische Pythonversionen gehören den
jeweiligen aktuellen Locks. `ci/tools/bootstrap-python.sh` ist der bestehende
Framework-Bootstrap. Er installiert Abhängigkeiten und aktualisiert pip; nur bei
autorisierter Vorbereitung mit externem `VENV_DIR` und geeignetem explizitem
`PYTHON_BIN` verwenden. Er ist weder offline noch hashgesperrt.

Pythonmessung benötigt zusätzlich den bestehenden Parent-Hashlock
`ci/requirements/sonar-coverage.txt` in einer genehmigten isolierten kompatiblen
Werkzeugumgebung. Der Exporter selbst benötigt nur die Standardbibliothek.
Go-Messung benötigt Compiler/Cache pro tatsächlichem Modul und das zugelassene
Testoverlay; native Messung passende Compiler/gcov und frische externe
instrumentierte Builds. Vor nötiger Hostausführung den
[Hostausführungskontext](../host-execution-context.de.md) beachten. Fehlende
Voraussetzungen bleiben Blocker.

Aus Parent mit expliziten genehmigten absoluten Pfaden `P`, `F`, `PYTHON`,
`MEASUREMENT_ROOT`, `TMP_ROOT` und exaktem Parent-HEAD in `PARENT_SHA`:

```sh
rtk bypass env CONNECTOR_ROOT="$P" CONNECTOR_REVISION="$PARENT_SHA" \
  TEST_ROOT="$F" FRAMEWORK_ROOT="$F" PYTHONPATH="$F:$F/connector_suite" \
  PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "$PYTHON" -P \
  "$F/connector_suite/modsecurity_connector_ci/checks/analysis/run-sonar-coverage.py" \
  --language python --on-demand --output-root "$MEASUREMENT_ROOT" --temp-root "$TMP_ROOT"
```

Dieser Aufruf ist für spätere Autorisierung vorbereitet. Nur ausgewählte Sprachen
(`python`, `go`, `native`) ausführen, anschließend `finalize-python` mit derselben
Ausgabewurzel. Jede Sprache benötigt ein frisches Unterverzeichnis. Parent-only-
Pythonattribution, echte Ausführungszeugen, Testauswahl und ungemessene
Timingpartition bleiben erhalten. Manifeste enthalten nun zusätzlich die
tatsächliche Frameworkrevision und deren Änderungszustand. Finalisierung weist
fehlenden/abweichenden Frameworkbezug vor der Kombination zurück. Alte Manifeste
bleiben historische Nachweise und dürfen dafür nicht umgeschrieben werden.
`--allow-dirty` liefert ausschließlich Entwicklungsnachweise.

## Partieller SBOM-Export expliziter Eingaben

`ci/tools/export-component-sbom.py` erzeugt deterministisches
[CycloneDX-1.6-JSON](https://cyclonedx.org/docs/1.6/json/) mit Komposition
`incomplete`. Der Exporter löst keine Abhängigkeiten auf und scannt nicht.
Eingabeflags sind wiederholbar. JSON-/Go-Eingaben sind auf 16 MiB begrenzt und
müssen reguläre Dateien ohne Symlinkpfad und mit genau einem Hardlink sein.
Eingabehashes/-pfade, tatsächliche Repositoryrevisionen/-zustände und Exporterhash
binden die Ausgabe. Eine neue externe Ausgabedatei ist erforderlich; vorhandene
Dateien bleiben erhalten. Exit 77 bezeichnet ungültige/fehlende Eingaben,
abweichenden/unsauberen Quellzustand oder ungültige Ausgabe. Fehlermeldungen geben
keine beliebigen Eingabedaten wieder. Nur geprüfte Metadaten ohne Geheimnisse liefern.
Mehrfache Auswahl derselben Eingabe scheitert; identische Komponenten aus mehreren
ausgewählten Eingaben erscheinen einmal, alle Eingabebelege bleiben erhalten.

Unterstützte Eingaben:

- `--source`: Runtime-Lock mit `profiles` oder Objekt mit `components`.
  Je Eintrag `component`/`name`, `version`, optional `id`/`profile` und entweder
  `download_url` mit `sha256` oder `repository_url` mit exaktem `commit`.
  HTTPS-URLs müssen ohne Zugangsdaten, Query und Fragment sein. Releasehashes
  gehören zur Distributionsreferenz; Commits sind keine Dateihashes. Der aktuelle
  Lock enthält acht Cacheprofile, weitere native Buildabhängigkeiten fehlen;
  daraus folgen keine zehn qualifizierten Runtimeprofile.
- `--go`: Objektstrom von `go list -mod=readonly -m -json all` im jeweiligen
  Modulverzeichnis mit der vorgesehenen Buildkonfiguration. Offline aus dem Cache:
  `rtk bypass env GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off go list
  -mod=readonly -m -json all > "$INPUT_ROOT/module.json"`. Cachelücken scheitern;
  Vorbereitung nur über autorisierten Abhängigkeitsweg. Replacements und nicht
  aufgelöste Module werden zurückgewiesen. Eine Modulliste beweist keinen
  Binär-/Paketabhängigkeitsgraphen.
- `--python`: JSON-Array von `rtk bypass "$PYTHON" -m pip list --format=json
  --disable-pip-version-check > "$INPUT_ROOT/packages.json"`. Es beschreibt
  installierte Distributionen dieser Umgebung, keine Produktverlinkung.
- `--artifacts`: JSON-Array mit `name`, `version`, `profile`, `path` und nichtleerem
  `build`-Objekt für geprüfte Compiler-/Flag-/Quellangaben. Relative Pfade beziehen
  sich auf die Eingabedatei. Tatsächliche Artefaktbytes werden gestreamt gehasht;
  Änderungen währenddessen scheitern. Buildangaben bleiben gelieferte Aussagen,
  werden nicht ausgeführt und beweisen keine Verlinkung. Beispiel:

```json
[{"name":"connector-module","version":"development","profile":"nginx-h2",
  "path":"build/connector.so","build":{"compiler":"record actual compiler",
  "flags":["record actual flags"],"source_revision":"record actual source"}}]
```

Beispiel mit bekannten Eingaben und exakten ausgewählten HEADs:

```sh
rtk bypass "$PYTHON" "$F/ci/tools/export-component-sbom.py" \
  --parent-root "$P" --parent-revision "$PARENT_SHA" \
  --framework-root "$F" --framework-revision "$FRAMEWORK_SHA" \
  --source "$F/ci/provisioning/runtime-component-lock.json" \
  --go "$INPUT_ROOT/module.json" --python "$INPUT_ROOT/packages.json" \
  --artifacts "$INPUT_ROOT/artifacts.json" --output "$INPUT_ROOT/components.cdx.json"
```

Ausgelassene Klassen bleiben ungemessen. Auch mit allen vier Eingabeklassen bleibt
die Ausgabe unvollständig: native Transitivität, OS-/Containerpakete, tatsächliche
Binärverlinkung, Sicherheitsfreiheit und Runtimeerfolg sind nicht belegt. Für eine
vollständige native/Container-SBOM zuerst Artefakte/Images, Build-/OS-/Linkagebelege
und einen genehmigten Resolver/Generator festlegen. Ausgabe gegen das offizielle
[1.6-Schema](https://github.com/CycloneDX/specification/blob/1.6/schema/bom-1.6.schema.json)
in vorhandener genehmigter Validierungsumgebung prüfen. Keine neue Scannerpflicht
oder Abhängigkeit entsteht. Versionsalter allein rechtfertigt kein Update;
konkret betroffene Komponenten/Features gegen primäre Advisories bewerten.

Gezielte On-demand-Exporterprüfung:
`rtk bypass "$PYTHON" -m unittest -v tests.ci_security.test_component_sbom`.
