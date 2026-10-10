# Änderungsnachweis

**Sprache:** Deutsch | [English](20261008-26-nginx-explicit-native-authority.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change ID | 20261008-26-nginx-explicit-native-authority |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | `fd928ad7f7d864048a065106f17a7af2f6ba4a52` |

## Motivation und Problemstellung

Native Operationsbelege dürfen ihre vertrauenswürdigen Build-/Quell-Digests nicht selbst liefern. Eine explizit gewählte lokale Autoritätsdatei benötigt striktes Laden und Originalbyte-Erhalt, bevor der Koordinator ihren Kontext dem nativen Bundle-Reader übergibt.

## Betroffene Komponenten und Sicherheitsgrenzen

Nur neuer Framework-Autoritätshelfer, gezielte Tests und dieses Nachweispaar. Parent-Autoritätsproduzent, zentraler Validator/Schema/CLI/Normalizer, Aufbewahrungsschreibzugriffe, Git-Zustandsprüfungen, MRTS und Gitlinks bleiben außerhalb dieses Slice.

## Akzeptanzkriterien

Explizites exaktes Lauf-/Parent-/Framework-/MRTS-Tupel und geschlossene Schema1-nginx-Metadaten verlangen. Unsichere/fehlende Wurzeln, Aliasse, Artefakt-/Quellüberlappung, beschreibbare oder fremdeigentümere Dateien/Verzeichnisse, Symlink-Komponenten, Hardlinks, nichtreguläre oder übergroße Dateien, doppelte/nichtendliche JSON-Werte und fehlerhafte Digests ablehnen. Legitime Framework-Verschachtelung unter Parent erhalten. Immutablen Kontext und Originalbytes/-Hash ohne Schreiben oder Pfadfallback liefern.

## Untersuchte Alternativen

Erwartete Autorität aus einem Operationsbeleg abzuleiten, aktuelle Revisionen zu erraten oder eine feste Framework-Wurzel vorauszusetzen würde explizite Quellauswahl umgehen. Metadaten-Neuserialisierung erhält nicht das Originalbyteseal.

## Implementierungsentscheidung

`load_native_operation_authority(path, expected)` liest höchstens16384 Bytes über den strikten No-follow-/Eigentümer-/Single-link-/Regular-/Stable-Reader. Expected enthält exakt run_id und die drei exakten40-Revisionen. Metadaten enthalten exakt schema_version, connector, run_id, explizite Artefakt-/Parent-/Framework-Wurzeln, diese Revisionen, Binary-/Modul-SHA256 und das geschlossene ausgewählte Fault-Digest-Mapping. Wurzeln müssen existieren, unterschiedliche tatsächliche Verzeichnisse sein und ohne Gruppen-/Welt-Schreibrechte dem Eigentümer gehören. Artefakte dürfen Quellcheckouts nicht überlappen; Quellverschachtelung ist erlaubt.

Zurückgegebene Mappings sind rekursiv schreibgeschützt. `dict(result['sources'])` liefert das konkrete Koordinatordictionary des bestehenden Readers. `authority_bytes` und `authority_sha256` erhalten die exakte Originaldatei für koordinatorverantwortete geprüfte Aufbewahrung. `serialized_mapping(result)` liefert nach Prüfung der Originalbyte-/Metadatenbindungen ein frisches einfaches Schema1-Mapping; es schreibt nichts und ist kein neues Seal.

## Geänderte Dateien und Tests

`tests/runners/nginx_native_operation_authority.py`, `tests/no_crs/test_nginx_native_operation_authority.py` und dieses Nachweispaar. Neun gezielte Tests prüfen exakte Bindungen, verschachtelte Quellgrenzen, Immutable-/Kopierverhalten, aufbewahrte Originale und negative Datei-/JSON-/Pfad-/Digest-Kontrollen. Fixtures sind lokale Unit-Eingaben, keine native Build- oder Runtime-Autorität.

## Befehle und Ergebnisse

Test-first wurde Missing-module-RED beobachtet; anschließend bestanden neun gezielte Autoritätstests. Die zuständige Framework-Python-Umgebung bestand48 Autoritäts-/Reader-/Projektions-/Registry-Tests. Repository-natives `make test-no-crs-contract` bestand alle309 Tests; `make check-documentation` und gestagte Whitespace-Prüfungen bestanden. Exakte Befehle und externe Logs bleiben im Handoff erhalten. RTK umschloss jeden Shell-Befehl.

## Sicherheitsauswirkung

Kein Digest, keine Revision und keine Wurzel werden aus Kandidatenbelegen abgeleitet. Jedes Autoritätsfeld ist geschlossen und typisiert; Schlüssel des kompilierten Fixture-Mappings sind auf die acht tatsächlichen Fault-Fälle begrenzt. Leere Fault-Mappings erlauben nur Nicht-Fault-Operationen; der Bundle-Reader verlangt weiterhin einen ausgewählten kompilierten Fault-Digest für Fault-Fälle. Fremde Eigentümer werden mit tatsächlichen Deskriptoren und kontrollierten Unit-Metadaten geprüft, weil Eigentümerwechsel im verwalteten Testdateisystem nicht unterstützt werden.

## Dokumentation und Runtime-Evidenz

Dieser Loader prüft nur die ausgewählte lokale Manifestgrenze. Root stellt weiterhin tatsächliche Produzenten-/Build-/Git-/Laufautorität her, prüft Snapshot-Digests über den Bundle-Reader und führt sicheres aufbewahrtes Kopieren aus. Originalbytes müssen unverändert aufbewahrt und erneut geprüft werden, nicht durch serialized_mapping-Ausgabe ersetzt werden.

## Nicht ausgeführte Prüfungen

Kein nativer Build/E2E/Runtime. Keine Git-Cleanliness- oder Gitlink-Ableitung. Ruff nicht verfügbar und nicht installiert; kein Remote-SonarQube-Abschluss behauptet.

## Einschränkungen und Restrisiko

Ein passendes lokales Manifest allein belegt keine vertrauenswürdige Build-Provenienz. Explizite Dateiauswahl und erwartetes Tupel gehören dem Koordinator, nicht dem Beleg. Root-/Quellpfade werden zum Ladezeitpunkt geprüft; spätere Artefakt-/Quelllesezugriffe müssen weiter den strikten Reader verwenden, und Aufbewahrung muss das Originalseal vergleichen.

## Finaler Diff- und Review-Status

Nur gezielter Vier-Dateien-Autoritätsslice. Keine Status-/PASS-Aufwertung, Belegmutation, zentralen Policy-/Schemaänderungen oder beliebigen Wurzelfallbacks.
