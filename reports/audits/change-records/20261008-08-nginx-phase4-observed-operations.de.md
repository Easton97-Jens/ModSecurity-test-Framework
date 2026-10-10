# Änderungsnachweis

**Sprache:** Deutsch | [English](20261008-08-nginx-phase4-observed-operations.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261008-08-nginx-phase4-observed-operations |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | `044720551348c77ce52b476bd8a20abf4496bceb` |

## Motivation und Problemstellung

Acht Required-Operationen benötigen eine strikte Auswertung aufbewahrter nativer Evidenz. Upstream-Blöcke beweisen keine nativen Append-Grenzen. Die von Common an die Engine gelieferten Bytes beweisen nicht deren tatsächlich behaltene Länge. Eine alte späte Reject-Beobachtung mit unvollständigem HTTP 200 und 65 weitergeleiteten Bytes beweist keine sofortige Ablehnung.

## Betroffene Komponenten und Sicherheitsgrenzen

Eigenständiger Framework-Validator und fokussierte Tests. Der umgebende kanonische Validator bindet weiterhin Revisionen, Artefakte, Lauf, Prozessrollen und Cleanup. Parent besitzt native Produzenten und Client-Aufzeichnung. MRTS bleibt unverändert.

## Akzeptanzkriterien

Alle acht Identitäten bleiben ausgewählt. Hashes der Rohdaten, genaue Quellenwiederverwendung, tatsächliche Append-Größen und Rückgaben, Abschluss/EOS, SAFE-Intervention und sofortiger Engine-Reject müssen übereinstimmen. Widersprüchliche Rohdaten und unvollständige gewöhnliche Antworten schlagen fehl.

## Untersuchte Alternativen

Eine aus der Fixture-Größe abgeleitete Engine-Länge oder alleinige Upstream-Blockzahlen würden die native Grenze offenlassen. Der Validator verwendet stattdessen transaktionsgebundene native Append- und Abschluss-JSONL.

## Implementierungsentscheidung

`validate_phase4_operation(record_id, receipt, raw_artifacts)` liefert eine Fehlerliste. Eine leere Liste bestätigt nur diese Operationsschicht. Beobachtungen oder globales PASS werden nicht erzeugt. Aufbewahrte Dateien sind `phase4-events.jsonl`, `response.headers`, `response.bin`, Client-stdout/stderr, Regeln, Konfiguration und Engine-Fehlerlog. Jede erforderliche Datei muss zum SHA256 ihres Receipts passen.

Native Append-Gründe binden tatsächliche API-Rückgabe, Länge, Aufrufindex ab eins und behaltene Engine-Bytes. Native Abschlussgründe binden behaltene Bytes und Aufrufzahl; ihr Quellkonstruktor verlangt tatsächliche Prozessrückgabe 1 und abgeschlossene Common-Phase 4. Die inspizierten Common-Bytes behalten ihre Bedeutung als gelieferte Bytes. Split/EOS verlangt native 16/11-Byte-Appends und 27 behaltene Bytes; Teilverarbeitung verlangt 65 gelieferte und 64 behaltene Bytes.

Die veraltete minimal-Required-Identität führt ausdrücklich bestehendes SAFE aus. Engine-Reject verlangt den genauen nativen regel-ID-freien 403 und die Diagnose ohne EOS-Abschluss oder Marker-Auswertung. Bereits gesendete HTTP-200-Header sind nur mit tatsächlichem Verbindungsabbruch, null weitergeleiteten Body-Bytes und genauer curl-18-Framingdiagnose zulässig. Der alte späte Reject mit 65 weitergeleiteten Bytes schlägt fehl. Eine Ablehnung vor Commit darf vollständiges HTTP 403 liefern.

## Geänderte Dateien und Tests

Neuer eigenständiger Helfer, `test_nginx_phase4_operations.py` und dieses Dokumentpaar. Gemeinsame Katalog-, Schema- und Collector-Änderungen gehören dem Koordinator. Die vier MIME-Operationen liegen außerhalb dieses geschlossenen Helfers für acht Operationen.

## Befehle und Ergebnisse

RTK-verpackte unittest-Erkennung mit Framework-eigenem Python schlug zunächst wegen des fehlenden Helfers fehl. Die fokussierte phase4-Erkennung bestand anschließend 17 Tests, einschließlich neun vorhandener Eingabevertragstests. Negativkontrollen prüfen Identität, Rohdatenhash, gelieferte/behaltene Bytes, EOS, native Blockgrenzen, SAFE-Modus, gewöhnliche unvollständige Antworten und alten späten Reject. Abschließende Prüfungen stehen in der Aufgabenübergabe.

## Sicherheitsauswirkung

Keine reduzierte Required-Auswahl, aus Fixtures erzeugte Ereignisse, Validator-Abschwächung oder Payload-Protokollierung. Die Reject-Behandlung bleibt auf das beobachtete Engine-Prädikat und die genaue eigene Operation begrenzt.

## Dokumentation und Runtime-Evidenz

Unit-Fixtures sind ausdrücklich synthetische Testeingaben und niemals Laufzeitevidenz. Die früheren Diagnosen wurden geprüft; ihnen fehlen neue native Append-/Abschlussereignisse, deshalb werden sie nicht hochgestuft. Root muss Produzent und Neubau integrieren und frische quellgebundene native Läufe aufzeichnen.

## Nicht ausgeführte Prüfungen

Vollständige integrierte Framework-Suite, nativer Neubau/Lauf und abschließendes CI/Sonar bleiben beim Koordinator. Für diese Teilaufgabe wurde kein Laufzeitfenster zugewiesen.

## Einschränkungen und Restrisiko

Der umgebende Validator muss Produzent, Revisionen, Artefakte, Rollen und Cleanup authentifizieren. Curl-Rückgabe 0 bestätigt erfolgreiches Parsen des aufgezeichneten Framings; dekodierte Antwortbytes sind kein Paketmitschnitt.

## Finaler Diff- und Review-Status

Fokussierte Teilaufgabe im eigenen Worktree; keine Veröffentlichung, Gitlink- oder MRTS-Änderung.
