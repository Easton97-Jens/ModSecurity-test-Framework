# Traefik-Capture-Quellvorbereitung

**Sprache:** [English](20261103-traefik-capture-source-contract.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261103-traefik-capture-source-contract |
| Repository | Framework |
| Lieferung | Prüfbarer Taskbranch; Integration ausstehend |

## Motivation und Problemstellung

Die vollständige forwardAuth-Vorbereitung brach an der Profilversiegelung ab.
Zusätzlich waren historische Live-Repositoryreferenzen der Objekte veraltet und
migrierte Framework-Hilfsquellen fehlten im vollständigen Parent-Export.
Historische Observer-Varianten hätten neuere Snapshot-/Finalize- und ABI-Guards
entfernt.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-Traefik-Quellvorbereitung und gemeinsame I12-Objektregistry.
Parent-Produktdateien und MRTS liegen außerhalb dieser Änderung.

## Akzeptanzkriterien

Vollständige Request-/Companion-Vorbereitung, strikte Versiegelung, Erhalt aktueller
Produktbytes, reproduzierbare Generierung und gezielte Positiv-/Negativtests bestehen.

## Untersuchte Alternativen

Reine Digestupdates, abgeschaltete Registryprüfung und historische
Produktsnapshots würden Drift verbergen oder aktuelle Guards entfernen;
alle wurden verworfen.

## Implementierungsentscheidung

Das Framework liefert jetzt ein geprüftes Rezept und einen reproduzierbaren
Generator mit `--check`, aktuelle kontextgebundene Produkt-Beobachtungsdeltas,
aktuelle Hilfsquellbindungen und einen versiegelten generierten Adaptervertrag.
Der Generator prüft getrennt festgelegte Eingabe-/Ausgabebytes und erhält Hashes
und Positionen unveränderter Bereiche. Nach Entfernen ausschließlich ihrer
Beobachtungszeilen erhält die native Instrumentierung jedes Produktbyte.
Historische Objekte behalten exakt ihre Identitäten als inerte verlustfreie
Zeilendaten samt ursprünglicher Git-Provenienz. Globale Registryprüfung sowie
Quell-, Ziel- und Ausgabeprüfungen bleiben aktiv. Reine Quellbelege erfassen die
tatsächliche Framework-Revision und getrennte Hashes der Hilfsquellen.

## Geänderte Dateien und Tests

`current_capture.py`, `regenerate_capture.py`, Rezept/generierter Vertrag,
zentrales Manifest samt inerten Objekten/Deltas, Auth-/Native-Vorbereitung,
vorhandene CurrentCapture-/Auth-Tests und gepaarte Auth-README. Neue Regressionen
sind On-Demand; dieses Paket ändert das gemeinsame Standardinventar mit 100 Fällen
nicht.

## Befehle und Ergebnisse

Gezielte Quellvorbereitungs-, positive/negative Adapter- und allgemeine
Quellkopiekontrollen bestanden mit Framework-CPython 3.15.2. Vollständige
Request- und Companion-CLI-Vorbereitung bestanden getrennt. Die regenerierte
Registry mit 169 Objekten und 10 Profilen sowie Generator-`--check` bestanden.
Aufrufe verwenden RTK, explizite `CONNECTOR_ROOT`, `CONNECTOR_REVISION`,
`TEST_ROOT`, `PYTHONPATH` und externe Ausgabeziele. Exakte umhüllte Aufrufe und
Exitcodes bleiben in den Tasknachweisen erhalten.

## Sicherheitsauswirkung

Fail-closed-Zulassung bleibt bindend: unbekannte Produkt-/Hilfsquellbytes,
geänderte Versiegelungen/Deltas und Zielpfadausbrüche werden vor Quellschreibzugriffen
abgewiesen.

## Dokumentation und Runtime-Evidenz

Gepaarte Auth-README dokumentiert Regenerierung und Byte-/Quellgrenzen.
Keine neue Runtime-Evidenz wird beansprucht.

## Nicht ausgeführte Prüfungen

Dieser begrenzte Implementierungsworker führte keine Hostläufe, Vollkampagne,
lokales Sonar oder Remotelieferungsprüfungen aus. Vorhandene Remotegates bleiben
erforderlich.

## Einschränkungen und Restrisiko

Dies ist Framework-eigene Quell-/Testinfrastruktur. Der gewählte Parentstand
`11fab78a5447f75cb254ddf963eca770fa04ba04` ist eine externe Abhängigkeit; weder
Parent-Produktdateien noch MRTS-Dateien ändern sich. Eine Parent-Pinübernahme
benötigt getrennte Lieferung und Integration. Native Quellanwendung bestand;
vollständige native Hostvorbereitung benötigt weiterhin historische
Artefakte/private Toolchain und unabhängige Zulassung. Kein Host wurde gestartet;
Protokoll-, P1–P4-, EOS-, First-byte-, aktuelle Methodenprüfungs- oder
Metadatenabnahme wird nicht behauptet. Historische Fehler bleiben getrennt.
Lokales Sonar war für diesen Auftrag ausdrücklich ausgesetzt; vorhandene
Remoteprüfungen bleiben erforderlich.

## Finaler Diff- und Review-Status

Gezielte Prüfungen und Diff-Whitespacevalidierung bestanden. Unabhängige
Integrationsprüfung, Remotechecks und getrennte Parent-Pinübernahme stehen aus.
