# Änderungsnachweis

**Sprache:** Deutsch | [English](20261008-24-nginx-native-operation-bundles.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change ID | 20261008-24-nginx-native-operation-bundles |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | `3435e0aa131034dd56b022adbaeda04cda4ae8e1` |

## Motivation und Problemstellung

Ein Operationsbeleg oder HTTP-Status allein authentifiziert keine aufbewahrten nativen Beobachtungen. Zweiundvierzig geschlossene native NGINX-Operationen benötigen einen gemeinsamen strikt ablehnenden Leser, bevor der separat verantwortete kanonische Normalizer ihre Evidence verarbeitet.

## Betroffene Komponenten und Sicherheitsgrenzen

Nur neuer Framework-Leser, gezielte Tests und dieses Nachweispaar. Bestehende eigenständige Operationshelfer werden wiederverwendet. Parent-Produzenten, Katalog, Schemas, kanonische Statuszuordnung, versiegelte Aufbewahrung, MRTS und Gitlinks bleiben in diesem Slice unverändert.

## Akzeptanzkriterien

Originalbelege und Rohartefakte unter expliziter Artefaktautorität erneut öffnen. Unsichere Pfade, Symlinks in jeder Komponente, Hardlinks, fremde Eigentümer, beschreibbare Verzeichnisse/Dateien, nichtreguläre oder übergroße Dateien, abweichende Digests/Quellen/Läufe/Rollen/Operationen sowie H2/H3-Ersatz ablehnen. Tatsächliche Konfiguration, Build-Snapshots, native Transaktions-/Fehler-/Cleanup-Fakten und geschlossene Helferprüfung verlangen. Niemals Ereignisse erfinden oder Status aufwerten.

## Untersuchte Alternativen

Vom Beleg gewählte Quell-Whitelists, abgeleitetes Framing, unversiegelte Originalbelege und HTTP-only-Akzeptanz belegen die ausgewählte Beobachtungsschicht nicht. Lokaler Erfolg darf weder als vertrauenswürdige Build-Provenienz noch als Remote-Quality-Abschluss dargestellt werden.

## Implementierungsentscheidung

`validate_native_operation_bundle(record, authority, sources, canonical=False)` liefert geprüfte Schichtfakten oder löst `ValueError` aus. Die Aufruferautorität liefert exakte Parent-/Framework-/MRTS-Revisionen, Quellwurzeln und erwartete Digests von Binary, Modul und ausgewählter Fault-Library. `required_source_paths(case_id)` exportiert die geschlossene namespaced Quell-Whitelist für den Produzentenwrapper. Originalbelegbytes bleiben unverändert; das zurückgegebene Dateimanifest versiegelt erneut gelesene Bytes für anschließendes geprüftes Kopieren.

Routing umfasst rohe H1-Ablehnung, Common-Pointerfehler, Phase 4/MIME, Lifecycle-/Framing-/Soft-Budget-Sequenzen und Ereignisgrenzen. Ereignisgrenzen binden den Originalelternbeleg und verschiedene Kindbelege. Tatsächliche native Ereignisse bleiben flach und unverändert; echte technische Fehler benötigen eine leere Rule. Mapping-Fehler vor Admission haben keine Engine-Transaktion oder Cleanup. Native Allokationsfehler benötigen das begrenzte NULL-Rückgabeledger und Common-Cleanup mit nativer Completion null. Rohe H1-Ablehnung hat keine zugelassene Fault-Transaktion; die gültige Kontrolle benötigt eine tatsächliche native Transaktion und Cleanup.

## Geänderte Dateien und Tests

`tests/runners/nginx_native_operation_bundle.py`, `tests/no_crs/test_nginx_native_operation_bundle.py` und dieses Nachweispaar. Gezielte Tests prüfen alle Routinggruppen mit aufbewahrten Unit-Bytes und echten geschlossenen Helferimplementierungen einschließlich neu versiegelter Negativkontrollen. Unit-Fixtures sind ausdrücklich synthetisch und keine neue native Runtime-Evidence.

## Befehle und Ergebnisse

Die zuständige Framework-Python-Umgebung bestand 23 gezielte Bundle-Tests plus 17 explizite Phase-4-Helfertests (insgesamt 40). Das repository-native `make test-no-crs-contract` bestand alle 284 Tests; `make check-documentation` und die gestagte Whitespace-Prüfung bestanden ebenfalls. RTK umschloss die Ausführung; Caches, temporäre Daten und Logs liegen unter den externen Projektwurzeln. Exakte Befehle und Logs bleiben im Task-Handoff erhalten.

## Sicherheitsauswirkung

Jedes Artefakt wird über No-follow-Dateideskriptoren mit Eigentümer-, Link-, Berechtigungs-, Größen- und stabilen Metadatenprüfungen gelesen. Tatsächliche Build- und kompilierte Fixture-Bytes müssen expliziten Aufruferdigests entsprechen. Doppelte JSON-Schlüssel, nichtendliche Zahlen, verschachtelte native Metadaten und Payload-/Secret-Felder werden abgelehnt. Quellhelfer laufen erst, wenn aktuelle Bytes dem aufruferautorisierten geschlossenen Quellseal entsprechen; dieses wird nach der Prüfung erneut geprüft. Keine beliebige beleggelieferte Quelle wird importiert.

## Dokumentation und Runtime-Evidenz

Dieser Nachweis umfasst ausschließlich lokale Quell- und Unit-Prüfung. Der zurückgegebene Beweis enthält `layer_verified` und Rohfakten, kein kanonisches PASS. Der Koordinator verantwortet Integration, Laufeindeutigkeit, finale Provenienzautorität und versiegeltes geprüftes Kopieren.

## Nicht ausgeführte Prüfungen

Keine neue native NGINX-Runtime und kein vollständiger Build wurden ausgeführt. Ruff ist in der zuständigen Umgebung nicht verfügbar und wurde nicht installiert. Kein Remote-SonarQube-Abschluss wird behauptet.

## Einschränkungen und Restrisiko

Projektionsfrische beruht auf dem authentifizierten Direct-child-Erzeugungsvertrag des Produzenten und exakten Lauf-/Fallnamen; dieser Leser prüft keine beliebigen beleggewählten externen Pfade per stat und stellt keine globale Laufeindeutigkeit her. UID-Ablehnung wird über echte Dateideskriptoren mit kontrollierten `fstat`-Metadaten geprüft, weil Eigentümerwechsel auf dem verwalteten Testdateisystem nicht unterstützt werden. Fehlende Produzentenfelder werden strikt abgelehnt und benötigen Integration, keine erfundenen Beobachtungen.

## Finaler Diff- und Review-Status

Das finale Review ist auf neuen Leser, Tests und Nachweispaar begrenzt. Required-Scope, native Semantik, Schemas und kanonische Policy bleiben unverändert.
