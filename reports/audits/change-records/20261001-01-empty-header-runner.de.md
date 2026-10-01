# Change Record: echter Leerheader-Runner

**Sprache:** [English](20261001-01-empty-header-runner.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20261001-01-empty-header-runner` |
| UTC-Datum | `2026-10-01` |
| Framework-Basisrevision | `62e4fa8901f80114234f6cafa38a0a8364ace35d` |
| Issue oder Pull Request | Lokaler Framework-Teil; externer Parent-PR #396 bleibt Draft |

## Motivation und Problemstellung

Das ausgewählte Pflichtszenario `empty_header_value` hatte keinen konkreten
Runner. HTTP 200 allein unterschied keinen fehlenden von einem vorhandenen
leeren Header. Der externe Parent-Curl-Treiber unterdrückte materialisierte
Leerheader ebenfalls; seine separat getestete Korrektur ist hier nicht enthalten.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework besitzt YAML, Katalog, generierte öffentliche Ressource und Tests.
Echte Host-Treiber, native Event-Produzenten und Runtime-Promotion liegen
außerhalb dieser Framework-Änderung. Kein Validator oder Event-Produzent
wird geändert.

## Akzeptanzkriterien

Der Runner erreicht den Katalogpfad mit vorhandenem Leerheader. Eine verkettete
Phase-1-Regel verlangt genau einen Header und einen leeren Wert. Audit- und
Native-Event-Erwartung binden Regel `1100503`. Fehlende native Evidence hält
einen behaupteten Source-PASS auf FAIL. Auswahl-Capabilities bleiben unverändert.

## Untersuchte Alternativen

Eine bedingungslose Regel oder reine HTTP-Statusprüfung bewiese kein
Header-Mapping. Der Ausschluss des Pflichtfalls oder fremde Evidence würde
die Lücke verbergen. Die eigene Zweibedingungsregel ist das kleinste echte Fixture.

## Implementierungsentscheidung

`empty_header_value.yaml` hinzufügen, seinen Katalog-Runner verbinden und
Regel-/Phase-Event-Felder verlangen. `request_headers`/`phase1`-Voraussetzungen
und Allow-/HTTP-200-Semantik bleiben erhalten. Die öffentliche Contract-
Ressource mit ihrem Generator erneuern und das YAML-Inventar von 185 auf 186
aktualisieren; 166 No-CRS-Records und 339 eindeutige öffentliche Tests bleiben.

## Geänderte Dateien und Tests

- `tests/cases/no-crs-baseline/catalog.json` und `empty_header_value.yaml`
- `tests/no_crs/test_empty_header_runner.py`
- `tests/no_crs/test_no_crs_baseline.py` (exaktes Inventar implementierter Runner)
- `tests/contract_api/test_public_contract_api.py`
- `modsecurity_test_framework/data/framework-contract-catalog.json`
- `docs/testing-and-evidence.md` / `.de.md` und dieses Record-Paar

## Befehle und Ergebnisse

Alle Shell-Befehle verwendeten RTK. Beide fokussierten Fixture-/Evidence-Tests
scheiterten vor dem Fix und bestehen danach. Die API-Regression der generierten
Ressource beobachtete 186 YAML-Einträge gegenüber der alten Erwartung 185.
Vollständiges `make lint` beendete danach mit Exit0, einschließlich Contract-
API20, Katalog166, Security und Dokumentationsprüfungen. Die erste No-CRS-
Suite bestand131/132 und scheiterte nur, weil ihr exaktes Runner-Inventar das
neue Fixture nicht enthielt. Das Hinzufügen dieses einen implementierten IDs
ohne entfernte Erwartungen ergab132/132 (Exit0). Nach dem vollständigen Lint
wurde kein Produktions- oder Validatorcode geändert, nur dieses Testinventar
und finale Dokumentationsfakten. Abschließende Dokumentations-/Diffprüfungen
werden vor dem Commit erneut ausgeführt. Der erste vollständige Lint lehnte
die deutschen Record-Überschriften ab; ihre Korrektur zum Template erhielt
die Prüfung unverändert.

## Sicherheitsauswirkung

Evidence-Integrität wird verstärkt: Ein fehlender Header oder fehlendes natives
Event erfüllt den Case nicht. Keine Payload, Secrets, neue Eventtypen, Common-
Semantik, Protokollauswahl, Required-Herabstufung oder Statusvalidator-Änderung.

## Dokumentation und Runtime-Evidenz

Testing-Guide und dieser Record liegen als EN/DE-Paare vor. Die externe
Parent-eigene isolierte Diagnose `nginx-empty_header_value-MKUpI7qd`
verwendete den vorhandenen C-Build mit Task-Harness/-Fixture. Sie beobachtete
HTTP 200, Master-UID 0, Worker-UID 65534 und echte native Regel 1100503.
Der unveränderte Parent-Collector sah das Event; Framework-Normalisierung
akzeptierte den einzelnen Source-Case sowie dessen individuelle PASS-
Completeness-Prüfung. Eine echte Nichtleerheader-Kontrolle,
`nginx-empty_header_value-pvB0el3W`, antworteteHTTP200, aber CaseFAIL ohne
natives Zielregel-Event. Die unveränderte Required-Pfad-Diagnose bleibtROT:
53 fehlend nach54, Auswahl97 unverändert. Sein Aggregat bleibt FAIL. Dies ist
diagnostische Evidence, kein neuer Exact-Head-/Full-Lifecycle-Canonical-PASS.

## Nicht ausgeführte Prüfungen

Kein Full-E2E, Parent-Gitlink-Update, Remote-CI, Push, PR-Eingriff oder Merge.
Required-Coverage bleibt rot. MRTS und master bleiben unverändert.

## Einschränkungen und Restrisiko

Einer der ursprünglich 54 fehlenden Ausführungspfade ist implementiert und
lokal beobachtet; weitere Szenarien brauchen getrennte echte Treiber. Runtime-
Ergebnisse aus dem vorhandenen C-Build werden nicht als neuer Exact-Head-Lauf
umetikettiert. Ein späterer Exact-Head-Lifecycle muss vollständige kanonische
Evidence und Prüfsummen erzeugen.

## Finaler Diff- und Review-Status

Die fokussierte unabhängige Read-only-Prüfung fand kein blockierendes Problem.
Source- und begrenzte Diff-/Whitespace-Prüfung fanden keine Secrets oder fremde
Source-Änderungen. Der separate Framework-Commit ist nur lokal; keine Remote-
Delivery oder Parent-Gitlink-Aktualisierung wird behauptet.
