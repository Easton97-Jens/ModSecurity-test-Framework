# Change Record

**Sprache:** [English](20261103-03-hosted-sonar-source-remediation.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261103-03-hosted-sonar-source-remediation |
| UTC-Datum | 2026-11-03 |
| Geprüfter Framework-Head | `61982f066a58177a87567116da15bc370dba7d9c` |
| Lieferung | Gezielt im bestehenden Framework-PR167; Parent443/MRTS6 bleiben getrennt |

## Motivation und Problemstellung

Die bestehende Hosted-Analyse lieferte36 neue Anmerkungen:29 Quell-/Testqualitätsbefunde, sechs vermeintliche Credentials in erzeugten Integritätsmetadaten und einen vermeintlichen HTTP-Transport in einem Schema-Identifier. Der bisherige PR-Text überdehnte die Sonar-Ausnahme. Nur lokale Vorprüfung, Installation und Authentifizierungsreparatur bleiben ausgesetzt; Quellkorrekturen und bestehende Hosted-Checks sind erlaubt.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-eigene Quellzulassung, Evidencereader, Dispatch, SBOM-Metadaten und ihre
Negativtests. Parent-/MRTS-Quellen und Pins bleiben getrennt und unverändert.

## Akzeptanzkriterien

Fehlende aktuelle Produktquelle ausdrücklich vor Patch-/Schreibzugriffen abweisen; alle versiegelten Quell-/Profil-/Outputguards erhalten. Protokoll-Receipt-, Access-/Native-/QUIC-Prüfung und Dispatch entlang vorhandener Grenzen zerlegen, ohne Entscheidungen zu ändern oder Fallback zuzulassen. Unbekannte Shell-Downstreamwerte vor H1-Dispatch abweisen. Auth-Erzeugung und SBOM-Eingaben ohne Änderung erzeugter Bytes/Komponentenbedeutung zerlegen. Negative Tests auf ihren einzigen beabsichtigten Ausnahmeaufruf begrenzen.100 Standardfälle erhalten, neue Spezialregressionen nur on demand.

Die Quellkorrekturen betreffen pythonbugs:S2259, sieben python:S3776-Funktionen, sieben python:S1192-Literale, acht python:S5778-Assertions, zwei python:S1172-Parameter, python:S1481, python:S1186, python:S6035 und shell:S131. Keine Regel-, Exclusion-, Suppression-, Schwellen-, Workflowrechte- oder Scannerkonfigurationsänderung.

## Untersuchte Alternativen

Digestdaten, Schemaaliase oder Scannerkontrollen zu ändern würde die Verträge
verfälschen. Dies ist unnötig, wenn der konkrete Vorwurf widerlegt ist.

## Implementierungsentscheidung

Bestehende Quellentscheidungen durch kohärente Validierungsstufen erhalten;
die tatsächlichen Missing-Source-/Unknown-Protocol-Fehlergrenzen korrigieren.
Jeden Metadatenbefund anhand Producer, Consumer und tatsächlichem Sink bewerten.

## Geänderte Dateien und Tests

Protokollreader/-katalog/-dispatch, Auth-Adapter/-Generator, SBOM-Exporter und
vorhandene gezielte Testmodule; gepaarte Guides und regulär erzeugte Metadaten.

### Sechs einzelne Auth-/Digestbefunde

| Issue | Basisfundstelle | Rolle und unabhängig geprüfte Herkunft |
| --- | --- | --- |
| AaGhspyuOBUNh9beDPwi | capture_contract.json:18 | Aktueller Input-SHA256 aus exakten öffentlichen Parent11fab78a-Quellbytes. |
| AaGhspyuOBUNh9beDPwj | capture_contract.json:30 | Nativer Output-SHA256; diese Quelle bleibt unverändert. |
| AaGhspyuOBUNh9beDPwk | capture_contract.json:38 | ForwardAuth-Output-SHA256 nach exaktem gepinntem Beobachtungsdelta auf aktueller öffentlicher Quelle. |
| AaGhspyiOBUNh9beDPwf | capture_recipe.json:171 | Generator-Inputzulassung, unabhängig gleich aktueller öffentlicher Quelle. |
| AaGhspyiOBUNh9beDPwg | capture_recipe.json:183 | Unabhängig berechneter unveränderter nativer Outputpin. |
| AaGhspyiOBUNh9beDPwh | capture_recipe.json:191 | Unabhängig rekonstruierter ForwardAuth-Beobachtungsoutputpin. |

Alle sechs benennen `common/runtime/http_authorization_service.c`; daher die Auth-Heuristik. Jeder Wert wurde unabhängig nachgerechnet, nicht wegen Name/Länge als sicher angenommen. Producer-/Consumerreview verfolgt ausschließlich Input-/Outputvergleiche, Quellobjektauflösung und Evidence; kein Credential-Sink wurde in diesem begrenzten Fluss gefunden. Erzeugter Vertrag und Rezept bleiben bytegleich. Jeder Befund erhielt einen eigenen Nachweiskommentar und bestätigten FALSE_POSITIVE-Readback. Keine pauschale Schließung, Risikoakzeptanz oder allgemeine Auth-/Sicherheitsfreigabe. Digestwerte werden ausgelassen.

### Kanonischer Schema-Identifier

AaGhsp5tOBUNh9beDPw7 (python:S5332, Exporterbasis224) betrifft ausgegebenes `$schema`. Das offizielle [CycloneDX1.6-Schema](https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/bom-1.6.schema.json) hat genau diese HTTP-URI als `$id`. [JSONSchema draft07 core8.3–8.3.1](https://json-schema.org/draft-07/draft-handrews-json-schema-01#rfc.section.8.3) trennt Identifikation von Abruf. Der Exporter führt keinen HTTP-Abruf aus; Offlinevalidierung liefert vertrauenswürdige lokale Schemabytes und verweigert externes Nachladen. Der kanonische Identifier bleibt mit erklärendem Kommentar erhalten; kein Aliaswechsel oder Stringverschleierung. Dieser einzelne Transportvorwurf wurde begründet als FALSE_POSITIVE bewertet. Unbekannte nachgelagerte Verbraucher bleiben für sicheren Abruf verantwortlich.

## Befehle und Ergebnisse

RTK und vorhandenes exaktes Framework-Python3.15.2 wurden verwendet. Die ursprüngliche61982f0-Missing-Source-Grenze wirft AttributeError; die Korrektur wirft ausdrücklich ValueError vor Schreibzugriffen. Gezielte Workerauswahlen bestanden29 Protokoll-/Wiring-,40 Auth-/CurrentCapture-/Quellkontroll- und18 SBOM-/Callertests. Quellerzeugung meldet19 Ausgaben/keine Änderung. Die reine Entwicklungs-SBOM erhält alle78 Komponenteneinträge und besteht offline das offizielle1.6-Schema.

Der Koordinator hält kombinierte Prüfungen, reguläre Quellbindungs-/Archivregeneration, frischen echten H2/H3-Verkehr nach Commit, kanonische Wiederöffnung und terminale Head-CI/Quality Gate getrennt fest. Kein älterer SHA-Nachweis wird umetikettiert. Exakte private Aufrufe, alle36 Befundzuordnungen und sieben einzeln zurückgelesene Kommentare liegen unter dem sonar-followup-20261103T1500Z-Nachweispfad des Laufs.

## Sicherheitsauswirkung

Receipthashes, tatsächliches ALPN/QUIC, native Eventbytes/Transaktionen/Phasen, Rollentrennung und Cleanup bleiben verpflichtend. Standardauswahl unverändert; neue Negative bleiben Spezialfälle/on demand. Gepaarte Protokoll-/Messguides erläutern Shellablehnung und kanonische Schema-Semantik. Keine breite Abnahme, Vollmessung, Integration, administrative Regeländerung oder vorzeitige Pinübernahme. Parent-/MRTS-Quellen und übergeordnete gewöhnliche Gitlinks bleiben unverändert.

## Dokumentation und Runtime-Evidenz

Gepaarte Protokoll-/Messguides und dieses Record dokumentieren die tatsächlichen
Verträge. Frische betroffene H2/H3- und kanonische Nachweise folgen nach Commit;
bestehende Ergebnisse behalten ihre ursprüngliche Quellidentität.

## Nicht ausgeführte Prüfungen

Keine lokale Sonaranalyse, Installation oder Authentifizierungsreparatur. Keine
umfassende Profilkampagne, Vollmessung, Integration, Regelverwaltung oder vorzeitiger Pin.

## Einschränkungen und Restrisiko

Einzelgegenbelege betreffen nur den gemeldeten Feld-/Transportvorwurf; unbekannte
Schemaverbraucher und allgemeine Produktauthentifizierung bleiben getrennt.

## Finaler Diff- und Review-Status

Unabhängige Quellreviews fanden keinen Guardverlust oder materielle Regression. Sieben einzelne nicht zutreffende Vorwürfe besitzen Quell-/Standard-/Datenflussgegenbelege; Hosted-Quellabschluss und vollständiges aktuelles Gate sind nach Lieferung noch zurückzulesen. Dieses Record behauptet keinen zukünftigen Scan, aktuellen Runtimeerfolg oder Mergefreigabe.
