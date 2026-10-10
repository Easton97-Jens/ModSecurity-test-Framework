# Change record

**Sprache:** [English](20261008-32-nginx-native-canonical-authority.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261008-32-nginx-native-canonical-authority |
| UTC-Datum | 2026-10-08 |
| Framework-Basis-Revision | `7b5a7c2d735e3d20564717ce19dd5e0168fd9a6c` |
| Issue oder Pull Request | Framework-PR137; Parent-PR396 bleibt Draft |

## Motivation und Problemstellung

Die42 deklarierten nativen Operationen benötigen echte Originalartefaktprüfung statt Driver-Exit-Akzeptanz. Ein Canonical-Consumer muss explizite unabhängige Run-/Source-/Build-Autorität binden, Originalbytes erhalten und alle akzeptierten Felder offline reproduzieren. Host-Mappings bleiben getrennt von Common-Eventkeys.

## Betroffene Komponenten und Sicherheitsgrenzen

No-CRS-Koordinator, geschlossenes Case-Result-Schema, kontrollierte Binding-Tests und dieses Paar. Wiederverwendbarer strikter Reader, Original-Authority-Loader und geschlossener Faktvertrag bleiben unabhängige Grenzen. Keine Produkt-, MRTS-, Required-Auswahl- oder generische Validator-Abschwächung.

## Akzeptanzkriterien

Native PASS benötigt deklarierten Case-/Host-Descriptor, unabhängig gebundenen Run/P/F/M, typisierten Parent-Framework-Gitlink, tatsächlichen Driver0 plus gültige originale Native-/Config-/Wire-/Fault-/Identitäts-/Cleanup-Evidence und explizite Erwartungen. Fehlende Autorität, Widersprüche, Mutationen, doppelte Bundles und gefälschte Canonical-Summaries abweisen. Originales FAIL/BLOCKED behält Vorrang. Alle97 Required Records und45 finalen Lücken bleiben bis zur frischen Ausführung unverändert.

## Untersuchte Alternativen

Exit0, selbst deklarierte Autorität, aufgefüllte erwartete Felder, erfundene Events und pauschale NOT_EXECUTED-Promotion beweisen keine Runtime. Erwartete Namen in observed_event_fields kopieren vermischt Native-/Host-Verträge. Erste Append-Metadaten repräsentieren keine spätere tatsächliche Intervention.

## Implementierungsentscheidung

`finalize --native-operation-authority <original-owned-json>` lädt separat produzierte Metadaten unter Run-/Parent-/Framework-Identität aus der Canonical-Initialisierung und aktuellem Framework-Gitlink zu MRTS. Originalbytes unter `inventory/native-operation-authority.json` erhalten, im Manifest versiegeln und offline erneut laden; niemals Source-Autorität aus Resultzeilen ableiten.

Striktes Native-Bundle erneut lesen, jede kopierte Datei gegen originale begrenzte Bytes vergleichen, Canonical-Kopie versiegeln und nur Wrapper-bundle_root auf `inventory/native-operations/<case_id>` ändern. Raw-Receipts, Events, Konfiguration und Captures bleiben bytegleich. Doppelte Case-Retention scheitert. Exakte native-only Descriptor-Overrides auf frische Case-Kopie anwenden. Selected Native PASS ohne originalen Operation-Wrapper ist im full_lifecycle-Profil ungültig.

Native Canonical-Records behalten echte Source-Identitäten, tatsächlichen Driver-Exit, geschlossenes Receipt und `native_evidence_mapping`: gemappte Felder/Ursprünge, unveränderte native Ursachen, semantisches Ergebnis/Scope und originale kausale Eventherkunft. observed_event_fields enthält weiterhin nur echte native Keys. Die Summary nutzt den unveränderten relevanten Event des geschlossenen Selectors, nicht den ersten Append oder LOGGING als Phase1-Ersatz. Faktmessungen und Mapping gemeinsam hashen. Offline-Completeness öffnet alle erhaltenen Originalbytes neu, leitet denselben Vertrag erneut ab und vergleicht jedes Akzeptanzfeld; nur reason-/artifact-Anzeigefelder ausnehmen. Generische Cases behalten ihre bestehenden Validatoren.

## Geänderte Dateien und Tests

`ci/checks/catalog/no_crs_baseline.py`, `tests/schemas/no-crs-baseline/case-result.schema.json`, `tests/no_crs/test_nginx_native_canonical_binding.py` und dieses Paar. Kontrollierte Strict-Reader-Fixtures prüfen fehlende Autorität, Source-/Run-/Gitlink-/Driver-/Receipt-/Pfadwidersprüche, Originale/Kopien, doppelte Retention, geschlossenes Schema, Offline-Summary-/Origin-Mutationen, echtes FAIL/BLOCKED und Selected-Wrapper-Pflicht. Alle12 kontrollierten Phase4-/MIME-Summaries nutzen den originalen kausalen Event und weisen geänderte Summary-Actions ab.

## Befehle und Ergebnisse

Initiale Integrationskontrollen vor API-Implementierung rot. Zwei zusätzliche Regressionen rot wegen FAIL/BLOCKED-Promotion und fehlender Faktenherkunft. Unabhängige Source-Kontrolle fand42 fehlende Dependency-Seals. Frische kontrollierte Batches:30 Integrationskontrollen Exit0;61 Reader-/Contract-/Projector-/Binding-Kontrollen Exit0;17 Binding-/Captured-Parser-/Source-Kontrollen Exit0 (6.992s). Die vollständige No-CRS-Contract-Suite bestand361 Tests (150.661s), der frische Wiederlauf mit finalen Selector-/Loader-/Dependency-Ergänzungen372 Tests (153.361s). Ein früherer Aufruf mit falsch benanntem optionalem Testmodul endete Exit1 und gilt nicht als Suite-PASS.

Logs extern im All-required-Task-Analyseroot: `root-framework-no-crs-contract-r1.log`, `root-framework-no-crs-contract-r2.log`, `root-native-dependency-green-r2.log`, `root-native-canonical-phase4-r1.log`. Originalmetadaten-Erhalt deckte state/produced-Artefaktsealing auf und korrigierte es. Der anschließende Dokumentationsschritt des kombinierten Wiederlaufs scheiterte an Entwicklerlokalpfaden in Record26; eine enge EN/DE-Textkorrektur und separater Dokumentationswiederlauf bestanden alle vier Prüfungen (Exit0; `root-framework-docs-r2.log`). Der kombinierte Befehl gilt nicht als Exit0. Vollständiger Lint bleibt bis zum Endergebnis unbestätigt.

## Sicherheitsauswirkung

Strengere Evidence-Autorität/Provenance; keine Guardrail entfällt. Receipts autorisieren keine externen Lesezugriffe, dynamischen Helperpfade, Source-Roots oder kompilierten Artefaktidentitäten. Root/nobody-Identitäten bleiben tatsächlich erhaltene Host-Beobachtungen statt erfundener Metadaten. Kontrollierter Fixture-PASS ist kein nativer Runtime- oder geschützter Trusted-Base-Nachweis.

## Dokumentation und Runtime-Evidenz

EN/DE-Paar und expliziter CLI-Vertrag oben. Originaler Canonical-Status bleibt NOT_EXECUTED. Kein frischer All97-Nativlauf, aktueller sauberer Artefaktbuild, neuer Head-E2E oder Remote-Qualitätsnachweis behauptet. Lokale Candidate-Funktion und unabhängig administrierter geschützter Workflow bleiben getrennt.

## Nicht ausgeführte Prüfungen

Frischer nativer Build/vollständiger E2E, sauberer finaler P/F/M-Pin, Remote-Readback/Delivery/CI/Sonar und geschützte Trusted Base/Host-Gate offen. Vollständiger Lint nicht zertifiziert; keine Werkzeug-/Dependency-Installation.

## Einschränkungen und Restrisiko

Source-Authority-Roots/originaler Artefaktroot müssen für Revalidierung erreichbar bleiben. Retention erhält Bytes, schreibt keine portable Source-Provenance um. Tatsächlich kompilierte Release-/Modul-/Library-/Fixture-Provenance benötigt separate Build-Bereitschaftsprüfung. Required-Felder ohne echte Native- oder explizite Host-Evidence scheitern weiterhin geschlossen.

## Finaler Diff- und Review-Status

Nur Koordinator, Schema, fokussierte Tests und Record-Paar. Separate Ursachen-Commits erhalten Reader-Vokabular, Originalautorität, Faktmapping, echte semantische Auswahl, Dependency-Seals und Captured-Parser-Ausführung. Unabhängiger Reader-Review führte zu Priority-, Source-Byte- und kausalen Summary-Negativkontrollen. Der finale Read-only-Review fand keinen neuen handlungsbedürftigen Defekt;44 fokussierte Tests bestanden (8.744s), dazu unabhängige Priority-/Origin-/Tuple-/Seal-Negativkontrollen. Logs: `stream-c-canonical-final-review.log` und `stream-c-canonical-final-negatives.log`. Syntaxkompilierung und Whitespace-Prüfung bestanden. Kein Amend, Gitlink- oder MRTS-Schreibzugriff in diesem Commit; finaler gestagter Diff wird vor Commit geprüft.
