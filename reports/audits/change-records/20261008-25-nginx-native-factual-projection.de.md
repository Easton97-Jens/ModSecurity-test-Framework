# Änderungsnachweis

**Sprache:** Deutsch | [English](20261008-25-nginx-native-factual-projection.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change ID | 20261008-25-nginx-native-factual-projection |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | `f14b2cf0744fe30f3d64ccb421b98adaf1dfd863` |

## Motivation und Problemstellung

Geprüfte native Operationsbelege müssen abgebildet werden, ohne Belegmessungen oder connectorspezifische Erwartungen in erfundene native Ereignisfelder umzuwandeln. Logging-Cleanup-Allow darf niemals zu Request-Header-Allow werden.

## Betroffene Komponenten und Sicherheitsgrenzen

Nur neue Framework-Faktenprojektion, gezielte Tests und dieses Nachweispaar. Aktuelle eigenständige Native-Descriptor-Registry und Phase-eins-Override-Abhängigkeiten wurden regulär eingespielt. Generischer Validator, Katalog, Schemas, Root-Integration, MRTS und Gitlinks werden durch den Projektionsslice nicht verändert.

## Akzeptanzkriterien

Strikten Reader-Schichtbeweis und exakte Fall-/Lauf-/Operations-/Originalinvokationsidentität verlangen. Deklarierten nativen Descriptor gegen aktuelles CaseSchema und alle42 geschlossenen Routen prüfen. Echte flache native Ereignisse unverändert halten; tatsächliche Phasen und Rules auswählen, Cleanup separat ausgeben und Terminaloperations-, Deny-Aktions- sowie Cleanup-Reihenfolgewidersprüche ablehnen. Generische Fallerwartungen erhalten und immutable connectorspezifische Overrides ausgeben. Keine Status- oder canonical_status-Entscheidung.

## Untersuchte Alternativen

observed_event_fields aus erwarteten Namen zu füllen oder Ereignismetadaten aus einem Beleg zu erraten, würde Evidence erfinden. Logging-Cleanup als Request-Header-Allow auszuwählen würde eine Lifecycle-Grenze überschreiten.

## Implementierungsentscheidung

`project_native_operation(case, proof)` liefert kopierte faktische Beobachtungen und schreibgeschützte native Descriptors/Overrides. Der repository-eigene CaseSchema-Validator wird unverändert wiederverwendet. `observed_event_fields` enthält ausschließlich echte ausgewählte native Schlüssel. Belegmessungen, geparste numerische Reason-Felder, exakte ursprüngliche JSONL-Zeilengrößen/-Digests und dekodierte Socket-Framing-Messungen liegen ausdrücklich separat in `mappingEvidenceFacts`; Response-Bodies werden dort nicht kopiert. Vollständige native Ereignisse und cleanup_native_events behalten ihre tatsächlichen Phasen und Felder.

Rohe fehlerhafte Requests behalten tatsächliches HTTP400 ohne zugelassene Fault-Transaktion/-Ereignis. Finish-Fehler behalten sichtbares200 und natives Logging-HTTP0. Budgetfälle behalten tatsächliches504 vor Commit oder sichtbares200 danach mit echtem Timeout-/Timing-Paar. Clean-Shutdown behält tatsächliches200. MIME-/Body-Limit-/Ereignisgrenzenbeobachtungen und alte Safe-Modus-Erwartungen bleiben explizit; kein fehlender erwarteter Ereignisschlüssel wird synthetisiert.

Integrationskorrektur: Der tatsächliche Request-Header-Interventionscallback gibt `phase1_intervention` / `MSCONN_EVENT_REQUEST_BLOCKED`, natives HTTP403, leeres `actual_action` und sichtbares HTTP0 vor Versand der Hostantwort aus. Die Projektion verlangt nun diese exakten Felder statt einer erfundenen bereits gesendeten Deny-Aktion; widersprüchliche Rule-Match-, Allow-, sichtbare Status- und Aktionsbehauptungen bleiben abgelehnt.

## Geänderte Dateien und Tests

`tests/runners/nginx_native_operation_projection.py`, `tests/no_crs/test_nginx_native_operation_projection.py` und dieses Nachweispaar. Reine Fixtures prüfen alle42 Descriptors sowie Null-/Fall-/Phasen-/Rule-/Lauf-/Schema-/Mutationskontrollen, Cleanup-Scope, tatsächliche Deny-Aktion/Status, Terminalwidersprüche, Budget-/Finish-Unterschied und rohe Framing-Fakten. Fixtures sind keine native Runtime-Evidence.

## Befehle und Ergebnisse

Test-first wurde die Modulabwesenheit als RED beobachtet. Die zuständige Framework-Python-Umgebung bestand acht gezielte Projektionstests und 56 breitere Reader-/Registry-/Phase4-/Projektionstests. Repository-natives `make test-no-crs-contract` bestand alle300 Tests; `make check-documentation` und gestagte Whitespace-Prüfungen bestanden. Exakte Befehle und externe Logs bleiben im Task-Handoff erhalten. RTK umschloss sämtliche Shell-Ausführung.

Root-Integration beobachtete die sourcegetreue Callback-Fixture als RED; nach exakter Callback-Korrektur bestanden 34 gemeinsame Projektions-/Strict-Reader-Tests. Dies bleibt kontrollierte Fixture-Prüfung, keine Runtime-Evidence.

## Sicherheitsauswirkung

Projektion verleiht keine Source-/Build-Autorität. Sie verlangt einen strikten Reader-Beweis und erhält tatsächliche Phasen-/TX-/Rule-Grenzen; finale Source-/Digest-/Rerun-/Aufbewahrungsautorität bleibt beim Koordinator. Falsche native Ereignisreihenfolge, fremde Operationen nach Pointer-Ablehnung, Deny-actual_action-Allow oder HTTP200 und manipulierte Descriptors werden abgelehnt. Immutable Overrides migrieren keine generischen Erwartungen anderer Connectoren.

## Dokumentation und Runtime-Evidenz

Dies ist eine faktische Mapping-Schnittstelle, kein kanonisches Akzeptanzgate. Kein PASS/status/canonical_status wird zurückgegeben. Ausgewählte Ereignisse schließen Cleanup bewusst aus Request-Operationsbeobachtungen aus; separat ausgegebenes echtes Logging-Cleanup bleibt für koordinatorgewählte Cleanup-Verträge verfügbar.

## Nicht ausgeführte Prüfungen

Keine native Runtime und kein vollständiger Build. Ruff nicht verfügbar und nicht installiert; kein Remote-SonarQube-Abschluss behauptet.

## Einschränkungen und Restrisiko

Ein Dictionary mit behauptetem layer_verified ist keine kryptografische Authentifikation; Aufrufer müssen das tatsächliche strikte Reader-Ergebnis unter kontrollierter Source-Autorität übergeben. Generische Request-Ereignisse, die in der nativen Quelle fehlen, bleiben fehlend und werden nicht erfunden. Schreibgeschützte Descriptor-Mappings benötigen bewusstes Kopieren, falls ein Aufrufer connectorspezifische Erwartungen serialisieren oder zusammenführen will.

## Finaler Diff- und Review-Status

Nur gezielter Vier-Dateien-Projektionsslice. Generische Erwartungen, native Ereignisse, Required-Scope und kanonische Policy bleiben unverändert.
