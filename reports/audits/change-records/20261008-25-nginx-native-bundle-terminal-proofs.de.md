# Change record

**Language:** Deutsch | [English](20261008-25-nginx-native-bundle-terminal-proofs.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change ID | 20261008-25-nginx-native-bundle-terminal-proofs |
| UTC date | 2026-10-08 |
| Framework base revision | `b184389621e81d1d7ef1bd320140731900b1f8ae` |

## Motivation und Problemstellung

Unabhängige Kontrollen am öffentlichen Reader reproduzierten drei akzeptierte falsche Beweisformen: ein nichtdisruptives/erlaubtes Event als Denial-Beweis, weitere native Arbeit nach Transaction-Cleanup und ein P4-Technikfehler nach terminalem P1-Mapperfehler. Neu versiegelte Hashes machen widersprüchliche Beobachtungen nicht gültig.

## Betroffene Komponenten und Sicherheitsgrenzen

Nur nativer Operation-Bundle-Reader, seine bestehenden Unit-Tests und dieses Record-Paar. Freigegebene geschlossene Helper-Abhängigkeiten wurden zuvor in den eigenen Worktree übernommen. Katalog, Projektion, Canonical-Normalisierung, Parent-Produktquellen, Build/Runtime, Gitlinks und MRTS bleiben unverändert.

## Akzeptanzkriterien

Tatsächliche aktuelle P1-Denial-Felder verlangen, keine zukünftige Hostaktion oder Pass-Callbacks. Cleanup muss das letzte Event seiner Transaktion sein. Terminaler Mapperfehler enthält genau seinen echten P1-Protocol-Error und danach erfolgreiches Cleanup mit erhaltenem Fehler. Flache begrenzte Quellskalare ohne Typkonvertierung erzwingen; positive Routen, Source-/Artifact-Authority und Payload-/Typ-/Digest-Negative erhalten.

## Untersuchte Alternativen

Denial-Auswahl nur anhand blocked/action/Rule akzeptiert widersprüchliche Eventtypen und Auslieferungsfelder. Cleanup-Klassifikation ohne Zeitfolge erlaubt native Arbeit nach Freigabe. Filterung nur auf P1-Protocol-Errors verwirft widersprechende spätere Phasen. Lockerungen oder Canonical-PASS aus neu versiegelten Bytes lösen die Fehler nicht.

## Implementierungsentscheidung

sequence_denials verlangt phase1_intervention / MSCONN_EVENT_REQUEST_BLOCKED, request_headers, blocked/deny/deny, Rule1100001, native403 und visible0. Aktuelles access.c emittiert actual_action leer, bevor Core Header sendet; weder allow noch erfundenes zukünftiges deny sind zulässig. Positive kontrollierte Fixtures nutzen diese tatsächliche Quellsprache statt des früheren engine_decision-Ersatzes.

cleanup_events verwirft jede spätere Zeile derselben Transaktion, erhält aber verschachtelte andere Transaktionen. Common-Pointer-Operationen akzeptieren nur den quellgebundenen P1-Protocol-Error und danach Cleanup; spätere/fremde Phasen oder Fehler scheitern statt auszufiltern. native_event_shape prüft das tatsächliche flache Common-Feldvokabular, Pflichtidentität/Phase/Status, maximal255 UTF-8-Bytes ohne NUL, echte Booleanwerte, begrenzte unsigned-Zähler und ganzzahlige Statusfelder. JSON-Duplikat-/Nonfinite-, Nested-/Payload-/Secret- und sichere Dateikontrollen bleiben erhalten.

## Geänderte Dateien und Tests

tests/runners/nginx_native_operation_bundle.py; tests/no_crs/test_nginx_native_operation_bundle.py; dieses EN/DE-Paar. Negativkontrollen ändern originale Unit-Bytes und aktualisieren alle zugehörigen Child-, Parent- und Envelope-Seals; der öffentliche Reader führt tatsächliche geschlossene Helper ohne Validator-Mocks aus. Synthetische Unit-Fixtures sind keine Runtime-Evidenz.

## Befehle und Ergebnisse

Die finalen Kontrollen gegen Original-Reader54f96ad erzeugten genau20 erwartete Fehler in26 Tests. Der korrigierte Reader besteht alle26 Fokustests. Die Operation-Helper-Regressionsmenge besteht88 Tests; make test-no-crs-contract besteht303 Tests. RTK-gekapselte Ausführung verwendet externes TMPDIR/PYTHONPYCACHEPREFIX sowie Logs stream-c-bundle-fix-red-final.log, stream-c-bundle-fix-green.log, stream-c-bundle-fix-cross.log und stream-c-bundle-fix-broad.log. Katalog166, Dokumentlinks, Variablen und Pfadprüfungen bestehen. Das neue Record-Paar besteht den tatsächlichen record_errors-Checker; Diff-Whitespace ist sauber.

Der vollständige check-documentation-Target stoppt am importierten Record20261008-04 mit EN/DE-Überschriftenabweichung: Die erhaltenen Transport-/Finish-Abhängigkeitsbeschreibungen enthalten einen zusätzlichen Unterabschnitt. Dieses ältere Paar liegt außerhalb des Vier-Dateien-Fixes und bleibt unverändert. Details stehen in stream-c-bundle-fix-docs.log.

## Sicherheitsauswirkung

Der Reader akzeptiert weder Cleanup-allow als Denial-Ersatz noch nichtdisruptive Callbacks als Block-Beweis, unmögliche native Arbeit nach Cleanup oder versteckte fremde Phasenfehler in terminalen Mapper-Receipts. Typkonvertierung und unbegrenzte Strings können keine tatsächlichen Beobachtungen erfinden.

## Dokumentation und Runtime-Evidenz

Read-only-Quellautorität: aktuelles Parent access.c request_intervention_log_event, Common-Status-/Phase-/Event-Serializer und native Cleanup-Reihenfolge. Ergebnisfakten bleiben nur layer_verified; weder Canonical-Status noch Events werden erzeugt.

## Nicht ausgeführte Prüfungen

Kein nativer Build, Runtime, E2E oder Remote-CI/Sonar. Der Koordinator verantwortet frische integrierte Evidenz und administrative Source-/Build-Trust.

## Einschränkungen und Restrisiko

Diese Prüfungen belegen Konsistenz der Beobachtungsschicht, keine vertrauenswürdige Build-Provenance, globale Run-/Projektions-Eindeutigkeit zwischen Bundles oder authentifizierte native Ausführung. Source-Admission-Authority und Canonical-Integration bleiben getrennt verantwortet.

## Finaler Diff- und Review-Status

Fokussierter Vier-Dateien-Fix. Die drei ursprünglich akzeptierten falschen Beweisformen werden auch nach vollständiger Neuversiegelung abgewiesen; positive quellgetreue Routen bleiben als Unit-Beobachtungsschichten akzeptiert. Keine Root-Worktree-/Quellmutation oder Veröffentlichung.
