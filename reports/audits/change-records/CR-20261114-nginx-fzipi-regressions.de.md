# Change Record: CR-20261114-nginx-fzipi-regressions

**Sprache:** [English](CR-20261114-nginx-fzipi-regressions.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | CR-20261114-nginx-fzipi-regressions |
| Datum (UTC) | 2026-11-14 |
| Basis-Revision | `31531f74cfe26c2a40d4bb5f6eaae4c0920127e1` |

Der Evidence-Alias `<evidence-root>` bezeichnet den privaten externen Root für Run `20261114-fzipi-review`; dessen genaue Host-Bindung bleibt in den privaten Task-Belegen erhalten.

## Motivation und Problemstellung

Gezielte Regressionen für die extern verantworteten nativen NGINX-/Common-Korrekturen aus fzipis Review von Upstream-PR377 ergänzen.

## Betroffene Komponenten und Sicherheitsgrenzen

Nur vorhandene Framework-Regressionsorte, betroffene Common-Helper-/Adoption-Checker-Verträge und dieser Record als Paar. Parent-Produktdateien und MRTS bleiben getrennt; Parent-Gitlink unverändert.

## Akzeptanzkriterien

Echte Produktschnittstellen zu Audit/Routing/Konfiguration, optionalen Safe-Events gegenüber Strict/echten Fehlern, Beobachtungsbreite, verworfenen Steuerketten, Parser-Herkunft und nativen Append-Limits kompilieren und ausführen. Soweit praktikabel Negativkontrollen gegen alten Code bewahren.

## Untersuchte Alternativen

Quellstring-Assertions und ein neues Parent-Testverzeichnis belegen das geforderte Verhalten nicht. Echte C-Funktionen mit kontrollierten Nachbarn, echte Engine-Serialisierung und einen begrenzten nativen Host-Runner wiederverwenden.

## Implementierungsentscheidung

Tests bleiben über vorhandene Selektoren bedarfsweise ausführbar; keine Erweiterung des automatischen100-Case-Inventars oder der historischen I12-Kampagne. Parent-Quelle explizit mit CONNECTOR_ROOT/CONNECTOR_REVISION und Testinfrastruktur mit TEST_ROOT wählen.

## Geänderte Dateien und Tests

`test_nginx_native_logging.py`, `test_nginx_error_page_intervention.py`, `test_nginx_late_error_results.py`, `test_nginx_context_accounting.py`, Fixture zu `test_nginx_phase4_observation.py`, Fixture zu `test_nginx_response_body_limit.py`; neu `test_nginx_replaced_body.py`, `test_rule_id_metadata.py`; betroffene Fixture `checks/common/check-common-helpers.sh` und `checks/connectors/nginx/check-nginx-common-adoption.py` mit Mutationstests zum Entfernen von Guards. Neu `run_nginx_fzipi_review.py` und statische Fixture `replaced-followup` prüfen echtes Audit/Routing/Konfiguration und Writer-Abschluss. Der Writer-Double weist leere nicht spezielle Links und NULL-Aufrufe ohne Arbeit ab; Fälle zum Leeren ausstehender Ausgabe bleiben erhalten.

## Befehle und Ergebnisse

Die abschließende explizite Unittest-Auswahl bestand75 Methoden aus10 betroffenen Modulen, einschließlich28 Parser-Szenarien mit echter System-libModSecurity3.0.14 und36 Limitvarianten im echten Collector zu Append-Modus/Commit/Prosa. Altcode-Kontrollen kompilierten und lieferten beabsichtigte Laufzeitfehler. Common-Helper-Smoke bestand. Common-Adoption-Checker bestand;11 Mutationsmethoden wiesen28 negative Varianten ab. Vier vorhandene Request-Datei-/Speicher-Testmethoden und zwei Szenarien des vorhandenen Helpers bewahrten ProcessPartial und unabhängige Dateifehler. Befehle/Belege unter `<evidence-root>`.

## Sicherheitsauswirkung

Negativkontrollen schützen vor Fehlerseiten-Bypass, Nutzlast-Regel-ID-Spoofing, Safe-Abbruch bei Sink-Fehler und Herabstufung echter Fehler. Keine Guards, aktiven Inventare oder Pflicht-CI wurden abgeschwächt.

## Dokumentation und Runtime-Evidenz

Dieses EN/DE-Paar beschreibt ausschließlich Framework-Validierung. Der native Parent-Build ist externer Kompilierungsnachweis und keine Framework-Host-/Runtime-Hochstufung. Der extern verantwortete Parent-H1-Stand `b478aeb02c26bf6e44627f43b49678f1abc3081b` bestand9 Host-/Konfigurationsszenarien mit zugelassenen Hashes des geänderten Runners/Fixtures. Beleg `<evidence-root>/native-host-v2/private/result.json`, SHA256 `0364231b54ca098f69666f52777bb0162460b1b1f5ae39001789f0c92388738b`; Root-Master-/nobody-Worker-Vorprüfungen und Cleanup bestanden. Dies ist ausschließlich begrenzte H1-Evidenz.

## Nicht ausgeführte Prüfungen

Keine breite Matrix-/I12-/andere Connector-Kampagne und kein MRTS-Lauf. Kein bestandener CI-/Sonar-Stand am aktuellen Head wird behauptet; maßgeblich sind die PR-Prüfungen.

## Einschränkungen und Restrisiko

Der neue Parser lässt mehrdeutige Roh-Metadaten unbekannt. Test-Doubles belegen keine native HTTP-Auslieferung; der separat beobachtete H1-Lauf mit9 Szenarien liefert diese begrenzte Schicht.32-Bit- und Sink-Fehlerprüfungen bleiben kompilierte Modelle und keine Live32-Bit-/Fehlerhost-Kampagnen. Framework-Auslieferung ändert keinen Parent-Pin.

## Finaler Diff- und Review-Status

Task-Branch `test/nginx-fzipi-review`; tatsächliche Commit-/Push-/PR-Fakten werden im Auslieferungsabgleich erfasst. Kein Merge ist autorisiert. Kombinierter Enddiff/Whitespace und Framework-Change-Record-Prüfungen bestanden vor Auslieferung. Remote-CI/Sonar und PR-Status müssen am aktuellen Head zurückgelesen werden; kein Merge ist autorisiert.

CI-Folgekorrektur: Der erste Lint-Lauf wies wörtliche lokale Host-Pfade in diesem Record ab. Portable Evidence-Aliase ersetzen diese Pfade; kein Checker und keine Prüfregel wurden geändert.

Sonar-Kompilierungsfolgekorrektur: Der Workflow verwendet ausdrücklich den historischen Parent `cfd5e49cada3fc793ef50993147e3796a0907443`. Zwei geänderte Fixtures kompilieren nun gegen diesen Eingang und gegen das begleitende Produkt: Eine redundante interne Helper-Assertion entfällt, während die öffentlichen Sättigungsprüfungen der Antwortbuchhaltung bleiben; typisierte C17-Adapter wählen die alte beziehungsweise neue Signatur des Response-Limit-Prädikats. Kein Produktverhalten wird ersetzt. Beide Fixtures kompilieren mit den Workflow-Warnflags gegen exakt die historischen Header; beide Testmethoden gegen das begleitende Produkt bestehen einschließlich Sanity-Check-Varianten. Die historische Response-Limit-Fixture scheitert bei Ausführung weiterhin an der Prüfung geänderter/fehlender Prosa (Exit10), sodass die Regression wirksam bleibt. Remote-Sonar/Quality-Gate erfordern weiterhin einen Abgleich am aktuellen Head.
