# Private gehostete Sonar-Diagnose

**Sprache:** Deutsch | [English](20261109-01-private-sonar-diagnostics.md)

## Identität

| Field | Value |
| --- | --- |
| Change ID | 20261109-01-private-sonar-diagnostics |
| UTC | 2026-11-09 |

## Motivation und Problemstellung

Bestandene gehostete Gates bestehen neben Shell-/JSON-Auslassungen und CFamily-Parser-/IR-Lücken. Öffentliches DEBUG kann Geheimnisse offenlegen. Ursachenfakten benötigen einen privaten Produzenten.

## Betroffene Komponenten und Sicherheitsgrenzen

Das Framework verantwortet die neue reguläre Node-Aktion und Offline-Tests. Phase 1 ändert keinen Workflow mit Token. Nach Prüfung und Veröffentlichung muss ein späterer Aufrufer-Commit den exakten vorherigen unveränderlichen Remote-Aktions-SHA verwenden. Lokaler ausführbarer PR-Head-Code darf das Token nicht erhalten. Native Pins/Prüfer müssen denselben vorherigen SHA binden. Parent und MRTS behalten getrennte Verantwortung.

## Akzeptanzkriterien

Offizieller Aktions-Pin, Scannerversion, Signaturprüfung, voller Umfang, Quellidentität, native Eingaben und Gate-Warten bleiben erhalten. Alle Warn-/Fehlerzeilen werden mit festen Kategorien oder ausdrücklichen unbekannten Anzahlen erfasst. Veröffentlicht werden nur inventargebundene relative Quellorte, feste Codes und begrenzte Zahlen. Rohprotokolle/Befehlsdateien bleiben privat, werden entfernt und vererbte Prozessgruppen werden beendet.

## Untersuchte Alternativen

Öffentliches DEBUG, lokale Token-Ausführung am PR-Head, eigene Profile, Ausschlüsse, verkleinerte JSON-Baselines und spekulative Semantikänderungen werden verworfen.

## Implementierungsentscheidung

Runner-verwaltetes Node 24 ruft die unveränderte gepinnte offizielle Aktion mit demselben Interpreter auf. Rohausgabe und Kindprozess-Workflowbefehle bleiben privat. Das Framework behält Compile-Commands und die exakte cfd5-Fixture; Parent behält AutoConfig und seine exakten Include-/Standard-/Projekt-/Gate-Verträge. Ausführbarer Workspace-Code wird nicht importiert. Bekannte JSON-Budgets, Parserzähler und IR-Signale bleiben getrennt; Unbekanntes wird kein Abdeckungsbeleg.

## Geänderte Dateien und Tests

Aktionsmetadaten/-implementierung, Offline-Node-Kindprozesstests und dieser zweisprachige Bericht. Spätere Workflow-/native Vertragsvorlagen bleiben nicht ausführbar, bis der vorherige geprüfte Wrapper-Commit feststeht.

## Befehle und Ergebnisse

Die Syntaxprüfung endete mit 0, und alle 14 gezielten Offline-Tests bestanden für den geprüften Quellstand. Die Tests erfassen Warnungsenden, vererbte Kindprozessgruppen, Credential- und Befehlsisolation, geprüfte Identität/Readback, kanonische Include-Grenzen, sichere Zähler und das gemeinsame Rohdateibudget. Die Testausgabe enthielt keinen Canary. Private Aufgabenbelege bewahren die Evidenz des exakten Quellstands. Gehostete Ausführung oder Auslieferung werden nicht behauptet.

## Sicherheitsauswirkung

Hooks werden weder deaktiviert noch umgeleitet. Fremde Credentials und Variablen zur Ausführungsinjektion werden ausgeschlossen. Rohbytes und Ausnahmetexte werden nie wiedergegeben. Die vollständige Erfassungsdatei ist über alle Kindprozesse auf 128 MiB begrenzt. Include-Pfade müssen kanonische Schreibweise und aufgelöste Eingrenzung bewahren. Projekt-/Scanneridentität sind je Eigentümer fest; CE-Aufgabenkennungen stammen ausschließlich aus begrenztem Readback regulärer Dateien ohne Linkverfolgung mit exakter Projektübereinstimmung. Die unveränderliche Aufrufergrenze ist verpflichtend. DEBUG bleibt sensibel; historischer öffentlicher Engine-Code belegt keine Vertraulichkeit des aktuellen Cloud-Kontexts.

## Dokumentation und Runtime-Evidenz

Private Kandidaten/Evidenz bleiben in externen Aufgabenwurzeln. Connector-Laufzeitkampagne, Deployment und MRTS-Änderungen werden nicht behauptet.

## Nicht ausgeführte Prüfungen

Native Mutationssuiten für die späteren Aufruferänderungen, unveränderliche Aufruferintegration, gehostete Diagnosen mit vollem Umfang und Gate-Readback des exakten Heads stehen aus.

## Einschränkungen und Restrisiko

Vererbte Prozessgruppen werden kontrolliert; bewusste Ausbrüche in neue Sitzungen benötigen Runner-Isolation. Unbekannte Diagnosen bleiben ausdrücklich sichtbar. Ähnliche Parent-/Framework-Zähler beweisen keine identischen Ursachen. Diese Vorbereitung schließt keine Analyzer-Lücke.

## Finaler Diff- und Review-Status

Private Korrektur zur unabhängigen Prüfung; Gesamtbereitschaft bleibt offen.
