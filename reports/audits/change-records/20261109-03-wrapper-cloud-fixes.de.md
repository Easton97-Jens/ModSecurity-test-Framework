# Quellkorrekturen am privaten Sonar-Wrapper

**Sprache:** Deutsch | [English](20261109-03-wrapper-cloud-fixes.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change ID | 20261109-03-wrapper-cloud-fixes |
| UTC | 2026-11-09 |

## Motivation und Problemstellung

Die gehostete Framework-PR-Analyse meldete 21 JavaScript-Befunde im privaten Diagnose-Wrapper und seinen Offline-Tests. Feste Git-Ausführung, begrenztes Parsing und kleinere Funktionen beheben deren Quellursachen vor Veröffentlichung einer neuen unveränderlichen Action.

## Betroffene Komponenten und Sicherheitsgrenzen

Das Framework besitzt Wrapper, Offline-Tests und diesen zweisprachigen Änderungsnachweis. Parent- und MRTS-Quellen sowie Gitlinks bleiben unverändert. Veröffentlichung der Aufrufer und gehostete Validierung sind separate Schritte.

## Akzeptanzkriterien

Diagnosezählung, begrenzte Quellidentitäten, private Aufzeichnungen, Zugangsdaten, Cleanup und Scannerparameter erhalten. Git-Auflösung über PATH, wiederholte Regex-Versuche, übermäßige Funktionskomplexität und Await-Schleifen beseitigen; abhängige Bootstrap-Schritte bleiben sequenziell.

## Untersuchte Alternativen

Unterdrückungen, Ausschlüsse, akzeptierte Befunde, abgeschwächte Tests und parallele abhängige Bootstrap-Operationen wurden verworfen.

## Implementierungsentscheidung

Git verwendet das Ubuntu-Systemprogramm `/usr/bin/git`. Feste Trenntexte identifizieren Übersetzungseinheitenzähler vor einer rückwärts gerichteten Ziffernsuche; Projektbindungen verwenden Trimmen und einen verankerten literalen Schlüssel mit Trennzeichen. Hilfsfunktionen trennen Pfadbegrenzung, Schweregrade, Signale, Zähler und Quellpositionen. Git-Initialisierung, Fetch und Checkout bleiben explizit sequenziell. Unabhängige Timeout-/Überlauffälle behalten eigene Cleanup-Prüfungen; die Nachkommenabfrage verwendet einen begrenzten Timer-Helfer.

## Geänderte Dateien und Tests

`.github/actions/sonar-private/main.cjs`, `tests/security_regression/sonar-private-diagnostics.test.cjs` und dieser zweisprachige Nachweis. Eine Regression mit manipuliertem PATH liest das tatsächliche Repository über System-Git und prüft, dass ein vorgeschobenes Programm nie läuft. Ein Unterprozess mit Frist prüft lange Ziffernfolgen, fehlerhafte und doppelte Projektbindungen, überlange Schweregrad-/Parser-Enden und Datenschutz-Canaries.

## Befehle und Ergebnisse

Node-24-Syntaxprüfungen bestanden für beide JavaScript-Dateien. Alle 17 Offline-Tests bestanden ohne Skips: Die ursprünglichen 14 Fälle bleiben abgedeckt, Timeout und Überlauf sind getrennte Fälle, zwei neue Regressionen prüfen Git-Verdrängung und adversariales Parsing. Der adversariale Unterprozess benötigte ungefähr 121 ms bei einer harten Frist von 2500 ms. Dateigenaue Secrets-Prüfungen bestanden vor Lesezugriffen und nach Quelländerungen. Kein privater Canary erschien in der Ausgabe.

## Sicherheitsauswirkung

Keine Kontrolle für Token, Umgebung, Inventar, Signaturprüfung, kumulative 128-MiB-Aufzeichnung, Prozessgruppen-Cleanup, Scannerversion oder Analyseumfang wird abgeschwächt. Rohlogs und Kindprozess-Befehlsdateien bleiben privat. Unbekannte Diagnosen bleiben explizit; `diagnosis_complete` bleibt false.

## Dokumentation und Runtime-Evidenz

Dies ist eine Offline-Qualifikation des Wrapper-Quelltexts. Sie belegt weder Connector-Laufzeitverhalten noch die Schließung einer Analyselücke. Die Action-Metadaten bleiben unverändert mit SHA-256 `2f8f446c1ec1fe765060fdadb54c854f29f474f4eb0091e2001e43d6e6474229`.

## Nicht ausgeführte Prüfungen

Frische gehostete Analyse, Cloud-Befundschließung am exakten Head und Gate-Prüfung folgen nach separater Veröffentlichung. Der neue unveränderliche Wrapper-Commit-SHA ist noch nicht eingefroren und ausstehend; bisherige Aufrufer-/SHA-Verträge werden separat nach Veröffentlichung aktualisiert.

## Einschränkungen und Restrisiko

Bestehende gehostete Shell-/JSON-/CFamily-Diagnosen bleiben offen. Offline-Tests bestätigen keine Cloud-Befundschließung. Der feste Git-Pfad gilt für die unterstützte Ubuntu-Umgebung der gehosteten Action.

## Finaler Diff- und Review-Status

Die Quelländerungen sind lokal für unabhängige Prüfung qualifiziert; Veröffentlichung und übergreifende Integrationsreife bleiben ausstehend.
