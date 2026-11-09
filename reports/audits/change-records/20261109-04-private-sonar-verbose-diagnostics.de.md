# Private ausführliche Sonar-Diagnosen

**Sprache:** Deutsch | [English](20261109-04-private-sonar-verbose-diagnostics.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261109-04-private-sonar-verbose-diagnostics |
| UTC-Datum | 2026-11-09 |
| Framework-Basisrevision | b36565af8f401ce381cd4bca396f30bfef420944 |
| Issue oder Pull Request | Framework PR #169 |

## Motivation und Problemstellung

Der private Wrapper ergänzte DEBUG-Protokollierung zusammen mit einem expliziten `sonar.verbose=false`. Dadurch wurde die beabsichtigte ausführliche Diagnosekonfiguration verhindert. Parsewarnungen ohne Zeilenangabe besaßen außerdem keine separate inventargebundene Darstellung; Dokumentlimits wurden ausschließlich nach ihrem Zahlenwert gruppiert.

## Betroffene Komponenten und Sicherheitsgrenzen

Das Framework besitzt die private Action-Ausführung, Offline-Node-Tests und diesen zweisprachigen Nachweis. Bestehende Aufrufer behalten ihren zuvor eingefrorenen Action-Commit, bis eine separate Aufruferänderung die neu veröffentlichte unveränderliche Action auswählt. Diese Änderung aktualisiert keine Parent- oder MRTS-Quellen, Pins oder Gitlinks.

## Akzeptanzkriterien

Nach Prüfung der ursprünglichen exakten Aufruferparameter DEBUG und `sonar.verbose=true` für Framework und alle drei Parent-Profile erzwingen. Zusätzliche Verbosity-Parameter ablehnen. Die bestehenden 17 Offline-Kontrollen sowie Inventar-, Datenschutz-, Aufzeichnungs-, Cleanup- und Analyseverträge erhalten. Aus mehrdeutigen oder unterbrochenen Exception-Ereignissen keine Quelle ableiten.

## Untersuchte Alternativen

Übernommene Runner-Debug-Einstellungen, öffentliche DEBUG-Rohdaten, erweiterte generische Fehlerklassifikatoren, verkleinerter Analyseumfang und eine künstliche Zeile null für Dateiwarnungen wurden verworfen. Ein Dokumentlimit ohne hinreichenden zusammenhängenden Nachweis bleibt `UNBOUND`.

## Implementierungsentscheidung

Der validierte private Parametersuffix setzt Verbose nun explizit auf true. Dateiwarnungen erfordern eine vollständige Warnhülle mit Zeitstempel und einfachen Anführungszeichen sowie eine vom bestehenden Inventarvalidator akzeptierte Quelle. Als `file_failures` erscheinen nur inventargebundene repositoryrelative Fakten, feste Kategorien und Häufigkeiten. Ein privater schwacher Index je Ergebnis verweist auf höchstens 10.000 gespeicherte Häufigkeitseinträge; wiederholte Warnungen aktualisieren den vorhandenen Eintrag ohne Suche durch das öffentliche Array. Überlaufidentitäten werden nicht indiziert; getrennte Ergebnisse bleiben unabhängig.

Ein privater Streaming-Kontext erlaubt vorausschauend Java-Exception-Köpfe für die ursprüngliche [SnakeYAML-Engine-Basisausnahme](https://github.com/snakeyaml/snakeyaml-engine/blob/master/src/main/java/org/snakeyaml/engine/v2/exceptions/YamlEngineException.java) und die [klassische SnakeYAML-Basisausnahme](https://github.com/snakeyaml/snakeyaml/blob/master/src/main/java/org/yaml/snakeyaml/error/YAMLException.java) sowie eng erkannte Java-Stackfortsetzungen. Diese Klassendefinitionen begründen die vorausschauende Positivliste; sie belegen nicht das Format eines gehosteten Scanner-Ereignisses. Der Kontext endet nach höchstens 32 gesamten Ereigniszeilen oder 16 KiB und wird bei unbekannten/eingeschobenen Zeilen, anderen Logger-Ereignissen, Kürzung, Dekodierverlust oder Eingabeende zurückgesetzt. Limits werden nach Zahlenwert und gebundener Repository-/Pfadidentität gruppiert; ungebundene Limits bleiben separat. Frühere Ausnahmen werden niemals rückwirkend gebunden.

Die erste erkannte Ausnahme muss ein Wurzelkopf sein. Nachfolgende erkannte Köpfe müssen explizite `Caused by`-Fortsetzungen sein. Ein anfänglicher Ursachenkopf oder ein zweiter unpräfixierter Wurzelkopf löscht die Zuordnung, statt eine frühere Dateiidentität zu übernehmen.

## Geänderte Dateien und Tests

Geändert wurden `.github/actions/sonar-private/main.cjs`, `tests/security_regression/sonar-private-diagnostics.test.cjs` und dieser zweisprachige Nachweis. Sechs zusätzliche Testgruppen prüfen vorausschauende Bindung, verschiedene und wiederholte Dateien, ungebundene frühere Ereignisse, unsichere Pfade und mehrdeutige Anführungszeichen, Kontext-Reset und Lebensdauer, Reihenfolge von Wurzel- und Ursachenköpfen, CRLF, Lesechunk-Grenzen und tatsächlichen UTF-8-Dekodierverlust. Bestehende Parametertests prüfen Verbose true und die Ablehnung zusätzlicher Parameter für alle vier Profile; GPG-Warnzählung und adversarialer Fristtest wurden verstärkt. Die reale Fristlast speichert 10.000 Dateiidentitäten, wiederholt die letzte Identität 50.000-mal über das exportierte `acceptLine` ohne Stream-Zustand und prüft Reihenfolge, exakte Häufigkeiten, Überlaufzählung und Ergebnis-Isolation.

## Befehle und Ergebnisse

Node-24-Syntaxprüfungen bestanden für beide JavaScript-Dateien. Der fokussierte Node-Testlauf bestand alle 23 Tests ohne Fehler oder Skips. Die ursprünglichen 17 Kontrollen bleiben abgedeckt, einschließlich privater Ausgabe, Token-Isolation während des Bootstraps, Aufzeichnungsrechten, kumulativem Überlauf, Timeout, Nachkommen-Cleanup und festem System-Git. Der adversariale Kindprozess behält seine harte Frist von 2500 ms. Dateigenaue Secrets-Prüfungen bestanden für die qualifizierten Postimages. Kein privater Canary erschien in der Testausgabe.

## Sicherheitsauswirkung

Offizielle Upstream-Action, Scannerversion, Signaturprüfung, exakte Quellrevisionen, vollständiger Analyseumfang, native Parameter, Include-Pfade, Sprachstandards und Quality-Gate-Wartezeit bleiben unverändert. Rohaufzeichnungen bleiben privat und begrenzt; übernommenes Runner-Debug bleibt ausgeschlossen. Der Parser veröffentlicht keinen Exception-Rohtext, Quellinhalt oder erfundene Position. `diagnosis_complete` bleibt false.

## Dokumentation und Runtime-Evidenz

Dieser englische/deutsche Nachweis beschreibt Quelländerungen und Offline-Qualifikation. Die Tests führten keine Scanner-Qualitätsanalyse aus und erhoben keinen Connector-Laufzeitnachweis. Die neue unveränderliche Action-Commit-Identität steht bis zur Veröffentlichung aus; eine spätere separate Aufruferänderung muss sie einfrieren.

## Nicht ausgeführte Prüfungen

Frische gehostete Verbose-Ausführung, Cloud-Befund- und Gate-Prüfung am exakten Head sowie kausale Schließung der Shell-/JSON-/CFamily-Diagnosen stehen aus. Bestehende Aufrufer-/Quelldigest-Zulassung muss vor Integration über die normale Producer- und Veröffentlichungsreihenfolge abgeglichen werden.

## Einschränkungen und Restrisiko

Die Exception-Hülle ist vorausschauend. Nicht unterstützte künftige Scannerformate bleiben ungebunden, einschließlich Fortsetzungszeilen mit Zeitstempel. Quellbindung identifiziert ein zusammenhängendes akzeptiertes Ereignis; sie beweist weder Analyzer-Vollständigkeit noch die Schließung historischer Parsinglücken. Offline-Erfolg belegt kein gehostetes Ergebnis ohne Befunde.

## Finaler Diff- und Review-Status

JavaScript-Diff und Whitespace-Prüfung bestanden die lokale Durchsicht. Die Quellqualifikation steht für unabhängige Prüfung bereit; Veröffentlichung, Einfrieren der Aufrufer, gehostete Validierung und übergreifende Integration bleiben ausstehend.
