# Privater Sonar-Cachevergleich und Diagnosesichtbarkeit

**Sprache:** Deutsch | [English](20261109-05-private-sonar-cache-visibility.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261109-05-private-sonar-cache-visibility |
| UTC-Datum | 2026-11-09 |
| Framework-Basisrevision | d521ea718149e6b5fc719a0dc4fecf07eb733e7f |
| Veröffentlichte Action-Revision | 5181cedba82af8d83de4b123080fb80ff414de15 |
| Issue oder Pull Request | Framework PR #169 |

## Motivation und Problemstellung

Die gehostete Analyse enthält trotz ausführlicher Protokollierung und bestandenem Gate ungeklärte Parsinglücken. Eine überlange physische Protokollzeile behält bislang Schweregrad- und Parsermarkerzählungen, überspringt jedoch Positions- und Signalextraktion. Diese Beobachtungen identifizieren weder eine Cacheursache noch binden sie ein unzugeordnetes Dokumentlimit an eine Quelle.

## Betroffene Komponenten und Sicherheitsgrenzen

Das Framework besitzt die private Action-Ausführung, Offline-Tests und diesen zweisprachigen Nachweis. Die veröffentlichte Implementierung bewahrte bestehende Aufrufer und generierte Ansichten. Die getrennt geprüfte Aufrufermigration bindet jetzt nur ihre veröffentlichte Identität und den exakten Implementierungshash. Parent behält seinen eigenen reinen Datenvertrag; MRTS bleibt unverändert. Scannerrohzustände bleiben runnerprivat und werden gelöscht.

## Akzeptanzkriterien

Für jeden Aufruf einen neuen leeren privaten Dateisystem-Analysecache ohne Wiederherstellung verwenden. Alle vier validierten Analyseprofile und die ursprünglichen 23 Kontrollen erhalten. Nur begrenzte Zahlen- oder Enum-Fakten ausgeben; nicht unterstützte Ereignisformate und kausale Übersetzungseinheitsidentitäten bleiben unbekannt.

## Untersuchte Alternativen

Projekteinstellungen, kostenpflichtige Profiländerungen, Änderungen der Analysetiefe, Ausschlüsse, Aufrufer-Cachepfade, größere unbegrenzte Protokollpuffer und Zuordnung über benachbarte Pfaderwähnungen wurden verworfen. Der Wechsel des Cachespeichers prüft eine Hypothese; er beweist keine Ursache früherer Lücken.

## Implementierungsentscheidung

Nach exakter Prüfung der Aufruferparameter erzeugt der Wrapper ein neues privates Cacheverzeichnis und ergänzt feste Einstellungen für `sonar.cfamily.analysisCache.mode=fs` und `sonar.cfamily.analysisCache.path`. Der Pfad muss für den Argument-Tokenizer der gepinnten Action sicher sein. Vorhandene Einträge und Aliase werden abgelehnt. Der Cache bleibt während des Scanneraufrufs erhalten und wird mit dem bestehenden Cleanup privater Läufe auch bei Fehlern entfernt. Der Downloadcache des Scanners bleibt separat. Die Einstellungen folgen der [Cloud-CFamily-Cachedokumentation](https://docs.sonarsource.com/sonarqube-cloud/analyzing-source-code/languages/c-family/customizing-the-analysis#analysis-cache).

Die CFamily-Versionsextraktion akzeptiert einen vollständigen erkannten Loggerinhalt mit vier begrenzten Dezimalkomponenten. Fehlende oder widersprüchliche Beobachtungen bleiben explizit. Tracking mit festem Speicher meldet Literalmarker und Dekodierverlust überlanger Zeilen, ohne deren Inhalt auszugeben oder Quellen zu binden. Zwei bestehende SnakeYAML-Klassenliterale werden festen Bibliotheks-Enums zugeordnet; sie identifizieren keine JSON- oder IaC-Sensorzuständigkeit. Separate Kontext-Reset-Zählungen und Dokumentbindungsgründe erklären erkannte Grenzen ohne Wiederverwendung abgelaufener Zuordnungen. Bestehende ROOT/CAUSE-, Inventar-, Zeilen- und Bytegrenzen bleiben wirksam.

## Geänderte Dateien und Tests

Die veröffentlichte Implementierung ändert `.github/actions/sonar-private/main.cjs`, ihren Diagnoseregressionstest und diesen zweisprachigen Nachweis. Fünf neue Gruppen prüfen echten Cachelebenszyklus, Cache-/Pfadablehnung, numerische Versionsbeobachtungen, späte Marker überlanger Zeilen und Exception-/Bindungssichtbarkeit. Bestehende Profiltests lehnen Cacheüberschreibungen ab; bestehende Timeout-/Überlauftests erzeugen vor der Cleanup-Prüfung einen Cache. Der Test mit echtem Git kann für eine Testkopie außerhalb eines Git-Checkouts eine explizite Quellwurzel wählen; die tatsächliche integrierte Prüfung ließ diese Überschreibung ungesetzt.

## Befehle und Ergebnisse

Die gehostete Aufruferrevision `4e7f359ace6a8fed9bbe7e692fe86d3c7dd8472c` beendete CI und Serveranalyse; alle fünf Gate-Bedingungen bestanden, ohne verbleibende Hotspots. Der vorherige S5906-Befund wurde als behoben geschlossen. Ein neuer S7780-Befund verlangte String.raw für einen maskierten Backslash im Cachepfad-Ablehnungstest. Diese Quellkorrektur verwendet das gleichwertige rohe Suffix mit denselben sieben Codepoints und bewahrt jede Assertion sowie alle 28 Testgruppen. Aktionsimplementierung, Metadaten und Aufrufer-Pin bleiben unverändert; die gehostete Bestätigung dieser Stilkorrektur am exakten Head steht aus.

Node-24-Syntaxprüfungen bestanden für beide JavaScript-Dateien. Die tatsächliche integrierte Prüfung bestand 28 Tests ohne Fehler oder Skips in 1631.655 ms; die adversariale Gruppe dauerte 619.873 ms innerhalb ihrer harten Frist von 2500 ms. Alle ursprünglichen 23 Gruppen bleiben erhalten, einschließlich des Kindprozesses mit 10.000 Identitäten und 50.000 Wiederholungen. Kein Canary erschien in der Testausgabe. Exakte integrierte JavaScript-Postimages bestanden die Secrets-Qualifikation. Das getrennte vollständige native Ergebnis mit 19 Gruppen und 703 Methoden gilt für den früheren committeten Stand `d521ea718149e6b5fc719a0dc4fecf07eb733e7f` und belegt das gehostete Verhalten dieser Implementierung nicht.

## Sicherheitsauswirkung

Offizielle Action- und Scannerpins, Signaturprüfung, Token-Positivliste, sequenzieller Bootstrap, Prozessgruppen-Cleanup und kumulatives Rohaufzeichnungslimit von 128 MiB bleiben unverändert. Quellumfang, native Eingaben, Sprachstandards, Analysetiefe und Gate-Anforderungen bleiben erhalten. Konfigurierte Leer-Cache- und Verbose-Fakten bleiben von beobachteten Analyzerfakten getrennt. Keine Rohfragmente, unbekannten Pfade oder Exception-Inhalte werden ausgegeben; `diagnosis_complete` bleibt false.

## Dokumentation und Runtime-Evidenz

Regulärer Commit und Push veröffentlichten `5181cedba82af8d83de4b123080fb80ff414de15` unter der erhaltenen Referenz `refs/heads/codex/preparation-private-sonar-cache-20261109`. Diese veröffentlichte Referenz ist eine Laufzeitabhängigkeit festgesetzter Aufrufer und muss spätere Squash- und Task-Branch-Bereinigung überstehen. Der geprüfte Main-SHA-256 lautet `a13995cf0b52e3ccc1bb0476ed3dad290e8a9e1bf88d8397cc77afaf1ee06084`; die Action-Metadaten sind unverändert. Die getrennt geprüfte Aufrufermigration setzt die veröffentlichte Identität über normale Zulassungs- und native Generierungsverträge fest. Die Offline-Tests führten keine Scanner-Qualitätsanalyse aus und erhoben keine Connector-Laufzeitevidenz.

## Nicht ausgeführte Prüfungen

Gehostete Bestätigung der S7780-Quellkorrektur am exakten Head und kausale Schließung der Shell-, JSON- und CFamily-Lücken stehen aus. Offline-Prüfungen und ein bestandenes Gate belegen weder Cachewiederverwendung noch Parser-Vollständigkeit. Keine Projekt- oder Qualitätsprofileinstellung wurde geändert.

## Einschränkungen und Restrisiko

Leerer privater Cachespeicher kann Laufzeit und Plattenbedarf erhöhen. Literalmarker überlanger Zeilen zeigen verworfene Evidenz, keine Parserursachen oder Quellzuständigkeit. Keine neue Grammatik für kausale Übersetzungseinheiten wird eingeführt. Das aktuelle Dokumentlimit bleibt ungebunden, solange die ursprüngliche strenge Ereignisgrammatik keine Quelle direkt belegt. Offline-Erfolg beweist kein gehostetes Ergebnis ohne Befunde.

## Finaler Diff- und Review-Status

Implementierung und Aufrufermigration wurden unabhängig geprüft und regulär veröffentlicht. Veröffentlichung und gehostete Bestätigung dieser Teststil-Folgeänderung, der passende Parent-Zielstand und verbleibende kausale Diagnoseverifikation stehen aus. Übergreifende Integration und geschlossene Analyzer-Lücken werden nicht behauptet.
