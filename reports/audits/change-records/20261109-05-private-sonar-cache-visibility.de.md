# Privater Sonar-Cachevergleich und Diagnosesichtbarkeit

**Sprache:** Deutsch | [English](20261109-05-private-sonar-cache-visibility.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261109-05-private-sonar-cache-visibility |
| UTC-Datum | 2026-11-09 |
| Framework-Basisrevision | d521ea718149e6b5fc719a0dc4fecf07eb733e7f |
| Issue oder Pull Request | Framework PR #169 |

## Motivation und Problemstellung

Die gehostete Analyse enthält trotz ausführlicher Protokollierung und bestandenem Gate ungeklärte Parsinglücken. Eine überlange physische Protokollzeile behält bislang Schweregrad- und Parsermarkerzählungen, überspringt jedoch Positions- und Signalextraktion. Diese Beobachtungen identifizieren weder eine Cacheursache noch binden sie ein unzugeordnetes Dokumentlimit an eine Quelle.

## Betroffene Komponenten und Sicherheitsgrenzen

Das Framework besitzt die private Action-Ausführung, Offline-Tests und diesen zweisprachigen Nachweis. Der Kandidat lässt bestehende Aufrufer, Quelldigest-Zulassung, generierte Ansichten, Parent und MRTS unverändert. Scannerrohzustände bleiben runnerprivat und werden gelöscht.

## Akzeptanzkriterien

Für jeden Aufruf einen neuen leeren privaten Dateisystem-Analysecache ohne Wiederherstellung verwenden. Alle vier validierten Analyseprofile und die ursprünglichen 23 Kontrollen erhalten. Nur begrenzte Zahlen- oder Enum-Fakten ausgeben; nicht unterstützte Ereignisformate und kausale Übersetzungseinheitsidentitäten bleiben unbekannt.

## Untersuchte Alternativen

Projekteinstellungen, kostenpflichtige Profiländerungen, Änderungen der Analysetiefe, Ausschlüsse, Aufrufer-Cachepfade, größere unbegrenzte Protokollpuffer und Zuordnung über benachbarte Pfaderwähnungen wurden verworfen. Der Wechsel des Cachespeichers prüft eine Hypothese; er beweist keine Ursache früherer Lücken.

## Implementierungsentscheidung

Nach exakter Prüfung der Aufruferparameter erzeugt der Wrapper ein neues privates Cacheverzeichnis und ergänzt feste Einstellungen für `sonar.cfamily.analysisCache.mode=fs` und `sonar.cfamily.analysisCache.path`. Der Pfad muss für den Argument-Tokenizer der gepinnten Action sicher sein. Vorhandene Einträge und Aliase werden abgelehnt. Der Cache bleibt während des Scanneraufrufs erhalten und wird mit dem bestehenden Cleanup privater Läufe auch bei Fehlern entfernt. Der Downloadcache des Scanners bleibt separat. Die Einstellungen folgen der [Cloud-CFamily-Cachedokumentation](https://docs.sonarsource.com/sonarqube-cloud/analyzing-source-code/languages/c-family/customizing-the-analysis#analysis-cache).

Die CFamily-Versionsextraktion akzeptiert einen vollständigen erkannten Loggerinhalt mit vier begrenzten Dezimalkomponenten. Fehlende oder widersprüchliche Beobachtungen bleiben explizit. Tracking mit festem Speicher meldet Literalmarker und Dekodierverlust überlanger Zeilen, ohne deren Inhalt auszugeben oder Quellen zu binden. Zwei bestehende SnakeYAML-Klassenliterale werden festen Bibliotheks-Enums zugeordnet; sie identifizieren keine JSON- oder IaC-Sensorzuständigkeit. Separate Kontext-Reset-Zählungen und Dokumentbindungsgründe erklären erkannte Grenzen ohne Wiederverwendung abgelaufener Zuordnungen. Bestehende ROOT/CAUSE-, Inventar-, Zeilen- und Bytegrenzen bleiben wirksam.

## Geänderte Dateien und Tests

Der Kandidat ändert `.github/actions/sonar-private/main.cjs`, seinen Diagnoseregressionstest und diesen zweisprachigen Nachweis. Fünf neue Gruppen prüfen echten Cachelebenszyklus, Cache-/Pfadablehnung, numerische Versionsbeobachtungen, späte Marker überlanger Zeilen und Exception-/Bindungssichtbarkeit. Bestehende Profiltests lehnen Cacheüberschreibungen ab; bestehende Timeout-/Überlauftests erzeugen vor der Cleanup-Prüfung einen Cache. Der Test mit echtem Git kann für eine Testkopie außerhalb eines Git-Checkouts eine explizite Quellwurzel wählen.

## Befehle und Ergebnisse

Node-24-Syntaxprüfungen bestanden für beide JavaScript-Dateien. Die vollständige Offline-Kandidatensuite bestand 28 Tests ohne Fehler oder Skips. Alle ursprünglichen 23 Gruppen bleiben erhalten, einschließlich des Kindprozesses mit 10.000 Identitäten, 50.000 Wiederholungen und harter Frist von 2500 ms. Die erste gemessene Suite dauerte ungefähr 1,59 Sekunden; ihre adversariale Gruppe ungefähr 586 ms. Kein Canary erschien in der Testausgabe. Exakte JavaScript-Postimages des Kandidaten bestanden die Secrets-Qualifikation.

## Sicherheitsauswirkung

Offizielle Action- und Scannerpins, Signaturprüfung, Token-Positivliste, sequenzieller Bootstrap, Prozessgruppen-Cleanup und kumulatives Rohaufzeichnungslimit von 128 MiB bleiben unverändert. Quellumfang, native Eingaben, Sprachstandards, Analysetiefe und Gate-Anforderungen bleiben erhalten. Konfigurierte Leer-Cache- und Verbose-Fakten bleiben von beobachteten Analyzerfakten getrennt. Keine Rohfragmente, unbekannten Pfade oder Exception-Inhalte werden ausgegeben; `diagnosis_complete` bleibt false.

## Dokumentation und Runtime-Evidenz

Dieser Nachweis beschreibt einen privaten Kandidaten und Offline-Evidenz. Die Tests führten keine Scanner-Qualitätsanalyse aus und erhoben keine Connector-Laufzeitevidenz. Veröffentlichung und exakte unveränderliche Commit-/Main-Hash-Identität stehen aus. Eine spätere separate Aufrufermigration muss die tatsächlich veröffentlichte Action über normale Zulassungs- und Generierungsverträge einfrieren.

## Nicht ausgeführte Prüfungen

Der Kandidat lief noch nicht in gehosteter CI. Cloud-Prüfung am aktuellen Head, beobachtete Cachewiederverwendung, exakte eingesetzte CFamily-Version und kausale Schließung der Shell-, JSON- und CFamily-Lücken bleiben ungeprüft. Keine Projekt- oder Qualitätsprofileinstellung wurde geändert.

## Einschränkungen und Restrisiko

Leerer privater Cachespeicher kann Laufzeit und Plattenbedarf erhöhen. Literalmarker überlanger Zeilen zeigen verworfene Evidenz, keine Parserursachen oder Quellzuständigkeit. Keine neue Grammatik für kausale Übersetzungseinheiten wird eingeführt. Das aktuelle Dokumentlimit bleibt ungebunden, solange die ursprüngliche strenge Ereignisgrammatik keine Quelle direkt belegt. Offline-Erfolg beweist kein gehostetes Ergebnis ohne Befunde.

## Finaler Diff- und Review-Status

Der Kandidat ist für lokale Diff- und unabhängige Prüfung vorbereitet. Er wurde weder in den Framework-Checkout kopiert noch veröffentlicht oder von Aufrufern ausgewählt. Die übergreifende Integration bleibt ausstehend.
