# Privater Sonar-Cachevergleich und Diagnosesichtbarkeit

**Sprache:** Deutsch | [English](20261109-05-private-sonar-cache-visibility.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261109-05-private-sonar-cache-visibility |
| UTC-Datum | 2026-11-09 |
| Framework-Basisrevision | d521ea718149e6b5fc719a0dc4fecf07eb733e7f |
| Veröffentlichte Action-Revision | 865e4ec4fd0a745d1d125b3f43b3dd8d56b3ca7a |
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


Die Folgeänderung ergänzt höchstens acht Dokumentlimit-Zuordnungsfakten aus einer strengen nativen Drei-Ereignis-Sequenz: inventargebundene Parse-WARN-Meldung, unmittelbar folgende DEBUG-Limitdetails und unmittelbar folgender DEBUG-ParseException-Stack für dieselbe kanonische Datei. Der Stack muss beide erwarteten IaC-Konvertierungs-/Analyzerframes enthalten und innerhalb von 32 Zeilen und 16 KiB bleiben. Fehlende, vertauschte, fremde, widersprüchliche, abgeschnittene, dekodierungsbeschädigte oder zu große Eingaben setzen die Sequenz zurück; Lesefehler finalisieren sie niemals. Explizite Logger-/Threadidentitäten müssen übereinstimmen und werden verworfen. Ohne Identitäten entsteht nur `SEQUENCE_CORRELATED`, bei Übereinstimmung `LOGGER_THREAD_MATCHED`. Bestehende `UNBOUND`-Beobachtungen, Schweregradzählungen und `diagnosis_complete=false` bleiben erhalten. Die öffentliche [IaC-Protokollimplementierung](https://github.com/SonarSource/sonar-iac/blob/9ab7daea8377cb59a27c89cabb223916263c3480/iac-common/src/main/java/org/sonar/iac/common/extension/analyzer/AbstractAnalyzer.java#L122) begründet diese prospektive Sequenz, identifiziert jedoch keinen eingesetzten Build.

Der numerische CFamily-Parser akzeptiert jetzt optional genau ein Leerzeichen und einen eingeklammerten Suffix aus 40 kleinen Hexadezimalzeichen und verwirft diesen Suffix. Andere Anhänge bleiben abgewiesen. Das Format erscheint in [Scanneroriginalprotokollen](https://community.sonarsource.com/t/random-failure-of-sonarqube-throwing-java-lang-nullpointerexception-exception/141145), belegt jedoch keine aktuelle Hostversion.

## Geänderte Dateien und Tests

Die historische veröffentlichte Cacheimplementierung ergänzte fünf Gruppen für Cachelebenszyklus, Cache-/Pfadablehnung, numerische Versionen, überlange Marker und Exceptionsichtbarkeit. Diese Folgeänderung betrifft nur die Action-Ausführung, ihren Diagnosetest und diesen zweisprachigen Nachweis. Fünf weitere Gruppen erhalten alle bisherigen 28 Gruppen und prüfen die Drei-Ereignis-Sequenz, fehlenden/vertauschten/widersprüchlichen Kontext, Eingabegrenzen, Vertraulichkeit und den strengen Versionssuffix. Der Test mit echtem Git behält für integrierte Prüfungen seine native Repositorywurzel; die explizite Quellwurzelüberschreibung bleibt auf private Kandidatentests begrenzt.

## Befehle und Ergebnisse

Die gehostete Revision `9a9c1b6e95950f6afc50537ee586db4470907dff` bestand 19 CI-Prüfungen bei drei bedingten Skips. Alle fünf Gate-Bedingungen bestanden; keine OPEN- oder ACCEPTED-Befunde und keine Hotspots blieben offen. Der Server meldete 167 FIXED-Befunde und die bestehenden 26 False-Positive-Klassifizierungen. S5906 und S7780 wurden durch Quellkorrekturen als behoben geschlossen. Diese gehosteten Ergebnisse gelten für die vorherige Revision, nicht für diese Diagnosefolgeänderung.

Der geprüfte private Kandidat bestand 33 Node-Tests ohne Fehler oder Skips in 1847.302 ms; seine adversariale Gruppe mit 10.000 Identitäten und 50.000 Wiederholungen dauerte 841.365 ms innerhalb der harten Frist von 2500 ms. Die tatsächlichen integrierten Syntaxprüfungen bestanden für beide JavaScript-Dateien; Node bestand alle 33 Gruppen ohne Fehler oder Skips in 1683.006 ms bei ungesetzter Quellwurzelüberschreibung. Die adversariale Gruppe dauerte 726.114 ms innerhalb von 2500 ms. Kanonische Aktualität, Wartungsaktualität und der Hauptsicherheitsvertrag bestanden. Die 29 Zulassungsmethoden ergaben 27 bestandene Methoden und zwei Fehler: Beide wiesen die geänderte Implementierung gegen den noch festgesetzten historischen Rollenhash ab. Die tatsächliche Composite-Zulassung wies denselben Unterschied ab; dies war der vorherige Übergangsfehler, kein bestandener Lauf mit 20 Composites und einer Node-Action. Weder Rolle noch Testerwartung wurden gelockert. Die historische integrierte Cacheprüfung mit 28 Gruppen und das getrennte vollständige native Ergebnis mit 19 Gruppen und 703 Methoden unter `d521ea718149e6b5fc719a0dc4fecf07eb733e7f` bleiben ihren früheren Quellständen zugeordnet.

## Sicherheitsauswirkung

Offizielle Action- und Scannerpins, Signaturprüfung, Token-Positivliste, sequenzieller Bootstrap, Prozessgruppen-Cleanup und kumulatives Rohaufzeichnungslimit von 128 MiB bleiben unverändert. Quellumfang, native Eingaben, Sprachstandards, Analysetiefe und Gate-Anforderungen bleiben erhalten. Konfigurierte Leer-Cache- und Verbose-Fakten bleiben von beobachteten Analyzerfakten getrennt. Keine Rohfragmente, unbekannten Pfade oder Exception-Inhalte werden ausgegeben; `diagnosis_complete` bleibt false.

## Dokumentation und Runtime-Evidenz

Die historische Cacheimplementierung `5181cedba82af8d83de4b123080fb80ff414de15` mit Main-SHA-256 `a13995cf0b52e3ccc1bb0476ed3dad290e8a9e1bf88d8397cc77afaf1ee06084` bleibt unter `refs/heads/codex/preparation-private-sonar-cache-20261109` erhalten. Die geprüfte Drei-Ereignis-Folgeimplementierung wurde regulär unter `865e4ec4fd0a745d1d125b3f43b3dd8d56b3ca7a` auf `refs/heads/codex/preparation-private-sonar-three-event-20261109` veröffentlicht; ihr Main-SHA-256 lautet `234bb01ea1a24e03ea374bd37dbf65a6c04dc2a80d4f98ecec14e8afe6ea8fe8`, die Action-Metadaten bleiben unverändert. Beide veröffentlichten Referenzen bleiben über spätere Squash- und Task-Bereinigung erhalten. Die neue Referenz schützt die unveränderliche Laufzeitabhängigkeit der hier neu gebundenen Aufrufer. Die Offline-Tests führten keine Scanner-Qualitätsanalyse aus und erhoben keine Connector-Laufzeitevidenz.

Die aktuelle Bindungsprüfung bestand 97 Vertragsmethoden einschließlich 14 nativer Produzenten- und 29 Zulassungsmethoden; auch 11 echte Projektionsmethoden und alle 56 physischen Updater-Methoden bestanden. Die tatsächliche Quellprüfung ließ 20 Composites und die eine geprüfte Node-Aktion zu. Beide JavaScript-Syntaxprüfungen und alle 33 Node-Tests bestanden ohne Quellwurzelüberschreibung (0 Fehler, 0 Skips; 1786,674 ms). Parent-eigenes Python bestand seinen nativen Nachweis unabhängig. Kanonische Aktualität und Wartungsaktualität, primäre Sicherheits-/native CI-Verträge, Ruff-Prüfung und Formatprüfung über 44 Dateien sowie festgesetztes Pyright bestanden. Der erste Projektionsaufruf scheiterte an fehlendem RUNNER_TEMP; der korrigierte Aufruf mit externem Verzeichnis bestand alle 11 Methoden ohne Quelländerung. Die native Generierung änderte nur einen Lock-Commit, zwei Inventar-Digests und vier Archiv-Skalare; sämtliche Mitgliedschaften, 100 Standardfälle, 80 Selektoren und 8316 Archivdefinitionen bleiben unverändert. Gehostete Verifikation und der synchronisierte committete Parent-Zielstand stehen aus.

## Nicht ausgeführte Prüfungen

Der neue unveränderliche Wrapper ist veröffentlicht. Aktuelle Rollen-/Aufruferprüfung und Gesamtquellzulassung bestanden wie oben dokumentiert und lösten die vorherigen zwei Zulassungsfehler sowie den Composite-Fehler ohne Lockerung der Rolle. Vollständige native Prüfung des passenden Zielpaars, gehostete Verifikation und kausale Schließung der Shell-, JSON- und CFamily-Lücken stehen aus. Keine Projekt- oder Qualitätsprofileinstellung wurde geändert.

## Einschränkungen und Restrisiko

Leerer privater Cachespeicher kann Laufzeit und Plattenbedarf erhöhen. Literalmarker überlanger Zeilen zeigen verworfene Evidenz, keine Parserursachen oder Quellzuständigkeit. Das bisherige Dokumentlimitsignal bleibt ungebunden; zusätzliche Sequenzkorrelation ist keine kausale Gewissheit. Eine Zuordnung des öffentlichen Quellstands `2.27-SNAPSHOT` zur eingesetzten `2.27.0.24646` ist nicht belegt. Der strenge optionale Versionssuffix ist durch öffentliche Scannerprotokolle belegt, nicht durch eine aktuelle Hostversion. Offline-Erfolg und bestandenes Gate beweisen keine Parser-Vollständigkeit.

## Finaler Diff- und Review-Status

Die historische Implementierung und Aufrufermigration wurden unabhängig geprüft und regulär veröffentlicht. Der neue private Kandidat wurde vor der Integration unabhängig geprüft. Die lokale Folgeprüfung und die behobenen Übergangsfehler der Zulassung sind oben dokumentiert. Die unveränderliche Veröffentlichung ist erfolgt. Aktuelle Prüfung der erneuten Aufruferbindung und Gesamtquellzulassung bestanden; gehostete kausale Verifikation steht aus. Übergreifende Integration und geschlossene Analyzer-Lücken werden nicht behauptet.
