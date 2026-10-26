# Framework Sonar follow-up

**Sprache:** [English](20261026-04-framework-sonar-followup.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261026-04-framework-sonar-followup |
| UTC-Datum | 2026-10-26 |
| Framework-Basisrevision | 5ef4dc3c |
| Issue oder Pull Request | [PR #138](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/138) |

## Motivation und Problemstellung

Der erste vollständige CLI-Scan zeigte Git-Binärmetadaten-Warnungen, gezielte Qualitätsbefunde und vier vom Quellkontext abhängige Sicherheitsmeldungen im Compiler-Recorder.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-Sonar-Helfer, Scanner-Properties, strenger Workflow-Prüfer und Offline-Regressionen. Parent-Gitlink unverändert; MRTS read-only. Alle 31 Ubuntu-Runner-Felder bleiben auf 26.04.

## Akzeptanzkriterien

Git-Metadaten aus MAIN und TEST ausschließen, ohne gepflegte Dateien auszunehmen; strikte Validierung und Compiler-Verhalten erhalten; exakte Head-Analyse und quellgestützte Befundeinstufungen dokumentieren.

## Untersuchte Alternativen

Breite Quellausschlüsse, Regelunterdrückung und Gate-Änderungen würden Evidence verbergen. Notwendige Path-Klammerung und gültige Shell-Arithmetik werden nicht allein wegen Analyzer-Warnungen umgeschrieben.

## Implementierungsentscheidung

Nur .git/** als Metadaten ausschließen, kohärente Helferverantwortungen aufteilen, eine ausdrückliche Ubuntu-Runner-Konstante verwenden und das zusammengesetzte Loader-Assert trennen. Vier Meldungen wurden nach unabhängiger Quellprüfung einzeln als FALSE-POSITIVE abgeschlossen: feste private Evidence-Ziele, gleich privilegierte lokale Executable-Auswahl, Listenargumente und JSON-Inhalte überschreiten keine HTTP- oder zusätzliche Privilegiengrenze. Keine Regeln oder Gates geändert.

## Geänderte Dateien und Tests

Nativer Capture-Helfer, sonar-project.properties, Sicherheitsvertragsprüfer, Bereitschafts-/Native-Analyse-Regressionen und gepaarter Sicherheitsleitfaden. Compiler-Recorder und Main-Verhalten, exakte Publisher-Digests, Rechte und Action-Pins bleiben unverändert.

## Befehle und Ergebnisse

77 betroffene Sicherheits-/Updater-Methoden bestanden; neun Native-Analyse-Methoden mit zehn Fällen bestanden, einschließlich kausaler Ablehnung des fehlenden .git-Ausschlusses vor der Korrektur und Erfolg danach. Die Helferrekonstruktion erhielt AST-Semantik und Ausführungsreihenfolge. Hosted-Head 5ef4dc3c schloss freigegebenen SDK-Build, eine reale C-Kompilierung, CLI-8.2.0.6438-Upload und CE-Analyse eb2599ca-c449-4e33-8cb3-e643eb0b593d ab. Elf weitere Workflow-Läufe bestanden. Die vier Befundeinstufungen wurden frisch als RESOLVED/FALSE-POSITIVE zurückgelesen.

## Sicherheitsauswirkung

CFamily führte acht Taint-Regeln ohne daraus resultierende Befunde aus; Python aktivierte 32 Taint-Regeln. Nach den vier geprüften Einstufungen meldete der Gate-Readback für die abgeschlossene Analyse OK mit Sicherheitsrating A; Coverage war keine Gate-Bedingung. Dies behauptet weder vollständige Sicherheit noch Schwachstellenfreiheit.

## Dokumentation und Runtime-Evidenz

Der Scan vor der Korrektur indexierte 764 Dateien mit C-/Python-/Shell-/YAML-/JSON-Profilen, ohne analysierte C++- oder Go-Einheit. Standardlogs liefern kein vollständiges Inventar indexierter Pfade. Die Shell-Warnung common.sh:2617 ließ sich mit statischem bash -n und sh -n nicht reproduzieren; Ausdruck erhalten. Keine Connector-Runtime-Evidence.

## Nicht ausgeführte Prüfungen

Der ursprüngliche Hosted-Job behält sein zuvor fehlgeschlagenes Gate-Ergebnis. Für den Follow-up-Head ist frische Hosted-SDK-/CLI-/Server- und Gate-Prüfung erforderlich. Keine Runtime-, E2E-, I12- oder Updater-Veröffentlichungskampagne.

## Einschränkungen und Restrisiko

Fehlalarm-Einstufungen gelten für die aktuelle lokale CLI-Vertrauensgrenze. Neue Service-Aufrufer oder Privilegienübergänge erfordern erneute Prüfung. Statisches Shell-Parsing belegt kein Laufzeitverhalten.

## Finaler Diff- und Review-Status

Für Koordinatorprüfung und reguläres Follow-up in PR #138 vorbereitet; kein Merge. Hosted-Prüfung der exakten Follow-up-Head-SHA steht aus.
