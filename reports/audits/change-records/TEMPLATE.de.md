# Change Record

**Sprache:** [English](TEMPLATE.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | Dokumentiere die eindeutige UTC-basierte ID |
| UTC-Datum | Dokumentiere das Abschlussdatum in UTC |
| Framework-Basisrevision | Dokumentiere die Git-Revision am Ausgangspunkt |
| Issue oder Pull Request | Dokumentiere die Referenz oder dass keine existiert |

## Motivation und Problemstellung

Erkläre, warum diese Framework-eigene Änderung erforderlich ist und welches
Verhalten, welchen Prozess oder welche Evidenzgrenze sie beeinflusst.

## Betroffene Komponenten und Sicherheitsgrenzen

Liste Framework-Pfade und die relevante Grenze auf. Nenne, wenn keine
Sicherheitsgrenze betroffen ist; leite kein Connector-Verhalten ab.

## Akzeptanzkriterien

Liste konkrete, beobachtbare Kriterien auf, die die Fertigstellung bestimmen.

## Untersuchte Alternativen

Fasse wesentliche Alternativen zusammen und warum der gewählte Ansatz zur
Framework-Grenze passt.

## Implementierungsentscheidung

Beschreibe den finalen Ansatz, Kompatibilitätsüberlegungen sowie Cleanup- oder
Grenzbehandlung.

## Geänderte Dateien und Tests

Liste geänderte Dateien, hinzugefügte oder angepasste Tests sowie gegebenenfalls
positive, negative oder Grenzfallabdeckung auf.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Dokumentiere jeden ausgeführten Befehl | Dokumentiere den tatsächlichen Exit-Code | Dokumentiere eine sichere Zusammenfassung | Dokumentiere nur zulässige Referenzen |

## Sicherheitsauswirkung

Nenne die Sicherheitswirkung, bei einem Security-Fix die erneute Prüfung des
ursprünglichen Pfads und der alternativen Umgehung, oder dass keine
Security-Remediation durchgeführt wurde.

## Dokumentation und Runtime-Evidenz

Liste englische/deutsche Dokumentationsänderungen. Dokumentiere beobachtete
Runtime- oder Lifecycle-Evidenz oder ausdrücklich, dass keine solche Evidenz
erfasst wurde.

## Nicht ausgeführte Prüfungen

Liste jede relevante ausgelassene Prüfung und ihren Grund.

## Einschränkungen und Restrisiko

Nenne bekannte Einschränkungen, nicht behobene Voraussetzungen und verbleibende
Risiken, ohne sensible Inhalte zu kopieren.

## Finaler Diff- und Review-Status

Dokumentiere Review von staged/unstaged Diff, Whitespace-Review, Secret-Review
und finalen Commit- oder Übergabestatus.
