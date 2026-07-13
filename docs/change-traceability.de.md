# Änderungsnachverfolgbarkeit

**Sprache:** [English](change-traceability.md) | Deutsch

Dieses Dokument definiert den Framework-eigenen Record für nicht triviale
Änderungen. Es macht nachvollziehbare Entscheidungen und
Verifikationsevidenz dauerhaft, ohne einen Record in ein Log-Archiv oder eine
Behauptung über Connector-Runtime zu verwandeln.

## Scope und Ownership

Jeder Record betrifft ausschließlich dieses Git-Repository. Vermische keine
Framework-Änderungen, Tests, Security-Findings, Revisionen oder Commits mit
denen eines Parent-Connector-Repositories. Connector-eigenes Host-Verhalten,
Capability-Deklarationen, Runtime-Artefakte und Promotion-Entscheidungen
bleiben Connector-Evidenz.

## Ablage und Benennung

Records liegen in `reports/audits/change-records/`. Erstelle ein englisches und
deutsches Paar namens `YYYYMMDD-SEQ-short-name.md` und
`YYYYMMDD-SEQ-short-name.de.md`; UTC-Datum und Sequenz machen die ID eindeutig.
Beginne mit der gepaarten Vorlage in diesem Verzeichnis.

## Wann ein Record erforderlich ist

Erstelle einen Record für eine nicht triviale Implementierung, Bugfix,
Security-Remediation, Änderung eines Test- oder Validierungsvertrags,
Generatoränderung, Änderung der Dokumentationsrichtlinie, Workflow-Änderung
oder wesentliche Integrationsentscheidung. Kleine reine Tippfehlerkorrekturen
können ohne Record bleiben, wenn sie keinen Vertrag, Befehl, Evidenzgrenze oder
Nutzerhinweis beeinflussen.

## Erforderliche Fakten

Beide Sprachfassungen enthalten dieselben Fakten.

| Bereich | Erforderlicher Inhalt |
| --- | --- |
| Identität | Change-ID, UTC-Datum, Framework-Basisrevision, Issue- oder Pull-Request-Referenz |
| Begründung | Motivation, Problemstellung, betroffene Komponenten und relevante Sicherheitsgrenze |
| Entscheidung | Akzeptanzkriterien, untersuchte Alternativen und Implementierungsentscheidung |
| Umfang | Geänderte Dateien, hinzugefügte oder geänderte Tests, Dokumentationsänderungen und berücksichtigtes kompatibles Verhalten |
| Verifikation | Exakte Befehle, Exit-Code, kurze Ergebnisse, zulässige Run-ID oder Evidenzpfad falls vorhanden |
| Evidenz | Runtime- oder Lifecycle-Evidenz oder eine ausdrückliche Aussage, dass keine vorliegt |
| Risiko | Sicherheitsauswirkung, nicht ausgeführte Prüfungen mit Gründen, bekannte Einschränkungen und Restrisiko |
| Review | Finaler Diff-Status, Review-Status und Bestätigung, dass keine Secrets oder rohen sensiblen Daten dokumentiert wurden |

## Sicherer Umgang mit Evidenz

Kopiere keine vollständigen Logs, Request- oder Response-Bodies, Cookies,
Credentials, Tokens, Secrets oder vollständigen Umgebungswerte in einen Record.
Bevorzuge Befehl, Exit-Code, kurzes Ergebnis, zulässigen Artefaktpfad, Run-ID,
geprüften Hash, Größe und Redaktionsfakt. Ein statischer Check oder Generator-
Lauf muss als solcher beschrieben werden; er ist keine Host-Runtime- oder
Lifecycle-Evidenz.

## Review und Validierung

Halte den Record vor dem Commit mit dem finalen Framework-Diff und seiner
gepaarten Übersetzung synchron. Führe den fokussierten Check für geänderten
Validierungscode aus, danach die relevanten Prüfungen für Zweisprachigkeit,
Links, Dokumentation, Linting und Diff. Nenne jede nicht ausgeführte Prüfung
und ihren Grund. Nutze die Record-Vorlage und die Regeln in
[Entwicklung](development.de.md); bearbeite keine generator-eigenen Reports
von Hand, nur damit ein Record vollständig wirkt.

## Security-Arbeit

Security-Scans, Validierung und Fixes sind getrennte Phasen. Ein bestätigtes
Finding benötigt einen belegten Angriffspfad, eine Grenze, Kontrolle, Sink oder
gebrochenen Vertrag, Auswirkung, Voraussetzungen, Gegenbeweise und sichere
Reproduktion. Ein Remediation-Record muss zeigen, dass der ursprüngliche Pfad
und eine alternative Umgehung erneut geprüft wurden, ohne eine
Sicherheitskontrolle aus Testbequemlichkeit abzuschwächen.
