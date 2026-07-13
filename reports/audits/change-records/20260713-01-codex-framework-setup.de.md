# Change Record: 20260713-01-codex-framework-setup

**Sprache:** [English](20260713-01-codex-framework-setup.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260713-01-codex-framework-setup` |
| UTC-Datum | 2026-07-13 |
| Framework-Basisrevision | `77b4e89d230a23a75bff4d871d87345d55fcad28` |
| Issue oder Pull Request | Keines; Repository-Einrichtungsaufgabe |

## Motivation und Problemstellung

Das eigenständige Framework benötigte lokale Codex-Anweisungen, einen
Framework-eigenen Nachverfolgbarkeitsprozess und zweisprachige
Zusammenarbeitsvorlagen. Der bisherige Dokumentationsvalidator deckte nur
ausgewählte Dokumentationspartner ab, nicht Audit-Records oder Issue-Vorlagen.
Auch der Pull-Request-Vorlage fehlten die erforderlichen englischen/deutschen
Abschnitte und Review-Fakten.

## Betroffene Komponenten und Sicherheitsgrenzen

Dies ändert lokale Codex/RTK-Anweisungen, Dokumentations- und
Repository-Pfad-Validierung, Zusammenarbeitsvorlagen und Framework-Audit-
Records. Es fügt kein Connector-Runtime-Verhalten, keinen Host-Adapter, keine
Capability, Promotionsentscheidung oder Runtime-Evidenz hinzu. Die relevante
Grenze ist der sichere Umgang mit lokalen Anweisungen und Review-Evidenz:
lokale Einrichtung bleibt ignoriert, Records bleiben payload- und secret-frei.

## Akzeptanzkriterien

1. Lokale `AGENTS.md`-, `RTK.md`- und `.codex/`-Anweisungen existieren und
   werden über die aufgelöste lokale Git-Exclude-Datei ignoriert.
2. Der bestehende Validator deckt getrackte manuelle Dokumente, Change Records
   und Issue-Vorlagenpaare ab und schließt lokales Codex/RTK-Material
   ausdrücklich aus.
3. Die Pull-Request-Vorlage enthält englische und deutsche Abschnitte für
   Zusammenfassung, Motivation, Change-ID, Kriterien, Änderungen, Tests,
   Sicherheit, Dokumentation, Runtime-Evidenz, Einschränkungen, ausgelassene
   Prüfungen und Secrets.
4. Gepaarte Dokumentation zur Nachverfolgbarkeit, Audit-README und Change-
   Record-Vorlagen liegen unter Framework-eigenen Pfaden vor.
5. Fokussierte Dokumentationsprüfungen, Linting, statische Vertragstests und
   Whitespace-Prüfungen bestehen, ohne das Parent-Repository zu ändern.

## Untersuchte Alternativen

- Ein neuer eigenständiger Zweisprachigkeitschecker wurde verworfen. Die
  Erweiterung von `check-variable-documentation.py` erhält den bestehenden
  Einstieg; eine getrennte Leserdokument-Inventarisierung vermeidet, Vorlagen
  mit Variablen- und Platzhalterextraktion zu vermischen.
- Ein Audit-Verzeichnis im Parent-Repository wurde verworfen, weil das
  Framework ein eigenständiges Git-Repository ist.
  `reports/audits/change-records/` ist von Connector-erzeugter Testausgabe
  getrennt.
- Eine manuelle Bearbeitung generierter deutscher Reports wurde verworfen, weil
  generiertes Material seinem Generator gehört.

## Implementierungsentscheidung

Der bestehende Checker verwendet jetzt getracktes Markdown, um Paare für
manuelle Framework-Dokumente, Audit-Records und Issue-Vorlagen zu verlangen.
Er behält Generator- und Upstream-Ausnahmen bei, validiert zweisprachige Pull-
Request-Abschnitte und ist als `make check-bilingual-docs` verfügbar, ohne das
bestehende Kompatibilitätsziel zu entfernen. Die Repository-Pfad-Validierung
überspringt lokale Codex- und RTK-Pfade, damit ignorierte lokale Anweisungen
Linting nicht beeinflussen.

Der versionierte Prozess ergänzt englische/deutsche Dokumentation zur
Nachverfolgbarkeit, Vorlagen und diesen Record. Issue-Vorlagen erhalten deutsche
Gegenstücke; Pull-Request-Vorlage und automatischer Versionsupdate-Pull-
Request-Text sind inline zweisprachig.

## Geänderte Dateien und Tests

Versionierte geänderte oder hinzugefügte Dateien:

- `.github/ISSUE_TEMPLATE/{bug_report,documentation,feature_request,security_hardening,test_case_request}.md`
  und ihre `.de.md`-Gegenstücke sowie `.github/ISSUE_TEMPLATE/config.yml`.
- `.github/pull_request_template.md` und
  `.github/workflows/check-common-versions.yml`.
- `Makefile`,
  `ci/checks/documentation/check-variable-documentation.py` und
  `ci/checks/documentation/check-repository-path-references.py`.
- `README.md`, `README.de.md`, `docs/README.md`, `docs/README.de.md`,
  `docs/development.md`, `docs/development.de.md`,
  `docs/change-traceability.md` und `docs/change-traceability.de.md`.
- `reports/audits/change-records/{README,TEMPLATE}.md` und ihre `.de.md`-
  Gegenstücke sowie dieses gepaarte Record.

Die lokale ignorierte Einrichtung besteht aus `AGENTS.md`, `RTK.md` und
`.codex/`; sie ist nicht Teil des Framework-Commits. Die fokussierte
Validierung prüfte die geänderten Dokumentationsskripte; die bestehenden
No-CRS- und Protokollvertragssuiten lieferten positive und negative Abdeckung
der Sicherheitsgrenze.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk init --codex` | 0 | Lokale RTK-Anweisungen und Codex-Referenz erstellt | Nicht zutreffend |
| `rtk git check-ignore -v AGENTS.md RTK.md .codex/config.toml` | 0 | Alle lokalen Pfade entsprachen der aufgelösten lokalen Exclude-Datei | Nur lokaler Git-Exclude |
| `rtk make check-bilingual-docs` | 0 | Erforderliches manuelles/Vorlagen-Inventar bestanden; lokale und generierte Ausnahmen gemeldet | Nicht zutreffend |
| `rtk make check-doc-links` | 0 | Getrackte Markdown-Links und Anchors bestanden | Nicht zutreffend |
| `rtk make check-repository-path-references` | 0 | Gepflegte Dateien geprüft; keine veralteten Pfade gefunden | Nicht zutreffend |
| `rtk make lint` | 0 | Shell-, Python-, Workflow-, Security-Data-Flow-, Katalog-, Dokumentations- und Diff-Prüfungen bestanden | Nicht zutreffend |
| `rtk make test-no-crs-contract` | 0 | 81 Tests bestanden | Nur temporäre Testartefakte |
| `rtk make test-protocol-client` | 0 | 16 Tests bestanden | Nur temporäre Testartefakte |
| `rtk make quick-check` | 0 | Linting, Importer-Check und Diff-Check bestanden | Nicht zutreffend |
| `rtk git diff --check` und `rtk git diff --cached --check` | 0 | Keine Whitespace-Fehler | Staged Framework-Diff |

## Sicherheitsauswirkung

Es wurde kein Anwendungs-, Connector-, Authentifizierungs-, Autorisierungs-,
Validierungs-, Sandbox-, Pfad- oder Protokollverhalten geändert. Die Änderung
verbessert die Review-Sicherheit, indem lokale Anweisungen außerhalb der
Versionsverwaltung bleiben und Records Secrets sowie rohe Payloads weglassen
müssen. Es wurde kein Security-Scan oder keine Remediation durchgeführt;
deshalb gibt es keine erneute Prüfung eines ursprünglichen Angriffspfads oder
einer alternativen Umgehung.

## Dokumentation und Runtime-Evidenz

Framework-Navigation, Entwicklungsanleitung, Nachverfolgbarkeitsprozess,
Audit-Vorlagen, Pull-Request-Vorlage, Issue-Vorlagen und der automatische
Versionsupdate-Pull-Request-Text bieten jetzt englische und deutsche Inhalte.
Es wurde keine Runtime-, Smoke-, Integrations- oder Lifecycle-Evidenz erfasst
oder behauptet.

## Nicht ausgeführte Prüfungen

Connector-Provisioning, Host-Smokes, Runtime-Matrix, Full-Lifecycle- und
Generator-Refresh-Prüfungen wurden nicht ausgeführt. Sie benötigen Connector-
eigene Harnesses oder können generierte Ausgaben umschreiben, und diese
begrenzte Einrichtung ändert weder Runtime-Verhalten noch Generator-Source.
Feature-, Bug- und Security-Remediation wurden absichtlich nicht durchgeführt.

## Einschränkungen und Restrisiko

Generator-eigene deutsche Report-Gegenstücke sind bereits zuvor materiell
veraltet; der aktuelle Generator erzeugt englischen Report-Inhalt und muss
erweitert werden, bevor repository-weite Gleichwertigkeit generierter Reports
behauptet werden kann. Generierte Reports wurden nicht von Hand bearbeitet.

Eine Read-only-Analyse fand außerdem einen bereits bestehenden CI-Fallzahl-
Guard, der nicht zum aktuellen Korpus passt, und einen separaten bereits
bestehenden Fehlschlag eines Security-Regressionstests bezüglich einer
gemeinsam verwendeten temporären Runtime-Root-Policy. Keine der Beobachtungen
ist ein bestätigtes Security-Finding oder eine Remediation-Behauptung, und
keine wurde durch diese Einrichtung geändert.

## Finaler Diff- und Review-Status

Der staged Framework-Diff wurde auf Umfang, Trennung lokaler Pfade, Whitespace
und sensible Inhalte geprüft. Beide Diff-Checks bestanden. Das Parent-
Repository wurde bewusst ausgeschlossen; der Framework-Commit folgt diesem
Record nach der finalen Dokumentationsverifikation.
