# Importe und Diagnosen der Komponentenwartung reparieren

**Sprache:** [English](20261102-03-component-maintenance-repair.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261102-03-component-maintenance-repair |
| UTC-Datum | 2026-11-02 |
| Framework-Basisrevision | 67483d5140b531e77c12f8a32252f72bc889f8ee |
| Issue oder Pull Request | Folgearbeit zu Actions-Run 41403875624; Task-Branch codex/component-maintenance-repair-20261102 |

## Motivation und Problemstellung

Der gemeinsame Maintenance-Resolver startet den CRS-View-Synchronizer direkt.
Ohne einen vom Caller gesetzten Importpfad konnte das Skript das Framework-Paket
nicht importieren und blockierte den gesamten Plan. Fehlerdetails fehlten im
Bericht; nach einem fehlgeschlagenen Schritt wurde das Plan-Artefakt übersprungen.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-eigene Generator-Importe, kanonische Maintenance-Diagnosen und die
Artefaktgrenze des vertrauenswürdigen Workflows. Parent-Quellcode, dessen
Framework-Gitlink und MRTS bleiben unverändert. Upstream-Diagnosetext darf nicht
zu Markdown-Markup oder GitHub-Runner-Kommandos werden.

## Akzeptanzkriterien

Direkte CRS-Prüfungen und Schreibvorgänge funktionieren ohne `PYTHONPATH` aus
einem getrennten Datenverzeichnis. Fehlgeschlagene generierte Prüfungen bewahren
die abschließende Fehlerursache. Berichte enthalten begrenzte, escapte Gründe;
Logs deaktivieren bei deren Ausgabe die Kommandointerpretation. Fehlgeschlagene
Resolver-/Reconciliation-Jobs bewahren ihren Plan desselben Runs, ohne eine
Downstream-Veröffentlichung zu erlauben.

## Untersuchte Alternativen

`PYTHONPATH` ausschließlich im ersten Job zu setzen lässt andere direkte Caller
weiter betroffen. Eine Paketinstallation ergänzt eine unnötige Voraussetzung.
Fehler generierter Prüfungen zu ignorieren würde den bestehenden Vertrag
abschwächen und wurde verworfen.

## Implementierungsentscheidung

Den vertrauenswürdigen Paketpfad unabhängig von `--root` aus dem aufgelösten
Skriptpfad einrichten. Bei fehlgeschlagenen Generatoren die letzte nichtleere
Fehlerzeile bewahren. Begrenzten Diagnosetext escapen und den Bericht zwischen
unvorhersehbaren Stop-/Resume-Markern des Runners ausgeben. Den an Run und Attempt
gebundenen Plan mit `!cancelled()` hochladen; Resolver-Exitcodes, Digest-Prüfungen,
Berechtigungen und Downstream-Gates bleiben erhalten.
Der Security-Checker verlangt den exakten geprüften Resolver-Body-Digest und die
exakte Bedingung zur Fehleraufbewahrung; entfernte Kommandosperren oder geänderte
Artefaktbedingungen bleiben Vertragsverletzungen.

## Geänderte Dateien und Tests

- `ci/tools/sync-crs-contract-views.py` und seine bestehenden Tests mit echten Unterprozessen.
- `ci/tools/canonical_maintenance.py` und `tests/ci_security/test_canonical_maintenance.py`.
- `.github/workflows/check-common-versions.yml` und `tests/ci_security/test_unified_common_maintenance_workflow.py`.
- `ci/checks/security/check-ci-security-contract.py` und `tests/ci_security/test_ci_security_contract.py` binden das geprüfte Workflow-Profil und weisen veränderte Aufbewahrungs-/Kommandosperren ab.
- `docs/github-actions-workflow-security.md` / `docs/github-actions-workflow-security.de.md` und dieses Record-Paar.

Die Importregression entfernt `PYTHONPATH` und läuft aus dem Fixture-Verzeichnis.
Die Diagnoseabdeckung umfasst einen langen Traceback, HTML-/Markdown-/Steuertext
und die Ausführung des Workflow-Berichtsblocks mit fatalem Exit und kommandoartigem Text.

## Befehle und Ergebnisse

Die Befehle liefen im Framework-Task-Worktree mit deaktiviertem Bytecode und
temporären Dateien unter dem externen Task-Verzeichnis. In den portablen Befehlen
unten bezeichnet `$FRAMEWORK_PYTHON` den bestehenden Interpreter der
Framework-Virtualenv und `$ACTIONLINT` das bestehende actionlint-v1.7.12-Binary.
Der lokale Task-Plan bewahrt deren exakte Host-Pfade auf.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk bypass env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 PYTHONSAFEPATH=1 "$FRAMEWORK_PYTHON" ci/tools/sync-crs-contract-views.py --check` | 0 | Ursprünglicher Importfehler vor der Korrektur reproduziert; direkter Check besteht danach | Task-Worktree |
| `rtk bypass env PYTHONDONTWRITEBYTECODE=1 "$FRAMEWORK_PYTHON" -m unittest tests.ci_security.test_sync_crs_contract_views -v` | 0 | 10 bestehende Testmethoden bestanden, einschließlich direktem Check/Write und portablen Vertragsfällen | Task-Worktree |
| `rtk bypass env PYTHONDONTWRITEBYTECODE=1 "$FRAMEWORK_PYTHON" -m unittest tests.ci_security.test_canonical_maintenance tests.ci_security.test_unified_common_maintenance_workflow` | 0 | 30 Tests bestanden, einschließlich inerter Diagnosen und fatalem Berichts-Exit | Task-Worktree |
| `rtk bypass "$ACTIONLINT" -config-file .github/actionlint.yaml .github/workflows/check-common-versions.yml` | 0 | Geänderter Workflow besteht actionlint v1.7.12 | Task-Worktree |

Das bestehende gesperrte Ruff-0.16.10-Binary bestand `check --no-cache` und
`format --check` für alle fünf geänderten Python-Dateien. Es wurde kein Tool installiert.

Die CI am ersten Head zeigte die zusätzliche Anforderung eines exakten
Workflow-Profils. Nach dessen Aktualisierung bestanden der direkte
CI-Security-Checker, 36 bestehende Vertragstests und der betroffene Test zur
Validierung des vorgeschlagenen Tool-Baums. Drei zusätzliche Mutationen in einem
bestehenden Negativtest weisen fehlende oder geänderte Artefaktbedingungen und
eine entfernte Kommandosperre ab. Ruff Lint/Format bestand für die zwei weiteren
Python-Dateien. Hosted-Prüfungen sind am Folgecommit zu bewerten.

## Sicherheitsauswirkung

Die Importquelle ist der vertrauenswürdige Skript-Checkout statt der vom Caller
ausgewählten Vertragsdaten. Neu angezeigte Gründe sind begrenzt und escapet; die
Verarbeitung von Log-Kommandos ist während des Berichts deaktiviert. Es wurden
keine Secret-Werte, vollständigen Logs, Credentials oder Payloads ergänzt.
Aufbewahrte Artefakte machen aus einem fehlgeschlagenen Plan keine Erlaubnis
zur Anwendung oder Veröffentlichung.

## Dokumentation und Runtime-Evidenz

Den gepaarten Workflow-Security-Leitfaden und dieses Record-Paar aktualisiert.
Echte lokale Unterprozesse belegen die Importkorrektur. Es wird keine
Connector-Runtime- oder Hosted-Maintenance-Publikationsevidenz behauptet;
ursprünglicher Checkout und Gitlinks bleiben unverändert.

## Nicht ausgeführte Prüfungen

Kein live veröffentlichender Maintenance-Workflow wurde gestartet. Vollständige
Connector-Builds und historische Runtime-Matrizen liegen außerhalb dieser
CI-Helper-Änderung. Hosted-PR-Prüfungen und anwendbare Quality Gates sind
getrennte Delivery-Evidenz.

## Einschränkungen und Restrisiko

Die Verfügbarkeit der Upstream-APIs kann einen Plan weiterhin blockieren. Eine
frühere anonyme Online-Prüfung erreichte ein GitHub-Ratenlimit; deterministische
lokale Prüfungen belegen keine Live-Upstream-Verfügbarkeit oder erfolgreiche
Veröffentlichung. Abgebrochene Runs garantieren keinen Artefakt-Upload.

## Finaler Diff- und Review-Status

Task-eigener Code wurde geprüft und `git diff --check` bestand. Dokumentations-
und Remote-Delivery-Prüfungen werden separat im Task-Plan und PR festgehalten.
Dieser Record behauptet weder Merge, Hosted-Qualifikation noch automatische Veröffentlichung.
