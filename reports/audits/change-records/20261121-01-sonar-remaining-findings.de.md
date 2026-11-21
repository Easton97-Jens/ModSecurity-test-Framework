# Change Record

**Sprache:** [English](20261121-01-sonar-remaining-findings.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261121-01-sonar-remaining-findings |
| UTC-Datum | 2026-11-21 |
| Framework-Basisrevision | `95f228936efe17fda24f21323ad87cd698940b48` |
| Issue oder Pull Request | Folgearbeit zu Framework-PR #176 |

## Motivation und Problemstellung

SonarCloud meldet drei S1110-Befunde zu Python-Ausdrücken, die in ihrer ursprünglichen Form eine Gruppierung benötigen. Gleichwertige Ausdrücke machen die beabsichtigte Auswertung klar. Die Basisanalyse `601c9eb1-0472-4b67-af6d-01d4b91765a3` meldet außerdem 23 Sicherheitsbefunde, die am geprüften Quellstand einzeln als Fehlalarme bewertet wurden.

## Betroffene Komponenten und Sicherheitsgrenzen

CI-Evidenzvertrag und Python-Versionscheck prüfen denselben Pfad wie zuvor. Der Importer-Check verlangt weiterhin die erwartete Fehlermeldung zum ungültigen synthetischen Overlay.

## Akzeptanzkriterien

Die drei Ausdrücke behalten ihr Verhalten bei und die bestehenden Prüfungen bestehen. Jeder Sicherheitsbefund erhält eine quellengestützte Bewertung. Der tatsächliche Cloud-Status wird separat erfasst.

## Untersuchte Alternativen

Das Entfernen der Klammern würde Pythons Auswertung verändern. Die neue Form drückt die Gruppierung in den Operanden aus und kommt ohne Sonar-Unterdrückung aus.

## Implementierungsentscheidung

Beide Existenzprüfungen verwenden `Path.joinpath()`. Der stderr-Ersatzwert wird vor der Teilstringprüfung gebildet.

## Geänderte Dateien und Tests

- `ci/checks/security/check-ci-security-evidence-contract.py`
- `ci/checks/security/check-python-version.py`
- `ci/checks/catalog/check-mrts-importer.py`
- Dieses englisch/deutsche Change-Record-Paar.

Der bestehende Importer-Check verwendet vier synthetische Fälle.

## Befehle und Ergebnisse

| Befehl mit konfiguriertem Framework-`PYTHON` | Exit-Code | Ergebnis |
| --- | --- | --- |
| `rtk bypass "$PYTHON" -B ci/checks/security/check-ci-security-evidence-contract.py` | 0 | CI-Sicherheitsvertrag für Evidenz bestanden |
| `rtk bypass "$PYTHON" -B ci/checks/security/check-python-version.py` | 0 | Python-Versionsvertrag bestanden |
| `rtk bypass env PYTHONPATH="$FRAMEWORK_ROOT" "$PYTHON" -B ci/checks/catalog/check-mrts-importer.py` | 0 | Vier synthetische Fälle importiert |
| `rtk bypass git diff --check` | 0 | Quelltext ohne Whitespace-Fehler |

Die genaue Befehls- und Umgebungsevidenz steht im konfigurierten Laufverzeichnis unter `framework-sonar-rest-20261121/s1110/results.json`.

## Sicherheitsauswirkung

Die Prüfausdrücke behalten ihr bisheriges Erfolgs- und Fehlerverhalten. Die statische Prüfung der 23 Meldungen fand bereits aktive HTTPS-Server, lokale Pfadbildung oder Tests, feste Pfade hinter Verzeichnisprüfungen und vom Operator ausgewählte lokale Eingaben. Die vorbereiteten Sonar-Kommentare nennen für jeden Befund die Kontrolle oder den konkreten Datenfluss. Die Bewertung gilt für den geprüften Stand und den vorhandenen CLI-Vertrauensvertrag.

## Dokumentation und Runtime-Evidenz

Das Change-Record-Paar dokumentiert Quellcode und Scannerbefunde. Die Validierung umfasst lokale Prüfer und synthetische Fixtures.

## Nicht ausgeführte Prüfungen

Eine neue Sonar-Analyse der Änderungen benötigt den Framework-CI-Workflow. Es waren weder Host-Tests noch historische Qualifikationsläufe ausgewählt.

## Einschränkungen und Restrisiko

Der Sonar-SSH-Dienst meldet `allowed_mutations: []`. Die 26 Cloud-Befunde bleiben bis zur Veröffentlichung oder einer Schließung mit Betreiberfreigabe offen. Das aktuelle Master-Gate scheitert am Sicherheitsrating E. Ein künftiger privilegierter Dienst, der nicht vertrauenswürdige Argumente an ein lokales CLI weitergibt, bräuchte eine separate Bewertung.

## Finaler Diff- und Review-Status

Lokaler Framework-Worktree auf `codex/framework-sonar-rest-20261121`. Der ausgewählte Quellcode und die Evidenz haben den Secrets-Check bestanden. Veröffentlichung und Schließung in SonarCloud stehen aus.
