# SonarCloud-Reparaturplan

**Sprache:** [English](sonarcloud-remediation-plan.md) | Deutsch

Quelle: SonarCloud API für Projekt
`Easton97-Jens_ModSecurity-test-Framework`, Zweig `master`, abgefragt am 15.05.2026.
Die Abfrage hat 31 offene Probleme im aktuellen Remote-Analyse-Snapshot zurückgegeben:
14 `shelldre:S131`, 8 `shelldre:S7679`, 6 `python:S3776`,
2 `python:S8495` und 1 `shelldre:S1192`. Die folgenden Status beschreiben die
Sanierung auf Quellenebene in diesem Zweig; SonarCloud schließt nur Remote-Probleme
Schlüssel nach dem nächsten Analyselauf.

| Problem | Kategorie | Schweregrad | Betroffene Datei | Echtes Problem oder falsch positives Ergebnis | Strategie festlegen | Status |
| --- | --- | --- | --- | --- | --- | --- |
| `AZ4tAdJg9wBRmoDDtssa` | Robustheit der Schale | kritisch | `ci/runtime/probe-response-body-blocking.sh` | echt | Fügen Sie den Standardzweig `case` für den generierten Pfadschutz hinzu | behoben |
| `AZ4tAdJg9wBRmoDDtssb` | Robustheit der Schale | kritisch | `ci/runtime/probe-response-body-blocking.sh` | echt | Fügen Sie den Standardzweig `case` für die wiederholte Validierung hinzu | behoben |
| `AZ4s4GI2gYpe4Bv-weG2` | Python-Komplexität | kritisch | `tests/runners/case_cli.py` | echt | Ersetzen Sie die bedingte Kette durch die Zuordnung von Fähigkeiten zu Variablen | behoben |
| `AZ4ssKb2W4Q6haNCFVpJ` | Python-Komplexität | kritisch | `tests/runners/case_cli.py` | echt | Teilen Sie die Zusammenfassung loading/counting/metadata beim Rendern in Helfer auf | behoben |
| `AZ4si0gF6hf2ZRDnADZt` | Python-Komplexität | kritisch | `tests/runners/runner_core.py` | echt | Teilen Sie die Fallvalidierung in metadata/request/response/expect-Helfer auf | behoben |
| `AZ4si0gF6hf2ZRDnADZu` | Python-Komplexität | kritisch | `tests/runners/runner_core.py` | echt | Unterteilen Sie die Fallermittlung in Pfadauflösungs- und Kandidatenauswahlhilfen | behoben |
| `AZ4si0gF6hf2ZRDnADZv` | Python gibt Konsistenz zurück | Hauptfach | `tests/runners/runner_core.py` | echt | Gibt `list[str]` konsistent aus Antwortzusicherungen zurück | behoben |
| `AZ4si0gF6hf2ZRDnADZw` | Python gibt Konsistenz zurück | Hauptfach | `tests/runners/runner_core.py` | echt | Gibt `list[str]` konsistent aus Audit-Behauptungen zurück | behoben |
| `AZ4si0gF6hf2ZRDnADZx` | Python-Komplexität | kritisch | `tests/runners/runner_core.py` | echt | Teilen Sie die Prüfungswartezeit und die Feldprüfungen in Helfer auf | behoben |
| `AZ4oLv83Rucw6R5zlwc_` | Shell-Positionsparameter | Hauptfach | `ci/provisioning/prepare-nginx-build.sh` | echt | Weisen Sie `$1` vor der Verwendung `target_path` zu | behoben |
| `AZ4oLv83Rucw6R5zlwdA` | Shell-Positionsparameter | Hauptfach | `ci/provisioning/prepare-nginx-build.sh` | echt | Weisen Sie `$1` vor der Verwendung `target_path` zu | behoben |
| `AZ4oLv83Rucw6R5zlwdB` | Robustheit der Schale | kritisch | `ci/provisioning/prepare-nginx-build.sh` | echt | Fügen Sie den Standardzweig `case` für den generierten Pfadschutz hinzu | behoben |
| `AZ4oLv83Rucw6R5zlwdC` | Robustheit der Schale | kritisch | `ci/provisioning/prepare-nginx-build.sh` | echt | Fügen Sie den Standardzweig `case` für den Aktualisierungsschutz hinzu | behoben |
| `AZ4oLv83Rucw6R5zlwdD` | Robustheit der Schale | kritisch | `ci/provisioning/prepare-nginx-build.sh` | echt | Fügen Sie den standardmäßigen `case`-Zweig für die GitHub-Repo-URL-Analyse hinzu | behoben |
| `AZ4oLv_yRucw6R5zlwdE` | Robustheit der Schale | kritisch | `connectors/nginx/harness/run_nginx_smoke.sh` | echt | Fügen Sie den Standardzweig `case` für den generierten Pfadschutz hinzu | behoben |
| `AZ4oLv_yRucw6R5zlwdF` | Shell-Positionsparameter | Hauptfach | `connectors/nginx/harness/run_nginx_smoke.sh` | echt | `$1` zu `raw_value` in `escape_sed()` zuweisen | behoben |
| `AZ4oEgW0zQbBYyxTDd5x` | Python-Komplexität | kritisch | `tests/runners/runner_core.py` | echt | Verschieben Sie die Fallback-YAML-Analyse in `MinimalYamlParser`-Helfer | behoben |
| `AZ4n9oXR_9oVCvgyS3Qi` | Robustheit der Schale | kritisch | `connectors/apache/harness/run_apache_smoke.sh` | echt | Fügen Sie den Standardzweig `case` für den generierten Pfadschutz hinzu | behoben |
| `AZ4n9oXR_9oVCvgyS3Qk` | dupliziertes Literal | Moll | `connectors/apache/harness/run_apache_smoke.sh` | echt | Einführung der `IFMODULE_END`-Konstante | behoben |
| `AZ4n9oXR_9oVCvgyS3Qj` | Shell-Positionsparameter | Hauptfach | `connectors/apache/harness/run_apache_smoke.sh` | echt | `$1` zu `raw_value` in `escape_sed()` zuweisen | behoben |
| `AZ4n9oVN_9oVCvgyS3Qe` | Shell-Positionsparameter | Hauptfach | `ci/provisioning/prepare-apache-build.sh` | echt | Weisen Sie `$1` vor der Verwendung `target_path` zu | behoben |
| `AZ4n9oVN_9oVCvgyS3Qf` | Shell-Positionsparameter | Hauptfach | `ci/provisioning/prepare-apache-build.sh` | echt | Weisen Sie `$1` vor der Verwendung `target_path` zu | behoben |
| `AZ4n9oVN_9oVCvgyS3Qg` | Robustheit der Schale | kritisch | `ci/provisioning/prepare-apache-build.sh` | echt | Fügen Sie den Standardzweig `case` für den generierten Pfadschutz hinzu | behoben |
| `AZ4n9oVN_9oVCvgyS3Qh` | Robustheit der Schale | kritisch | `ci/provisioning/prepare-apache-build.sh` | echt | Fügen Sie den Standardzweig `case` für den Aktualisierungsschutz hinzu | behoben |
| `AZ4n6KQK9eBhNcyBKSiZ` | Robustheit der Schale | kritisch | `ci/runtime/run-v3-api-smoke.sh` | echt | Fügen Sie den Standardzweig `case` für den `BUILD_ROOT`-Schutz hinzu | behoben |
| `AZ4n6KQK9eBhNcyBKSia` | Robustheit der Schale | kritisch | `ci/runtime/run-v3-api-smoke.sh` | echt | Fügen Sie den Standardzweig `case` für den `BUILD_DIR`-Schutz hinzu | behoben |
| `AZ4n6KOS9eBhNcyBKSiU` | Shell-Positionsparameter | Hauptfach | `ci/provisioning/build-v3-under-src.sh` | echt | Weisen Sie `$1` vor der Verwendung `target_path` zu | behoben |
| `AZ4n6KOS9eBhNcyBKSiV` | Shell-Positionsparameter | Hauptfach | `ci/provisioning/build-v3-under-src.sh` | echt | Weisen Sie `$1` vor der Verwendung `target_path` zu | behoben |
| `AZ4n6KOS9eBhNcyBKSiW` | Robustheit der Schale | kritisch | `ci/provisioning/build-v3-under-src.sh` | echt | Fügen Sie den Standardzweig `case` für den generierten Pfadschutz hinzu | behoben |
| `AZ4n6KOS9eBhNcyBKSiX` | Robustheit der Schale | kritisch | `ci/provisioning/build-v3-under-src.sh` | echt | Fügen Sie den Standardzweig `case` für den Zielschutz hinzu | behoben |
| `AZ4n6KOS9eBhNcyBKSiY` | Robustheit der Schale | kritisch | `ci/provisioning/build-v3-under-src.sh` | echt | Fügen Sie den Standardzweig `case` für den Aktualisierungsschutz hinzu | behoben |

## Nachreinigung

Die folgenden zusätzlichen SonarCloud-Code-Smells wurden nach dem ersten gemeldet
Behebungsdurchlauf und sind ohne Unterdrückungen in der Quelle fixiert:

| Problem | Kategorie | Schweregrad | Betroffene Datei | Echtes Problem oder falsch positives Ergebnis | Strategie festlegen | Status |
| --- | --- | --- | --- | --- | --- | --- |
| Screenshot L43 | Geruch nach Python-Code | Moll | `ci/reporting/write-case-matrix.py` | echt | Entfernen Sie den nicht verwendeten `path`-Parameter aus `case_kind()` | behoben |
| Screenshot L45 | Geruch nach Python-Code | Moll | `ci/reporting/write-case-matrix.py` | echt | Ersetzen Sie verkettete `startswith()`-Aufrufe durch ein Tupelargument | behoben |
| Screenshot L17 | Regex-Bereinigung | Moll | `tests/normalizers/audit_log_normalizer.py` | echt | Entfernen Sie den redundanten Kleinbuchstabenbereich aus einer `IGNORECASE`-Zeichenklasse | behoben |
| Screenshot L12 | Regex-Bereinigung | Moll | `tests/normalizers/response_normalizer.py` | echt | Entfernen Sie den redundanten Kleinbuchstabenbereich aus einer `IGNORECASE`-Zeichenklasse | behoben |
| Screenshot L159 | Geruch nach Python-Code | Moll | `tests/runners/case_cli.py` | echt | Verwenden Sie `dict.fromkeys()` für die stabile Duplikatentfernung in verifizierten Variablen | behoben |

Split-Status: `tests/runners/case_cli.py` in diesem Repository bereits enthalten
der `dict.fromkeys()` Duplikat-Entfernungs-Fix. Es wird keine Unterdrückung verwendet.

Kein Thema wird absichtlich unterdrückt. Wenn SonarCloud Folgeprobleme meldet oder
Hält einen dieser Schlüssel nach der nächsten Analyse offen, aktualisieren Sie diese Tabelle mit dem
neue Nachweise und eine Lösungsstrategie, anstatt die Warnung zu verbergen.
