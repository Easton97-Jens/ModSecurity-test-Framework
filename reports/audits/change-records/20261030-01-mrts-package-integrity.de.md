# MRTS-Paketvollständigkeit und Quellenbindung

**Sprache:** Deutsch | [English](20261030-01-mrts-package-integrity.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261030-01-mrts-package-integrity |
| UTC-Datum | 2026-10-30 |
| Framework-Basisrevision | `1d1e73fb069598e0f0f809d0bf16b5e59047ff88` |
| Auslieferung | Separater Framework-Nachtrag; Merge und Parent-Pin benötigen eigene Autorisierung |

## Motivation und Problemstellung

Die nichtrekursive Auswahl ließ verschachtelte YAML-Definitionen still aus.
Ein Paket ließ sich nach Ergänzung von `extra/additional.yaml` weiterhin prüfen.
Die integrierte Basis band `runtime_path_safety.py` bereits, ließ aber vier
transitive Framework-Imports aus, die beim Laden des Runners zur Prüfung
importierter Fälle verwendet werden.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-Paketvorbereitung, Wiederverwendung und direkte Prüfung von
Definitionsverzeichnissen. MRTS-Quellen und Gitlink bleiben schreibgeschützt bei
`8a6bb546c4c81d8ffc7be801dceac60c6925685f`. Dieser Patch ändert weder
Parent-Code noch Pins. Vertrauenswürdige Benutzer derselben UID bleiben
außerhalb einer Prozessisolationszusage.

## Akzeptanzkriterien

`base.yaml` neben `extra/additional.yaml` darf keinen validierten Teilkorpus
erzeugen. Eine neue verschachtelte Definition verhindert Wiederverwendung.
Schon die Änderung eines verwendeten Framework-Guards oder Runner-Helfers
verhindert Wiederverwendung bei unverändertem HEAD. Bestehende Demo-,
YAML-Typ-, Header-/Kontrollzeichen- und Teilveröffentlichungsprüfungen bestehen.

## Untersuchte Alternativen

Rekursiver Erhalt würde Änderungen am flachen Generator-/Importer-Vertrag und
an Provenienzpfaden erfordern. Explizite Ablehnung erhält diesen Vertrag.
Ein pauschal sauberer Framework-Arbeitsbaum würde unabhängige Änderungen
abweisen; stattdessen bindet das Paket seine tatsächlichen lokalen Abhängigkeiten.

## Implementierungsentscheidung

Eine Funktion `select_definition_files` in `mrts_definition_guard.py` weist
Unterverzeichnisse sowie nichtreguläre oder symbolisch verknüpfte YAML-Dateien
ab. Direkter Verzeichnis-Guard und Paketauswahl verwenden dieselbe Funktion.
Das Paket lädt die feste benachbarte Framework-Quelle mit `runpy`, ohne
Modulalias oder zusätzlichen globalen Suchpfad. Vorbereitung und Prüfung teilen
diese Auswahl.

Die Quellenliste bindet zusätzlich `tests/runners/adapter_interface.py`,
`tests/runners/case_roots.py`, `tests/runners/msconnector_models.py` und
`ci/lib/generated_report_utils.py`. Deren eigene Imports sind Module der
Standardbibliothek. Pfad-Guards, Shell-Bibliotheken, Provisionierungseinstiege,
Importer, Klassifizierungen und Runner-Core bleiben gebunden; Python-/PyYAML-
Versionsidentität und sauberer gepinnter MRTS-Checkout bleiben vorgeschrieben.

Die Zusammensetzung mit migrierten öffentlichen Imports bindet zusätzlich alle
Python-Quellen im festen Namensraum `modsecurity_test_framework/`. Durchlauf und
Öffnen relativ zu Verzeichnisdeskriptoren folgen keinen Symlinks; reguläre
Dateien werden mit höchstens 1 MiB je Datei, 16 MiB insgesamt, 1.024 Python-
Dateien, 4.096 Einträgen und 32 Verzeichnisebenen gelesen. Quelldateimetadaten
werden über jeden Lesevorgang geprüft. Der vollständige Vergleich erkennt neue,
entfernte und geänderte Quellen. Öffentliche Kontext-/Ergebnishelfer und
Namensraumaliase sind ohne Parent-Abhängigkeit eingeschlossen.

## Geänderte Dateien und Tests

Zwei Provisionierungsdateien, die zweisprachige Vorbereitungsanleitung, dieser
zweisprachige Record und zwei vorhandene Regressionsmodule ändern sich. Zwölf
einzeln benannte Methoden sind explizite On-demand-Framework-Regressionen in
`MrtsPackageTests` und `MrtsDefinitionGuardTests`: zwei verschachtelte Paketfälle,
ein direkter Guard-Fall, fünf Änderungen an Ausgangsquellen sowie vier Fälle für
Änderung, Ergänzung, Entfernung und Symlink im öffentlichen Namensraum. Jede Methode hat einen
direkten unittest-Selektor. Automatische Standardauswahl und unabhängige
Szenariozahlen werden nicht implizit vergrößert.

## Befehle und Ergebnisse

Die Befehle liefen über RTK im separaten Framework-Worktree mit Framework-
Python 3.14, deklariertem PyYAML, explizitem Framework-`PYTHONPATH`, ohne
User-Site oder Bytecode-Ausgaben und mit externem `TMPDIR`/`RUNNER_TEMP`.
Der äußere Interpreter nutzte `-P`; geerbtes `PYTHONSAFEPATH` wurde entfernt,
weil das unveränderte gepinnte MRTS-Skript benachbarte `path_utils`-Imports
benötigt. Es wurde kein globaler Pfadalias ergänzt.

| Befehl | Ergebnis |
| --- | --- |
| `rtk bypass env … <Framework-python> -P -m unittest` mit den acht neuen exakten Methodenselektoren | Basis: sieben Fehler; vorhandene Runtime-Guard-Bindung besteht |
| `rtk bypass env … <Framework-python> -P -m unittest tests.security_regression.test_mrts_common_posix_reliability tests.security_regression.test_mrts_common_sonar tests.security_regression.test_mrts_package tests.security_regression.test_mrts_import_integrity tests.security_regression.test_import_mrts_cases_sonar tests.security_regression.test_mrts_definition_guard tests.security_regression.test_mrts_result_integrity -q` | 97 PASS, 65,251 Sekunden; 85 bestehende und zwölf neue Methoden |
| `rtk bypass env … <Framework-python> -P ci/checks/catalog/check-mrts-importer.py` | PASS, vier Importer-Fixtures |
| `rtk bypass env … make PYTHON='<Framework-python> -P' FRAMEWORK_ROOT=<worktree> TEST_ROOT=<worktree> BUILD_ROOT=<task-root>/build TMP_ROOT=<task-root>/tmp OUTPUT_ROOT=<task-root>/output check-documentation` | PASS, Links, zweisprachige Variablen, Repository-Pfade und Change Records |
| Python-AST-Prüfung lokaler Imports der gebundenen Vorbereitungsquellen | PASS, 17 feste Ausgangsquellen und der vollständige begrenzte öffentliche Python-Namensraum |
| `rtk bypass <locked-ruff> format --check` für die vier eigenen Python-Dateien | PASS; vollständige Modul-ASTs durch Formatierung unverändert |
| `rtk bypass <locked-ruff> check` für dieselben vier Dateien | Nur zwei vorhandene E402-Diagnosen; keine neuen Befunde |
| `rtk bypass git diff --check` | PASS |

Exakte Befehle und Logs liegen im externen Task-Evidenzverzeichnis. Ein erster
Testbefehl vererbte Safe-Path-Verhalten an MRTS und scheiterte vor der Generierung
am benachbarten Import. Der korrigierte Befehl oben belegt die tatsächlichen
Akzeptanzkriterien, ohne MRTS zu ändern.

## Sicherheitsauswirkung

Verschachtelte Eingaben scheitern vor Veröffentlichung; Wiederverwendung kann
neue verschachtelte Definitionen nicht ignorieren. Reine Quellenänderungen
invalidieren betroffene Pakete. Hash-, Validator-, Isolations-, Pfad-,
Veröffentlichungs- und CI-Kontrollen bleiben erhalten. Keine neue Abhängigkeit.
Eine begrenzte Secret-Mustersuche vor dem Lesen meldete keine Treffer.

## Dokumentation und Runtime-Evidenz

Die zweisprachige [Vorbereitungsanleitung](../../../docs/mrts-preparation.de.md)
erklärt flache Eingaben und transitive Quellenbindung. Echte gepinnte
Generierung und Import werden geprüft; dies belegt Paketintegrität, weder
Host-Runtime noch Connector-Promotion.

## Nicht ausgeführte Prüfungen

Keine Host-Runtime, historische Matrix, Coverage-Kampagne, Installation oder
Downloads. Keine MRTS-Codeänderungen oder Auslieferungsaktionen. Das per Prüfsumme
gesperrte Ruff 0.16.10 formatierte die vier eigenen Python-Dateien bei
identischem vollständigem Modul-AST vor und nach der Formatierung; abschließendes
format --check besteht. Lint meldet ausschließlich die beiden vorhandenen
E402-Imports in mrts-package.py nach dem nötigen Pfad-Bootstrap. Die anderen
drei Dateien bestehen Lint. Keine Unterdrückung oder Bootstrap-Umstrukturierung.

## Einschränkungen und Restrisiko

Verschachtelte, auch leere Verzeichnisse werden absichtlich abgewiesen. Pakete
mit älterer Quellenliste müssen neu vorbereitet werden. Neue lokale
Abhängigkeiten müssen in die explizite Quellenliste aufgenommen werden.
Dies ist weder ein signiertes Paketsystem noch Schutz vor einem bösartigen
Prozess derselben UID, der den Verifier verändert.

## Finaler Diff- und Review-Status

Der begrenzte Patch erhält vorhandene Assertions und explizite On-demand-Auswahl.
Separate Framework-Auslieferung und abhängige Parent-Pin-Integration bleiben
beim koordinierenden Task; weder Default-Branch-Schreibzugriff noch
automatischer Merge sind autorisiert.
