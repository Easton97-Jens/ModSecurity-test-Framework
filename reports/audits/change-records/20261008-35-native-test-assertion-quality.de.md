# Change Record

**Sprache:** [English](20261008-35-native-test-assertion-quality.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261008-35-native-test-assertion-quality |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | 4e208ad9b700467f98b9fbef26bfa47295db5e62 |
| Issue oder Pull Request | Framework PR137, sechs veröffentlichte TEST-Befunde |

## Motivation und Problemstellung

Die veröffentlichten Regeln S3415, S5778 und S5906 melden inkonsistente
Assertion-Operandenklassifikation, mehrdeutige Exception-Ziele und unspezifische
Assertions in vier Native-Evidence-Testmodulen. Vollständige veröffentlichte
Regelbeschreibungen und Issue-Flows wurden vor Änderungen gelesen.

## Betroffene Komponenten und Sicherheitsgrenzen

Nur vier `tests/no_crs/test_nginx_native_*.py`-Module und dieses Record-Paar
ändern sich. Produktvalidatoren, Katalog/Schema, Selection-Implementierung,
Canonical-Nachweis und Connector-Source bleiben unverändert. Tests müssen
ihre ursprüngliche negative Nachweisstärke behalten.

## Akzeptanzkriterien

Assertions bleiben actual-first. Exception-Kontexte enthalten nur die
Zieloperation, Setup liegt außerhalb. False bedeutet den Boolean-Singleton,
nicht beliebige Falsiness. Die Teilmengenprüfung behält dieselbe inklusive
Grenze. Vollständige betroffene Tests, Syntax, Diff und alle Doc-Checks müssen
grün sein.

## Untersuchte Alternativen

Oracle-Umkehr oder Sonar-Unterdrückung würden den Testvertrag verdecken.
`assertFalse` allein würde andere false-artige Werte akzeptieren. Zentrale
Validatoränderungen sind weder nötig noch autorisiert.

## Implementierungsentscheidung

Das Input-Tupel nach der Operation wird explizit benannt und mit dem
Original-Snapshot verglichen. Namespace-Konstruktion und Strict-Reader-
Validierung liegen außerhalb erwarteter Exceptions. `assertIs(actual, False)`
und `assertLessEqual(actual_set, expected_set)` ersetzen unspezifische
Assertions, ohne Fixtures oder Fälle zu ändern.

## Geänderte Dateien und Tests

Canonical-Binding-, Operation-Contract-, Operation-Projection- und Native-
Selection-Testmodule erhalten sechs gezielte Änderungen. Externe
Charakterisierung des tatsächlichen Phase1-Tests lehnt `None`, Integer null,
leere Liste/String und `True` an der strikten False-Assertion ab. Keine neuen
Runtime-Fälle entstehen.

## Befehle und Ergebnisse

Befehle liefen RTK-wrapped mit Framework-Python, explizitem isoliertem
`FRAMEWORK_ROOT` und externen Cache-/Temp-Wurzeln aus der Umgebung.
Run-Logs werden unten per Basename identifiziert; checkout-spezifische absolute
Pfade werden hier nicht veröffentlicht.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `python -m unittest -v tests.no_crs.test_nginx_native_canonical_binding tests.no_crs.test_nginx_native_operation_contract tests.no_crs.test_nginx_native_operation_projection tests.no_crs.test_nginx_native_selection` vor Änderungen | 0 | 47 Tests grün; Baseline-Verhalten | `stream-c-test-quality-baseline.log` |
| Derselbe Befehl nach Änderungen | 0 | 47 Tests grün | `stream-c-test-quality-green.log` |
| Kontrollierter tatsächlicher Phase1-Test mit gepatchten Ergebniswerten | 0 | Fünf unzulässige false-artige/Boolean-Werte abgewiesen | `stream-c-test-quality-assertion-controls.log` |
| `make check-documentation` | 0 | Links, Sprachpaar-/Variablen-, Repository-Pfad- und Record-Prüfung grün; 892 Dateien, null alte Pfade | `stream-c-test-quality-docs.log` |
| `python -m py_compile tests/no_crs/test_nginx_native_canonical_binding.py tests/no_crs/test_nginx_native_operation_contract.py tests/no_crs/test_nginx_native_operation_projection.py tests/no_crs/test_nginx_native_selection.py` | 0 | Alle vier Module kompilieren | Task-Befehlsausgabe |
| `rtk proxy git diff --check` | 0 | Whitespace grün | Task-Befehlsausgabe |

## Sicherheitsauswirkung

Keine Security-Remediation wird behauptet. Exception-Tests schließen jetzt
Setup-Fehler vom Ziel-Fehlernachweis aus; Boolean-Identität wird strikter statt
schwächer. Bestehende Negativfälle und Required-Selection-Umfang bleiben erhalten.

## Dokumentation und Runtime-Evidenz

Dieses englische/deutsche Record-Paar dokumentiert die Teständerung. Keine
native Runtime-, Build- oder Lifecycle-Evidenz wurde erhoben. Die 97 Required-
Fälle und 45 finalen nativen Runtime-Lücken bleiben unverändert.

## Nicht ausgeführte Prüfungen

Native Builds/Runtime, Dependency-Änderungen und Sonar-Veröffentlichung gehören
Root und wurden nicht ausgeführt. Lokale Tests beweisen keine Scanner-Schließung.

## Einschränkungen und Restrisiko

Eine frische Root-Sonar-Analyse muss die Schließung aller sechs Befunde
bestätigen. Dieser Slice ändert oder beweist keine Canonical-Produktakzeptanz.

## Finaler Diff- und Review-Status

Der fokussierte Vier-Modul-Diff wurde auf Assertion-Richtung, exakten Boolean-
Typ, Exception-Grenzen und unveränderte Fixtures geprüft. Keine Secrets oder
sensiblen Rohdaten sind enthalten. Syntax, alle Dokumentationsprüfungen und
Whitespace sind grün. Der normale atomare Framework-Commit wird bei Übergabe
angegeben.
