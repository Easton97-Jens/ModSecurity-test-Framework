# Zentrale native Qualitätsextraktionen

**Sprache:** [English](20261008-34-central-native-quality-extractions.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261008-34-central-native-quality-extractions |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | 4e208ad9b700467f98b9fbef26bfa47295db5e62 |
| Issue oder Pull Request | Framework-PR 137, Sonar-Readback r2 der veröffentlichten Revision |

## Motivation und Problemstellung

Zehn zentrale Findings betreffen wiederholte Literale (S1192), verschachtelte bedingte Ausdrücke (S3358) und kognitive Komplexität (S3776). Das bestehende Komplexitätsfinding der Konfigurationsvorlage ist eingeschlossen und wird nicht als remote geschlossen behandelt.

## Betroffene Komponenten und Sicherheitsgrenzen

Nur `ci/checks/catalog/no_crs_baseline.py`, ein unabhängiger Charakterisierungstest und dieses EN/DE-Paar ändern sich. Quellenautorität, unveränderte Originalbytes, typisierte Provenienz, Auswahl und kanonische Evidenzablehnung bleiben strikt.

## Akzeptanzkriterien

Exakte öffentliche Ergebnisse und Diagnosepriorität erhalten, alle Required-Fälle beibehalten, Charakterisierung gegen Original und Refactoring sowie aktuelle No-CRS- und Dokumentationsprüfungen bestehen.

## Untersuchte Alternativen

Suppressions, verringerte Validierung und geänderte Katalogerwartungen wurden verworfen. Eine breite Validator-Neufassung war unnötig; kleine deterministische Extraktionen genügen.

## Implementierungsentscheidung

First-Byte-Fixture- und Katalogschema-Literale erhalten Konstanten. Runner-Pfadprüfung, exaktes natives Probeprädikat, Parserdiagnostik, native Ergebnisauswahl, Einzelrecord-Finalisierung und generische PASS-Vollständigkeitsprüfung werden extrahiert. Das native Prädikat behält das echte serialisierte Common-Engine-Decision-Vokabular; kein Event wird erzeugt oder umbenannt. Aufrufreihenfolge, Ausnahmebehandlung, Beweisrouten und Diagnosetexte bleiben erhalten.

## Geänderte Dateien und Tests

`tests/no_crs/test_central_quality_characterization.py` prüft fehlende/ungültige Runner-Pfade, Identitätsdiagnosereihenfolge, geschlossene Vertragsausnahmen, native Status-/Grundkombinationen, fehlende Autorität, Priorität der Konfigurationsvorlage, spezialisierte frühe Rückgaben, generische Vollständigkeitsreihenfolge, Retentionsreihenfolge und doppelte native Beobachtungen derselben Transaktion. Bestehende Raw-Artefakt- und Valid-Rules-Tests prüfen neu gehashte fremde Identitäten, Regeln, Phasen, Payload-Grenzen und Cleanup.

## Befehle und Ergebnisse

Alle Befehle liefen über RTK mit Framework-Virtualenv, deaktiviertem Bytecode und extern vorgegebenem TMPDIR. Evidenzbasenames bezeichnen das vom Koordinator freigegebene Analyseverzeichnis, keine checkoutlokalen Ausgaben.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `python -m unittest tests.no_crs.test_central_quality_characterization tests.no_crs.test_configtest_artifacts tests.no_crs.test_valid_rules_file_receipt -v` | 0 | 31 Baseline- und 31 Tests nach Refactoring | `stream-a-central-quality-baseline.log`, `stream-a-central-quality-green.log` |
| In-Memory-Kompilierung von `git show 4e208ad9b700467f98b9fbef26bfa47295db5e62:ci/checks/catalog/no_crs_baseline.py`, danach finales Charakterisierungsmodul | 0 | Alle 13 Tests bestehen auch gegen das Originalverhalten | `stream-a-central-quality-final-characterization-baseline.log` |
| `python -m unittest discover -s tests/no_crs -v` | 0 | 384 Tests einschließlich aktueller Auswahl | `stream-a-central-quality-full-no-crs.log` |
| `python -m unittest tests.no_crs.test_central_quality_characterization tests.security_regression.test_no_crs_catalog_maintainability_wave tests.no_crs.test_nginx_native_selection tests.no_crs.test_protocol_selection_scope -v` | 0 | 34 finale Charakterisierungs-/Auswahltests nach Trennung der Status- und Fehlertestmethoden | `stream-a-central-quality-final-focus.log` |
| `python ci/checks/documentation/check-change-records.py`, `check-repository-path-references.py`, `check-doc-links.py`, `check-variable-documentation.py` | jeweils 0 | Record-Struktur, repositorylokale Pfade, Links und EN/DE-Prüfungen | `stream-a-central-quality-doc-*.log` |
| `python -m ruff check ci/checks/catalog/no_crs_baseline.py tests/no_crs/test_central_quality_characterization.py` | 1 | Ruff fehlt in der bestehenden Framework-Umgebung; keine Installation | `stream-a-central-quality-ruff.log` |

## Sicherheitsauswirkung

Dies ist verhaltenserhaltende Qualitätsarbeit, keine Security-Remediation oder neue Runtime-Evidenz. Keine Autoritäts-, Identitäts-, Validierungs-, Cleanup- oder Datenschutzanforderung wird gelockert.

## Dokumentation und Runtime-Evidenz

Dieses Paar dokumentiert Source-Arbeit und kontrollierte Fixtures. Keine native Ausführung, kein Build und keine Host-Evidenz wurden erhoben. Alle 97 ausgewählten Required-Fälle bleiben erhalten; die 45 finalen Runtime-Lücken bleiben NOT RUN.

## Nicht ausgeführte Prüfungen

Kein nativer Build/Runtime, keine Dependency-Installation, kein remote Sonar-Rescan, Push, Gitlink-Update oder MRTS-Eingriff. Ruff konnte wegen des fehlenden Moduls nicht laufen; Integrationslint durch den Koordinator bleibt erforderlich.

## Einschränkungen und Restrisiko

Source-Refactoring belegt weder remote Issue-Auflösung noch Quality Gate. Sonar-Verifikation bleibt bis zu einem Scan der integrierten Revision offen. Unit-Fixtures belegen keine Host-Runtime-Akzeptanz.

## Finaler Diff- und Review-Status

Begrenzter Diff auf exakte Prädikats-, Aufruf- und Diagnoseerhaltung sowie Whitespace geprüft. Nur normale Übergabe aus isoliertem Worktree; Integration und finale Source-/Runtime-Verifikation gehören dem Koordinator.
