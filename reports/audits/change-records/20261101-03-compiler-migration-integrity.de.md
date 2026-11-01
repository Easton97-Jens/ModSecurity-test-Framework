# Folgekorrektur der Compiler- und Apache-Migrationsintegrität

**Sprache:** [English](20261101-03-compiler-migration-integrity.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261101-03-compiler-migration-integrity |
| UTC-Datum | 2026-11-01 |
| Framework-Basisrevision | `91f5370c7eddcebdc7e49d2099c58054ec2d5d5d` |
| Issue oder Pull Request | Followup zu gemergtem Framework #148 für Parent-Draft #348; neuer PR ausstehend |

## Motivation und Problemstellung

Finale Integrationsprüfungen zeigten veraltete Compiler-Erwartungen vor der
Migration und einen Apache-AST-Goldenwert ohne die Ownership-Migration aus #142.
Dies sind Integritätsfehler bestehender Tests, keine neuen Connector-Runtime-Findings.

## Betroffene Komponenten und Sicherheitsgrenzen

Das Framework besitzt beide bestehenden Testmodule, Quellbindungen und
generierte Inventaransichten. Externe Parent-Eingabe ist
`b43faa78d403afd492c007e8f4a740ad21da1ac9` mit separat verantworteter,
uncommitteter Compiler-Generator-Korrektur. Kein Parent-Code gehört zu dieser
Framework-Änderung. MRTS bleibt unverändert/schreibgeschützt.

## Akzeptanzkriterien

Alle bestehenden Assertions, vollständigen Apache-AST-Schutz,
Mutationsempfindlichkeit und echte Make-Regelprüfung erhalten. Alle 44
bestehenden Methoden und acht Target-Kontrollen bestehen. Native
Inventarregenerierung/-prüfung und öffentliche Admission erhalten Auswahl und
historische IDs. Frische gehostete Followup-Prüfung und abhängiger Parent-Pin
bleiben erforderliche Auslieferungsschritte.

## Untersuchte Alternativen

Keine gelöschten Parent-Tests wiederherstellen, beliebige Targets akzeptieren,
Weiterleitung mocken, AST-Knoten ignorieren, zwei Golden-Hashes akzeptieren oder
Provenienz/Gates abschwächen. Nur unabhängig geprüfte Migrationserwartungen und
tatsächliche Regelerkennung anpassen.

## Implementierungsentscheidung

Compilerprüfungen verwenden migrierte Apache-/HAProxy-Harness-URLs und lesen
tatsächliche Regeln aus `connector_suite/connector.mk` nur, wenn das ausgewählte
Parent-Makefile seine explizite Weiterleitung enthält; Make-Zuweisungen sind
keine Targets.

Die unabhängige Rekonstruktion von Parent `c5993ed9` verwendet genau sechs
Ersetzungen: expliziter `connector_context`-Import, `ROOT` zu `connector_root()`
und `source_path` für Apache-Quelle, Dokumentation, Architekturreport und
APXS-Wrapper. Ihr Ergebnis ist byteidentisch zum Prüfercode seit #142.
Prädikate, Meldungen, Reihenfolge und Kontrollfluss bleiben erhalten. Nur der
geprüfte vollständige AST-Goldenwert ändert sich von
`2ea7f8e9c46f644deea24fe8879d7f9e30f2d820ce355302c0901779a762c49b` zu
`bb412c592b9d09f7e65224a51f005c8c7f07e150cad22302e2ff7e8fcf8c7722`.

## Geänderte Dateien und Tests

`test_compiler_guides.py` und `test_apache_common_adoption.py` unter
`connector_suite/modsecurity_connector_tests/` anpassen; keine neuen Methoden,
Fälle oder Selektoren. Eine bestehende Compiler-Quellbindung in
`active-cases.json` aktualisieren, danach Auswahlarchiv und Migrationsbaseline
nativ regenerieren. 526 feste Framework-Bindungen, 235 dynamische Produktquellen,
100/80 Standard- und 2586/1140 optionale Fälle/Ausführungen sowie alle 1993
Baseline-IDs bleiben erhalten. Der gepaarte #148-Record korrigiert nur die
Go-Bezeichnung: 1.27.3 ist die ausgewählte Toolchain; 1.26.9 ist das Modulminimum,
kein Toolchain-Pin. Versionen und Abhängigkeiten bleiben unverändert.

## Befehle und Ergebnisse

Befehle verwenden RTK, Framework-Python, explizite Parent-/Framework-Roots und
externe Ausgabe-/Temp-Roots. Run: `pr348-test-migration-20261101.GnuEMR`.

| Befehl oder dokumentiertes Verfahren | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Compiler-Import vor externer Parent-Korrektur | 1 | Gelöschten Provisionierungspfad reproduziert | Gleicher Run, Befehlsnachweis des Koordinators |
| Bestehendes Compilermodul vor Erwartungskorrektur | 1 | 20 bestanden, zwei veraltete Vertragsfehler | Gleicher Run, Befehlsnachweis des Koordinators |
| `make check-apache-common-adoption ON_DEMAND_TESTS=1` vor Goldenwert-Korrektur | 2 | 21 bestanden, ein veralteter Goldenwert-Fehler | Gleicher Run, Befehlsnachweis des Koordinators |
| Bestehendes Compilermodul plus acht echte Target-Kontrollen | 0 | Alle 22 Methoden; vier gültige Targets akzeptiert, vier ungültige Namen/Variable abgelehnt | `compiler-followup/compiler-tests-validation.md` enthält vollständigen expliziten Aufruf |
| Kombinierte bestehende Compiler-/Apache-Module über `python -m unittest` | 0 | 44 Methoden bestanden, 27.660s | Gleicher Run, Befehlsnachweis des Koordinators |
| `make check-apache-common-adoption ON_DEMAND_TESTS=1` mit diesem Framework | 0 | Natives Target nach Korrektur bestanden | Gleicher Run, Befehlsnachweis des Koordinators |
| Native Bindungs-/Archiv-/Map-Generierung und Prüfungen | 0 | Eine bestehende Bindung aktualisiert; Zahlen/IDs erhalten | Gleicher Run, Befehlsnachweis des Koordinators |
| `python -m modsecurity_test_framework.connector --check` | 0 | Öffentliches Inventar zugelassen; keine Testausführung | Gleicher Run, Befehlsnachweis des Koordinators |
| Framework-Dokumentationsskripte: `check-change-records.py`, `check-variable-documentation.py`, `check-doc-links.py`, `check-repository-path-references.py` | Je 0 | Record-Vertrag; 348 versionierte EN/DE-Paare; Links; 2153 gescannte Pfade, keine alten Pfade | Expliziter Framework-Root; Struktur unversionierter Records direkt geprüft |
| `make check-documentation check-canonical-common-pins check-canonical-python-pins check-canonical-workflow-pins check-canonical-crs-contract-pins` nach Staging | 0 | 350 zweisprachige Prüfungen, Links, Pfade, Records und alle vier kanonischen Pin-Prüfungen bestanden | Expliziter Framework-Root und Framework-Python; neues Paar enthalten |

Ein früher Map-Generierungsaufruf lief vor Abschluss des Archivs und scheiterte
mit Exit 1. Die korrekte serielle Regenerierung und Folgeprüfungen bestanden;
dieser Reihenfolgefehler wird nicht verborgen. Die externe Parent-Korrektur
wählt die verschobene Provisionierungsquelle mit `source_path` und korrigiert
zwei Harness-Links; alle 18 generierten Compilerleitfäden entsprechen danach
den versionierten Bytes. Diese Korrektur ist kein Teil dieses Framework-Commits.

## Sicherheitsauswirkung

Integritätswartung, keine Security-Remediation einer validierten Schwachstelle.
Vollständige AST-Abdeckung und bestehende Mutationsprüfungen bleiben erhalten;
kein alternativer Hash, ignoriertes Prädikat, Kontextbypass, gelockerte
Compilerwarnung oder abgeschwächtes Gate.

## Dokumentation und Runtime-Evidenz

`docs/connector-test-suite.md` / `.de.md` und diesen gepaarten Record anpassen.
Begrenzte Tests und statische/Katalognachweise belegen kein echtes
Host-/TLS-/H2-/H3-Verhalten. Framework #148 ist bereits an der genannten Basis
gemergt; dieses Followup hat am Vorbereitungsstand keinen veröffentlichten PR,
headgenauen gehosteten Nachweis oder Merge.

## Nicht ausgeführte Prüfungen

Frische gehostete Followup-CI/Sonar, Review und Integration stehen noch aus.
Keine breite Qualifikationskampagne, Live-TLS-/H2-/H3-Verkehr, neue
Toolchain/Version, MRTS-Ausführung oder Standard-Suite-Erweiterung; dies liegt
außerhalb dieses Inkrements.

## Einschränkungen und Restrisiko

Externe Parent-Generator-Korrektur und exakter finaler Framework-Pin sind
getrennte erforderliche Änderungen; Parent #348 bleibt Draft/ungemergt.
Katalog-Admission führt keine Fälle aus und erledigt nicht die breitere
ursprüngliche Protokollqualifikation.

## Finaler Diff- und Review-Status

Task-eigene Framework-Vorbereitung; staged Whitespace-Prüfung, unabhängiges
begrenztes Code-/Katalogreview und unabhängiges EN/DE-Review bestanden.
Sechsundzwanzig isolierte Make-Parser-Kontrollen erhalten exakte Target- und
Zuweisungsgrenzen; dies ist statische Erkennung, keine Make-Ausführung.
Frische gehostete Prüfung steht noch aus. Die Dokumentation enthält nur sichere
Zusammenfassungen und geprüfte Hashes, keine Secrets, Roh-Bodies,
Zugangsdaten oder vollständigen Umgebungsdumps.
