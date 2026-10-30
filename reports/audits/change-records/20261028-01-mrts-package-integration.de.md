# Änderungsnachweis zur MRTS-Paketanbindung

**Sprache:** Deutsch | [English](20261028-01-mrts-package-integration.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change ID | 20261028-01-mrts-package-integration |
| UTC-Datum | 2026-10-28 |
| Framework-Basisrevision | `3a4f2281568139d94fda6b51dc2e07bb8fc06c67` |
| Issue oder Pull Request | Getrennter Task-Branch `codex/mrts-package-integration-20261028`; Draft-PR nach lokaler Verifikation |

## Motivation und Problemstellung

Generierung/Import der deaktivierten optionalen Demo konnten den Basiskorpus
blockieren. Unquotierte YAML-Schlüssel machten Headername `"2"` wieder zu einer
Zahl; unquotierte Strings, mehrzeilige Werte und wiederholte Header verloren
ebenfalls Typ/Inhalt/Reihenfolge. Sourcebare Shell-Funktionen konnten Fehler
von Teilschritten verbergen. Native Berichte konnten PASS-Zahlen aus Summen
erfinden. Die bisherigen Dateiprüfungen banden weder Quellen noch Artefakte.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-Vorbereitung, YAML-Import, private Veröffentlichung,
Runner-Ergebnisprojektion und nativer Berichtsverbrauch. MRTS bleibt
schreibgeschützt bei `8a6bb546c4c81d8ffc7be801dceac60c6925685f`; Quellen,
Fixtures und Gitlink bleiben unverändert. Parent-Hostcode und -Lieferung bleiben
ein getrenntes Repository.

## Akzeptanzkriterien

Deaktivierte Demo wird nicht gelesen; aktivierte ungültige/kollidierende Demo
schlägt fehl. Strings und geordnete/wiederholte Header bleiben bei strenger
Validierung erhalten. Nur ein vollständig validiertes Paket wird veröffentlicht;
Quellen, Auswahl, eindeutige IDs und Hashes werden vor Wiederverwendung geprüft.
Connector-Materialisierungen sind privat. Fehlende/übersprungene/doppelte/
erzwungene Ergebnisse und Writerfehler können kein Laufzeit-PASS erzeugen.
Importierte Katalogeinschränkungen bleiben in Ergebnisdaten erhalten.

## Untersuchte Alternativen

Ungültige Demo-Requests als pending zu importieren würde den Fehler erhalten
und einen Validatorbypass riskieren. Umbenennen der numerischen Header-Fixture
würde den Serialisierungsfehler verdecken. `PREPARED` oder alte Teilausgaben
belegen keine Paketidentität. Ein zweiter Importer wurde zugunsten des
vorhandenen Generator-Wrappers, Definition-Guards, Importers und Load-Writers
verworfen.

## Implementierungsentscheidung

`mrts-package.py prepare|verify|materialize` implementiert den Vertrag aus
[MRTS-Vorbereitung](../../../docs/mrts-preparation.de.md). Private Snapshots
speisen Guard und vorhandenen Importer; ein vollständiges Verzeichnis wird
durch Umbenennen veröffentlicht. Das Manifest bindet Revisionen, relevante
Quell-/Umgebungsidentität, vollständige Definitionsauswahl, Hashes, IDs und
Status. Materialisierung passt nur private FTW-Ports/Pfadreferenzen an.
Shell-Verbraucher prüfen das Manifest und erstellen je Host-Shell eine neue
Kopie. Eindeutige kombinierte Präambeln verhindern Selbsteinbindung und geben
Writerfehler weiter. Bestehende Make-Einstiege verwenden diesen Pfad.

Der Importer nutzt die bereits deklarierte PyYAML-Abhängigkeit, quotiert
Strings/Schlüssel, erhält wiederholte Header und stellt vollständige Kataloge
privat bereit. `mrts_results.py` liefert eine gemeinsame Ergebniszählung anhand
beobachteter IDs für Producer und Bericht. `runner_core.case_info` erhält
importiertes `metadata.runtime_verified=false` und trennt beobachtetes
Fall-PASS von breiter Variablen-/Capability-Promotion; der
real-world-summary-Validator bleibt unverändert.

## Geänderte Dateien und Tests

Betroffen sind `Makefile`, `ci/lib/mrts-common.sh`, neues
`ci/lib/mrts_results.py`,
`ci/provisioning/{mrts-package.py,generate-mrts.sh,mrts_definition_guard.py,import-mrts-cases.py}`,
`ci/reporting/generate-mrts-native-report.py`, `tests/runners/runner_core.py`,
drei bestehende MRTS-Regressionsmodule und drei neue On-Demand-Module für
Import-, Paket- und Ergebnisintegrität. Zweisprachige Integrations- und
Variablenreferenzen verlinken den neuen Leitfaden. Die Standardtestauswahl wird
nicht erweitert.

## Befehle und Ergebnisse

Alle Befehle liefen im Framework-Task-Worktree unter RTK. Python war
`<Framework-python>` (3.14.4,
PyYAML 6.0.3); `PYTHONNOUSERSITE=1`, `PYTHONDONTWRITEBYTECODE=1`, externes
`TMPDIR`/`RUNNER_TEMP` und `PYTHONPYCACHEPREFIX` waren ausdrücklich gesetzt. Lokale Pfade sind als `<pinned-checkout>`, `<Framework-python>` und
`<task-root>` normalisiert; exakte ausgeführte Befehle liegen
extern in `evidence/framework-validation-commands.json`, damit portable
Dokumentation keine Entwicklercheckoutpfade enthält.

| Befehl | Exit-Code | Kurzergebnis | Run-ID oder erlaubter Evidence-Pfad |
| --- | --- | --- | --- |
| `rtk bypass env MRTS_ROOT=<pinned-checkout> RUNNER_TEMP=<task-root>/evidence PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX=<task-root>/pycache TMPDIR=<task-root>/evidence <Framework-python> -m unittest tests.security_regression.test_mrts_common_posix_reliability tests.security_regression.test_mrts_common_sonar tests.security_regression.test_mrts_package tests.security_regression.test_mrts_import_integrity tests.security_regression.test_import_mrts_cases_sonar tests.security_regression.test_mrts_definition_guard tests.security_regression.test_mrts_result_integrity -q` | 0 | 67 Tests bestanden | `<task-root>/evidence` |
| `rtk bypass env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX=<task-root>/pycache TMPDIR=<task-root>/evidence <Framework-python> ci/checks/catalog/check-mrts-importer.py` | 0 | Vier Importer-Fixture-Fälle | Derselbe externe Evidence-Root |
| `rtk bypass sh -n ci/lib/mrts-common.sh ci/provisioning/generate-mrts.sh ci/provisioning/write-mrts-load.sh` | 0 | Shell-Syntax | Keine |
| `rtk make check-bilingual-docs check-doc-links check-repository-path-references PYTHON=<Framework-python>` | 0 | Zweisprachige Variablen, Links und Pfadreferenzen | Keine |
| `rtk bypass git diff --check` | 0 | Keine Whitespace-Fehler | Keine |

Der erste integrierte Lauf hatte fünf Testumgebungsfehler durch fehlendes
`RUNNER_TEMP`; seine übrigen 59 Methoden bestanden. Das temporäre Verzeichnis
der Ergebnistests unterstützt nun auch `TMPDIR`. Kein Produktfehler wurde
verborgen. Tests mit bloßer vorbereiteter Load-Datei verlangen nun ein Manifest;
echte Prepared-Akzeptanz wird durch die Paket-CLI geprüft.

## Sicherheitsauswirkung

Keine Kontrolle wird abgeschwächt. Negativprüfungen decken ungültige
Header/Kontrollzeichen, verbotene Definitionsglobals, fehlende/manipulierte
Pakete, veränderte Definitionsauswahl, Teilimporte, alte Generatorausgaben,
private Portisolation, Präambel-Writerfehler und erfundene Summenergebnisse ab.
Framework-Gitleaks-Scans vor Quelllektüre und nach Implementierung fanden keine
Secrets (beide Exit 0; redigierte Berichte im externen Evidence-Root). Dies ist kein breiter
Security-Scan und kein Nachweis signierter Artefakte/Prozessisolation.

## Dokumentation und Runtime-Evidenz

Aktualisierte zweisprachige Connectorintegration und Variablenreferenz, neuer
Leitfaden `docs/mrts-preparation.md` mit Begleiter. Der Parent-eigene
H1-Nachweis verwendet eine lokale Auftragsdefinition mit ausdrücklichem
Deny-Status über echten gepinnten Generator, Importer und Apache. Der
Parent-Nachweis besitzt diese Laufzeitfakten; Framework-Generierung/Katalogprüfung
allein qualifizieren keinen Host.

## Nicht ausgeführte Prüfungen

Keine historische MRTS-/Protokollgesamtmatrix, HTTP/2/HTTP/3,
Coverage-Kampagne oder vollständige Abhängigkeitsprüfung gemäß Auftragsumfang.
Ruff fehlt in der Framework-Umgebung und wurde nicht installiert. Erforderliche
GitHub-Prüfungen und geltende Cloud-Gates werden nach PR-Erstellung abgerufen;
lokale Ergebnisse behaupten deren Erfolg nicht.

## Einschränkungen und Restrisiko

Der gepinnte Upstream-Korpus wird bei unzureichender Klassifikation als pending
importiert; seine DetectionOnly-Initialisierung und reinen Log-Erwartungen werden
nicht zu disruptivem PASS hochgestuft. Die gepinnte Demo enthält überlappende
Regel-IDs und kann bei ausdrücklicher Aktivierung scheitern. Fallstatus und
Evidence-Ebenen bleiben sichtbar. Vertrauenswürdige Änderungen derselben UID
liegen außerhalb der Prozessisolation. Ein Paket bindet genauen Ort und
Quellenidentität; Revisionsänderungen erfordern Neugenerierung. Der allgemeine
Testumzug bleibt getrennt.

## Finaler Diff- und Review-Status

Unabhängiges Review fand Auswahlwiederverwendungs-, geerbte
Materialisierungs- und Präambel-Selbsteinbindungsfehler; fokussierte Korrekturen
und Regressionen adressieren sie. Abschließender gestagter Diff, Secret-Scan
und Lieferprüfung erfolgen vor Commit/PR. MRTS-Lieferung, Parent-Pin-Update
oder Merge sind nicht autorisiert.
