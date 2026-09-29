# Framework-Eingangsgrenze für MRTS-Definitionen

**Sprache:** Deutsch | [English](CR-20260929-mrts-definition-intake.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change ID | `CR-20260929-mrts-definition-intake` |
| UTC date | 2026-09-29 |
| Framework-Basisrevision | `f9e48b0774b5bdf7aaa8e38ce98eb6c50bf293c8` |
| Quellbefund | `B03` / `csf_24b4dcf793c63c691309c9af` |
| Unveränderter MRTS-Gitlink | `8a6bb546c4c81d8ffc7be801dceac60c6925685f` |
| Lieferziel | Nur Framework-Draft-PR; kein Merge |

## Motivation und Problemstellung

Der gelieferte Befund B03 beschreibt die unbeschränkte globale
Attributzuweisung im separat besessenen MRTS-Generator. Der Nutzer hat Parent
und Framework für Änderungen ausgewählt, nicht MRTS. Dieser Draft ergänzt
daher eine begrenzte Mitigation am vorhandenen Framework-Generierungseingang.
Er kopiert oder ändert den Generator nicht und behauptet keine Behebung der
ursächlichen Generatorlücke.

Das [Eingangsregister](../findings/20260929-mrts-intake.json) erhält originale
Befund-ID, gemeldeten Schweregrad, Repository-Grenze und ausstehende
Verifikation. Der separate Parent-Draft erhält die vollständige Zuordnung
von 72 Quellen zu 59 Arbeitseinträgen. Andere Befunde gelten nicht
stillschweigend als erledigt.

## Betroffene Komponenten und Sicherheitsgrenzen

Der Framework-Wrapper delegiert an einen neuen Framework-eigenen
Python-Launcher. Dieser begrenzt Definitionsdaten vor dem vertrauenswürdigen,
vom Betreiber ausgewählten MRTS-Programm. Er isoliert keinen Generatorcode,
authentisiert keinen feindlichen Same-UID-Prozess und ersetzt die vorhandenen
Ausgabepfadprüfungen nicht.

Das Schema stammt aus den globalen README-Schlüsseln und RuleGenerator des
gepinnten MRTS-Baums. Sowohl die dokumentierte historische Schreibweise
`default_tests_phase_methods` als auch die implementierte Schreibweise
`default_test_phase_methods` bleiben ohne Übersetzung zulässig.
`default_constants` wird aus der Implementierung erhalten. Attributnamen
außerhalb dieser expliziten Menge werden abgelehnt; Objektintrospektion ist
kein Konfigurationsschema.

## Abnahmekriterien

- Undokumentierte globale Schlüssel und nicht als Mapping vorliegende
  Global-Konfiguration vor Generatoraufruf ablehnen, einschließlich skalarer
  Ersetzung des gesamten Global-Blocks.
- Alle ausgewählten Definitionen vor dem Generatoraufruf prüfen.
- Private Kopien der geparsten und geprüften Dokumente übergeben, statt einen
  Quellpfad zu prüfen und anschließend vom Generator erneut öffnen zu lassen.
- Lexikalische Reihenfolge, unterstützte Daten, Ausgabeparameter und
  erfolglosen Child-Exitstatus erhalten.
- Vorhandene Runtime-/Ausgabewurzelprüfungen des Aufrufers erhalten.
- Vor Promotion den vollständigen gepinnten Default- und Feature-Demo-Korpus prüfen.
- Direkten MRTS-Aufruf und den offenen MRTS-Root-Fix ausdrücklich getrennt halten.

## Betrachtete Alternativen

Eine Änderung am MRTS-Submodul aus diesem Framework-Task würde die ausgewählte
Repository-Grenze überschreiten. Prüfen und erneutes Öffnen ließe ein Fenster
für Datenaustausch offen. Private Kopien der geparsten Daten vermeiden dieses
Fenster, ohne eine Prozesssandbox zu behaupten oder den Generator in das
Framework zu kopieren.

## Implementierungsentscheidung

Der bestehende Shell-Wrapper ruft `mrts_definition_guard.py` mit ausgewähltem
Generator, Wurzeln und Definitionsdateien auf. Der Launcher verwendet den
bereits benötigten sicheren PyYAML-Loader und eine explizite Global-Allowlist.
Anschließend schreibt er nummerierte Kopien in ein privates temporäres
Verzeichnis unter dem bestehenden externen MRTS-Build-Root. Dateien erhalten
Modus 0600, das Verzeichnis Modus 0700. Cleanup erfolgt bei normalem Abschluss
und Exceptions. MRTS erhält die Dateien in derselben lexikalischen Reihenfolge.

Die bestehende Shell-Ausgabebereinigung bleibt vor dem Launcheraufruf.
Dieser Draft verspricht deshalb nicht, frühere generierte Ausgaben zu
erhalten, wenn anschließend eine Eingabe abgelehnt wird. Er verändert weder
die rulefile/testfile-Begrenzung in MRTS noch erlaubt er beliebige neue
globale Objektattribute.

Ein dedizierter Exact-Head-Workflow mit Leserechten installiert nur bestehende
Hash-gebundene CI-Abhängigkeiten und führt das neue Regressionsmodul aus.
Action-Pins, Dependency-Locks, Quality Gates und vorhandene Tests werden
nicht gelockert.

## Sicherheits- und Kompatibilitätsauswirkung

Definitionen, die über `global` undokumentierte Objektattribute setzten,
werden an diesem Eingang jetzt abgelehnt. Dies ist beabsichtigt; vollständige
Korpuskompatibilität wurde in der Bearbeitungsumgebung jedoch nicht ausgeführt.
Der ursprüngliche Generator bleibt unverändert, direkte Aufrufe liegen
außerhalb der Mitigation. B03 kann durch diesen Wrapper nicht geschlossen werden.

## Geänderte Dateien und Tests

- `ci/provisioning/generate-mrts.sh`
- `ci/provisioning/mrts_definition_guard.py`
- `tests/security_regression/test_mrts_definition_guard.py`
- `.github/workflows/ci-findings-regressions.yml`
- `reports/audits/findings/20260929-mrts-intake.json`
- Dieses englisch/deutsche Change-Record-Paar.

## Befehle und Ergebnisse

| Prüfung | Tatsächlicher Stand bei Vorbereitung |
| --- | --- |
| Originale Shell-Dateiübernahme | Vollständiger Inhalt stimmte vor Änderung mit dem Git-Blob-SHA-1 überein |
| Python-Syntax / Register-JSON | Als Daten geparst; keine Verhaltenstest-Ausführung |
| Neue Launcher-Tests | Ergänzt; lokal NOT RUN, da verpflichtendes RTK nicht verfügbar ist |
| Generator-Testdouble | Für Parameter-, Snapshot-, Rechte-, Ablehnungs- und Cleanup-Tests definiert; keine Ausführung behauptet |
| Vollständiger gepinnter MRTS-Korpus | NOT RUN; direktes Generatorverhalten bleibt eine eigene Prüfgrenze |
| Shell-Syntax / natives git diff --check | NOT RUN; Quelldiff und Whitespace neuer Zeilen separat untersucht |
| Neue Exact-Head-CI | Konfiguriert; Ergebnis im Draft-PR ausstehend |
| Gesamte CI / SonarQube / Securityscan | Hier kein erfolgreicher Nachweis behauptet |

Der verfügbare Code-Work-Skill wurde gelesen. Der im Repository referenzierte
globale Ausführungsskill war nicht zugänglich. Kein lokaler Projektbefehl
umgeht den vorgeschriebenen RTK-Pfad; erfolgreiche Testausgaben werden nicht
erfunden.

## Verbleibende Arbeit und Lieferung

Dies ist `candidate_entrypoint_mitigation`, keine vollständige Behebung oder
verifizierte Schließung von B03. Der direkte MRTS-Fix benötigt einen separat
autorisierten Task im MRTS-Repository. Legitime Korpusgenerierung, bestehende
Pfadbegrenzungsregressionen und finale aktuelle Quality Checks bleiben nötig.

Parent-Auswirkung: Ein separat gelieferter Framework-Commit ändert nicht die
vom Parent ausgewählte Abhängigkeit. Parent-Gitlink: `unchanged`.
MRTS-Auswirkung: `default_read_only`; MRTS-Gitlink: `unchanged`.
Kein fremder Repository-Branch, Default-Branch, Dependency-Pin oder bestehender
PR wird verändert. Kein Merge, Force-Push, automatische Risikoakzeptanz oder
Release-Claim.
