# Framework-Eingangsgrenze für MRTS-Definitionen

**Sprache:** [English](CR-20260929-mrts-definition-intake.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `CR-20260929-mrts-definition-intake` |
| Datum (UTC) | 2026-09-29 |
| Basis-Revision | `f9e48b0774b5bdf7aaa8e38ce98eb6c50bf293c8` |
| Quellbefund | `B03` / `csf_24b4dcf793c63c691309c9af` |
| Unveränderter MRTS-Gitlink | `8a6bb546c4c81d8ffc7be801dceac60c6925685f` |
| Lieferziel | Framework-Draft-PR #128; kein Merge |

## Motivation und Problemstellung

B03 beschreibt unbeschränkte globale Attributzuweisung im separat besessenen
MRTS-Generator. Der Nutzer wählte Parent und Framework, nicht MRTS. Dieser
Draft ergänzt eine begrenzte Mitigation am vorhandenen Framework-Eingang,
ohne den Generator zu kopieren, zu ändern oder dessen Ursache als behoben auszugeben.

Das [Eingangsregister](../findings/20260929-mrts-intake.json) erhält originale
Befund-ID, gemeldeten Schweregrad, Zuständigkeitsgrenze und ausstehende Verifikation.
Der separate Parent-Draft erhält die Zuordnung von 72 Quellen zu 59 Arbeitseinträgen.
Andere Befunde gelten nicht stillschweigend als erledigt.

Die CI am ersten Head 95dd0a95d39ea77679832b888aba745d7954d23d lehnte die
Flow-Schreibweise der Branchliste und den auf Jobebene nicht verfügbaren
runner-Kontext ab. Die Nachbesserung verwendet Block-YAML sowie temporäre
und Cachevariablen auf Schrittebene. Das Record-Paar folgt dem bestehenden
Dokumentationsvertrag; Checker und Quality-Gate-Anforderungen werden nicht gelockert.

## Akzeptanzkriterien

- Undokumentierte globale Schlüssel und nicht als Mapping vorliegende Konfiguration
  vor Generatorausführung ablehnen, einschließlich skalarer Global-Ersetzung.
- Jede ausgewählte Definition vor dem Generatoraufruf prüfen.
- Private Kopien geparster und geprüfter Dokumente übergeben; keinen Quellpfad
  prüfen und danach durch den Generator erneut öffnen lassen.
- Lexikalische Reihenfolge, unterstützte Daten, Ausgabeparameter und erfolglosen
  Child-Exitstatus sowie bestehende Runtime-/Ausgabewurzelkontrollen erhalten.
- Vor Promotion den vollständigen gepinnten Default-/Feature-Demo-Korpus prüfen.
- Direkten MRTS-Aufruf und offenen ursächlichen Fix ausdrücklich getrennt halten.
- Dedizierte Regression und bestehende Checks müssen am reparierten Head bestehen;
  vor einer Sonar-Korrekturaussage muss der tatsächliche Sonar-Befund gelesen werden.

## Implementierungsentscheidung und Begründung

Der bestehende Shell-Wrapper delegiert an den neuen Framework-eigenen Python-Launcher.
Dieser begrenzt Definitionsdaten vor einem vertrauenswürdigen, vom Betreiber
ausgewählten MRTS-Programm. Er ist keine Sandbox für Generatorcode oder feindliche
Same-UID-Prozesse und ersetzt vorhandene Ausgabepfadprüfungen nicht.

Das Schema stammt aus globalen README-Schlüsseln und RuleGenerator des gepinnten
MRTS. default_tests_phase_methods und default_test_phase_methods bleiben ohne
Übersetzung zulässig; default_constants wird aus der Implementierung erhalten.
Andere Attribute werden abgelehnt. Objektintrospektion ist kein Schema.

Der Launcher verwendet den vorhandenen sicheren PyYAML-Loader und schreibt
nummerierte validierte Kopien unter dem externen Build-Root. Dateimodus ist 0600,
Verzeichnismodus 0700; Cleanup erfolgt bei normalem Abschluss und Exceptions.
Lexikalische Reihenfolge bleibt erhalten. Direkte MRTS-Änderungen überschritten
die ausgewählte Repositorygrenze; Prüfen mit erneutem Öffnen ließe ein Austauschfenster.
Die Kopien vermeiden dieses Fenster, ohne den Generator in Framework zu importieren.

Die bestehende Shell-Ausgabebereinigung bleibt vor dem Launcher. Dieser Draft
bewahrt deshalb frühere Ausgaben nicht, wenn die spätere Validierung fehlschlägt.
Er ändert weder MRTS-rulefile/testfile-Begrenzung noch erlaubt er weitere globale
Objektattribute.

Der dedizierte Exact-Head-Workflow installiert nur vorhandene hashgebundene
Abhängigkeiten. Temporäre Verzeichnisse erhalten private umask. Eine temporäre,
unauthentisierte Diagnose liest ohne Checkout oder Zugangsdaten die ursprüngliche
öffentliche Sonar-Annotation, um Regel und Stelle festzustellen. Sie ist keine
neue Sonar-Analyse und ersetzt das Quality Gate nicht; nach Diagnose wird sie
entfernt. Action-Pins und Securitygates bleiben erhalten.

## Geänderte Dateien

- `ci/provisioning/generate-mrts.sh`
- `ci/provisioning/mrts_definition_guard.py`
- `tests/security_regression/test_mrts_definition_guard.py`
- `.github/workflows/ci-findings-regressions.yml`
- `reports/audits/findings/20260929-mrts-intake.json`
- Dieses englisch/deutsche Change-Record-Paar.

## Ausgeführte Befehle

| Prüfung | Tatsächlicher Nachweis und Einschränkung |
| --- | --- |
| Ursprüngliche Shell-Dateiübernahme | Vollständiger Inhalt stimmte vor der ersten Änderung mit Git-Blob-SHA-1 überein |
| Ursprüngliche Python-Syntax / Register-JSON | Als Daten geparst; keine Verhaltenstestausführung |
| Lokale Launcher-Tests | NOT RUN: vorgeschriebenes RTK nicht verfügbar |
| Generator-Testdouble | Für Parameter, Kopien, Rechte, Ablehnung und Cleanup definiert; keine lokale Ausführung behauptet |
| Vollständiger gepinnter MRTS-Korpus | NOT RUN; direkte Generatorkompatibilität bleibt separate Prüfgrenze |
| Lokale Shell-Syntax / git diff --check | NOT RUN in der Bearbeitungsumgebung |
| Ursprünglicher Action-Version-Job 109307180219 | An Flow-Branches in ci-findings-regressions.yml gescheitert |
| Ursprünglicher actionlint-Job 109307181277 | Am jobweiten runner-Kontext für TMPDIR und PIP_CACHE_DIR gescheitert |
| Ursprünglicher Sonar-Check 109307382232 | New-Code-Security-Rating gescheitert; genaue Annotation noch abzurufen |
| Reparierte Exact-Head-Regression und gesamte CI | Neue Ergebnisse nach diesem Commit ausstehend; hier kein Erfolg behauptet |

Code-Work- und Sonar-Skills wurden gelesen. Der repositoryreferenzierte globale
Ausführungsskill und vorgeschriebenes lokales RTK fehlen. Kein lokaler Projektbefehl
umgeht stillschweigend diese Ausführungsvorgaben.

## Security-Auswirkung

Undokumentierte globale Objektattribute werden am Framework-Eingang abgelehnt.
Dies ist beabsichtigt; vollständige Korpuskompatibilität bleibt ungeprüft.
Der Originalgenerator bleibt unverändert, direkter Aufruf liegt außerhalb der
Mitigation. B03 kann durch diesen Wrapper nicht geschlossen werden. Die
CI-Reparatur erteilt keine Schreibrechte, lockert keine Pins und deaktiviert keine Tests.

## Runtime-Evidence

Dieser Record belegt weder Live-Host-Evidence des ursprünglichen Szenarios noch
einen vollständigen gepinnten Korpuslauf. Erfolg mit dem Testdouble belegt nur
das getestete Launcher-Verhalten. Andere grüne Checks ersetzen weder dedizierte
Regression noch tatsächliches Sonar-Ergebnis am aktuellen Head.

## Bekannte Einschränkungen

Dies ist candidate_entrypoint_mitigation, keine vollständige Behebung oder
verifizierte Schließung von B03. Der direkte MRTS-Fix benötigt einen separat
autorisierten Task. Die Shell bereinigt Ausgaben vor der neuen Prüfgrenze.
Betreiberausgewählter Generatorcode und Same-UID-Prozessisolation bleiben außerhalb.

## Verbleibende Risiken

Vollständiger Default-/Feature-Demo-Korpus und bestehende Begrenzungsregressionen
müssen ausgeführt werden. Die ursprüngliche Sonar-Security-Annotation muss ohne
Unterdrückung oder Vermutung ihrer Regel diagnostiziert werden. Eine nötige
Quellkorrektur erfordert neue fokussierte Tests und headgebundene Analyse.

## Nicht ausgeführte Prüfungen mit Begründung

Lokale Repositoryausführung, native Laufzeitvalidierung und vollständiger MRTS-Korpus
wurden wegen fehlendem vorgeschriebenem RTK und provisionierten Repositorywerkzeugen
nicht ausgeführt. Keine ausgelassene oder übersprungene Prüfung ist PASS.
Neue Head-Ergebnisse werden nicht durch alte Erfolge oder Quellprüfung ersetzt.

## Finaler Diff- und Review-Status

Die erste CI-Nachbesserung ändert den dedizierten Workflow und dieses Record-Paar,
nicht den Guard, Originaltests, Dependency-Locks oder Quality-Gate-Einstellungen.
Der PR bleibt bis zu tatsächlichen aktuellen Headprüfungen und unabhängigem Review Draft.

Parent-Auswirkung: Dieser separate Framework-Commit ändert nicht dessen ausgewählte
Abhängigkeit. Parent-Gitlink: unchanged. MRTS-Scope: default_read_only;
MRTS-Gitlink: unchanged. Kein Merge, Force-Push, Risikoakzeptanz oder Release-Claim.
