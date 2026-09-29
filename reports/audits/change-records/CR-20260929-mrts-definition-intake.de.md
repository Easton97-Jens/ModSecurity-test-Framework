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
ohne den Generator zu ändern oder dessen Ursache als behoben auszugeben.

Das [Eingangsregister](../findings/20260929-mrts-intake.json) erhält originale
Befund-ID, gemeldeten Schweregrad, Zuständigkeitsgrenze und ausstehende Verifikation.
Der separate Parent-Draft erhält die Zuordnung von 72 Quellen zu 59 Arbeitseinträgen.
Andere Befunde gelten nicht stillschweigend als erledigt.

Der ursprüngliche Workflow verwendete unzulässigen jobweiten runner-Kontext
und Flow-YAML. Weitere Checks forderten Concurrency, eine Bash-Standardshell
und den Python-Vertrag des Repositorys. Diese Anforderungen werden erfüllt,
ohne deren Checker zu ändern. Das alte Beobachtungsdouble wandelte durch JSON
Integer-Schlüssel in Strings um; es verwendet jetzt verlustfreies YAML und
behält den ursprünglichen exakten Dokumentvergleich.

Sonar-Befund AaDsHe5ZOryZpzLd_yHy, Regel pythonsecurity:S8705, identifiziert
Argument-Injection am Subprocess-Aufruf von run_guarded einschließlich tests_out.
Eine argv-Liste verhindert Shell-Aufteilung, aber nicht die Interpretation
eines vorhandenen relativen Pfads mit führendem '-' als Option. Zwei harmlose
reale Subprocess-Regressionen zeigten dies vor der Quellkorrektur.

## Akzeptanzkriterien

- Undokumentierte globale Schlüssel und nicht als Mapping vorliegende Konfiguration
  vor Generatorausführung ablehnen, einschließlich skalarer Global-Ersetzung.
- Jede ausgewählte Definition vor dem Generatoraufruf prüfen.
- Private Kopien geparster und geprüfter Daten statt erneut geöffneter Originale übergeben.
- Lexikalische Reihenfolge, unterstützte Daten einschließlich Integer-Schlüssel,
  Ausgabeparameter, erfolglose Child-Exitcodes, Cleanup und Pfadkontrollen erhalten.
- Generator-, Snapshot- und Ausgabepfade als Daten statt CLI-Optionen behandeln.
- Auch ein relativ optionsartig benanntes ausgewähltes Skript tatsächlich ausführen.
- Vor Promotion vollständigen gepinnten Default-/Feature-Demo-Korpus prüfen.
- Direkten MRTS-Aufruf und offenen ursächlichen Fix getrennt halten.
- Aktuelle Head-Regression, CI und Sonar-Ergebnisse verlangen; kein vermutetes PASS.

## Implementierungsentscheidung und Begründung

Der Shell-Eingang delegiert an den Framework-eigenen Python-Launcher. Dieser
ist keine Sandbox für vertrauenswürdigen betreiberausgewählten Generatorcode
oder feindliche Same-UID-Prozesse und ersetzt vorhandene Ausgabepfadprüfungen nicht.

Das Global-Schema stammt aus gepinntem MRTS-README und RuleGenerator.
default_tests_phase_methods und default_test_phase_methods bleiben ohne
Übersetzung zulässig; default_constants bleibt unterstützt. Andere Attribute
werden abgelehnt, statt Objektintrospektion als Schema zu verwenden.

Der vorhandene sichere PyYAML-Loader bleibt erhalten. Nummerierte Kopien unter
dem externen Build-Root haben Dateimodus 0600 und Verzeichnismodus 0700,
erhalten die Reihenfolge und werden bei Abschluss sowie Exceptions entfernt.
Der Generator öffnet dadurch keine ersetzten Originaldefinitionen erneut.
Die Shell bereinigt Ausgaben weiterhin vor der Launcher-Validierung; frühere
Ausgaben bleiben bei späterer Eingabeablehnung deshalb nicht erhalten.

Die Sonar-Korrektur löst vorhandene Generator-, Ausgabe- und Snapshotpfade
vor der argv-Erzeugung absolut auf und beendet Pythons Optionsauswertung mit
-- vor dem Skript. Nummerierte Snapshotoperanden sind dadurch ebenfalls absolut.
Relative Pfade bleiben Daten, auch Namen mit führendem '-'. Vertrauenswürdiges
Programm und Ausgabewurzeln bleiben vom Betreiber gewählt; dies ist keine
neue Programm-Sandbox. Shellquoting oder Shellausführung werden nicht ergänzt.

Der Exact-Head-Workflow nutzt vorhandene immutable Action-Pins und hashgebundene
Abhängigkeiten. TMPDIR und PIP_CACHE_DIR stehen auf Schrittebene, Verzeichnisse
verwenden private umask, Concurrency-/Bash-Verträge werden erfüllt. Die temporäre
unauthentisierte Sonar-Diagnose ist abgeschlossen und entfernt. Kein Pflicht-
test oder Sonar-Check wird entfernt, unterdrückt oder herabgestuft.

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
| Ursprüngliche Quellübernahme | Vollständige Shell-Datei stimmte vor Änderung mit Git-Blob überein; Python/JSON als Daten geparst |
| Ursprüngliche Action-Version-/actionlint-Jobs | 109307180219 und 109307181277 scheiterten an Flow-YAML und ungültigem runner-Kontext |
| Zwischenprüfung des Security-Vertrags | 109347213959 zeigte fehlende Concurrency und Bash-Defaults; korrigiert |
| Erste dedizierte Tests bei 60a75c90500f765675059e341bf8e73f6008a023 | Job 109347213122: 9 bestanden, 1 wegen verlustbehafteter JSON-Beobachtung gescheitert |
| Test-vor-Fix-Lauf bei d1a6aeef864ad851f1f9f6b924c29719006c8c64 | Job 109350381183: alle bisherigen 10 Tests bestanden; die 2 neuen Argumentgrenztests mit Child-Exit 2 gescheitert |
| Sonar-Evidenceabruf | Jobs 109347213481 und 109350381226 lasen ursprüngliche öffentliche Annotation und exakten S8705-Datenfluss ohne Zugangsdaten |
| Lokale Projekttests / Builds / git diff --check | NOT RUN: vorgeschriebenes RTK und provisionierte lokale Repositorywerkzeuge fehlen |
| Quellfix-Head-Regression / gesamte CI / Sonar | Neue Ergebnisse nach dieser Korrektur ausstehend; nicht vorab bestätigt |

Der Test-vor-Fix-Befehl war python3 -m unittest discover -s
tests/security_regression -p 'test_mrts_definition_guard.py' -v in GitHubs
exaktem PR-Head-Checkout mit Repository-Python und hashgebundenen Abhängigkeiten.
Die bestehende Integer-Schlüssel-Assertion wurde nicht gelockert. Der optionsartige
Generator scheiterte in Pythons Optionsparser, relative Ausgabewurzeln im
Fixtureparser. Kein destruktiver Payload oder externes Ziel wurde verwendet.

## Security-Auswirkung

Undokumentierte globale Attribute werden am Framework-Eingang abgelehnt.
Führende Bindestriche in Pfadoperanden können den ausgewählten Child-Aufruf
nicht mehr als Interpreter-/Generatoroptionen umdeuten. MRTS-Originalcode bleibt
unverändert; direkter Aufruf liegt außerhalb der Mitigation. B03 kann nicht
allein durch spätere erfolgreiche Launcher-Tests oder Sonar geschlossen werden.

Keine Rechteausweitung, Dependency-Pin-Änderung, Scannerausnahme, Severityänderung,
Testabschaltung oder Lockerung von Quality Gates ist Teil dieser Korrektur.

## Runtime-Evidence

Die fehlgeschlagenen Argumentgrenztests und zehn erfolgreichen bisherigen
Kontrollen sind reale Subprocess-Tests am genannten Test-vor-Fix-Head mit
harmlosem Fixturegenerator. Sie sind kein vollständiger MRTS-Korpus- oder
Connector-Hostlauf. Neue Ergebnisse am Quellfix-Head sind unabhängig zu bewerten.

## Bekannte Einschränkungen

Dies bleibt candidate_entrypoint_mitigation, keine vollständige Behebung oder
verifizierte Schließung von B03. Ein direkter MRTS-Fix benötigt einen separat
autorisierten Task. Bestehendes Shell-Cleanup liegt vor der Validierung. Der
Launcher isoliert keine Prozesse und authentisiert kein betreiberausgewähltes Programm.

## Verbleibende Risiken

Gepinnter Default-/Feature-Demo-Korpus und bestehende Begrenzungsregressionen
müssen weiterhin ausgeführt werden. Same-UID-/Generator-Vertrauensannahmen
bleiben unverändert. Sonars CLI-Datenfluss wird als Pfad-/Optionsgrenze repariert;
die allgemeine HTTP-Quellbeschreibung der Annotation belegt keinen HTTP-Listener
in diesem Launcher. Der neue Scan muss die tatsächliche Korrektur bewerten.

## Nicht ausgeführte Prüfungen mit Begründung

Lokale Projektbefehle und vollständige Generator-/Hostläufe wurden mangels
vorgeschriebenem RTK und provisionierter Repositorywerkzeuge nicht ausgeführt.
Code-Work- und Sonar-Skills wurden gelesen; der referenzierte globale Ausführungsskill
war nicht verfügbar. Kein ungekapselter lokaler Projektbefehl ersetzte RTK.
Keine ausgelassene, übersprungene oder ausstehende Prüfung ist PASS.

## Finaler Diff- und Review-Status

Die CI-Nachbesserungen reparieren Workflow-/Dokumentationsverträge, korrigieren
das Beobachtungsformat, ergänzen zwei negative Regressionen und beheben danach
die Argumentgrenze. Alle ursprünglichen Guard-Assertions und Einschränkungen
bleiben erhalten. Der temporäre Diagnosejob wurde nach Auswertung entfernt.

Parent-Auswirkung: unveränderte ausgewählte Abhängigkeit. Parent-Gitlink: unchanged.
MRTS-Scope: default_read_only. MRTS-Gitlink: unchanged. Der PR bleibt bis zu
aktuellen Headchecks und Review Draft. Kein Merge, Force-Push, akzeptiertes
Risiko, neu behaupteter Hostsupport oder automatischer Findingabschluss.
