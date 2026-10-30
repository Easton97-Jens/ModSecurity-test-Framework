# MRTS-Pfad- und Prozessgrenzen korrigieren

**Sprache:** Deutsch | [English](20261030-01-pr139-sonar-remediation.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261030-01-pr139-sonar-remediation |
| UTC-Datum | 2026-10-30 |
| Framework-Basisrevision | `7488bbcd8dcbeea94744d0b46f46bc4143335c87` |
| Issue oder Pull Request | [Framework PR #139](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/139) |

## Motivation und Problemstellung

Die Cloud-Analyse von PR #139 meldete 24 Befunde in den neuen Paket- und
Ergebnis-Helpern. Das Quality Gate scheiterte an der neuen Sicherheitsbewertung.
Lokale Fixtures bestätigten, dass Ergebnis-Reader und -Writer Pfade außerhalb
des gewählten Laufzeitroots akzeptierten und eine fehlerhafte Liste von
Fehler-IDs ein Drei-Sekunden-Timeout überschreiten konnte. Paketbefehle
benötigten außerdem eine ausdrückliche Vertrauensgrenze für ausgeführte
Framework-Skripte. Regelbeschreibungen und vollständige Befund-/Hotspot-Seiten
wurden vor der Korrektur geprüft; Scannerbefunde wurden bis zur tatsächlichen
Quelle und Senke verfolgt, statt sie automatisch als Exploitnachweis zu werten.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-Paketvorbereitung, private Artefaktumschreibung, Ergebniszugriffe und
nativer Berichtsverbrauch. Der gemeinsame Helper `ci/lib/mrts_path_safety.py`
prüft dedizierte externe Roots unabhängig von eingehenden Artefaktpfaden. Keine
Parent-Quelle oder Gitlink, MRTS-Quelle/-Fixture/-Gitlink, Scannerausschlüsse,
Regeleinstellungen oder Quality-Gate-Einstellungen ändern sich. Parent-PR #432
ist bereits gemergt; diese Änderung setzt den vorhandenen Framework-PR fort,
ohne Merge oder Pin-Update zu autorisieren.

## Akzeptanzkriterien

Gültige Paketvorbereitung, Prüfung, private Portanpassung und PASS anhand
ausdrücklicher IDs bleiben erhalten. Traversal, fremde Geschwisterpfade,
Symlinkkomponenten, System-/Quellroots, öffentliche Schreibrechte und fremde
Framework-Ausführungsroots werden abgewiesen. Nicht reguläre/übergroße
Ergebniseingaben scheitern ohne Blockieren. Fehlerhafte Fehlerlisten enden zügig
und IDs behalten ASCII-Semantik. Frische Cloud-Ergebnisse und erforderliche
Checks müssen zum gepushten PR-Head geprüft werden.

## Untersuchte Alternativen

Befunde zu unterdrücken, zu akzeptieren oder Analyse-/Gate-Konfiguration zu
ändern würde die Grenzen nicht reparieren. Dem jeweiligen Eingabe-Elternpfad
zu vertrauen würde gerade den zu prüfenden Pfad autorisieren. Ein neues
Pflichtargument für den Ergebnis-CLI-Root würde den gemergten Parent-Aufrufer
brechen; stattdessen autorisiert der bereits vorhandene vertrauenswürdige,
exportierte `BUILD_ROOT` den Root. Prozessisolation derselben UID liegt
außerhalb dieses Dateiintegritätsvertrags.

## Implementierungsentscheidung

Eine gemeinsame Prüfung erzwingt eigene, nicht fremd beschreibbare,
symlinkfreie externe Roots und gegebenenfalls konfigurierte Laufzeitanker.
Containment von Ein-/Ausgaben, lexikalisches Traversal, Verzeichniseigentum und
Dateitypen werden vor Zugriffen geprüft. Ergebnis-Reads verwenden einen nicht
blockierenden No-follow-Deskriptor und eine Bytegrenze; Jobveröffentlichung
bleibt atomar. Der native Bericht übergibt seinen vertrauenswürdigen Root
ausdrücklich.

Paketskripte sind an den ausführenden Framework-Checkout gebunden. Geschlossene
Git-Operationen und Vorbereitungsschritte verwenden vertrauenswürdige
Programmpfade und einen System-PATH für Kindprozesse; der Launcher der
Framework-Virtualenv bleibt erhalten. Manifestblätter und vollständige
Artefaktbäume werden vor Reads oder Provenienz-/Portumschreibung geprüft. Der
Helper gehört zur Manifest-Quellenidentität. Komplexe Abläufe werden geteilt,
die Regex-Suche in Fehlerlisten durch Tokenprüfung ersetzt; ASCII-`\d` bleibt
erhalten. Bestehende CLI-Flags und Manifestprüfungen bleiben; geänderte
Quellenidentität erfordert frische Pakete.

## Geänderte Dateien und Tests

`ci/lib/mrts_path_safety.py`, `ci/lib/mrts_results.py`,
`ci/provisioning/mrts-package.py`, `ci/reporting/generate-mrts-native-report.py`,
die beiden Paket-/Ergebnisintegritäts-Testmodule, die zweisprachige
Vorbereitungsdokumentation und dieser zweisprachige Record. Achtzehn neue Tests
decken die genannten Grenzen einschließlich unveränderter Fremddatei-Sentinels
und erfolgreicher eigenständiger CLI-/Venv-Kontrollen ab. Standardinventar und
historische Matrix werden nicht erweitert.

## Befehle und Ergebnisse

Alle Befehle verwendeten RTK und die Framework-eigene Python-Umgebung. Portable
Befehle unten normalisieren lokale Präfixe als `<task-root>`,
`<Framework-python>` und `<pinned-checkout>`; genaue Aufrufe und Logs verbleiben
in externer Auftragsevidenz. Zugangsdaten werden nicht erfasst.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk bypass <Framework-python> -m unittest` mit den sieben fokussierten MRTS-Modulen | 0 | 85 Tests einschließlich 18 neuer Regressionen bestanden | `<task-root>/evidence/integrated-regressions.log` |
| `rtk bypass <Framework-python> ci/checks/catalog/check-mrts-importer.py` | 0 | Vier Fixture-Fälle bestanden | `<task-root>/evidence/importer-fixtures.log` |
| `rtk bypass <Framework-python> -m py_compile` für sechs geänderte Python-Dateien | 0 | Kompilierung bestanden | Externer Befehlsrecord |
| `rtk bypass sh -n ci/lib/mrts-common.sh ci/provisioning/generate-mrts.sh ci/provisioning/write-mrts-load.sh` | 0 | Shellsyntax bestanden | Externer Befehlsrecord |
| `rtk bypass gitleaks dir --redact=100` | 0 | Keine Leaks vor Inspektion oder nach Quelländerungen | `<task-root>/evidence/final-source-secrets.json` |
| `rtk bypass /usr/local/bin/sonar-with-env analyze` für die drei geänderten Helper | 1 | Lokale agentische Analyse nicht verfügbar: Dienst lieferte 403; alle drei Dateien übersprungen | `<task-root>/evidence/local-sonar.json` |

## Sicherheitsauswirkung

Fixtures zum ursprünglichen Pfad bestätigen Ergebnis-Read-/Write-Ausbrüche und
das Timeout der Fehlerliste. Aktuelle Positiv- und Umgehungstests weisen fremde
Geschwisterpfade, lexikalisches Traversal, Symlink-Vorfahren/-Blätter,
FIFO-/übergroße Eingaben, unsichere Laufzeitroots und fremde Framework-Roots ab,
während gültige Pakete und beobachtete Ergebnisse erhalten bleiben. Die
unabhängige Prüfung fand Venv-Präfixverlust und einen Manifest-Read vor der
Blattprüfung; beide wurden korrigiert und mit Regressionen geprüft. Keine
Validierung, Authentifizierung, Isolation, Scannerregel oder Gate wird geschwächt.

## Dokumentation und Runtime-Evidenz

`docs/mrts-preparation.md` und die deutsche Begleitdatei erläutern
Root-Autorisierung, feste Prozesseinstiege und den vertrauenswürdigen
`BUILD_ROOT`-Export des eigenständigen Writers. Bestehende H1-Evidenz bleibt
historisch; diese Korrektur ergänzt deterministische Paket-/Ergebnis-Fixtures
und behauptet keine neue Host-Laufzeitqualifikation.

## Nicht ausgeführte Prüfungen

Keine historische Protokoll-/MRTS-Matrix, neuer Hostlauf, Coverage-Kampagne oder
Abhängigkeitsaudit: Sie liegen außerhalb der begrenzten Helper-Korrekturen.
Lokale agentische Sonar-Analyse ist auf dieser Verbindung nicht verfügbar;
die gehostete PR-Analyse ist die erforderliche Quelle des abschließenden
Quality Gates. Erforderliche gehostete Checks stehen nach dem Push aus.

## Einschränkungen und Restrisiko

Vertrauenswürdige Änderungen derselben UID liegen außerhalb von
Prozessisolation. Vorbereitung und Manifestprüfung beweisen kein
Connector-Laufzeitverhalten. Bestehende optionale Demo-Kollisionen und
ausstehende Upstream-Klassifikationen bleiben sichtbar. Framework-Pin-Änderung
oder Merge dieses PRs benötigen eine separat autorisierte Aktion.

## Finaler Diff- und Review-Status

Paket-/Ergebnisänderungen erhielten unabhängige Grenzprüfung. Fokussierte lokale
Checks bestanden wie oben erfasst. Finale Dokumentation, Staging-Diff,
Whitespace-, Commitbereich-Secretsprüfung und aktuelle gehostete
Auslieferungsevidenz werden im Auslieferungszyklus abgeschlossen; hier wird
kein gehostetes PASS oder Merge behauptet.
