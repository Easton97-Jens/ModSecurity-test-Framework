# Automatische Update-PRs für ModSecurity-v3-Releases vorbereiten

**Sprache:** [English](20260930-01-automate-modsecurity-v3-release-prs.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260930-01-automate-modsecurity-v3-release-prs |
| Zugehöriges Issue / PR | #129 / #131 |
| Status | Implementierungsentwurf; nicht für Integration oder Runtime-Nutzung verifiziert |
| Basisrevision | `5cd7a7f96811b6d3021ce3c1e36bbc5d308806fb` |
| Commit der Kernimplementierung | `6b8f698cf1a8e83767b3cfd45b53da3c9b18e289` |
| Ausgangsstand der CI-Korrektur | `4e0173618fd543b57d5bf79bd9002e533107b346` |

## Motivation und Problemstellung

Issue #129 meldet den ModSecurity-v3-Releasewechsel von `v3.0.16` auf
`v3.0.17` als manuelle Provenienzprüfung. Der bestehende Wartungsworkflow
ermittelt bereits Abhängigkeitskandidaten und veröffentlicht Update-PRs.
Der ModSecurity-v3-Descriptor und sein spezialisierter Resolver wählen
jedoch noch den manuellen Pfad. Dieser Entwurf veröffentlicht die zuvor
vorbereitete Kernänderung zur Prüfung.

Der erste PR-Lint-Lauf scheiterte daran, dass beide neuen Change Records
eigene Überschriften und eine Identität als Aufzählung statt der geforderten
Vorlage mit tabellarischer Change-ID verwendeten. Korrigiert werden die
Dokumente, nicht der prüfende Validator.

## Betroffene Komponenten und Sicherheitsgrenzen

Ausschließlich Framework: der Common-Version-Resolver für ModSecurity v3 und
dieser gepaarte Change Record. Keine Änderungen an Parent- oder MRTS-Dateien.
Parent-Gitlink-Disposition: `unchanged`; MRTS-Auswirkung: `default_read_only`.
Dieser PR autorisiert weder Auto-Merge noch direkte `master`-Updates oder
Änderungen am Branch-Schutz.

## Akzeptanzkriterien

- [x] Kernpatch ohne Änderung der Release-Pins im bestehenden Aufgabenbranch veröffentlichen.
- [x] Vorgeschriebene Überschriften, tabellarische Identität und gegenseitige Sprachlinks verwenden.
- [x] Change-Record-Fehler reproduzieren und korrigiertes Paar mit unverändertem Checker und seinen vier Tests in einem isolierten Snapshot prüfen.
- [ ] Die nachstehenden Implementierungs-, Dokumentations- und Validierungsarbeiten abschließen.

- Vorhandene rein manuelle ModSecurity-Testfixtures und Erwartungen anpassen
  und die verbleibende Klassifizierung in `MANUAL_REVIEW_VARIABLES` prüfen.
- Automatische Kandidatenerstellung und einen anschließend aktuellen
  Zustand, atomare Tag/Commit-Updates, annotierte und einfache Tags,
  verschobene Tags, ungültige Repositories, Alias-Abweichungen, Prereleases
  und Releases außerhalb von v3 prüfen.
- Anwendung des kanonischen Plans, Konsistenz generierter Ansichten und
  Review-Issue-Abgleich ohne vorzeitigen Issue-Abschluss verifizieren.
- Die gepaarten Variablenreferenz- und Workflow-Sicherheitsdokumente aktualisieren.
- Betroffene Regressionstests ausführen und erforderliche Runtime-/Smoke-
  Evidenz erheben, bevor die Implementierung als integrationsbereit gilt.

## Untersuchte Alternativen

Die rein manuelle Klassifizierung erfüllt das gewünschte Automatisierungsziel
nicht. Entfernte Provenienzprüfungen oder Auto-Merge würden andere
Sicherheitsgrenzen verändern. Ein abgeschwächter Change-Record-Validator oder
eine zusätzliche Legacy-Ausnahme würde den Dokumentationsfehler verdecken;
beides wird nicht umgesetzt.

## Implementierungsentscheidung

In `ci/tools/check-common-versions.py` werden vier Zeilen geändert:
Update-Policy, Kompatibilitätsbeschreibung, Resolver-Docstring und der
Aufruf von `check_manual_git_provenance` zu
`check_automatic_git_provenance`. Diese Änderung hebt keinen Release-Pin an.

Das erlaubte Releaseformat bleibt `v3.x.y`, einschließlich stabiler
Minor-Releases innerhalb von v3, nicht nur Patch-Releases von v3.0.
Andere Hauptversionen werden nicht zur automatischen Anwendung ausgewählt.
Der feste Upstream-Repository-Hash, die aktuelle Tag/Commit-Prüfung, der
Resolver für vollständig aufgelöste Commits, Alias-Prüfungen und die atomare
Tag/Commit-Gruppe bleiben unverändert. Diese Provenienzprüfungen belegen
weder Connector-Kompatibilität noch die Sicherheit eines Upstream-Releases.

Die CI-Korrektur ordnet ausschließlich dieses englisch/deutsche Record-Paar
in die bestehenden dreizehn Pflichtabschnitte ein und stellt die Identität
tabellarisch dar.

## Geänderte Dateien und Tests

Der Kernpatch ändert `ci/tools/check-common-versions.py`. Die CI-Korrektur
ändert ausschließlich diesen deutschen Change Record und sein englisches Gegenstück. Die
Repository-Dateien `ci/checks/documentation/check-change-records.py` und
`tests/ci_security/test_change_record_contract.py` werden unverändert ausgeführt.
Diese Korrektur ändert weder Tests noch Validatoren, Workflows oder generierte
Ansichten.

## Befehle und Ergebnisse

CI-Evidenz am Ausgangsstand der Korrektur:
[Lint-Lauf 36700420156](https://github.com/Easton97-Jens/ModSecurity-test-Framework/actions/runs/36700420156),
Job `scaffold-lint`, führte `./ci/tools/safe-make.sh lint` aus und endete mit
Exit-Code 2. Die CI-Security-Suite führte 308 Tests mit einem Fehler aus:
`test_checked_in_change_records_pass`. Gemeldet wurden ungültige Überschriften
und das Change-ID-Format in beiden Sprachdateien. Sechs weitere PR-Workflows,
darunter `test-common` und CodeQL, waren an diesem Ausgangsstand erfolgreich.

Lokal wurden folgende Befehle mit Python 3.13.5 in einem isolierten Snapshot
aus diesem Record-Paar, dem unveränderten Checker und dessen unverändertem
Testmodul ausgeführt:

- `python3 -m unittest discover -s tests/ci_security -p 'test_change_record_contract.py' -v`: vor der Korrektur 4 Tests, 1 Fehler, Exit-Code 1; danach 4 Tests erfolgreich, Exit-Code 0.
- `python3 ci/checks/documentation/check-change-records.py`: korrigiertes Paar erfolgreich geprüft, Exit-Code 0.

Die Git-Blob-Hashes von Checker und Testmodul stimmten mit den abgerufenen
Quellen überein (`d1e5e4a5831670d112d272fbdb0ca100f547cc49` und
`e41e96e3673b4e2d8b7a9ba95842e0d4c97c43b2`). Dies ist begrenzte Evidenz für den
Dokumentationsvertrag, kein vollständiger Lint-Lauf und keine Runtime-Evidenz.
Das vollständige CI-Ergebnis des korrigierten Heads muss separat abgerufen
werden; ein noch laufender Check wird nicht als PASS bezeichnet.

## Sicherheitsauswirkung

Automatisierte Provenienzprüfungen ersetzen die rein manuelle
Kandidatenklassifizierung; sie sind keine menschliche Prüfung von
Migrationshinweisen. Bestehende Sicherheitsprüfungen bleiben erhalten,
aber die Verhaltensänderung bleibt bis zum Abschluss der offenen Tests
und Dokumentationsarbeiten unverifiziert. Die Änderung enthält keine
Secrets, Tokens, privaten Payloads oder Runtime-Logs.

## Dokumentation und Runtime-Evidenz

Die gepaarten Change Records entsprechen nun der bestehenden Repository-Vorlage.
Die Aktualisierung der Variablenreferenz und Workflow-Sicherheitsdokumentation
steht weiterhin aus. Generierte Ausgaben bleiben unverändert, da dieser PR
keinen Release-Pin anhebt. Keine Runtime-/Smoke-Evidenz und keine Aussage über
Connector-Promotion.

## Nicht ausgeführte Prüfungen

Vollständiger Lint-Lauf und komplette Regressionstests wurden nicht lokal
ausgeführt: Der Clone scheiterte an der DNS-Auflösung von `github.com`; die
vorgesehene Python-3.14.7-Umgebung und RTK waren nicht verfügbar. Die begrenzten
lokalen Dokumentationsprüfungen ersetzen GitHub CI nicht. Runtime-/Smoke-Tests
und die Ende-zu-Ende-Validierung des kanonischen Plans stehen noch aus.

## Einschränkungen und Restrisiko

Der Kernpatch für die Automatisierung bleibt ein Entwurf. Vorhandene manuelle
ModSecurity-Fixtures und `MANUAL_REVIEW_VARIABLES` müssen weiterhin geprüft
werden. Ein erfolgreicher Change-Record-Vertrag belegt weder
Release-Kompatibilität noch vollständige Automatisierungsabdeckung oder
Integrationsbereitschaft. Issue #129 bleibt offen; die Release-Pins sind
unverändert.

## Finaler Diff- und Review-Status

Der zurückgelesene Kerncommit enthielt genau vier vorgesehene
Zeilenersetzungen. Die CI-Korrektur beschränkt sich auf die gepaarten Change
Records; weder Implementierung noch Prüfungen werden abgeschwächt. Die
Auslieferung bleibt der bestehende Draft-PR #131 im Branch
`codex/issue-129-automatic-modsecurity-v3`. Kein Merge, Parent-Gitlink-Update
oder MRTS-Eingriff.
