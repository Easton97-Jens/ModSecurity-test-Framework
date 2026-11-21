# Change Record

**Sprache:** [English](20261121-01-canonical-go-tool-pins.md) | Deutsch

**Validierungs-Snapshot vor Veröffentlichung.** Dieser Record hält die umgesetzten kanonischen Pins und die beobachteten lokalen Prüfungen fest. Es wird kein erfolgreicher gehosteter CI-Lauf, kein Merge und keine Änderung des Parent-Pins behauptet.

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261121-01-canonical-go-tool-pins |
| UTC-Datum | 2026-11-21 |
| Framework-Basisrevision | `95f228936efe17fda24f21323ad87cd698940b48` |
| Issue oder Pull Request | Aufgabenbranch `claude/go-tool-pins-20261121`; Draft-Pull-Request nach diesem Snapshot eröffnet. |

## Motivation und Problemstellung

`ci/lib/common.sh` ist die kanonische Quelle für jeden geprüften CI-Pin; `actionlint`, `zizmor`, `gitleaks` und die übrigen Release-Asset-Werkzeuge sind dort bereits als `CI_SECURITY_TOOL_*` gepinnt. Die Go-Analysewerkzeuge `staticcheck` und `govulncheck` hatten keinen kanonischen Pin, daher führte der Parent einen eigenen Lock dafür. Sie können das Schema `CI_SECURITY_TOOL_*` nicht nutzen, weil sie kein Release-Asset und keine SHA-256 haben; diese Gruppenprüfung lehnt unbekannte oder unvollständige Felder bewusst ab.

## Betroffene Komponenten und Sicherheitsgrenzen

Nur die kanonische Pin-Quelle, ihr Leser und die Versionsprüfung ändern sich. Kein Workflow, keine generierte Lock-Ansicht, kein Runner, kein Fetcher und keine Parent-Datei ändert sich. Der neue Leser parst `common.sh` mit den bestehenden Regeln für vertrauenswürdige Pfade und Dekodierung und führt die Datei nie aus.

## Akzeptanzkriterien

Beide Go-Werkzeuge in `common.sh` über exaktes Modul, Paket, Release-Version und `h1:`-Modulsumme pinnen. Einen Leser bereitstellen, der sie nach Executable geordnet liefert und unvollständige Gruppen, Versionsbereiche, fremde Paketpfade, Shell-Ausdrücke, Duplikate sowie Gruppen ohne passenden Executable-Namen zurückweist. In `check-common-versions.py --validate-canonical` dieselbe Gruppenform und Komponentenzuordnung wie für die übrigen kanonischen CI-Pins erzwingen. `load_canonical_ci_pins()` und alle bestehenden Verbraucher unverändert lassen.

## Untersuchte Alternativen

Eine Wiederverwendung von `CI_SECURITY_TOOL_*` hätte Platzhalter-Asset-Felder oder eine Abschwächung der strikten Gruppenprüfung erfordert. Eine Erweiterung von `load_canonical_ci_pins()` hätte die neuen Schlüssel an dessen viele bestehende Verbraucher weitergegeben. Eine separate Lock-Datei hätte eine zweite Quelle der Wahrheit außerhalb von `common.sh` erhalten.

## Implementierungsentscheidung

`common.sh` erhält die Gruppen `CI_GO_TOOL_STATICCHECK_*` und `CI_GO_TOOL_GOVULNCHECK_*` (`MODULE`, `PACKAGE`, `VERSION`, `MODULE_SUM`) samt Export-Zeile. `common_canonical_pins.py` erhält `load_canonical_go_tools()`. `check-common-versions.py` erkennt die vier Felder über ein eigenes Namensmuster `CI_GO_TOOL_*`, ergänzt die Gruppe `go tool` mit ihren Pflichtfeldern und ordnet die Variablen der Komponente der kanonischen CI-Pins zu.

## Geänderte Dateien und Tests

- `ci/lib/common.sh`: zwei kanonische Go-Werkzeuggruppen und ihr Export.
- `ci/tools/common_canonical_pins.py`: `load_canonical_go_tools()`.
- `ci/tools/check-common-versions.py`: Erkennung der Go-Werkzeugfelder, Gruppenform und Zuordnung.
- `tests/ci_security/test_common_canonical_pins.py`: acht neue Tests (Leserergebnis, unvollständige Gruppe, Versionsbereich und fremdes Paket, Shell-Ausdruck und Duplikat, Executable-Benennung, Repository-Pins, Inventarform und Zuordnung, Meldung unvollständiger Gruppen).
- `docs/security/ci-security-tooling.md`, `docs/security/ci-security-tooling.de.md`: neuer Abschnitt zu Go-Werkzeug-Pins.
- `connector_suite/config/testing/active-cases.json`: Quell-Digest von `common.sh` über `update-inventory-bindings.py --apply` aktualisiert; Auswahl der Ausführungen unverändert.
- `connector_suite/reports/testing/test-selection-archive.generated.json`: über `update-test-archive.py` neu erzeugt; On-Demand-Definitionen 8476 auf 8484 (die acht neuen Tests), neuer `inventory_sha256` und Quell-Digest der Testdatei.
- `reports/audits/change-records/20261121-01-canonical-go-tool-pins.md` und `reports/audits/change-records/20261121-01-canonical-go-tool-pins.de.md`.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder freigegebener Evidence-Pfad |
| --- | --- | --- | --- |
| `check-common-versions.py --validate-canonical` nach Ergänzung nur der `common.sh`-Gruppen | 1 | `incomplete go tool group …; missing: MODULE, MODULE_SUM, PACKAGE` (Felder noch nicht erkannt) | Lokale Framework-Validierung |
| `make check-canonical-common-pins` | 0 | `canonical common.sh pins: PASS` | `fwgo-20261121T093506Z` |
| `make test-canonical-pin-sync` | 0 | Python- und Workflow-Pin-Ansichten unverändert | `fwgo-20261121T093506Z` |
| `python -m unittest tests.ci_security.test_common_canonical_pins` | 0 | 13 Tests, davon 8 neu | `fwgo-20261121T093506Z` |
| `python -m unittest tests.ci_security.test_canonical_maintenance` | 0 | bestanden | `fwgo-20261121T093506Z` |
| `make test-ci-security-contract` | 0 | 421 Tests in etwa 300 s bestanden | `fwgo-20261121T093506Z` |
| `check-common-versions.py --check`, vor und nach der Änderung | 2 / 2 | identische Upstream-Review-Statuszeilen; kein neuer Befund | `fwgo-20261121T093506Z` |
| Gehostetes `scaffold-lint` am ersten PR-Head, lokal mit `update-inventory-bindings.py --check` reproduziert | 1 | `SOURCE_DIGEST_DRIFT …/ci/lib/common.sh`, `INVENTORY_BINDINGS_DRIFT`; Archivprüfung ebenfalls veraltet | PR #182 Lauf `44915812649` |
| `update-inventory-bindings.py --apply`, `update-test-archive.py`, danach beide mit `--check` | 0 | `INVENTORY_BINDINGS_VERIFIED`; Archiv passt zu Inventar und Quellen | `fwgo-20261121T093506Z` |
| Parent `make security-tools` mit denselben Pins (Helper aus Parent-PR #456) | 0 | `staticcheck 2026.2.2 (0.8.2)` und `govulncheck v1.10.0` mit Go 1.27.4 gebaut; Modulsumme und Build-Informationen geprüft | Parent-Lauf `pyenv-20261119T191308Z` |

Die Prüfungen nutzten die Framework-eigene virtuelle Umgebung mit Python `3.15.2`.

## Sicherheitsauswirkung

Die Go-Werkzeuge erhalten einen exakten, geprüften kanonischen Pin mit inhaltsadressierter Modulsumme; im Framework ändert sich kein Installationspfad, kein Download, keine Anmeldeinformation und keine Berechtigung. Die Zurückweisung von Bereichen, fremden Paketen und Shell-Ausdrücken hält den Leser so streng wie den bestehenden Parser für kanonische Pins.

## Dokumentation und Runtime-Evidenz

Das englisch-deutsche Record-Paar und der gepaarte Abschnitt zum Security-Tooling dokumentieren denselben Umfang. Es wird keine Runtime-Evidenz erhoben oder beansprucht.

## Nicht ausgeführte Prüfungen

Gehostete Framework-CI, das vollständige `lint`-Aggregat und eine Nutzung dieser Pins durch den Parent über eine Gitlink-Aktualisierung wurden für diesen Snapshot nicht ausgeführt.

## Einschränkungen und Restrisiko

Das Framework pinnt die Go-Werkzeuge, baut sie aber nicht; Verbraucher bauen sie mit ihrer eigenen gepinnten Go-Toolchain. Eine spätere Aktualisierung folgt dem bestehenden manuellen Review kanonischer CI-Pins.

## Finaler Diff- und Review-Status

Lokaler Snapshot vor Veröffentlichung; unabhängiges Review ausstehend.
