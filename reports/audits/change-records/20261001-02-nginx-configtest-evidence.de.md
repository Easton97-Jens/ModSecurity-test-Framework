# Change Record: begrenzte NGINX-Konfigurationstest-Evidence

**Sprache:** [English](20261001-02-nginx-configtest-evidence.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20261001-02-nginx-configtest-evidence` |
| UTC-Datum | `2026-10-01` |
| Framework-Basisrevision | `896e4bd71fa3b1a07dd0109e2e8c7b7991d40d19` |
| Issue oder Pull Request | Lokaler Framework-Teil; externer Parent-PR #396 bleibt Draft |

## Motivation und Problemstellung

Der ausgewählte Phase-0-Pflichtrecord `invalid_boolean` hatte keine konkrete
NGINX-Konfigurationsoperation. Seine öffentliche Erwartung bildete
`config_rejected` als Event ab. Parserannahme/-ablehnung ist weder HTTP noch
Rule-/Event-Alias; behauptete Exits allein beweisen keine Ausführung.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework besitzt Katalog, öffentliche API, kanonische Normalisierung und
Validierung. Echte Parent-Host-Ausführung und Collector sind separate externe
Abhängigkeiten. MRTS, Connector-Source, Common-Events und Parent-Gitlinks bleiben unverändert.

## Akzeptanzkriterien

Nur der explizite NGINX-`configtest` für `modsecurity maybe;` nutzt diesen
Vertrag. PASS verlangt exakt Exit `1`, `invalid_boolean`, beide Diagnosen,
Case-/Run-/Source-/Komponentenidentität und das autorisierte Fünf-Dateien-Bundle.
Fehlende, fremde, verlinkte oder veränderte Artefakte scheitern. Negative
Ausführungsfehler bleiben Fehlerevidence, niemals PASS; HTTP-Cases bleiben strikt.

## Untersuchte Alternativen

Synthetische Events, geliehenes HTTP 200, pauschaler Nichtnull-Exit-PASS,
ausgeschlossene Pflichtrecords oder vertrauensbasierte Receipt-Behauptungen
würden die Lücke verbergen.

## Implementierungsentscheidung

Nur die konkrete NGINX-Realisierung deklarieren. Auswahl/Anwendbarkeit und
weitere Erwartungen bleiben erhalten. Finalisierung gewinnt Authority aus dem
Parent-Verzeichnis der expliziten Quelldatei und bewahrt `nginx-binary`,
`nginx-module.so`, `nginx.conf`, `stdout.log`, `stderr.log` sicher unter
`inventory/configtests/invalid_boolean` auf. Dateien erneut hashen und das
geschlossene nichtgeheime Template sowie exakte erfasste Diagnose prüfen.
Config-only-Evidence benötigt kein HTTP/native Event und behauptet weder
Daemonstart, Listener, Worker, Reload noch Request. Der öffentliche Typ
`configuration` prüft begrenzte Beobachtungen, keine echte Ausführung. Die
globale Full-Lifecycle-PASS-Prüfung bleibt unverändert.

## Geänderte Dateien und Tests

- `ci/checks/catalog/no_crs_baseline.py`, Katalog, Case-Result- und Configtest-Receipt-Schemas.
- Vier Module `tests/no_crs/test_configtest_*` für Receipts, Artefakte, negative Exits und Runtime-Fakten.
- `modsecurity_test_framework/contracts.py`, öffentlicher Kataloggenerator/-ressource und API-Tests.
- Gepaarter Testing-Guide, dieser Record und Archivindizes.

## Befehle und Ergebnisse

Alle Shell-Befehle verwendeten RTK und externe Temp-/Cache-/Log-Roots.
Öffentliche Tests reproduzierten den unbekannten Tagged-Typ und Event-only-
Generierung; Artefakt- und Signed-Exit-Regressionen waren vor den jeweiligen
Korrekturen rot.
Auch FIFO- und explizite Manifest-Host-Regressionen waren vor der Korrektur rot.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk proxy` mit `make test-contract-api` | `0` | 23 Tests und Katalogprüfung bestanden | Externes Analyselog `config-public-api-suite.log` |
| `rtk proxy` mit fokussierter Configtest-Unittest-Discovery | `0` | 27 Tests in 3.144 s bestanden, einschließlich FIFO-/Manifest-Host-/Bounded-Copy-Kontrollen | Externes Analyselog `config-all-focus.log` |
| `rtk proxy` mit Signed-Exit-Unittest-Modul | `0` | 3 Tests mit gültiger Artefakt-Authority bestanden; exakter Exit-Mismatch, kein fehlender Nachweis | Externes Analyselog `config-exit-authority-focus.log` |
| `rtk proxy` mit `make test-no-crs-contract` | `0` | 159 Tests in 112.402 s bestanden | Externes Analyselog `framework-configtest-frozen-no-crs-20261001.log` und `.exit` |
| `rtk proxy` mit `make lint` | `0` | Vollständiger Framework-Lint erfolgreich abgeschlossen | Externes Analyselog `framework-configtest-final-lint-20261001.log` und `.exit` |
| `rtk proxy` mit `make check-documentation` | `0` | Links, zweisprachige Variablen, Repository-Pfade und Change Records bestanden | Externes Analyselog `framework-configtest-docs.log` |
| `rtk proxy` mit `git diff --check` | `0` | Whitespace-Prüfung vor Dokumentationsübergabe bestanden | Lokaler Framework-Worktree |

## Sicherheitsauswirkung

Keine Validatorabschwächung, synthetische Runtime-Evidence, nativen Events,
Payloads, Secrets oder globalen Pfadfreigaben. Negative Kontrollen umfassen
falsche Exits, Directives/Diagnosen, fremde Identitäten, veränderte Dateien und Symlinks.

## Dokumentation und Runtime-Evidenz

Testing-Guide und Record haben inhaltsgleiche EN/DE-Companions. Unit-/Public-
Contract-Prüfungen sind von der separat beobachteten Retained-Build-Diagnose
`nginx-configtest-retained-jaYdBrvH` getrennt. Ihre echten NGINX-Binary-/Modul-
Aufrufe durchliefen den echten Parent-Collector und kanonischen Framework-Finalizer.
Der positive kanonische Record `invalid_boolean` ist PASS; die Wrong-Module-
Kontrolle ist FAIL, obwohl beide echten Prozess-Exits `1` waren. Alle fünf
aufbewahrten Dateien wurden erneut gehasht, die verwaltete Layoutprüfung hatte
null Fehler, und der externe Diagnosechecker hatte Exit `0`
(`nginx-configtest-retained-check-20261001.json`). Keine Events oder HTTP-
Requests wurden erzeugt; Daemonstart-/Listener-Fakten bleiben falsch. Source-
und kanonische Aggregate bleiben FAIL, weil Required-Requests nicht ausgeführt
wurden. Dies beweist nur eine Retained-Build-Diagnose-Konfigurationsausführung,
keinen neuen Exact-Head-Full-Lifecycle-PASS.

## Nicht ausgeführte Prüfungen

Kein Full-E2E, Remote-CI, Push, PR-Eingriff, Merge oder Parent-Gitlink-Update.
Optionales Ruff war nicht verfügbar; kein Paket wurde installiert.

## Einschränkungen und Restrisiko

Die weiteren neun konfigurationsbezogenen Pflichtrecords bleiben unimplementiert.
Auswahl-/Required-Scope wird nicht reduziert. Protokoll-, Fault-, Startup- und
Reload-Pflichten erfüllt dieser Configtest nicht. Globale Promotion verlangt
weiterhin sämtliche ausgewählten Pflichtcases und echte Lifecycle-Evidence.

## Finaler Diff- und Review-Status

Am ursprünglichen Übergabepunkt waren die Framework-Änderungen uncommittet;
finale begrenzte Diffprüfung und lokaler Commit standen noch aus. Diese lokale
Übergabe wurde anschließend als
`c4f53e1` (`fix(no-crs): require retained nginx configtest receipts`) committet.
Die obigen Befehle, neun verbleibenden Konfigurationsrecords und Runtime-
Beobachtungen beschreiben diesen historischen Stand; der spätere
[Size-Configtest-Record](20261003-01-nginx-size-configtest.de.md) dokumentiert
seine eigene Folgeänderung. Fokus-, No-CRS-, vollständige Lint- und
Dokumentationsprüfungen bestanden am ursprünglichen Punkt; eine unabhängige
Prüfung fand keinen verpflichtenden Blocker. Dieser Record attestiert keine
Remote-Delivery, Parent-Pointer-Änderung oder globalen Lifecycle-Erfolg.
Sensitive Runtime-Artefakte bleiben außerhalb versionierter Dokumentation.
