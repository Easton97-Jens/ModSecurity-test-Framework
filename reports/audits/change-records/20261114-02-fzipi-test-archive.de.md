# Änderungsnachweis: Adoptionsprüfungen angleichen und Testarchiv neu erzeugen

**Sprache:** Deutsch | [English](20261114-02-fzipi-test-archive.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change ID | 20261114-02-fzipi-test-archive |
| UTC-Datum | 2026-11-14 |
| Framework-Basisrevision | `2cc331d8bc4c86592afd7219ddeaba1e60dc0ced` |
| Issue oder Pull Request | Separate Framework-Auslieferung ausstehend |

## Motivation und Problemstellung

Das native Connector-Inventaraggregat verwarf sein veraltetes Archiv erhaltener
Definitionen. Nach der Neugenerierung zeigte der vollständige `quick-check` zwei
veraltete Adoptionsverträge: Apache verlangte weiterhin eine künstliche
`SIZE_MAX`-Auslieferungsgrenze; HAProxy erwartete den Regel-ID-Decoder im früheren
Collector statt im ausgelagerten Detailhelfer. Die HAProxy-Mutationsfixtures
übernahmen außerdem den echten Checkout-Kontext statt ihres veränderten Testrepos.
Ein späterer Gesamtlauf zeigte außerdem eine falsche Common-Pfadannahme:
Vier über die Quellzuordnung ausgewählte Framework-Dateien wurden relativ zu Parent berechnet.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-eigene statische Apache-/HAProxy-Prüfer, der Common-Sicherheitsprüfer, ihre vier Testmodule,
das generierte Archiv und dieses EN/DE-Paar ändern sich. Parent-Produktquellen,
aktives Inventar, Selektoren, Generatoren, CI-Prüfungen und MRTS bleiben unverändert.
Das automatische Inventar enthält weiterhin genau 100 Fälle. Dies belegt keine
zusätzliche Host-Unterstützung.

## Akzeptanzkriterien

Tatsächliche sättigende Beobachtung und geprüfte native Aufrufpfade akzeptieren;
Mutationen von Zählern, Pointern, nativen Ergebnissen, Cleanup und Entscheidungsresets
abweisen; Fixtures an ihre exakte isolierte Git-Revision binden; Archiv kanonisch
neu erzeugen; native Aggregate und Dokumentation vor Auslieferung prüfen.

## Untersuchte Alternativen

Die Antwortgrenze `SIZE_MAX` wiederherzustellen widerspräche der Produktvorgabe.
Bloße Tokenprüfungen erkennen toten Code und Resets nicht. Eine manuelle
Archiv-Hashkorrektur würde veraltete Quell-/Definitionsprojektionen übergehen.
Die vorhandenen nativen Prüfungen bleiben erhalten.

## Implementierungsentscheidung

Apache ersetzt nur den veralteten Antwortgrenzen-Operanden durch einen strikten
Vergleich des vollständigen, kommentarmaskierten Helferkörpers. Beide sättigenden
Zähler, Daten-/Invariantenprüfungen, vollständiger nativer Append und Intervention
müssen im tatsächlichen Pfad bleiben. Alle übrigen Prädikate, Meldungen, ihre
Reihenfolge und Request-Arithmetikprüfungen bleiben erhalten. Der geprüfte
normalisierte AST-Anker wird ausdrücklich aktualisiert. Negative Mutationen
prüfen ungesicherte/verlustbehaftete Zähler, geänderte Guards sowie fremde,
kommentierte und tote Scheinpfade.

HAProxy erhält den exakten begrenzten Decoder und prüft vollständige Collector-
und Detailkörper: positiver nativer Rückgabewert, tatsächliche Intervention,
Aktions-/Statusklassifizierung und Cleanup. Mutationen weisen `init_decision`,
`memset`, direkte Regel-ID-Schreibzugriffe, frühe Rückkehr und umgangene Umsetzung
nach dem Decodieren ab. Beide Fixturemodule verwenden das vorhandene gebundene
`fixture_environment` und den erforderlichen Marker `common/include`. Dies sind
strikte statische Quellverträge, kein allgemeiner C-Erreichbarkeitsbeweis oder
Host-Laufzeitnachweis.

Der Common-Sicherheitsprüfer erhält die vollständige physische Scanliste und alle
Sicherheitsprädikate. Logische Common-IDs begleiten die ausgewählten physischen
Pfade; die Host-API-Include-Ausnahme gilt weiterhin nur für `common/runtime`. Vier
Regressionen für getrennte Eigentümer weisen verbotene Includes/Aufrufe in beiden
Bereichen ab und reproduzieren den ursprünglichen ValueError mit altem Operanden.
Das vollständige Modul mit 11 Tests und das echte native Sicherheitsziel bestehen.
Keine Datei wird wegen Framework-Eigentums übersprungen.

Nach Einfrieren aller Quellen den vorhandenen Archivgenerator ohne `--check`
ausführen. Gegenüber der Basis: Definitionen 8096 → 8211, Quellen 643 → 648;
keine Entfernung oder Änderung ausgewählter Definitionen; 30 bestehende
Quelleinträge aktualisieren ihre Projektionen. Neun native Quellhashes ändern
sich bei unveränderter Anzahl 88. Inventar-Digest:
`bf346309d75aaf0aa15c0c5939b35b2caed38754f6180ac9fd5c051485be632c`.
Alle anderen Felder der obersten Ebene bleiben identisch. Vollständige Werte
liegen extern in `semantic-delta-integrated.json`. Neuer Archiv-SHA-256:
`4cf2c73b5aee0d163c4f7bb4d2a049ae643caa7907da240819728709abea3b24`.
Der Quellenbindungsprüfer meldet VERIFIED; das aktive Inventar braucht keine Änderung.

## Geänderte Dateien und Tests

Zwei Adoptionsprüfer, Common-Sicherheitsprüfer,
`test_event_runtime_security_contract.py`, `test_apache_common_adoption.py`,
`test_haproxy_adoption_rule_id.py`, `test_haproxy_common_adoption.py`, das generierte
`connector_suite/reports/testing/test-selection-archive.generated.json` und dieses
Nachweispaar. Testort bleibt `connector_suite/modsecurity_connector_tests/`.
Keine Produkt-, Generator-, Extraktionsmanifest-, Selektor- oder MRTS-Änderung.

## Befehle und Ergebnisse

`$PYTHON` ist das Framework-eigene `$VIRTUAL_ENV/bin/python`.
`$R` ist `$CODEX_TEMP_ROOT/runs/20261114-fzipi-review/framework-archive-remediation`;
`$F` und `$P` sind die Framework-/Parent-Arbeitsverzeichnisse unter
`$CODEX_TEMP_ROOT/worktrees/`. Externe Parent-Revision:
`b1017969f766209eb9401820a4aca01d71180636`.
Der tatsächliche Orchestrierungseinstieg ist `rtk bypass python3`, danach
`rtk bypass bash -c` mit `$R/context.sh`, danach die folgenden RTK-Kindbefehle.
Der Kontext setzt explizite Framework-/Connector-Pfade, exakte Parent-Revision,
Profil `h1`, externe Ausgabe-/Build-/Temp-/Logpfade und Framework-PYTHONPATH;
`ON_DEMAND_TESTS` ist für native Standardprüfungen ungesetzt, für gezielte Module `1`.

| Kindbefehl oder beobachtete Prüfung | Exit | Ergebnis / Nachweis |
| --- | --- | --- |
| Natives Inventaraggregat / Archiv `--check`, vor Korrektur | 2 / 1 | Veraltetes Archiv reproduziert |
| Gezielte Apache-Common-/Native-Adoptionsmodule | 0 | 36 Tests; extern `framework-apache-contract/focused-tests.log` |
| `rtk bypass "$PYTHON" -m unittest -v modsecurity_connector_tests.test_haproxy_adoption_rule_id modsecurity_connector_tests.test_haproxy_common_adoption` | 0 | 24 Tests; extern `framework-haproxy-contract/focused-final-combined.log` |
| `rtk bypass "$PYTHON" -P connector_suite/modsecurity_connector_ci/tools/update-inventory-bindings.py --check` | 0 | INVENTORY_BINDINGS_VERIFIED; `$R/logs/bindings-final.log` |
| `rtk bypass "$PYTHON" -P connector_suite/modsecurity_connector_ci/tools/update-test-archive.py`, danach `--check` | 0 / 0 | Kanonische Erzeugung / exakte Prüfung |
| `rtk make check-active-inventory` aus `$P` | 0 | Vollständiges Aggregat; `$R/logs/inventory-final.log` |
| Erster vollständiger `rtk make quick-check` nach Prüferkorrektur | 2 | Quellprüfungen bestanden; Apache-Compilerausgabe lag außerhalb beschreibbarer Wurzeln |
| Wiederholung mit `APACHE_C_STANDARDS_OUT=$BUILD_ROOT/apache-c-standards` | 2 | Connector-Adoptions-/C17-Schritte bestanden; Common-Pfadfehler aufgedeckt |
| `rtk make check-common-security-contract` | 0 | Vollständiger nativer Prüfer nach Identitätskorrektur |
| `ON_DEMAND_TESTS=1 rtk bypass "$PYTHON" -m unittest -v modsecurity_connector_tests.test_event_runtime_security_contract` | 0 | Vollständiges Modul: 11 Tests |
| Abschließender `rtk make quick-check` mit externer Apache-Ausgabe | 0 | Vollständiger geordneter Lint-/Quick-check-Pfad; `$R/logs/quick-integrated.log` |
| Übrige 13 Lint-Ziele und sechs Abschlussprüfungen, isolierte Vorprüfung | Je 0 | Extern `remaining-lint-preflight/` und `remaining-lint-tail/` |
| `rtk make check-documentation` / `rtk bypass git diff --check` | 0 / 0 | Beobachtete Vorbereitungsprüfungen; vor Veröffentlichung wiederholt |
| `rtk bypass /usr/local/bin/sonar-with-env analyze secrets --stdin` | 0 | Vollständige gewählte Quellen/Nachweise und gesamtes finales Archiv mit 1602900 Bytes; Logs in begrenzten überlappenden Abschnitten geprüft |

## Sicherheitsauswirkung

Stärkt die Prüfung tatsächlicher Zähler-/Entscheidungspfade und isoliert
Mutationsfixtures korrekt. Keine Regelunterdrückung, Warnungsabschwächung,
Gate-Änderung oder zusätzliche WAF-Ausnahme. Secrets-PASS gilt nur für die
gewählten Eingaben und belegt keine vollständige Codequalität.

## Dokumentation und Runtime-Evidenz

Dieses EN/DE-Paar dokumentiert die Framework-Korrektur. Parent-Prüfungen sind
explizit externe Integrationsnachweise. Kein neuer Host-Laufzeit-, Promotions-
oder Merge-Nachweis beansprucht. Parent-Gitlink bei Vorbereitung: `unchanged`;
anschließende Integration erfolgt separat. MRTS: `default_read_only`;
keine Initialisierung, Aktualisierung oder Checkout.

## Nicht ausgeführte Prüfungen

Neue Host-Laufzeitqualifizierung liegt außerhalb dieser Framework-Vertragskorrektur.
Hosted CI und aktuelles Quality Gate bleiben für die separate PR-Auslieferung
verpflichtend. Keine Pakete oder Toolchains installiert.

## Einschränkungen und Restrisiko

Das Archiv beschreibt Verfügbarkeit; 8211 Definitionen sind keine 8211 ausgeführten
Tests. Exakte Strukturprüfungen weisen ungeprüfte Quellrefactorings bewusst ab und
müssen mit getesteten Produktverträgen weiterentwickelt werden. Native statische
Prüfungen belegen keine vollständige Host-Laufzeitunterstützung. Der erfolgreiche
lokale Lauf verwendete den eingefrorenen Framework-Arbeitsstand auf Basis
`2cc331d8` gegen den externen Parent `b1017969`. PR-CI und aktuelles Quality Gate
bleiben eigenständige Prüfungen.

## Finaler Diff- und Review-Status

Apache-/HAProxy-Diffs und Common-Identitätskorrektur unabhängig geprüft. Gezielte positive
und negative Tests bestanden: 71 gezielte Tests in den betroffenen Modulen und
vollständiger nativer Quick-check. PR-Auslieferung und Parent-Integration bleiben
separate Schritte und werden hier nicht behauptet.
