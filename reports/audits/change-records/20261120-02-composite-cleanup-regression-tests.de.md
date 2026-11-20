# Change Record

**Sprache:** [English](20261120-02-composite-cleanup-regression-tests.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261120-02-composite-cleanup-regression-tests |
| UTC-Datum | 2026-11-20 |
| Framework-Basisrevision | `95f228936efe17fda24f21323ad87cd698940b48` |
| Issue oder Pull Request | Draft-Pull-Request vom Branch `claude/composite-cleanup-regression-tests-20261120`; externe Abhängigkeit: Connector-PR [#454](https://github.com/Easton97-Jens/ModSecurity-conector/pull/454) |

## Motivation und Problemstellung

Connector-PR #454 begrenzt das native Transaktions-Cleanup im
Composite-Coordinator, begrenzt das Warten des Traefik-Companion auf einen
Eintrag, den ein nativer Aufruf noch hält, validiert ForwardAuth-Redirect-Ziele
und korrigiert die `rule_id` im HAProxy-Phase-4-Event. Seine Regressionstests
liefen nur als externe Go-Overlays. Die Testimplementierung gehört dem
Framework (`docs/test-ownership-migration.md` im Connector), daher ergänzt diese
Änderung die Regressionen als erhaltene On-Demand-Framework-Tests.

## Betroffene Komponenten und Sicherheitsgrenzen

- `connector_suite/adapters/envoy/ext_proc/internal/composite/` und
  `.../compositetraefik/`: neue Go-Testquellen (Test-Doubles und Varianten mit
  echter Common-/libmodsecurity-Runtime hinter dem Build-Tag `libmodsecurity`).
- `connector_native_tests/connectors/haproxy/src/haproxy_spop_diagnostic_runtime.inc`:
  ein nativer Selbsttestfall für die `rule_id` im Phase-4-Event.
- `connector_suite/source-map.json`, die beiden geprüften Quell-Hash-Slots
  dieser zwei Framework-Dateien in `connector_suite/config/testing/active-cases.json`
  und das generierte `connector_suite/reports/testing/test-selection-archive.generated.json`.

Die Tests beobachten Fail-closed-, Cleanup-Sicherheits- und Header-Sink-Grenzen
des Connector-Codes; sie ändern keine Sicherheitskontrolle des Frameworks. Aus
ihnen wird kein Connector-Verhalten und keine Fähigkeit abgeleitet.

## Akzeptanzkriterien

- Jeder neue Go-Test wird über die Source-Map aufgelöst und erscheint im neu
  erzeugten Spezialarchiv; das aktive Standardinventar bleibt unverändert.
- Gegen den korrigierten Connector bestehen alle neuen Tests, auch mit `-race`,
  mit libModSecurity v3.0.17 und gebündeltem gepinntem PCRE2 10.49.
- Gegen die unkorrigierten Connector-Revisionen schlagen die Zieltests mit
  ihren spezifischen Meldungen fehl, während die legitimen Kontrollfälle
  bestehen.

## Untersuchte Alternativen

- Tests als aufgabenlokale Overlays belassen: für Reviewer nicht reproduzierbar.
- `*_test.go` im Connector ablegen: vom Eigentumsvertrag ausgeschlossen
  (`product-without-test-infrastructure`).
- Fälle in die aktive Standardsuite aufnehmen: Die Suite ist auf 100 Fälle
  begrenzt; die Tests bleiben ausdrückliche On-Demand-Definitionen.

## Implementierungsentscheidung

Neue Dateien folgen dem bestehenden Paketlayout. Tests, die von den neuen
Connector-APIs (`ClaimContext`, `AbortWithReasonContext`) abhängen, liegen
getrennt in `entry_wait_bounds_test.go`, damit die übrigen Dateien für die
Vorher-/Nachher-Prüfung auch gegen den unkorrigierten Connector kompilieren.
Kanäle synchronisieren das kontrollierte Blockieren; feste Obergrenzen erkennen
unbegrenztes Warten, ohne das Testbinary hängen zu lassen (blockierte Doubles
werden in `t.Cleanup` freigegeben, und Coordinatoren werden nach einem erkannten
Hänger nicht geschlossen). Der HAProxy-Fall serialisiert mit `open_memstream`
in den Speicher und schreibt keine Datei.

## Geänderte Dateien und Tests

| Datei | Abdeckung |
| --- | --- |
| `.../composite/cleanup_bounds_test.go` | Begrenztes direktes Cleanup nach `Open`, wenn vor der Registrierung ein Fault oder Shutdown eintritt (negativ), Kontrollfall mit normalem Close, fail-closed Cleanup mit Standardbudget, Budgetbeginn erst beim Cleanup für einen langlebigen Eintrag, abgebrochener und `nil`-Aufruferkontext, leerer Grund, Kapazitätsfreigabe, `Sweep` wird nicht durch einen gehaltenen Eintrag blockiert |
| `.../composite/entry_wait_bounds_test.go` | `ClaimContext` liefert `ErrBusy`, solange P1 den Eintrag hält, und gelingt danach; ein Abort bei belegtem Eintrag wird vermerkt, das späte P1-Ergebnis kann die Reservierung nicht aktivieren, genau ein Close und eine Slot-Freigabe; Abort bei freiem Eintrag und mit falscher Sitzung; leeres/unbekanntes Token und leere Sitzung |
| `.../composite/cleanup_runtime_test.go` (`libmodsecurity`) | Echte Engine: Das direkte Cleanup nach einem Fault mit und ohne abgebrochenen Request-Kontext lässt die Engine nutzbar |
| `.../compositetraefik/companion_bounds_test.go` | Claim während eines gehaltenen ForwardAuth-P2-Aufrufs gibt den Handler frei, keine späte Aktivierung, eine Slot-Freigabe; Response-Engine-Arbeit durch die Frame-Deadline begrenzt; normaler Lebenszyklus; 11 Redirect-Fälle (gültig absolut/relativ/Maximum, CR/LF, LF, NUL, DEL, führendes Leerzeichen, ungültiges UTF-8, leer, über dem Maximum); Client-Abbruch mit Lock-Semantik-Double |
| `.../compositetraefik/companion_runtime_test.go` (`libmodsecurity`) | Echte Engine: Abbruch nach einem nicht leeren und nach einem leeren ersten Body-Read lässt die Engine nutzbar |
| `.../haproxy_spop_diagnostic_runtime.inc` | `rule_id` 12345, 1, `INT_MAX` werden dezimal serialisiert; 0, -5 und `INT_MIN` als Leerstring |
| `connector_suite/source-map.json` | Fünf neue Bindungen |
| `connector_suite/config/testing/active-cases.json` | Zwei geprüfte Quell-Hash-Slots (das geänderte `.inc` und `source-map.json`) über `update-inventory-bindings.py --apply`; Selektoren, 80 Executions und 100 Fälle unverändert |
| `.../test-selection-archive.generated.json` | Neu erzeugt: 8476 auf 8496 On-Demand-Definitionen |

## Befehle und Ergebnisse

Run-ID `claude-pr454-review-20261120`. Evidenzpfade sind relativ zum
aufgabeneigenen Verzeichnis dieses Laufs außerhalb des Checkouts.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `update-inventory-bindings.py --check`, vor der Korrektur | 1 | `SOURCE_DIGEST_DRIFT` nur für das `.inc` und `source-map.json`, mit beiden Connector-Revisionen | claude-pr454-review-20261120 |
| `update-inventory-bindings.py --apply`, danach `--check` | 0 / 0 | `INVENTORY_BINDINGS_UPDATED`, `INVENTORY_BINDINGS_VERIFIED`; struktureller Vergleich: genau 2 geänderte Hash-Felder | claude-pr454-review-20261120 |
| `update-test-archive.py`, danach `update-test-archive.py --check` | 0 / 0 | Archiv neu erzeugt; Prüfung stimmt überein | claude-pr454-review-20261120 |
| `python3 -P -m modsecurity_test_framework.connector ... --check` | 0 | `active_case_count` 100 | claude-pr454-review-20261120 |
| `make framework-go-test GO_TEST_MODULE=connectors/envoy/ext_proc` (Standardinventar) | 0 | 2 von 2 ausgewählten Fällen bestanden | `logs/default-go-test-2.log` |
| `ON_DEMAND_TESTS=1 python3 -m unittest` für `test_inventory_bindings_maintenance` und zwei `ActiveTestInventoryTests` | 0 | 8 Tests bestanden, 0 übersprungen | claude-pr454-review-20261120 |
| `ON_DEMAND_TESTS=1 GOFLAGS='-tags=libmodsecurity -v' make framework-go-test GO_TEST_MODULE=connectors/envoy/ext_proc` gegen den korrigierten Connector | 0 | 8 Pakete ok; 20 neue Tests bestanden, 0 übersprungen | `out-after2/go-test.log` |
| Dasselbe mit `-race` | 0 | 8 Pakete ok; 0 Data Races; 20 neue Tests bestanden | `out-after-race/go-test.log` |
| Dasselbe Overlay ohne `entry_wait_bounds_test.go` gegen Connector `a79f78f3e5f9a612d854e3924cf2a7e43eb47ab7` | 1 | Nur erwartete Fehler: 2 unbegrenzte direkte Cleanups, blockierter `Sweep`, Claim wartet über 2 s; alle übrigen Tests bestanden | `out-before-prhead2/go-test.log` |
| Dasselbe Overlay ohne die drei Coordinator-Dateien gegen Connector `b79c3d93efbb8330f121caf8fb7c1a7874195e57` | 1 | Nur erwartete Fehler: gehaltener Claim, unbegrenzte Response-Arbeit, 8 ungültige Redirects lieferten 302, Abbruch mit Double und echter Engine versetzte den Coordinator in den Fault-Zustand; Kontrollfälle bestanden | `out-before-base/go-test.log` |
| `ON_DEMAND_TESTS=1 make -C connectors/haproxy self-test-spoa-runtime` mit diesem Framework, Connector `b79c3d93…` | 2 | Neuer Fall meldet `rule_id=0 did not serialize as ""` | `out-haproxy-before2/` |
| Dasselbe gegen den korrigierten Connector | 2 | Neuer Fall besteht; ein späterer, unveränderter Protokoll-Selbsttest scheitert ohne Meldung | `out-haproxy-after2/` |
| Dasselbe mit dem unveränderten Framework `95f22893…` gegen beide Connector-Revisionen | 2 / 2 | Derselbe stumme Fehler des Protokoll-Selbsttests: vorbestehend, unabhängig von dieser Änderung | `out-haproxy-pristine-*/` |
| `gofmt -l` auf den neuen Go-Dateien | 0 | Keine Ausgabe | claude-pr454-review-20261120 |
| `make check-change-records`, `check-doc-links`, `check-bilingual-docs`, `check-repository-path-references` | 0 | Alle bestanden (die Pfadprüfung wies zunächst einen lokalen Pfad in diesem Record zurück, danach bestanden) | claude-pr454-review-20261120 |

## Sicherheitsauswirkung

Keine Sicherheitskontrolle des Frameworks ändert sich. Die Tests prüfen die
ursprünglichen Pfade der Connector-Korrekturen erneut (unbegrenztes Cleanup
und Warten, späte Aktivierung nach einer abgebrochenen Sitzung, unvalidiertes
`Location`, Cleanup mit abgebrochenem Kontext) sowie ihre alternativen Pfade
(Shutdown statt Fault, Response-Arbeit statt Claim, leerer erster Read).

## Dokumentation und Runtime-Evidenz

Keine Änderungen an leserbezogener Dokumentation. Die Go-Tests sind
Laufzeittests auf Paketebene; die Varianten mit echter Engine nutzen die
Common-Runtime mit libModSecurity v3.0.17 und gebündeltem gepinntem PCRE2 10.49.
Es wurde kein Traefik-, Envoy- oder HAProxy-Hostprozess gestartet, daher wird
keine Host-Runtime-Evidenz beansprucht.

## Nicht ausgeführte Prüfungen

- Gehostete Framework-CI und SonarQube Cloud: für den Head des Pull Requests
  ausstehend; der SonarQube-Coverage-Job wird erwartbar beim Kompilieren
  scheitern, bis der Connector-Pin aktualisiert ist (siehe Merge-Reihenfolge
  unten).
- Die Varianten mit echter Engine laufen nur mit `-tags libmodsecurity` und
  CGo-Flags für das Common-Archiv des Connectors; ein einfaches
  `ON_DEMAND_TESTS=1 make framework-go-test` kompiliert sie nicht mit.

## Einschränkungen und Restrisiko

- Das native HAProxy-Selbsttest-Target endet in dieser Umgebung wegen eines
  vorbestehenden, stummen Fehlers eines Protokoll-Selbsttests ungleich null;
  der neue Fall wird nur über seine eigene Meldung vor der Korrektur und deren
  Ausbleiben danach beobachtet.
- Ein nativer Aufruf, der nicht zurückkehrt, lässt sich mit der echten Engine
  nicht erzeugen; diese Grenze decken Test-Doubles ab, die
  `commonRuntimeTransaction.Close` nachbilden.
- **Merge-Reihenfolge.** `cleanup_bounds_test.go` nutzt
  `Limits.CleanupTimeout` und `entry_wait_bounds_test.go` nutzt
  `ClaimContext`/`AbortWithReasonContext`. Der SonarQube-Workflow kompiliert
  `./...` von `connectors/envoy/ext_proc` gegen seinen gepinnten
  `CONNECTOR_REVISION` (`cfd5e49cada3fc793ef50993147e3796a0907443`), der älter
  als diese APIs ist; dieser Job kann die Änderung daher erst kompilieren, wenn
  der Pin eine Connector-Revision mit dem aktualisierten PR #454 auswählt.
  Dieser Pull Request muss deshalb Draft bleiben, bis PR #454 gemergt und der
  Pin hier aktualisiert ist; der Pin wird jetzt nicht geändert, weil es eine
  solche Connector-Revision noch nicht gibt.
- Bis ein Connector-Gitlink-Update eine Framework-Revision mit diesen Tests
  auswählt, pinnt der Connector weiterhin diese Framework-Basisrevision.

## Finaler Diff- und Review-Status

Der gestagte Diff wurde geprüft; `git diff --check` und ein Secrets-Scan jeder
geänderten Datei waren sauber. Ausgeliefert als Draft-Pull-Request; nicht
gemergt. Der Framework-Gitlink des Connectors bleibt unverändert.
