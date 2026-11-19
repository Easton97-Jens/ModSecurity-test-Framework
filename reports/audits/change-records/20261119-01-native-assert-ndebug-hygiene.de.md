# Change Record

**Sprache:** [English](20261119-01-native-assert-ndebug-hygiene.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261119-01-native-assert-ndebug-hygiene |
| UTC-Datum | 2026-11-19 |
| Framework-Basisrevision | `95f228936efe17fda24f21323ad87cd698940b48` |
| Issue oder Pull Request | Framework-Pull-Request für Branch `fix/test-assert-ndebug-hygiene-20261119`; zugehörige Parent-Änderung `CR-20261119-verified-cppcheck-findings-connector-hardening` |

## Motivation und Problemstellung

Native C-Tests nutzten `assert()` um Arbeit, die der Test zwingend ausführen muss:
Schreiben von Fixture-Dateien, `fclose()`, Pfadformatierung, Thread- und Socket-Aufbau sowie
die getestete Operation selbst. Mit `-DNDEBUG` expandiert `assert()` zu nichts. Ein solcher
Build übersprang diese Arbeit, konnte uninitialisierte Fixture-Pfade lesen, ließ
`FILE`-Handles offen und konnte `PASS` ausgeben, ohne den Code auszuführen. Reproduktion auf
der Basisrevision: `test_nginx_engine_call_budget.c`, mit `-DNDEBUG` und zwei absichtlich
falschen Erwartungen kompiliert, endete mit Exit 0; mit `-Werror` kompilierte er nicht
einmal, weil der gesamte Testkörper wegfiel. Cppcheck meldete diese Stellen als
`assertWithSideEffect` und `resourceLeak`.

## Betroffene Komponenten und Sicherheitsgrenzen

Native Framework-Testquellen unter `connector_suite/` und das generierte Spezialisten-Archiv.
Die Grenze ist die Testaussagekraft: Ein leeres Bestehen verdeckt Produktregressionen. Dieser
Record ändert weder Produktcode noch Connector-Laufzeitverhalten.

## Akzeptanzkriterien

- Jede nicht-I12-Framework-C/C++-Testquelle, die `<assert.h>` einbindet, hebt `NDEBUG` vor
  ihrem ersten Include auf.
- Jede `assertWithSideEffect`-Stelle, die ein realistischer Cppcheck-Lauf über die
  geänderten nicht-I12-Quellen meldet, ist auf `TEST_REQUIRE()` umgestellt, das sein
  Argument immer auswertet.
- Ein `-DNDEBUG`-Build führt die Prüfungen weiterhin aus und schlägt bei einer falschen
  Erwartung fehl.
- Ein Regressionstest für den Parent-Fix der SPOP-`rule_id`-Formatierung existiert.
- Das bestehende Verhalten der betroffenen Tests bleibt unverändert; das Spezialisten-Archiv
  stimmt mit seinem Generator überein, und das aktive Inventar bleibt bei 100 Fällen.

## Untersuchte Alternativen

- Nur `#undef NDEBUG`: garantiert die Ausführung, aber Analysewerkzeuge modellieren
  `assert()` weiterhin als entfernbar und melden weiter Lecks; als alleinige Maßnahme
  verworfen.
- Umstellung aller `assert()`-Aufrufe (rund 1.900): großer, nicht reviewbarer Diff;
  verworfen.
- Ein gemeinsamer neuer Header: Einige Quellen werden aus extrahierten oder materialisierten
  Kopien kompiliert, in denen ein neuer relativer Include fragil ist; gewählt wurde eine
  kleine Definition pro Datei.

## Implementierungsentscheidung

- 28 nicht-I12-Quellen/-Header erhielten einen `#undef NDEBUG`-Schutz vor dem ersten
  Präprozessor-Include, geschrieben als `#ifdef NDEBUG` / `#undef NDEBUG` / `#endif`, damit er
  nur bei gesetztem `NDEBUG` wirkt (der erste Pull-Request-Head scheiterte am Sonar Quality
  Gate mit 28 `c:S959`-Befunden für ein unbedingtes `#undef`). Die 16 Quellen/Header mit Seiteneffekt-Assertions erhielten eine
  geschützte `TEST_REQUIRE()`-Definition (`fprintf` nach `stderr` und `abort()` bei Fehler).
- 419 Assertion-Stellen wurden auf `TEST_REQUIRE()` umgestellt: die Stellen aus dem
  ursprünglichen Scan des gesamten Checkouts plus die, die ein realistischer Scan mit echten
  Include-Pfaden fand. Nur der Makroname änderte sich; die Ausdrücke sind unverändert.
- I12-Harnessquellen (`/i12/`-Pfade und `*_i12_*`-Probes) bleiben wegen des I12-Arbeitsstopps
  unverändert; dies setzt die Ausnahme im Regressionstest durch und ist dokumentiert.
- Neues `test_native_assert_ndebug_contract.py` (On-Demand): prüft die Schutzreihenfolge in
  allen erfassten Quellen und kompiliert `test_nginx_engine_call_budget.c` mit `-DNDEBUG`;
  die Kontrolle muss bestehen, ein verfälschtes `TEST_REQUIRE()` und ein verfälschtes
  einfaches `assert()` müssen fehlschlagen.
- `test_haproxy_spop_event_sink_failures.py`: neues Harness-Szenario `rule-id=` und
  `test_phase4_event_renders_only_positive_signed_rule_ids`.
- `connector_suite/reports/testing/test-selection-archive.generated.json` wurde mit seinem
  Generator `update-test-archive.py` neu erzeugt.

## Geänderte Dateien und Tests

- 26 C-Testquellen und 2 Test-Header unter `connector_suite/` (Schutz und/oder
  `TEST_REQUIRE()`), siehe Dateiliste des Pull Requests.
- `connector_suite/modsecurity_connector_tests/test_native_assert_ndebug_contract.py` (neu)
- `connector_suite/modsecurity_connector_tests/test_haproxy_spop_event_sink_failures.py`
- `connector_suite/reports/testing/test-selection-archive.generated.json` (generiert)
- Dieses Record-Paar.

## Befehle und Ergebnisse

Alle Befehle liefen über RTK mit dem Parent-Task-Worktree auf
`b79c3d93efbb8330f121caf8fb7c1a7874195e57` als Connector-Root und Ausgaben im task-eigenen
externen Run-Root `cppcheck-audit-20261119T095825Z`.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `cc -DNDEBUG` auf Basis-`test_nginx_engine_call_budget.c` mit falschen Erwartungen | 0 | Defekt reproduziert: leeres Bestehen | `cppcheck-audit-20261119T095825Z` |
| dasselbe mit dieser Änderung | 134 | `requirement failed`; unveränderte Kontrolle endet mit 0 | `cppcheck-audit-20261119T095825Z` |
| `ON_DEMAND_TESTS=1 python3 -m unittest ...test_native_assert_ndebug_contract` (einfaches `cc` und ASan/UBSan-`CC`) | 0 | 2 Tests OK | `cppcheck-audit-20261119T095825Z` |
| Cppcheck auf den 26 geänderten C-Quellen, Basis gegen Änderung, gleiche Optionen | 0 | `assertWithSideEffect` 432 auf 0, `resourceLeak` 15 auf 0 | `cppcheck-audit-20261119T095825Z` |
| `prepare-sonar-cfamily.py` gegen den sauberen Basis-Parent | 1 | stoppt an vorbestehender Drift in `haproxy_i10_host_caller_test.c`; 11 geänderte Units davor kompiliert | `cppcheck-audit-20261119T095825Z` |
| Rezept-Compile-Flags (`-Werror`) für die 14 übrigen geänderten Units | 0 | 14 von 14 kompilieren | `cppcheck-audit-20261119T095825Z` |
| `ON_DEMAND_TESTS=1`-Runner für alle geänderten Quellen | 1 | alle nicht bestandenen Fälle sind vorbestehend und auf der Basisrevision identisch (Strict-Modus-, Traefik-Dispatcher-/Mutations- und HAProxy-I10-Materializer-Drift, Apache-Rules-Set-IndexError, NGINX-Vertragsdrift) | `cppcheck-audit-20261119T095825Z` |
| SPOP-`rule_id`-Regressionstest: Basis-Parent gegen gefixten Parent | 1 / 0 | `'0' != ''`, `'4294967289' != ''` auf der Basis; OK mit Fix | `cppcheck-audit-20261119T095825Z` |
| `update-test-archive.py`, danach `--check` | 0 | Archiv stimmt mit Inventar und Quellen überein | `cppcheck-audit-20261119T095825Z` |
| Parent `rtk make check-active-inventory` | 0 | `active_case_count` 100, `hard_limit` 100 | `cppcheck-audit-20261119T095825Z` |
| Rezept-Compile-Flags für die 25 geänderten Units, mit und ohne `-DNDEBUG`, nach dem `#ifdef`-Schutz | 0 | 25 von 25 in beiden Varianten | `cppcheck-audit-20261119T095825Z` |

## Sicherheitsauswirkung

Stellt die Aussagekraft nativer Security- und Lifecycle-Tests für Builds mit `NDEBUG` wieder
her, sodass eine Regression nicht mehr durch ein leeres Bestehen verdeckt werden kann. Keine
Sicherheitskontrolle, kein Gate, keine Suppression und kein Schwellenwert wurde abgeschwächt.

## Dokumentation und Runtime-Evidenz

Nur dieses Record-Paar. Es wurde keine Runtime- oder Lifecycle-Evidenz erhoben; alle
Ergebnisse sind Compile-, Unit- und Statikanalyse-Evidenz.

## Nicht ausgeführte Prüfungen

- Vollständige Framework-CI und Sonar-Analyse: laufen in der CI des Pull Requests.
- I12-Harnessquellen: bewusst unverändert (I12-Arbeitsstopp).
- `make test` und die vollständige Default-Matrix: außerhalb dieses begrenzten Fixes.

## Einschränkungen und Restrisiko

- Nicht umgestellte `assert()`-Aufrufe mit Seiteneffekten, die Cppcheck nicht erkennt,
  bleiben bestehen; der `#undef NDEBUG`-Schutz hält sie ausführbar.
- Der SPOP-`rule_id`-Regressionstest erwartet den zugehörigen Parent-Fix; gegen eine ältere
  Parent-Revision schlägt er absichtlich fehl.
- Fünf `assertWithSideEffect`-Stellen in I12-Quellen bleiben bestehen.

## Finaler Diff- und Review-Status

Diff auf Umfang, Whitespace (`git diff --check`) und Secrets geprüft; es sind keine
Zugangsdaten oder sensiblen Nutzdaten erfasst.
