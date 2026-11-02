# Abhängigkeiten der NGINX-Mapper-Status-Fixture korrigieren

**Sprache:** Deutsch | [English](20261102-01-nginx-mapper-status-fixture.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change ID | 20261102-01-nginx-mapper-status-fixture |
| UTC date | 2026-11-02 |
| Framework base revision | `bc08ee7ca413012da189902b8b9c61c98151e76b` |
| Issue or pull request | Eigener Framework-PR für externen Connector-PR #348 vorbereitet; kein Merge autorisiert |

## Motivation und Problemstellung

Der echte Request-Mapper ruft jetzt `ngx_http_modsecurity_http3_authority` auf.
Die eigenständige Fixture extrahierte den Mapper, aber nicht diese im Header
definierte Abhängigkeit. Vor der Korrektur scheiterte C17 mit impliziter
Deklaration und `incompatible types when assigning to type ‘ngx_str_t’ from type ‘int’`;
setUpClass scheiterte und keine Methode lief. Reproduziert mit obiger aktueller
Framework-Basis und externem Connector-Input
`97dfcaddb698d5b95c3f78531eb81803699ffbe1`.

## Betroffene Komponenten und Sicherheitsgrenzen

Nur Framework-Testkonstruktion und nativ generierte Beschreibungen ändern sich.
Kein Connector-Produktcode, keine Runtime-Entscheidung, Abhängigkeitsversion oder
MRTS-Datei ändert sich. Echte Allokations-/interne Fehler und strenge Warnungen
bleiben erhalten; Compiler-Setupfehler dürfen nicht als bestandene Tests gelten.

## Akzeptanzkriterien

Die fünf vorhandenen Methoden kompilieren mit `-std=c17 -Wall -Wextra -Werror`,
laufen ohne Skips und behalten alle Assertions. Gültiges Mapping wird weiterhin
akzeptiert; beide Pointer-Fehler und acht Poolfehler bleiben HTTP500,
Headerüberschreitung bleibt HTTP400, das Null-Limit bleibt akzeptiert.
Standardauswahl erhalten und echte Helper-Übernahme unabhängig prüfen.

## Untersuchte Alternativen

Kein Authority-Stub, keine kopierte Alternativimplementierung, kein Entfernen von
`-Werror`, keine Produktänderung, entfernten Negativfälle oder weggefilterte
Fixture. Tatsächliche Header-Funktionen mit bestehendem Extraktor übernehmen.

## Implementierungsentscheidung

Echten `ngx_http_modsecurity_next_header` vor seinem echten Authority-Aufrufer
extrahieren; die vom zeilenbasierten Extraktor ausgelassenen Signaturen
`static ngx_inline ngx_table_elt_t *` und `static ngx_inline ngx_str_t` erhalten.
Hostfelder, Null-String-/Inline-/Versionsmakros und das Host-Primitiv für
Groß-/Kleinschreibungsvergleich bereitstellen. Der unveränderte HTTP/1.1-Request
initialisiert neue Hostfelder mit NULL. HTTP/3 ist zur Kompilierung standardmäßig
aktiv; explizites `CC='cc -DNGX_HTTP_V3=0'` prüft auch den deaktivierten Zweig.
Das ist bedingte Fixture-Kompilierung, keine neue Protokollqualifikation.

## Geänderte Dateien und Tests

Nur `connector_suite/modsecurity_connector_tests/test_nginx_request_mapper_status.py`,
natives Auswahlarchiv, Migrationsbaseline und Test-Map sowie diesen zweisprachigen
Record ändern. Keine neuen Methoden/Selektoren/Fälle. ASTs aller fünf Methoden und
von `probe` sind zur Basis identisch. Vierzehn Probes und zehn benannte Unterfälle
bleiben:1gültig,2Pointer-Fehler,8Allokationsfehler,2Headergrenzen,1Null-Limit.
Vorhandene Inventarbytes unverändert:100/80Standardfälle/-Ausführungen,
2586/1140On-Demand,528feste Framework-Quellbindungen,235revisionsgebundene
Product-Pfade und1993erhaltene Baseline-IDs.
Der native Migrationsgenerator aktualisiert außerdem bestehende externe
Envoy-Makefile-Aufruferzeilen für die explizit gewählte Connector-Revision;
kein Selektor oder Produktcode ändert sich.

## Befehle und Ergebnisse

Run-ID: `nginx-mapper-fixture-20261102`. RTK und Framework-eigener
`$FRAMEWORK_PYTHON` (beobachtet Python3.14.4;
Hosted-Python wird getrennt im Repository gepinnt). Compiler:Ubuntu cc15.2.0.
Jeder Python-Aufruf verwendet `rtk bypass env`, den expliziten Kontext unten,
dann diesen Interpreter und den Tabellen-Befehlsrest. Die Reproduktion verwendete
RUNNER_TEMP mit Endung `/before`; Nachprüfungen verwenden `/after`.

```text
ON_DEMAND_TESTS=1
TEST_ROOT=$FRAMEWORK_ROOT
FRAMEWORK_ROOT=<explicit selected Framework checkout>
FRAMEWORK_REVISION=bc08ee7ca413012da189902b8b9c61c98151e76b
CONNECTOR_ROOT=<explicit selected Connector checkout>
CONNECTOR_REVISION=97dfcaddb698d5b95c3f78531eb81803699ffbe1
CONNECTOR_TEST_PROFILE=protocol-integrity
CONNECTOR_TEST_OUTPUT_ROOT=$EXTERNAL_RUN
RUNNER_TEMP=$EXTERNAL_RUN/after
TMPDIR=$EXTERNAL_TMP
PYTHONPATH=$FRAMEWORK_ROOT:$FRAMEWORK_ROOT/connector_suite
PYTHONDONTWRITEBYTECODE=1
PYTHONNOUSERSITE=1
```

| Befehlsrest / Verfahren | Exitcode | Beobachtetes Ergebnis |
| --- | --- | --- |
| `-m unittest -v modsecurity_connector_tests.test_nginx_request_mapper_status` vor Korrektur | 1 | Ursprüngliche Authority-Deklarations-/Typfehler; Ran0tests |
| Gleiches Modul nach Korrektur | 0 | Alle5Methoden PASS |
| Natives `python_child` für jeden der fünf exakten Methodenselektoren, mit `CC='cc -DNGX_HTTP_V3=1'`, dann `=0` | je0 | Je Konfiguration:5Methoden,10Unterfälle,0Skips,0erwartete Fehler;14Probes |
| `-m unittest -v` mit Extraktion, Headeriteration und vier Mapper-Adoptionsselektoren | 0 | Alle11Methoden PASS;28.336s |
| `connector_suite/modsecurity_connector_ci/tools/update-inventory-bindings.py --apply`, dann `--check` | je0 | Bestehende Bindungen VERIFIED; kein Inventar-Digestfeld geändert |
| `connector_suite/modsecurity_connector_ci/tools/update-test-archive.py`, dann `--check` | je0 | Archiv generiert und verifiziert |
| `connector_suite/modsecurity_connector_ci/tools/build-migration-map.py` | 0 | Baseline/Map nativ generiert; Zählungen und1993IDs erhalten |
| `-m modsecurity_test_framework.connector --check` | 0 | Nur Admission:100aktiv,2586On-Demand,Limit100; kein Suitelauf |
| AST-Vergleich aller5Methoden und probe; Inventarbytes gegen Basis | 0 | Unverändert |
| `rtk bypass git diff --check` | 0 | Keine Whitespacefehler |

Exakte expandierte Methodenbefehle/-ergebnisse liegen in
`nginx-mapper-fixture-20261102/after/five-method-results.json`.
Natives Beobachterverfahren: `-c 'import sys; from modsecurity_connector_ci.lib.active_test_inventory import python_child; raise SystemExit(python_child(sys.argv[1]))'`,
gefolgt von `modsecurity_connector_tests.test_nginx_request_mapper_status.NginxRequestMapperStatusTests.`
und jedem der fünf vorhandenen Methodennamen. Beobachtete Unterfallzahlen in
Auftragsreihenfolge:0/2/8/0/0. Angrenzende Selektoren:
`test_c_source_contract.CSourceContractTests`,
`test_nginx_header_iteration_contract.NginxHeaderIterationContractTest` und
`test_nginx_common_adoption.NginxCommonAdoptionCheckerTests`-Methoden
`test_current_helper_aware_contract_is_accepted`,
`test_mapper_typed_error_status_cannot_be_success_or_client_default`,
`test_mapper_client_header_limit_cannot_be_removed_or_unbounded`,
`test_mapper_client_limit_counts_the_synthetic_authority_host`;
jeweils mit Modulpräfix `modsecurity_connector_tests.`.

## Sicherheitsauswirkung

Testintegritätskorrektur, keine Behebung einer validierten Produktlücke.
Kein Erfolgsstub, keine Warnungsunterdrückung, Auswahl-/Collector-Ausnahme,
Gate-Abschwächung oder manuelle Digeständerung. Fehlerkontrollen bleiben erhalten.

## Dokumentation und Runtime-Evidenz

Dieser EN/DE-Change-Record ist die einzige gepflegte Textänderung.
Ergebnisse belegen eigenständige C-Kompilierung und fokussierte Verträge,
kein gehostetes NGINX-/TLS-/H2-/H3-Verhalten. Keine Hostkampagne oder MRTS-Ausführung.

## Nicht ausgeführte Prüfungen

Vollständige Standard-/historische Suiten und H2-/H3-Qualifikation sind nicht Teil
dieses begrenzten Auftrags. Frische Dokumentations-/Secret-Prüfungen, finales
Commitpaar und New-Head-CI/CodeQL/Sonar bleiben an diesem Vorbereitungspunkt
Lieferschritte; alte grüne Heads sind keine Evidenz für neue Commits.

## Einschränkungen und Restrisiko

Eigener veröffentlichter exakter Fixcommit und unabhängige Hosted-Prüfungen stehen
noch aus. Connector #348 darf den veröffentlichten PR-SHA laut Abhängigkeitsvertrag
vorläufig pinnen; Framework muss vor einem späteren Connector-Merge integriert
werden. Hier ist kein Merge autorisiert. Externe Connector-/MRTS-Zuständigkeit
bleiben getrennt; lokal uninitialisiertes MRTS ist keine verifizierte Provenienz.

## Finaler Diff- und Review-Status

Unabhängiges Read-only-Fixture-Review bestätigt echte Bodies/Signaturen/Reihenfolge
ohne Assertion-/Probe-Änderung. Abschließendes Staging-/Generator-/Doc-/Secret-Review
und Lieferevidenz werden bei Beobachtung separat erfasst. Keine Zugangsdaten,
vollständige geerbte Umgebung, Request-Bodies oder unbeschränkten Rohlogs enthalten.

### Abschließende lokale Vorbereitungsprüfungen

Natives Migrationsmap-`--check` bestanden (Exit0), gleiche Zählungen/IDs erhalten.
`make check-documentation check-canonical-common-pins check-canonical-python-pins check-canonical-workflow-pins check-canonical-crs-contract-pins`
bestand mit explizitem Framework-Root/Interpreter und externem BUILD_ROOT/OUTPUT_ROOT:
358Sprachpaare,2165gescannte Pfade,0alte Pfade, Record-/Linkprüfungen und alle vier
kanonischen Pinprüfungen. Der erste Dokumentationslauf beanstandete lokale absolute
Entwicklerpfade in diesem neuen Paar (Exit2); portable Beispiele korrigierten
die Records ohne Checkeränderung. Exakte expandierte lokale Pfade bleiben nur
in den genehmigten externen Receipts.
Der Staged-Diff-Secret-Scan mit vorhandenem Gitleaks `stdin --redact=100`
bestand (Exit0,keine Funde); Whitespace- und Syntaxprüfungen bestanden.
Unabhängiges EN/DE-Review bestätigt Parität. Ein zunächst als laufende Session
gespeichertes Receipt einer beendeten Methode wurde um den beobachteten terminalen
Exit0 ergänzt; kein Rerun oder erfundener Status. Hosted-Prüfungen und finaler
Parent-Pin bleiben getrennte Lieferevidenz.
