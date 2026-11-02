# Change Record

**Sprache:** [English](20261102-01-parent-python-bootstrap-contracts.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261102-01-parent-python-bootstrap-contracts |
| UTC-Datum | 2026-11-02 |
| Framework-Basisrevision | `91145b7ba721bdec4e89af754cf40bf496fd2a08` |
| Issue oder Pull Request | Angeforderte Reparatur der Parent-Runs `41412784227` und `41412832386`; bei Erstellung noch kein PR |

## Motivation und Problemstellung

Aktuelle Parent-Python-Updater-Prüfungen lehnen die Framework-Composite-
Bootstrap-Reihenfolge, veraltete Job-Inventare und nicht unterstützte geschützte
oder historische Workflow-Komposition ab. Der Kontext-Binder führte zuvor Python
vor Setup und Interpreter-Verifikation aus. Diese Framework-Änderung repariert
wiederverwendbare Verträge; native Parent-Änderungen bleiben eine eigene Lieferung.

## Betroffene Komponenten und Sicherheitsgrenzen

Die 18 Implementierungen unter `.github/actions/connector-ci/`, der
Framework-eigene Python-Workflow-Checker und
`modsecurity_test_framework/workflow_sources.py` erhalten die Grenze zwischen
Parent-Gitlink, ausgechecktem Framework-Code, unveränderlichen Remote-Actions
und authentifizierter geschützter Ausführung. MRTS bleibt unverändert.

## Akzeptanzkriterien

Shell-Source-Nachweis vor ausgechecktem Interpreter-Verifier; Setup und
Verifikation vor Kontextbindung. Normales Inventar entspricht 47 aktuellen Jobs.
Geschützte Jobs behalten den exakten authentifizierten Verifier. Historische
Komposition akzeptiert nur ihre geprüfte unveränderliche Form. Bestehende
negative Umgehungstests bestehen.

## Untersuchte Alternativen

Eine pauschale First-Use-/Kontext-Ausnahme würde ungeprüftes Python akzeptieren.
Ein direkter Verifier statt geschütztem Wrapper verlöre Authentifizierung. Den
historischen Reusable-Aufrufer als lokalen normalen Job einzuordnen würde
Ausführung erfinden. Alle drei Alternativen wurden abgelehnt.

## Implementierungsentscheidung

Shell-Gitlink-/HEAD-Gleichheit, exakte Setup-/Verifier-/Kontext-Reihenfolge,
getrennte geschlossene Inventarklassen und ein geschlossenes historisches
Workflow-Call-Mapping. Geprüft werden sechs verpflichtende String-Inputs,
gleichnamige Weitergabe, Deny-Default-Berechtigungen, `contents: read`, genau ein
unveränderlicher verschachtelter Aufruf auf
`8ae707d72f1a8acb25d239e55e28a73cbc7522b1` und fehlende Concurrency-Overrides.
Nur zwei geschützte Broker-Jobs erlauben den exakten authentifizierten Verifier
`ci/run-trusted-framework.py --tool python-interpreter`.

## Geänderte Dateien und Tests

18 Composite-Action-Definitionen; Connector-Python-Workflow-Checker und dessen
`test_python_version_contract.py`; `workflow_sources.py` und
`tests/connector_adapter/test_workflow_sources.py`; zweisprachige
Connector-Integrationsdokumentation und dieser Record. Tests führen positive und
negative Source-Gates aus, lehnen unbelegte Kontext-Ausnahmen ab, mutieren
historische Grants/Pins/Inputs/Jobs und lehnen direkte Verifier in geschützten
Jobs ab.

## Befehle und Ergebnisse

`FRAMEWORK_PYTHON` bezeichnet die explizite Framework-eigene Python-3.14-Test-venv.
Der lokale Ausführungsplan enthält vollständige Kontext-/Umgebungsargumente.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk bypass env ON_DEMAND_TESTS=1 PYTHONPATH=.:connector_suite "$FRAMEWORK_PYTHON" -m unittest tests.connector_adapter.test_workflow_sources modsecurity_connector_tests.test_python_version_contract -q` mit explizitem Source-/Revisionskontext | 0 | 62 Tests bestanden; Parent-Aufrufer von `430d3194fa04ca4aafcdaef6aeb256d21dc18f0c` auf Feature-Framework-Source projiziert | Lokale begrenzte Prüfung |
| `rtk bypass git diff --check` | 0 | Keine Whitespace-Fehler im Implementierungsdiff | Lokale begrenzte Prüfung |

Zusätzliche Regressionen aktualisieren `connector_suite/modsecurity_connector_tests/test_framework_workflow_pin_projection.py` und den unabhängigen Helper `framework_sha_fixture.py`. Gegen den getrennten Parent-Patch bestanden 10 Projektionstests und 39 Updater-Tests: Die sechs frühen Selected-Action-Gate-Pins bleiben geschlossen, folgen dem bestehenden Pin-Synchronisierer, weisen veraltete/fehlende/zusätzliche/symbolische Identitäten ab und stoppen einen geänderten Gitlink samt geändertem Checkout vor Verifier-Ausführung. Unabhängiges Review bestand außerdem 24 Shell-Zulassungsfälle. Native Dokumentationsprüfungen und Ruff-Lint bestanden. Vollständiger Datei-Formatter-Drift in drei historischen Python-Dateien besteht auch in der Basis; diese unabhängigen Bereiche wurden erhalten. Die zuvor formatierte `workflow_sources.py` bleibt formatiert.

## Sicherheitsauswirkung

Die Änderung repariert Bootstrap-/Source-Vertragskorrektheit und erhält
unveränderliche Referenzen, Berechtigungen, authentifizierte geschützte
Einstiegspunkte und Fehler-Gates. Ursprüngliche Reihenfolgefehler und alternative
Umgehungen durch unbelegten Kontext oder direkten geschützten Verifier decken
negative Tests ab. Dies ist keine Connector-Sicherheitsbewertung.

## Dokumentation und Runtime-Evidenz

`docs/connector-integration.md` und die deutsche Begleitdatei beschreiben den
Bootstrap und die begrenzte Komposition. Tests liefern statische Source- und
lokale Shell-Evidenz. Dieser Record belegt keine gehostete CI, Connector-Host-
Runtime, Merge oder Parent-Pin-Aktualisierung.

## Nicht ausgeführte Prüfungen

Gehostete CI und Sonar liefen für diesen uncommitteten Patch noch nicht.
Connector-Runtime-Matrizen liegen außerhalb dieser Workflow-Vertragsänderung.
Das vollständige Default-Inventar wurde nicht erweitert oder abgeschwächt.

## Einschränkungen und Restrisiko

Native Parent-Reihenfolgereparaturen und der Bezug dieser Framework-Revision
sind getrennte Voraussetzungen kombinierter CI-Kompatibilität. Der alte
Parent-Framework-Pin liefert diese neuen Verträge nicht. Historische
verschachtelte Workflow-Inhalte bleiben unveränderlich; ihre Schnittstelle zu
komponieren führt sie nicht aus.

## Finaler Diff- und Review-Status

Implementierungsdiff und Whitespace geprüft; keine Secrets oder Rohlogs erfasst.
Unabhängiges Review fand keinen offenen Blocker; gehostete Prüfungen bleiben vor finaler Lieferung offen.
