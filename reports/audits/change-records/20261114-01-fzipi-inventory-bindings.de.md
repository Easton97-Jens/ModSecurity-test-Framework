# Change record

**Sprache:** [English](20261114-01-fzipi-inventory-bindings.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261114-01-fzipi-inventory-bindings |
| UTC-Datum | 2026-11-14 |
| Framework-Basisrevision | `3ff8b75c9f4d2cb3614a4dcb7afd2e5360e074d8` |
| Issue oder Pull Request | Bei der Vorbereitung noch nicht erstellt; die koordinierende Aufgabe übernimmt die Auslieferung. |

## Motivation und Problemstellung

Die Framework-Teständerungen waren bereits geprüft, doch sieben Quell-Digest-Slots im Schema 5 beschrieben noch ältere Bytes. Das vollständige Inventar-Gate lehnte `tests/test_runtime_event_sink_failures.py` vor der Testauswahl ab. Die Aktualisierung der vorhandenen Bindungen stellt die Provenienzprüfung für die geprüften Quellinhalte wieder her.

## Betroffene Komponenten und Sicherheitsgrenzen

Nur `connector_suite/config/testing/active-cases.json` und dieses englisch/deutsche Change-Record-Paar ändern sich. Parent-Revision `80334858a1a1e1ad1ff65e647716584a18cf3e9c` ist eine externe Validierungsabhängigkeit. Die Parent-Integration benötigt später eine Aktualisierung des Framework-Pins durch die koordinierende Aufgabe. MRTS bleibt schreibgeschützt.

## Akzeptanzkriterien

Der kanonische Refresh-Checker und der vollständige Parent-gebundene Inventarverifier müssen bestehen. Genau sieben vorhandene SHA-256-Slots dürfen sich ändern. Alle 529 gebundenen Framework-Quelldateien, Auswahlfelder, Indexordinale, Produktsnapshots und Fallzuordnungen müssen identisch bleiben. Wartungsregressionen und Dokumentationsprüfungen müssen bestehen.

## Untersuchte Alternativen

Manuelles Bearbeiten der Digests würde den nativen Wartungs-Owner duplizieren. Eine Neugenerierung oder Änderung der Inventarzuordnung würde den Auftrag erweitern. Der vorhandene Schema-5-Updater führt den erforderlichen begrenzten Refresh aus und erhält den aktuellen Validierungsvertrag.

## Implementierungsentscheidung

Den kanonischen Updater vor dem Refresh im Prüfmodus ausführen. Das fehlschlagende vollständige Verifier-Ergebnis als Negativkontrolle des ursprünglichen Pfads bewahren, danach die atomische Aktualisierung anwenden und beide vollständigen Prüfungen wiederholen. Das geparste Inventar nach Normalisierung ausschließlich der sieben geänderten Digest-Felder vergleichen und unabhängig alle 529 gebundenen Framework-Quellen vor und nach der Änderung hashen.

## Geänderte Dateien und Tests

Das Manifest enthält sieben aktualisierte Bindungen: zwei Envoy-Testquellen, eine Traefik-Testquelle sowie die Quellen für Apache-Lifecycle, HAProxy-Binding, Runtime-Event-Sink und NGINX-Body-Buffer-Fixture. Testimplementierungen und Verifier bleiben unverändert. Alle übrigen Inventardaten sind identisch. Der vollständige Verifier meldet 100 automatische Fälle bei einer Grenze von 100, 2689 Katalogfälle und 2589 On-Demand-Fälle.

## Befehle und Ergebnisse

Der tatsächliche RTK-Einstieg war `rtk bypass python3 -B -` aus dem Framework-Checkout. Seine Python-Orchestrierung startete die hinter dem Pfeil aufgeführten Kind-Argumentvektoren; der Pfeil bezeichnet einen Prozessstart und keinen Shelloperator. `$PYTHON` kürzt den konfigurierten Framework-Interpreter ab. Der unittest-Kindprozess erhielt `ON_DEMAND_TESTS=1` über seine Umgebung. Der Dokumentations-Kindprozess nutzte `rtk make`. Der Kontext setzt `FRAMEWORK_ROOT`, `TEST_ROOT`, das externe Ausgabeverzeichnis, die Parent-Identität und `CONNECTOR_TEST_PROFILE=h1` explizit. Ersten reinen Kontextversuchen fehlten Profil-/Ausgabemetadaten; sie endeten mit 2 und zählen nicht als Digest-Negativkontrollen.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk bypass python3 -B -` → `$PYTHON connector_suite/modsecurity_connector_ci/tools/update-inventory-bindings.py --check` | 1 / 0 | Vorher: genau sieben veraltete Digests. Nachher: `INVENTORY_BINDINGS_VERIFIED`. | `framework-inventory-remediation` |
| `rtk bypass python3 -B -` → `$PYTHON -m modsecurity_connector_ci.lib.active_test_inventory --check` | 2 / 0 | Vorher: Abweichung eines geprüften Quell-Digests. Nachher: alle Bindungen und Definitionen zugelassen. | `framework-inventory-remediation` |
| `rtk bypass python3 -B -` → `$PYTHON connector_suite/modsecurity_connector_ci/tools/update-inventory-bindings.py --apply` | 0 | Sieben vorhandene Digest-Slots atomisch aktualisiert. | `framework-inventory-remediation` |
| `rtk bypass python3 -B -` → `$PYTHON -m unittest -v modsecurity_connector_tests.test_inventory_bindings_maintenance` | 0 | Sechs Wartungsregressionen bestanden, einschließlich Ablehnung ungültiger Schemata, Traversal, Symlinks und konkurrierender Änderungen. | `framework-inventory-remediation` |
| `rtk bypass python3 -B -` → `rtk make check-documentation PYTHON="$PYTHON" BUILD_ROOT="$RUNNER_TEMP/build" TMP_ROOT="$RUNNER_TEMP/tmp"` | 0 | Links, zweisprachige Variablen, Repository-Pfade und Change-Record-Struktur bestanden. | `framework-inventory-remediation` |

## Sicherheitsauswirkung

Es erfolgt keine Security-Remediation oder Lockerung von Kontrollen. Die vorhandenen Prüfungen für Digests, Pfade, Symlinks, Schemata, doppelte Auswahl und Fallbudget bleiben wirksam. Der ursprünglich fehlschlagende Provenienzpfad wird nach dem Binding-Refresh erfolgreich erneut geprüft.

## Dokumentation und Runtime-Evidenz

Dieses zweisprachige Paar dokumentiert die Framework-Provenienzreparatur. Die Prüfungen belegen Inventar- und Wartungsverhalten; neue Host-Runtime-, Lifecycle-, Transport-Abbruch- oder Connector-Promotion-Evidenz wird nicht behauptet.

## Nicht ausgeführte Prüfungen

Connector-Runtime-Matrizen und Host-Builds werden für eine reine Digest-Inventarreparatur bei unveränderten Test- und Produktquellbytes nicht wiederholt. Veröffentlichung, CI am aktuellen Head und Integration übernimmt die koordinierende Aufgabe.

## Einschränkungen und Restrisiko

Die aktualisierten Bindungen beziehen sich auf den aktuellen geprüften Quellinhalt. Zukünftige Quelländerungen erfordern einen weiteren expliziten Refresh. Eine erfolgreiche Katalogprüfung ersetzt nicht die Ausführung der ausgewählten Tests.

## Finaler Diff- und Review-Status

Der semantische Vergleich belegt ausschließlich sieben geänderte Digest-Werte; alle 529 Quellhashes sind unverändert. Secrets-Prüfungen nach der Änderung bestanden. Dies ist eine vorbereitete Framework-Übergabe; Commit, Pull Request und Parent-Pin bleiben bei der koordinierenden Aufgabe.
