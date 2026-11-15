# Change Record

**Sprache:** [English](20261115-02-connector-inventory-bindings.md) | Deutsch

**Prüfsnapshot vor der Veröffentlichung.** Auslieferungsidentität und aktuelle gehostete CI werden separat verfolgt. Framework-Merge oder Parent-Pinänderung werden nicht behauptet.

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261115-02-connector-inventory-bindings |
| UTC-Datum | 2026-11-15 |
| Framework-Basisrevision | `2b56f868fc7fcecbd78c15860b59604c3c63870c` |
| Issue oder Pull Request | Kein Pull Request bei diesem lokalen Prüfsnapshot; Aufgabenbranch `codex/repair-updater-source-bindings`. |

## Motivation und Problemstellung

Der Parent-Updater-Lauf `43717327488` blieb nach seiner früheren Updater-Reparatur blockiert. Die öffentliche Framework-Inventar-CLI reproduzierte `ACTIVE_INVENTORY_REJECTED` für `connectors/traefik/harness/i12/native/client.py`. Die kanonische Linux-Prüfung des Binding-Owners identifizierte zehn veraltete Quellbindungen.

## Betroffene Komponenten und Sicherheitsgrenzen

Diese Framework-eigene Änderung repariert die Integrität zwischen Inventar und Quellen und ergänzt eine Framework-eigene Lint-Prüfung. Parent-Dateien, dessen Framework-Gitlink und MRTS bleiben unverändert. Die Prüfung exakter Quellbindungen bleibt aktiv; daraus wird keine Runtime- oder Connector-Qualifikation abgeleitet.

## Akzeptanzkriterien

Die öffentliche Inventarprüfung muss die geprüften Quellbindungen mit `active_case_count=100` und `selected_executions=80` akzeptieren. Fallselektoren müssen unverändert bleiben. Generierte Archivdaten müssen mit ihrem nativen Owner übereinstimmen; unabhängiges Framework-Lint muss künftigen Binding-/Archivdrift ohne Produktcheckout zurückweisen.

## Untersuchte Alternativen

Das Abschalten der Binding-Prüfung oder eine geänderte Fallauswahl würde Drift verbergen und die Abdeckung verändern. Manuelle Änderungen generierter Archivbytes würden deren Owner umgehen. Nur geprüfte Digests mit dem kanonischen Owner aktualisieren und das Archiv mit seinem nativen Generator erneuern.

## Implementierungsentscheidung

Das unabhängige statische Review aller zehn Quelldifferenzen fand keine Probleme: zwei Traefik-Client-Guards, drei lighttpd-JSON-Pfadgrenzen, ein wirkungsloser `common.sh`-Fall und NGINX-Runner-Refactorings. `update-inventory-bindings.py --apply` aktualisierte zehn Hashslots. Aktive Selektoren, 100 Fälle und 80 Ausführungen bleiben unverändert. `update-test-archive.py` regenerierte das Archiv; dessen geänderte Felder sind `inventory_sha256`, `on_demand_definition_count` und `sources`, die alle diesem Generator gehören. Es kommt keine Standardausführung hinzu. Framework-Lint führt Binding- und Archiv-Owner jetzt im Prüfmodus mit read-only GitHub-Contents-Berechtigung und ohne Produktabhängigkeit vor dem bestehenden Framework-Lint-Schritt aus.

## Geänderte Dateien und Tests

- `.github/workflows/lint.yml`: unabhängige Binding-/Archivdrift-Prüfung.
- `connector_suite/config/testing/active-cases.json`: zehn geprüfte Quellhashslots.
- `connector_suite/reports/testing/test-selection-archive.generated.json`: natives generiertes Archivupdate.
- `reports/audits/change-records/20261115-02-connector-inventory-bindings.md` und `reports/audits/change-records/20261115-02-connector-inventory-bindings.de.md`: dieses Record-Paar.

Alle sechs bestehenden Binding-/Archivwartungstests bestanden (Exit 0, 0.084 Sekunden). Ein unabhängiger Quellvergleich belegte genau zehn kanonische Git-Quellhashänderungen, den Erhalt aller 529 Quellpfade und unveränderte Werte sämtlicher Inventarfelder außerhalb der Bindings. Es kommen keine aktiven Fälle hinzu.

Drei bestehende Kernregressionen des Inventars bestanden ebenfalls (Exit 0, 0.276 Sekunden): Geänderte Quellbytes verhindern die Ausführung, ein zu großes Inventar wird vor dem Start eines Kindes abgewiesen und die Fallauswahl schließt Ausführungsvarianten vollständig ein.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `"$PYTHON" -B -m modsecurity_test_framework.connector --check`, vor Reparatur | 1 | `ACTIVE_INVENTORY_REJECTED` an der Traefik-Client-Bindung reproduziert. | Parent-Lauf `43717327488` |
| `python -B "$TEST_ROOT/connector_suite/modsecurity_connector_ci/tools/update-inventory-bindings.py" --check`, kanonische Linux-Quellen | 1 | Zehn veraltete Bindings. | Lokale Framework-Prüfung |
| `update-inventory-bindings.py --apply` | 0 | Zehn Quellhashslots aktualisiert; Selektoren unverändert. | Lokale Framework-Prüfung |
| `update-inventory-bindings.py --check`, nach Reparatur | 0 | `INVENTORY_BINDINGS_VERIFIED`. | Lokale Framework-Prüfung |
| `update-test-archive.py` | 0 | Archiv über seinen nativen Owner regeneriert. | Lokale Framework-Prüfung |
| `update-test-archive.py --check` | 0 | Archiv entspricht den Generatoreingaben. | Lokale Framework-Prüfung |
| `"$PYTHON" -B -m modsecurity_test_framework.connector --check`, nach Reparatur | 0 | `active_case_count=100`, `selected_executions=80`. | Lokale Framework-Prüfung |
| Sechs bestehende Binding-/Archivwartungstests | 0 | Sechs Tests bestanden in 0.084 Sekunden. | Lokale Framework-Prüfung |
| Drei ausgewählte `ActiveTestInventoryTests` für Quellhash-Ablehnung, Überlaufablehnung und geschlossene Fallauswahl | 0 | Drei Tests bestanden in 0.276 Sekunden. | Lokale Framework-Prüfung |
| `verify_framework_inventory.py` | 0 | Genau zehn kanonische Binding-Änderungen; 529 Pfade und sämtliche übrigen Inventarfelder erhalten; 100 Fälle / 80 Ausführungen unverändert. | Externes Aufgabenprüfartefakt |
| YAML-Parsing und `bash -n` des neuen Lint-`run`-Blocks | 0 | Genau zwei `--check`-Aufrufe, kein `--apply`, vor bestehendem Framework-Lint. | Lokale Framework-Prüfung |

Die Prüfungen verwendeten die Framework-Virtualenv auf vorhandenem WSL-Python `3.13.7`. Ein nativer Linux-Checkout mit LF-Bytes war nötig: Die Windows-CRLF-Materialisierung erzeugte 529 falsche Driftmeldungen, und der Windows-Worktree-Gitpfad war mit WSL inkompatibel. Der aufgabeneigene native Clone initialisierte MRTS nicht.

`PYTHON` bezeichnet diesen Framework-eigenen Virtualenv-Interpreter. Der gehostete Lint-Lauf `43721324960` bestand die neue Binding-/Archivprüfung und wies anschließend die maschinenspezifischen Interpreterpfade in diesem Record-Paar zurück. Diese Befehlsbeispiele verwenden jetzt die portable Variable; die bestehende Pfadreferenzprüfung bleibt unverändert.

Der explizite öffentliche CLI-Kontext wählte die Parent-Revision `ab7a32ab464a3dd8fe119b10d3936acd4b4ae557`, den nativen Framework-Checkout über `TEST_ROOT` und `PYTHONPATH`, Profil `h1` und einen aufgabeneigenen externen Ausgaberoot. `PYTHONNOUSERSITE=1` und `PYTHONDONTWRITEBYTECODE=1` waren gesetzt. Die Quellowner-Befehle verwendeten denselben Framework-eigenen Interpreter und exakten nativen Checkout.

## Sicherheitsauswirkung

Es wird keine Security-Remediation behauptet. Das Inventar weist abweichende Quellbytes weiterhin zurück; ausschließlich unabhängig geprüfte Hashes wurden aktualisiert. Read-only-Lint-Prüfungen erkennen künftigen Drift. Berechtigungen, Scanner, Quality-Gates und Runtime-Vertrauensgrenzen wurden nicht abgeschwächt.

## Dokumentation und Runtime-Evidenz

Dieses englisch-deutsche Record-Paar dokumentiert denselben Umfang, dieselben Fakten und Einschränkungen. Es wurde keine Connector-Runtime- oder Lifecycle-Evidenz erfasst. Eine bestandene Inventarprüfung belegt nur Quellbindungs- und Auswahlkonsistenz.

## Nicht ausgeführte Prüfungen

Kanonische Python-`3.15`-CI, der vollständige gehostete Parent-Updater, vollständiger `quick-check` und native Runtime-Ausführung wurden lokal nicht nachgewiesen. Produktbuilds, Connector-Runtime-Matrizen und MRTS-Ausführung liegen außerhalb dieser Framework-Wartung. Finale Record-Schema- und Diff-Prüfungen werden nach der letzten Dokumentationsänderung separat erfasst.

## Einschränkungen und Restrisiko

Quellhashes belegen Byteidentität statt Runtime-Korrektheit. Künftige Quelländerungen müssen Binding-Owner und Archivgenerator verwenden; Lint soll ausgelassene Aktualisierungen sichtbar machen. Dieser Prüfsnapshot vor der Veröffentlichung behauptet weder Auslieferungsidentität noch Erfolg gehosteter CI. Framework-Delivery bleibt getrennt; Framework-Merge oder Parent-Gitlink-Update werden nicht behauptet.

## Finaler Diff- und Review-Status

Alle zehn Quelldifferenzen wurden unabhängig statisch ohne Befunde geprüft. Sechs Wartungstests, Binding-Validierung nach Reparatur, Archivprüfung, unabhängiger Inventarvergleich und Syntax-/Platzierungsprüfungen des CI-Blocks bestanden. Finale Secrets-Scans der geänderten Bytes, Record-Schema-Prüfungen und Whitespace-/Diff-Review erfolgen nach dieser letzten Dokumentationsänderung separat. Framework-Delivery bleibt von Parent- und MRTS-Delivery getrennt; dieser Record behauptet weder Merge noch Parent-Pinänderung.
