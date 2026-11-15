# Change Record

**Sprache:** [English](20261115-03-connector-c-standard-temp-root.md) | Deutsch

**Prüfsnapshot vor der Veröffentlichung.** Dieser Record erfasst die implementierte Consumer-Reparatur und beobachtete lokale Prüfungen. Erfolg gehosteter CI, Auslieferungsidentität, Merge oder Parent-Pinänderung werden nicht behauptet.

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261115-03-connector-c-standard-temp-root |
| UTC-Datum | 2026-11-15 |
| Framework-Basisrevision | `03f50ce2f6854ad9a02227dfc5939ded23e838f6` |
| Issue oder Pull Request | Für diese Reparatur bei diesem Snapshot kein Pull Request; Aufgabenbranch `codex/fix-updater-runner-temp`. |

## Motivation und Problemstellung

Der Parent-Updater-Lauf `43723917343` erreichte den Quick-Check, scheiterte aber an `check-remaining-connectors-c-standards.sh:93`, wo `RUNNER_TEMP` verlangt wird. Der ältere vertrauenswürdige Namespace-Helfer erstellt und übergibt ein privates `TMPDIR`, ohne `RUNNER_TEMP` zu setzen. Der Consumer weist daher einen explizit übergebenen privaten temporären Root zurück.

## Betroffene Komponenten und Sicherheitsgrenzen

Die Änderung beschränkt sich auf die Auswahl des temporären Roots in der Framework-C-Standardprüfung. Namespace-Helfer, authentifizierte Brücke, Parent und MRTS bleiben unverändert. Das ausgewählte temporäre Verzeichnis muss explizit bleiben; ein impliziter `/tmp`-Fallback liegt außerhalb des Vertrags.

## Akzeptanzkriterien

Ein übergebenes `RUNNER_TEMP` weiterhin bevorzugen. Explizit übergebenes `TMPDIR` nur verwenden, wenn `RUNNER_TEMP` nicht gesetzt ist. Ein gesetzter, aber leerer oder nicht existierender primärer Root darf nicht auf `TMPDIR` zurückfallen; ohne beide Roots muss die Prüfung fehlschlagen. `/tmp` nicht ableiten. Bestehende C-Standardprüfungen, Compilerfehlerstatus, Ausgabebereinigung und Namespace-Isolation erhalten.

## Untersuchte Alternativen

Eine Änderung des vertrauenswürdigen Helfers, der Brücke oder des Parents würde die Ownership-Grenze ausweiten und eine separate Auslieferungskette benötigen. Ein implizites temporäres Systemverzeichnis würde den Vertrag eines expliziten privaten Roots verlieren. Nur den Consumer an das bereits vom vertrauenswürdigen Namespace übergebene private `TMPDIR` anpassen.

## Implementierungsentscheidung

Der dreizeilige Consumer-Fix wählt zuerst `RUNNER_TEMP` und fällt nur bei ungesetzter primärer Variable auf explizites `TMPDIR` zurück. Fehlende, leere oder nicht existierende ausgewählte Roots bleiben Fehler. Namespace-, Brücken-, Parent- und MRTS-Implementierung werden nicht geändert. Das generierte Archiv wurde durch seinen nativen Generator für sieben neue On-demand-Tests aktualisiert: Der Definitionszähler änderte sich von 8469 auf 8476, während `inventory_sha256` und das aktive Inventar unverändert blieben.

## Geänderte Dateien und Tests

- `check-remaining-connectors-c-standards.sh`: ausgewählte temporäre Rootbehandlung des Consumers.
- `connector_suite/modsecurity_connector_tests/test_remaining_connectors_c_standard_temp.py`: sieben On-demand-Shellregressionen.
- `connector_suite/reports/testing/test-selection-archive.generated.json`: natives generiertes Archivupdate für diese sieben Tests.
- `reports/audits/change-records/20261115-03-connector-c-standard-temp-root.md` und `reports/audits/change-records/20261115-03-connector-c-standard-temp-root.de.md`: dieses Record-Paar.

Die sieben neuen Tests führen den echten POSIX-Consumer mit einem Compilerstub, tatsächlichen `-o`-Ausgabepfaden und Bereinigungsprüfungen aus. Die Abdeckung umfasst primäre Rootauswahl, expliziten Fallback, Vorrang sowie Negativfälle für beide fehlenden Roots, leeren primären Root, nicht existierenden primären Root und Compilerstatus `23`. Daraus wird keine native Compiler- oder Runtime-Qualifikation abgeleitet. Sechs bestehende Wartungstests und ein bestehender Namespace-Umgebungstest bestanden ebenfalls.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Parent-Updater-Quick-Check / Ergebnisdurchsetzung | 2 / 1 | Fehlendes `RUNNER_TEMP` am C-Standard-Consumer zurückgewiesen, obwohl der vertrauenswürdige Namespace privates `TMPDIR` übergibt. | Parent-Lauf `43723917343` |
| `"$PYTHON" -B -m unittest -v modsecurity_connector_tests.test_remaining_connectors_c_standard_temp`, vor dem Fix | 1 | Sieben Tests: fünf bestanden, zwei fehlgeschlagen in 7.173 Sekunden; expliziter `TMPDIR`- und Compilerfehlerfall stoppten beide mit fehlendem `RUNNER_TEMP`, Exit 2. | Lokale Framework-Prüfung |
| Derselbe Regressionsbefehl nach dem Fix | 0 | Alle sieben bestanden in 5.335 Sekunden. | Lokale Framework-Prüfung |
| `sh -n` des Consumers | 0 | POSIX-Shellsyntax bestanden. | Lokale Framework-Prüfung |
| `update-inventory-bindings.py --check` | 0 | `INVENTORY_BINDINGS_VERIFIED`; Inventar unverändert. | Lokale Framework-Prüfung |
| Nativer Archivgenerator und `update-test-archive.py --check` | 0 | Archiv regeneriert und geprüft; On-demand-Definitionen von 8469 auf 8476, unverändertes `inventory_sha256`. | Lokale Framework-Prüfung |
| Sechs bestehende Wartungstests und ein bestehender Namespace-Umgebungstest | 0 | Alle sieben bestanden in 0.079 Sekunden. | Lokale Framework-Prüfung |
| `sonar analyze secrets` für Quellen, Tests und Archiv | 0 | Ausgewählte Eingaben bestanden; rohe Scannerausgabe unterdrückt. | Lokale Framework-Prüfung |

Die Prüfungen verwendeten die Framework-eigene Virtualenv (`PYTHON`) auf vorhandenem WSL-Python `3.13.7`, Parent-Revision `ab7a32ab464a3dd8fe119b10d3936acd4b4ae557` und die native Framework-Basis `03f50ce2f6854ad9a02227dfc5939ded23e838f6` zuzüglich Aufgabenänderungen. `ON_DEMAND_TESTS=1`, explizites `TEST_ROOT`/`PYTHONPATH` und externer temporärer Ausgabespeicher wählten den Testkontext. Das unabhängige Quellreview meldete keine Befunde. Der historische fehlgeschlagene Lauf belegt das Ergebnis dieser Reparatur nicht.

## Sicherheitsauswirkung

Die Reparatur erhält die Anforderung eines explizit übergebenen temporären Roots und ergänzt keinen impliziten Systemverzeichnis-Fallback. Der Fallback gilt nur bei ungesetzter Variable: Ein leerer oder nicht existierender primärer Root wird nicht still ersetzt. Negativtests erhalten die Ablehnung fehlender Roots, Compilerstatus `23` und Bereinigungsverhalten. Namespace-Isolation, Auswahl vertrauenswürdigen Codes, Berechtigungen und MRTS bleiben unverändert. Security-Remediation oder Runtime-Qualifikation werden nicht behauptet.

## Dokumentation und Runtime-Evidenz

Dieses englisch-deutsche Record-Paar dokumentiert denselben ausgewählten Umfang und dieselben Einschränkungen. Der fehlgeschlagene gehostete Lauf ist ausschließlich diagnostische Evidenz. Für den geänderten Consumer werden weder erfolgreiche Connector-Runtime noch vollständige gehostete Updater-Ausführung behauptet.

## Nicht ausgeführte Prüfungen

Ein vollständiger gehosteter Updater-Neulauf, vollständiger `quick-check`, native C-Compiler-/Runtime-Ausführung und kanonische Python-`3.15`-CI liefen für diesen Snapshot nicht. Die fokussierten Shelltests verwenden einen Compilerstub und belegen ausschließlich das genannte Consumer-Verhalten. Finale Record-Schema-, Secrets-Prüfungen der geänderten Records und Whitespace-/Diff-Prüfungen folgen der letzten Dokumentationsänderung separat.

## Einschränkungen und Restrisiko

Der Consumer verlässt sich auf einen vom Aufrufer übergebenen geeigneten expliziten privaten Root. Diese Reparatur qualifiziert nicht jeden Namespace-Lifecycle und jede Connector-Runtime. Auslieferungsidentität und aktuelle gehostete Prüfungen sind getrennt zu bewerten; Parent-Gitlink-Update oder Framework-Merge werden nicht behauptet.

## Finaler Diff- und Review-Status

Das unabhängige Quellreview meldete keine Befunde. Alle sieben neuen Shelltests, sieben ausgewählte bestehende Tests, Consumersyntax, Inventarvalidierung und generierte Archivprüfungen bestanden. Quellen, Tests und Archiv bestanden Secrets-Scans. Finale Secrets-Scans der geänderten Records, Schema-Prüfung des Record-Paars und Whitespace-/Diff-Prüfungen folgen dieser letzten Dokumentationsänderung. Framework-Delivery bleibt von Parent- und MRTS-Delivery getrennt; gehostete CI- oder Merge-Ergebnisse werden nicht behauptet.
