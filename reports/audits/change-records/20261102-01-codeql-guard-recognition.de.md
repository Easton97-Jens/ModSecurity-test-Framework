# Change Record: Erkennung bestehender Grenzprüfungen durch CodeQL

**Sprache:** Deutsch | [English](20261102-01-codeql-guard-recognition.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change ID | 20261102-01-codeql-guard-recognition |
| UTC-Datum | 2026-11-02 |
| Framework-Basisrevision | `bc08ee7ca413012da189902b8b9c61c98151e76b` |
| Issue oder Pull Request | Folgeänderung zu [#151](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/151); Folge-PR zum Entwurfsstand dieses Nachweises noch nicht erstellt |

## Motivation und Problemstellung

Der Nutzer hat die native Erkennung bestätigter Korrekturen ausgewählt, ohne Meldungen zu verwerfen. Nach #151 meldet CodeQL weiterhin #16, #25 und #26 trotz der geprüften vollständigen Target- und begrenzten Header-Zulassung. Die Änderung ergänzt ausdrückliche Schutzmaßnahmen an den Senken, die die aktiven Modelle erkennen. Sie belegt keine neue Runtime-Schwachstelle in der bereits geschützten Implementierung.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-eigene Traefik-Backend-Artefakte für Requests/Responses und der HTTP-Header im Lighttpd-Supervisor-Test. Parent-Produktcode und Parent-Gitlink bleiben unverändert; MRTS bleibt `default_read_only`. Für die übrigen 23 Meldungen gelten die Einzelbewertungen im [vorherigen Nachweis](20261101-04-codeql-boundaries.de.md).

## Akzeptanzkriterien

Beide vollständigen Target-Prüfungen vor Standardbibliothek-Normalisierung, 100-continue und Body-Lesen erhalten. Beide tatsächlichen Artefaktziele vor dem Body-Lesen gegen das mit Separator abgeschlossene Backend-Root prüfen. Alle bisherigen 16 Fälle, zusätzliche kanonische Namen, Sonderantworten und Receipt-Hashes erhalten. Ungültige Transaktionskennungen weiterhin mit 400 verwerfen und alle zugelassenen/erzeugten Kennungen erhalten. Kandidatenbezogene CodeQL-Evidenz erheben, dass die drei betroffenen Ergebnisse verschwinden und die übrigen 23 erhalten bleiben. Regeln, Kategorien, Berechtigungen, Ausschlüsse, echte private Namespace-Tests und Standardauswahl erhalten. Automatische Schließung auf Master erfordert einen separat autorisierten Merge und anschließende Master-Analyse.

## Untersuchte Alternativen

Pauschales Verwerfen, Unterdrückungen, Query-Änderungen und Scanner-Ausschlüsse belegen keine native Erkennung und liegen außerhalb der ausgewählten Option. Entfernen früher Guards oder Normalisieren fehlerhafter Targets zu zulässigen Namen ändert den bestehenden Zulassungsvertrag. Eine endliche Liste mit 16 Namen verwirft legitime kanonische Namen. Keiner dieser Ansätze wird verwendet.

## Implementierungsentscheidung

Nach strenger Target-Zulassung absolute Request- und Response-Artefaktpfade mit `os.path.abspath` berechnen. Jeder vollständige Pfad muss mit `os.path.abspath(root) + os.sep` beginnen; der abschließende Separator schließt benachbarte Pfade mit gleichem Präfix aus. Tatsächliche Schreiboperationen verwenden `Path` aus diesen geprüften Pfaden. Beide Prüfungen liegen vor dem Body-Lesen. Dies ist lexikalische Begrenzung, keine Garantie gegen Symlink-Ausbrüche.

Zulassung über `[A-Za-z0-9._:-]{1,128}` und die 400-Antwort bleiben erhalten. Bei `send_header` entfernen zwei ausdrückliche `replace`-Aufrufe CR und LF als zweite Serialisierungsgrenze. Jede Kennung, die diese Senke über die bisherigen Zulassungs-/Erzeugungspfade erreicht, bleibt unverändert. Ungültige Eingaben werden weiterhin verworfen und nicht zu zulässigen Werten bereinigt.

Basisanalyse `2073372882` verwendete CodeQL CLI `2.27.1`, `python-queries` `1.8.11` und `python-all` `7.2.6`: 26 Ergebnisse aus 43 Regeln. Modell-Quellrevision: `6e9f9e38390175c41b99070a423c875f450759ca`. Relevante Primärquellen sind [Header-Sanitizer](https://github.com/github/codeql/blob/6e9f9e38390175c41b99070a423c875f450759ca/python/ql/lib/semmle/python/security/dataflow/HttpHeaderInjectionCustomizations.qll#L62), [Standardbibliothek-Modelle](https://github.com/github/codeql/blob/6e9f9e38390175c41b99070a423c875f450759ca/python/ql/lib/semmle/python/frameworks/Stdlib.qll#L1118) und [Pfadinjektions-Query-Logik](https://github.com/github/codeql/blob/6e9f9e38390175c41b99070a423c875f450759ca/python/ql/lib/semmle/python/security/dataflow/PathInjectionQuery.qll). Modellinspektion allein ist keine Scan-Evidenz für den Kandidaten.

## Geänderte Dateien und Tests

- `connector_suite/adapters/traefik/harness/i12_auth/backend.py`: zwei ausdrücklich geprüfte Ziele und Schreiboperationen mit diesen Zielen.
- `tests/security_regression/test_traefik_auth_backend.py`: sechste Methode prüft vier kanonische Namen außerhalb des Katalogs, darunter Ein-Zeichen- und 23-Zeichen-Grenzen, tatsächliche Artefaktbytes sowie Receipt-Identität/-Hash.
- `connector_suite/modsecurity_connector_tests/test_trusted_lighttpd_runtime_supervisor.py`: Schutz bei Header-Serialisierung und erweiterte Raw-HTTP-Regression. Ungültige Werte umfassen leere, 129 Byte lange, gefaltete, SOH-, DEL- und Latin-1-Kennungen; unverändert gültige Werte die Längen 1, 8 und 128. Bestehende Kontrollen erzeugter Probes und zur Ablehnung gültiger Reflexion bleiben erhalten.
- Native Generatoren aktualisieren eine Backend-Bindung, Archiv-Quellidentitäten/neue Methode und Migrationsansichten. Geparster Inventarvergleich zeigt genau eine Quell-SHA-Änderung; jeder Selektor, Fall und jede Product-Quellauswahl bleibt erhalten.
- Dieses Change-Record-Paar ist die Dokumentationsänderung. Bestehende CI entdeckt sechs Backend-Methoden plus die unveränderten sieben strengen Selektoren: 13 Methoden/114 expandierte Szenarien. Native Erzeugung erhält 100 Standardfälle/80 Ausführungen, 2.586 optionale Fälle/1.140 Ausführungen, 528 feste/235 dynamische Quellen und alle 1.993 ursprünglichen IDs.

## Befehle und Ergebnisse

Alle lokalen Befehle verwenden RTK. `FRAMEWORK_ROOT` bezeichnet den Aufgaben-Worktree, `CONNECTOR_ROOT` den unveränderten Parent, `PYTHON` den Framework-eigenen Interpreter und `RUN_ROOT` den externen Evidenz-Root für Run-ID `framework-codeql-recognition-20261102`. Keine Rohbodys oder vollständigen Logs werden hier abgelegt.

| Befehl oder beobachtetes Verfahren | Exit-Code | Ergebnis | Evidenz |
| --- | --- | --- | --- |
| `rtk bypass env PYTHONPATH=${FRAMEWORK_ROOT}:${FRAMEWORK_ROOT}/connector_suite TMPDIR=${RUN_ROOT} PYTHONDONTWRITEBYTECODE=1 ${PYTHON} -m unittest discover -s tests/security_regression -p test_traefik_auth_backend.py -v` | 0 | Sechs Backend-Methoden bestehen, einschließlich vier Namen außerhalb des Katalogs | Aktueller lokaler Lauf des Aufgabenkoordinators |
| Fokussierte Ausführung von `test_probe_handler_rejects_folded_and_control_transaction_headers`, `test_fixed_probe_rejects_reflected_or_reused_transaction_identifier` und `test_fixed_probes_cover_control_detection_and_alternate_negative` in `modsecurity_connector_tests.test_trusted_lighttpd_runtime_supervisor.TrustedLighttpdRuntimeSupervisorTest` durch RTK und den Framework-Interpreter | 0 | Drei Methoden bestehen; sechs fehlerhafte und drei gültige Grenzwerte durch die erweiterte Methode abgedeckt | Aktueller lokaler Lauf des Aufgabenkoordinators |
| Gleicher expliziter Framework-/Parent-Kontext, `-m unittest -v` für die drei vollständigen Supervisor-/NGINX-/Lighttpd-Module | 0 | 84 Methoden: 81 bestehen, drei ausdrückliche BLOCKED-Namespace-Skips in normaler Sandbox | Aktueller lokaler Lauf |
| Exakter Runner mit sieben Selektoren aus bestehender CI, durch äußere User-Namespace mit Eigentümerabbildung in genehmigter Hostausführung | 0 | Sieben Methoden bestehen ohne Skips, einschließlich aller drei echten privaten Netzwerk-Wildcard-Fälle | RUN_ROOT/ci-selected-regressions.py |
| Native `update-inventory-bindings.py --apply`, `update-test-archive.py`, `build-migration-map.py`; alle drei `--check`; geparster Inventarvergleich | 0 | Erzeugung/Frische bestehen; nur ein Bindungshash geändert; Standard-/optionale Auswahl und Zählwerte oben erhalten | Aktueller lokaler Lauf |
| Syntaxkompilierung drei geänderter Python-Quellen; beide nativen CI-Sicherheitsvertragsskripte | 0 | Alles besteht; bestehende Workflow-Dateien unverändert | Aktueller lokaler Lauf |
| `rtk make check-documentation check-canonical-common-pins check-canonical-python-pins check-canonical-workflow-pins check-canonical-crs-contract-pins PYTHON=${PYTHON} FRAMEWORK_ROOT=${FRAMEWORK_ROOT} BUILD_ROOT=${RUN_ROOT}/build` | 0 | Dokumentations-/Link-/Pfad-/Change-Record-Prüfungen und alle vier kanonischen Pinprüfungen bestehen | Aktueller lokaler Lauf |
| Bestehender CodeQL-Workflow auf Aufgabenbranch ausgelöst, ohne Workflow-Änderungen | Noch nicht beobachtet | Kandidatenbezogene Differenz von drei Ergebnissen ausstehend | Aktuelle Aufgabe |

## Sicherheitsauswirkung

Die strengen Zulassungskontrollen aus #151 bleiben erhalten. Zusätzliche ausdrückliche Senkenschutzmaßnahmen verbessern die Analyzer-Erkennung und bilden eine zweite Grenze an tatsächlicher Schreib-/Headerausgabe. Absolute Pfadnormalisierung erfolgt erst nach vollständiger Target-Zulassung; Traversal oder kodierte fehlerhafte Targets werden dadurch nicht zugelassen. Der Header-Schutz schwächt die bisherige Ablehnung von Faltung, Steuerzeichen, Nicht-ASCII oder zu langen Werten nicht ab. Keine Änderung an Scanner-Status, Regel, Ausschluss, Kategorie oder Berechtigung.

## Dokumentation und Runtime-Evidenz

Dieses vollständige EN/DE-Paar dokumentiert die reine Framework-Folgeänderung. Aktuelle Evidenz sind begrenzte Backend-/Parser-/Loopback-Unittests, echte isolierte Kernelprüfungen und die Inspektion der Basismodelle. Die normale Sandbox blockiert drei Namespace-Fälle ausdrücklich; genehmigte Hostausführung besteht dieselben Fälle innerhalb des exakten Runners mit sieben Selektoren ohne Skips. Keine Connector-Host-/Profilqualifikation oder Promotion-Evidenz erzeugt. Parent-Pin unverändert; MRTS schreibgeschützt behandelt. Keine Meldungsverwerfung, Master-Integration oder automatische Zusammenführung.

## Nicht ausgeführte Prüfungen

Zum lokalen Commit stehen kandidatenbezogene Hosted-CI/CodeQL/Sonar noch aus; Ergebnisse für den exakten Head werden in PR-Beschreibung und externer Lifecycle-Evidenz nachgeführt. Frühere #151-Prüfungen sind keine Evidenz für diesen Kandidaten. Keine vollständige Connector-Suite oder historische Traefik-Kampagne für diese begrenzte Folgeänderung ausgeführt.

## Einschränkungen und Restrisiko

`abspath` und Separator-Präfixprüfungen sind lexikalisch und lösen keine Symlinks auf; dieser Nachweis behauptet keine weitergehende Dateisystemisolation. Ein modellkompatibles Muster reicht vor tatsächlicher Kandidatenanalyse nicht als Schließungsnachweis. Die 15 dokumentierten Fluss-Gegenbeispiele, fünf eingeschränkten TLS-Befunde und drei absichtlichen Wildcard-Befunde bleiben außerhalb dieser gezielten Änderung für drei Meldungen. Ihr Fortbestehen wird erwartet. Branch-Scan-Evidenz und tatsächlicher Master-Meldungsstatus sind getrennt: Master kann fehlende Ergebnisse erst nach separat autorisierter Integration und erfolgreicher Folgeanalyse als `Fixed` markieren. Keine Behauptung, alle 26 Meldungen zu schließen.

## Finaler Diff- und Review-Status

Frischer unabhängiger Review fand keinen konkreten Bypass oder Fehler im legitimen Verhalten der drei Quell-/Testdateien. Er hält die rein lexikalische Begrenzungsannahme gesondert fest und behauptet keinen Scanner-Erfolg. Der Koordinator prüfte native generierte Änderungen, bestätigte identisches Inventar bis auf einen Backend-Hash und beobachtete bestandene lokale Prüfungen sowie sauberen Whitespace; Hosted-Ergebnisse für den exakten Head bleiben bis zur Prüfung des tatsächlichen Branch-Scans und PRs ausstehend. Keine Secrets, Secret-Trefferwerte, Zugangsdaten, rohen Request-/Response-Bodys oder vollständigen Logs enthalten.
