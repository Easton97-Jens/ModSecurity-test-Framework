# Änderungsnachweis

**Sprache:** Deutsch | [English](20261101-01-host-execution-context.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261101-01-host-execution-context |
| UTC-Datum | 2026-11-01 |
| Framework-Basisrevision | d503ddbea1a3b6df7766edc247b0a9886ff10668 |
| Issue oder Pull Request | Record des Implementierungsstands; separate PR-Lieferung und reguläre Master-Integration sind im Folgeauftrag autorisiert. Der Repository-PR enthält den aktuellen Lieferstand. |

## Motivation und Problemstellung

Die Connector-Runtime-Vorbereitung kann UID 0 in einer Sandbox sehen, ohne die für einen realen Root-Master-/Worker-Wechsel nötigen Abbildungen oder Capabilities. Ein Voraussetzungsmangel muss vor dem gewählten Host-Runtime-Start von Connector-Verhalten unterschieden werden.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-eigener Hostruntime-Preflight, begrenzte Kontextproben, NGINX-Smoke-/Lifecycle- und Envoy-Start-/Runtime-Harness-Einstiegspunkte. Parent-Connector-Implementierung und Promotion bleiben externe Abhängigkeiten. Geschützte Broker-Namespace-/Vertrauensverträge bleiben unverändert. MRTS bleibt schreibgeschützt; ein Parent-Gitlink-Update ist nicht Teil dieser Framework-Änderung.

## Akzeptanzkriterien

Explizite Profilanforderungen erzeugen begrenzte Evidenz je Prüfung; reale Kindprozess-Credentials bestimmen Worker-Datei-/UDS-Proben; fehlende Abbildungen/Capabilities ergeben einen Umgebungsblocker; bestehende Preflight-Evidenz bleibt `runtime_status=NOT_RUN`. EN/DE-Anleitungen beschreiben frische Sitzungsprüfungen und Genehmigungsgrenzen. Runtime-Abschluss benötigt separat beobachtete Host-Evidenz.

## Untersuchte Alternativen

Aus UID 0 abgeleitete Berechtigung, Worker-Zugriffsprüfungen im Elternprozess, fehlende Pfade als belegte Verweigerung, stillschweigende Herabstufung von Root-Master-Profilen und automatisches Verlassen der Sandbox würden den Vertrag schwächen. Der gewählte Ansatz prüft explizite Anforderungen und stoppt, wenn sie fehlen.

## Implementierungsentscheidung

Die bestehende Framework-CLI erhält einen Kontextmodus und explizite Worker-/Root-/chown-/Pfad-/UDS-Anforderungen. Binary-Preflight und Runtime-Aussagen bleiben getrennt. Kindprozesslaufzeit und Metadaten begrenzen, nicht vertrauenswürdige Pfade ablehnen, Zusatzgruppen verifizieren und nur selbst erzeugte Probenartefakte entfernen. Host-Genehmigung pro Befehl bleibt außerhalb des Codes; dauerhafte Dienstkonfiguration bleibt unverändert.

## Geänderte Dateien und Tests

Die Lieferprüfung verlangt außerdem null neue SonarQube-Cloud-Issues und Security Hotspots am endgültigen Head. Ein früheres bestandenes Quality Gate meldete dennoch sieben neue Wartbarkeitsbefunde (vier komplexe Funktionen, eine verschachtelte Bedingung und zwei verschachtelte Kontextmanager). Der Folgecommit trennt Worker-Auflösung, Pfadoperationen, Kindprozess-Berichtstransport und Anforderungsprüfungen in begrenzte Helper und kombiniert Kontextmanager; Identitäts-, Deny-, Timeout- und Cleanup-Verhalten bleiben erhalten. Befunde werden nicht unterdrückt und Analyseregeln nicht geändert. Die endgültigen Serverzahlen werden anhand der aktuellen PR-Analyse geprüft.

`connector_suite/modsecurity_connector_ci/runtime/common/execution_context.py`, `hostruntime_preflight.py`, `connector_suite/modsecurity_connector_tests/test_execution_context_preflight.py`, NGINX-Smoke-/Lifecycle-Einstiegspunkte und Envoy-Start-/Runtime-Harnesses. Tests prüfen Kindprozessidentität, Schreiben, UDS, realen Worker-Wechsel bei verfügbaren Voraussetzungen, fehlende Capabilities/Abbildungen, Symlinks, Verweigerung, vorhandene Sockets, Timeout/Abholen, geerbten Daemon-Kontext mit setpriv-Launcher und CLI-Evidenzsemantik. Quellenbindung: `connector_suite/config/testing/active-cases.json` behält dieselben Selektoren/Fälle (100 aktive Standardfälle), aktualisiert drei Harness-Digests mit `update-inventory-bindings.py --apply` und bindet die zwei Preflight-Module an fünf betroffene Ausführungen. Die daemon-Launcher-Fixture legt Evidenz nun unter ihrem ausgewählten Testroot statt einem datierten Taskverzeichnis ab. Dokumentation: `docs/host-execution-context.md` und deutsche Begleitdatei sowie dieses Nachweispaar.

## Befehle und Ergebnisse

Der Koordinator des Implementierungsstands führte den expliziten Framework-Interpreter über `rtk bypass env PYTHONPATH=<Framework>:<Framework>/connector_suite TEST_ROOT=<Framework> CONNECTOR_ROOT=<Parent> CONNECTOR_REVISION=a6001a09210bc9516256d28af5da45d73f0fe2f2 <Framework-interpreter> -P -m unittest -v` aus: Die zehn Methoden in `test_execution_context_preflight` sowie drei ausgewählte bestehende Binary-Preflight-Regressionen bestanden (13 Tests im Hostkontext). Sieben gezielte NGINX-Pfad-/Orchestrierungsprüfungen bestanden, darunter die Sperre vor Projektion, Configtest und Kindprozessstart. Exakte Selektoren/Ergebnisse liegen in `private/final-preflight-tests.log` und `private/final-integration-tests.log` unter dem Task-Evidenzroot. Shell-Syntax (drei Skripte), Python-AST (fünf geänderte Module), begrenztes Gitleaks-Scanning (16 geänderte Quelldateien, keine Funde) und `git diff --check` beider Repositories bestanden. Framework `rtk make check-bilingual-docs check-doc-links check-change-records PYTHON=<Framework-interpreter> BUILD_ROOT=<task>/private/docs-checks TMP_ROOT=<task>/private/docs-checks/tmp LOG_ROOT=<task>/private/docs-checks/logs` bestand. Parent-V3.2-Struktur und die geänderten Kontext-Digests bestanden; die vollständige Inheritance-Prüfung behält unabhängige Altfehler.

Die Lieferverifikation wiederholte alle 13 Preflight-Tests im genehmigten Hostkontext und alle sieben gezielten Integrationsprüfungen in einem frischen externen Verzeichnis: Beide Auswahlen endeten mit Exit 0. `update-inventory-bindings.py --check` meldet `INVENTORY_BINDINGS_VERIFIED`; die Helper-Bindungen erhalten alle vorherigen Quellreferenzen und Fall-/Selektorsemantik. Lieferlauf: `20261101-context-delivery`. Neue private Logs/Evidenz bleiben außerhalb von Git.

## Sicherheitsauswirkung

Die Änderung stärkt Voraussetzungenprüfung und Evidenzklassifizierung; sie ist keine Behebung einer validierten Schwachstelle. Sie gewährt keine Host-Privilegien, verändert kein geschütztes Broker-Vertrauen und schwächt keine Isolation privater Pfade. Geheimnisse, Rohpayloads und Umgebungsdumps sind nicht enthalten.

## Dokumentation und Runtime-Evidenz

Die zweisprachige Anleitung ist über Framework- und Parent-`.codex/context/index.md` geroutet. Task-Evidenz: `<implementation-evidence-root>/private/verification.json`. Der reale Parent-NGINX-Aufruf `multiple_sequential_requests` nutzte den bestehenden nativen Sequenztreiber: Konfiguration/Readiness, HTTP 200/403/200, Deny-Regel `1100001`, tatsächlicher Master UID/GID 0 und Worker UID/GID 65534, danach verifiziertes Prozess-/Listener-Cleanup. Der zusätzliche reale `setpriv`-Launcher führte den aktuellen Preflight-Quellstand als daemon UID/GID 1 ohne Zusatzgruppen mit erfolgreichen Datei-/privaten UDS-Proben aus. Sein Ergebnis behält `runtime_status=NOT_RUN`. Alle 150 gespeicherten relevanten Parent-Produktquellhashes stimmen mit dem wiederverwendeten NGINX-Build überein; dessen historische Build-Revisionen weichen vom aktuellen HEAD ab. Das ist auf Quellhashes begrenzte Runtime-Evidenz, kein Exact-Head-Neubuild oder Broker-Attest.

## Nicht ausgeführte Prüfungen

Keine gehostete Envoy-Runtime: Es war kein Envoy-Programm verfügbar. Die Hooks erhielten Quell-/Syntaxprüfungen und gemeinsame UDS-Grenzregressionen. Vollständiges Lint/CI, historische Gesamtmatrizen, geschützte Broker und MRTS wurden nicht ausgeführt. Ruff fehlt in der Framework-Umgebung; es wurden keine Pakete installiert. Parent-/Framework-Inheritance meldet weiterhin bestehende unabhängige veraltete Digests/nicht registrierte lokale Policy; der Framework-Konfigurationsprüfung fehlt bereits zuvor `.codex/config.toml`. Die geänderten Parent-Index-/Preflight-Digests wurden aktualisiert und unabhängig geprüft, ohne MRTS-Pins zu verändern.

## Einschränkungen und Restrisiko

Ein Profillabel leitet keine Anforderungen ab. Frische Proben bleiben je tatsächlichem Launcher und Sitzung erforderlich. Der ursprüngliche historische Prozess ist nicht verfügbar; derselbe Namespace-/Capability-Blocker mit nur einer Identität wurde jetzt reproduziert und mit einem genehmigten Hostkontext verglichen. `systemd-detect-virt` meldet in beiden Kontexten KVM und Containerisolation nur in der Befehlssandbox. UDS-Clientproben nutzen nach Fixierung des Serververzeichnisses den tatsächlichen Pfad; ein Preflight belegt weiterhin nicht die pfadspezifische Policy jedes Connector-Programms. Die unabhängige Prüfung entdeckte Traversierungs- und separate UDS-Root-Probleme; diese wurden korrigiert und gezielt getestet. Die abschließende Read-only-Prüfung fand keinen verbleibenden wesentlichen Befund.

## Finaler Diff- und Review-Status

Bei der ursprünglichen Implementierungsübergabe bestanden begrenzte Diff- und Secret-Prüfungen; die Änderungen waren uncommittet. Der Folgeauftrag autorisiert Framework-PR-Lieferung und reguläre Integration des exakt geprüften Heads vor einem separaten Connector-Pin-PR. Aktuelle PR-/Head-/CI-/Merge-Fakten stehen in den Repository-PR-Metadaten; historische lokale Beobachtungen oben sind keine CI-Aussagen zum aktuellen Head. MRTS bleibt unverändert und private Runtime-Artefakte sind von der Lieferung ausgeschlossen.
