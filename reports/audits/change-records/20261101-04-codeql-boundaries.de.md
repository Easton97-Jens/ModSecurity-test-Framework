# Änderungsnachweis: Framework-CodeQL-Grenzen

**Sprache:** [English](20261101-04-codeql-boundaries.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change ID | 20261101-04-codeql-boundaries |
| UTC-Datum | 2026-11-01 |
| Framework-Basisrevision | `5ef57603a4933f18c988f1f9f32b93f478182440` |
| Integrationsbasis (regulärer Merge in Task-Branch) | `b85280278310f4034af78149ac13671438965c7b` (#150 unabhängig gemergt; Quellenänderungen bewahrt) |
| Issue oder Pull Request | [#151](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/151), `codex/framework-codeql-remediation-20261101`; #147 bereits gemergt, unabhängiger #150 erhalten |

## Motivation und Problemstellung

26 offene GitHub-CodeQL-Meldungen (#3–#28) benötigen getrennte Flussbewertungen. Bestätigt sind Backend-Pfadtraversal und ungeprüfte Headerreflexion; echte Wildcard-Negativtests benötigen nachgewiesene Isolation. Scannerkonfiguration, Unterdrückungen und Meldungsstatus werden nicht verändert.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-eigene Traefik-Testbackend-Artefakte, Lighttpd-Probeheader sowie NGINX-/Lighttpd-Kernel-Negativtests. Parent-Gitlink bleibt unverändert; MRTS bleibt `default_read_only`. Keine Connector-Produktqualifizierung.

## Akzeptanzkriterien

Vollständiges Request-Target vor Body-/Datei-/Receipt-Zugriff prüfen; alle 16 bestehenden Fälle erhalten. Originalangriff auf Basis reproduzieren, korrigiert und mit Umgehungsvarianten prüfen. Header-Kontrollzeichen abweisen; gültige Reflexion weiterhin vom Supervisor ablehnen. Wildcard-Binds nur in nachgewiesener privater Netzwerk-Namespace ausführen. Alle 26 IDs einzeln bewerten; reguläre CI, native Generatoren, EN/DE-Paar und abschließende Prüfungen abgleichen.

## Untersuchte Alternativen

Ein 16-Zeichen-Limit bricht bestehende Fälle (Maximum 23). Nur self.path zu prüfen verliert bereits normalisierte führende Slashes oder Whitespace. Dekodieren, Abschneiden oder Bereinigen wäre mehrdeutig. Wildcard-Mocks würden Kernel-Gegenevidenz entfernen; globale Scanner-Ausnahmen sind nicht gerechtfertigt.

## Implementierungsentscheidung

Raw-Request-Line und do_POST prüfen unabhängig das gesamte Target gegen `/[a-z0-9-]{1,23}`; Ablehnung erfolgt mit 400, auch vor 100-continue. Die begrenzte Grammatik ist keine endliche Fall-Allowlist. Headerreflexion akzeptiert ausschließlich `[A-Za-z0-9._:-]{1,128}`. Gemeinsamer Namespace-Helfer verlangt andere Namespace-Identität und genau `lo`; fehlende Voraussetzungen führen zu ausdrücklichem BLOCKED-Skip vor jedem Wildcard-Bind.

### Einzelbewertung der Meldungen

Zeilen beziehen sich auf die Basis bzw. die bezeichneten Funktionen; Änderungen können Zeilen verschieben. Jede Zeile nennt Quelle, Transformation, Senke, Schutz/Erreichbarkeit und Urteil/Gegenevidenz. Ein lokales Urteil ist keine GitHub-Schließung.

| ID | Quelle → Transformation → Senke | Schutz, Urteil und Evidenz |
| --- | --- | --- |
| #3 | `ci/checks/security/check-security-data-flow-cases.py:30–35` → boolean match `:72` → label diagnostic `:70,:122` | Nur feste Musternamen gelangen nach stderr; Trefferwerte werden nicht eingesetzt. |
| #4 | `connector_suite/adapters/traefik/scripts/runtime_smoke.py:635–645` → fixed socket name `:686` → YAML `socketPath:448` → write `:738` | Serialisiert wird der private Verzeichnis-/Socketpfad, kein Zugangsdateninhalt. |
| #5 | `connector_suite/modsecurity_connector_tests/test_go_version_contract.py:32–56` → static workflow text → temporary write `:60–63` | Keine Auswertung von GitHub-Ausdrücken oder Zugangsdatenabfrage; nur Fixture. |
| #6 | `connector_suite/modsecurity_connector_tests/test_python_version_contract.py:182–190` → checked-in workflow text → temporary write `:187` → `parse_jobs:188` | Öffentliches Programm zur Interpreterprüfung, keine Secret-Auflösung. |
| #7 | `connector_suite/modsecurity_connector_ci/runtime/lifecycle/i12/envoy/test_review_runs.py:137` → inert receipt fixture `:140–143` → `review_runs.client_summary:206`, `event_summary:399` | Geschlossene Ausgabefelder und Enum-Filter schließen synthetischen Marker aus; Assertions :147–150. |
| #8 | `connector_suite/modsecurity_connector_tests/test_update_go_components.py:64–90` → `baseline_go_sum()` → fixture write `:207` | Feste net/sys/text/grpc-Tokens oder öffentliche Go-Prüfsummen; keine Zugangsdaten. |
| #9 | `connector_suite/modsecurity_connector_tests/test_update_go_components.py:64–90` → `baseline_go_sum()` → fixture write `:479` | Gleiche Herkunft aus öffentlicher Prüfsummen-Fixture; keine Zugangsdaten. |
| #10 | `connector_suite/modsecurity_connector_tests/test_update_go_components.py:64–90` → `baseline_go_sum()` → fixture write `:489` | Gleiche Herkunft aus öffentlicher Prüfsummen-Fixture; keine Zugangsdaten. |
| #11 | `connector_suite/modsecurity_connector_tests/test_update_go_components.py:64–90` → `baseline_go_sum()` → fixture write `:516` | Gleiche Herkunft aus öffentlicher Prüfsummen-Fixture; keine Zugangsdaten. |
| #12 | `connector_suite/modsecurity_connector_ci/checks/common/check-python-version-contract.py:2093` → `test_trusted_lighttpd_namespace_dispatch_workflow.py:82–105` forbidden-marker tuple → diagnostic `:110` → checker output | Untersucht wird der literale secrets.-Marker, ohne Auflösung; feste Diagnose. |
| #13 | `connector_suite/modsecurity_connector_ci/checks/common/check-python-version-contract.py:2093` → same fixed marker diagnostic → checker stderr `:2248` | Kein Secret-Wert gelangt nach stderr; Quelle ist das literale Tupel verbotener Marker. |
| #14 | `connector_suite/modsecurity_connector_ci/runtime/common/hostruntime_preflight.py:103–122` → distinct `(Path, reason)` → unpack `:532` → reason-only `_check:534` → bounded JSON `:828` | Gemeldeter Fluss vermischt Tupelelemente; Ausgabe enthält feste Grund-/Statuscodes. |
| #15 | `connector_suite/modsecurity_connector_ci/runtime/broker/nginx_root_broker.py:1884` → validated build root → bundle `:2315` → manifest check `:2371` → directory `:2376` → print `:5046` | Senke gibt einen Verzeichnis-Path aus, keine Zugangsdaten oder Dateiinhalte. |
| #16 | `connector_suite/modsecurity_connector_tests/test_trusted_lighttpd_runtime_supervisor.py` request header → parsed transaction ID → `send_header` | Gefaltete/SOH/DEL-Ausgabe vor Fix bestätigt. Vollständiges ASCII-Token [A-Za-z0-9._:-]{1,128} verwirft jetzt mit 400 vor Reflexion; echte Loopback-Rot/Grün-Prüfung. |
| #17 | `connector_suite/adapters/haproxy/harness/i12_companion_host.py:176` default verified client → fixed loopback → `wrap_socket:182`, localhost | Keine spätere Abschwächung; CERT_REQUIRED und Hostnamenprüfung. Altes TLS auf aktuellem Host verworfen; nur eingeschränkte Gegenevidenz (TLS unten). |
| #18 | `connector_suite/adapters/haproxy/harness/i12_native_sequences.py:129` default verified client → loopback `connect:80–82` with fixed hostname | Keine spätere Abschwächung; CERT_REQUIRED und Hostnamenprüfung. Altes TLS auf aktuellem Host verworfen; nur eingeschränkte Gegenevidenz. |
| #19 | `connector_suite/modsecurity_connector_tests/test_envoy_transport_hardening_contract.py:54` default server context → certificate → TLS socket `:56` | Keine spätere Abschwächung; altes TLS auf aktuellem Host verworfen. Server-CERT_NONE belegt keine Clientprüfung; eingeschränkte Gegenevidenz. |
| #20 | `connector_suite/modsecurity_connector_tests/test_haproxy_htx_transaction_id.py:120` default server context → certificate `:121` → TLS socket `:122` | Keine spätere Abschwächung; altes TLS auf aktuellem Host verworfen; nur eingeschränkte Gegenevidenz. |
| #21 | `connector_suite/modsecurity_connector_tests/test_haproxy_i12_companion_host.py:36` default server context → certificate `:37` → accepted-socket wrap `:41` | Keine spätere Abschwächung; altes TLS auf aktuellem Host verworfen; nur eingeschränkte Gegenevidenz. |
| #22 | `connector_suite/adapters/lighttpd/tests/test_backend_close_harness_contract.py` IPv6-wildcard negative test → real :: bind → Linux no-listener guard | Gleiche Namespace-/Interfaceprüfung; beide IPV6_V6ONLY-Einstellungen und Abwesenheit nach Schließen bleiben geprüft; isolierter Test besteht. |
| #23 | `connector_suite/modsecurity_connector_tests/test_nginx_port_cleanup_probe.py` wildcard-listener negative test → real 0.0.0.0 bind → cleanup probe | Echtes Wildcard-Verhalten bleibt; nachgewiesen andere private Netzwerk-Namespace mit genau lo begrenzt jetzt Testkörper. Isolierter Kerneltest besteht. |
| #24 | `connector_suite/modsecurity_connector_tests/test_nginx_port_cleanup_probe.py` dual-stack negative test → real :: bind → reuseaddr/cleanup probe | Gleiche geschlossene Namespace-/Interfaceprüfung; EADDRINUSE und Freigabe nach Schließen bleiben geprüft; isolierter Test besteht. |
| #25 | `connector_suite/adapters/traefik/harness/i12_auth/backend.py` raw request target → self.path.lstrip('/') → request-body artifact write | Überschreiben externen Sentinels auf Basis bestätigt. Vollständige Raw-Target-/do_POST-Prüfungen liegen jetzt vor Body-/Datei-/Receipt-Operationen; Original und alternative Umgehungen verworfen. |
| #26 | `connector_suite/adapters/traefik/harness/i12_auth/backend.py` raw request target → same name → response-body artifact write | Gleiche bestätigte Pfadgrenze und gemeinsamer Fix; getrennte Request-/Response-Sentinels bleiben nach Fix unverändert. |
| #27 | `connector_suite/adapters/traefik/harness/i12_auth/auth_proxy.py:35` prefix/nonempty alphanumeric-hyphen validation → name `:37` → .sample.raw `:38` | Keine Separatoren, Punkte oder Prozentkodierung zugelassen; kein späteres Dekodieren. Traversal über geprüfte Identität unerreichbar; neun fehlerhafte Suffixkontrollen bestehen. |
| #28 | `connector_suite/adapters/traefik/harness/i12_auth/auth_proxy.py:35–37` validated unchanged name → .receipt.json `:55` | Gleiche Pfadbegrenzung; Prüfung folgt begrenztem Body-Lesen, daher keine Zusage vor Body-Zugriff. |


## Geänderte Dateien und Tests

- `connector_suite/adapters/traefik/harness/i12_auth/backend.py`: zwei Target-Grenzprüfungen.
- `tests/security_regression/test_traefik_auth_backend.py`: fünf Methoden prüfen 57 ungültige direkte Handler-Targets, ein echtes externes Sentinel-Szenario, 16 Raw-Parser-Targets, alle 16 gültigen Katalogfälle und vier echte Loopback-Requests. Assertions erhalten Request-/Response-Artefakte, Receipt-Hashes, Status/Header, p3-deny, p4-safe, die große 40.019-Byte-Antwort und das observer-abort-Längenverhalten.
- `connector_suite/modsecurity_connector_tests/test_trusted_lighttpd_runtime_supervisor.py`: begrenztes reflektiertes Token und echte Regression für fehlerhafte Header; bestehende Ablehnung gültiger Reflexion bleibt erhalten.
- `modsecurity_test_framework/private_network_test.py`, `connector_suite/modsecurity_connector_tests/test_nginx_port_cleanup_probe.py`, `connector_suite/adapters/lighttpd/tests/test_backend_close_harness_contract.py`: Isolationshelfer, echte Wildcard-Regressionen sowie geschlossene Prüfungen gleicher Namespace/fremdes Interface.
- `.github/workflows/ci-findings-regressions.yml` registriert im bestehenden Workflow fünf Backend-Methoden plus sieben explizite Selektoren: zwölf Methoden/104 expandierte Szenarien für diese Regressionen, davon acht neue Methoden. Jeder Skip schlägt fehl; Standardauswahl bleibt 100 Fälle/80 Ausführungen. Der CI-Launcher bildet UID/GID 0 einer äußeren User-Namespace auf Host-UID/GID des Checkout-Eigentümers ab. Verschachtelte private Netzwerk-Namespaces behalten diese Dateisystemidentität und können private Runner-Verzeichnisse lesen; Namespace- und Interfaceprüfungen bleiben vor Wildcard-Binds verpflichtend.
- Native Bindings aktualisieren eine Backend-Quelle. Archiv-Neugenerierung ergänzt acht neue Methoden dieser Aufgabe. Die zehn Host-Preflight-Definitionen und eine Sequenz-Methode aus #147 sind inzwischen durch den unabhängig gemergten #150 in der Integrationsbasis enthalten und werden bewahrt. Optionale Migrationszuordnung: 2.586 Fälle/1.140 Ausführungen, 528 feste/235 dynamische; 1.993 IDs erhalten.

## Befehle und Ergebnisse

Alle lokalen Befehle verwenden RTK. `FRAMEWORK_ROOT` bezeichnet den Framework-Worktree, `CONNECTOR_ROOT` den unveränderten Parent, `PYTHON` den Framework-eigenen Interpreter und `RUN_ROOT` den externen Evidenz-Root für Run-ID `framework-codeql-20261101`. Logs und temporäre Artefakte bleiben extern.

| Befehl | Exit-Code | Kurzergebnis | Run-ID oder freigegebener Evidenzpfad |
| --- | --- | --- | --- |
| `rtk bypass env TMPDIR=${RUN_ROOT} PYTHONPATH=${FRAMEWORK_ROOT} PYTHONDONTWRITEBYTECODE=1 ${PYTHON} -m unittest discover -s tests/security_regression -p test_traefik_auth_backend.py -k literal_traversal -v` gegen unverändertes Backend | 1 | Erwartetes Rot: kontrollierter externer Sentinel überschrieben | framework-codeql-20261101; begrenzte Reproduktion, keine Hostdateien als Ziel |
| Gleiche Backend-Discovery ohne `-k literal_traversal`, korrigierte Quelle | 0 | Fünf Methoden bestehen; Variantenanzahlen oben | framework-codeql-20261101 |
| `rtk bypass env PYTHONPATH=.:connector_suite ON_DEMAND_TESTS=1 CONNECTOR_ROOT=${CONNECTOR_ROOT} CONNECTOR_REVISION=2abad408cae7e5a103d12a9a9e432129bfe0468f TEST_ROOT=${FRAMEWORK_ROOT} TMPDIR=${RUN_ROOT}/header-listeners PYTHONDONTWRITEBYTECODE=1 ${PYTHON} -m unittest -v modsecurity_connector_tests.test_trusted_lighttpd_runtime_supervisor modsecurity_connector_tests.test_nginx_port_cleanup_probe connector_suite.adapters.lighttpd.tests.test_backend_close_harness_contract` | 0 | 84 Tests: 81 bestehen, drei ausdrückliche BLOCKED-Skips im normalen Kontext | framework-codeql-20261101/header-listeners/focused-modules.log |
| Gleiche Umgebung, drei Wildcard-Selektoren aus `framework-codeql-20261101/header-listeners/result.md`, genehmigte Hostausführung | 0 | Drei echte isolierte Wildcard-Tests bestehen; keine Skips | framework-codeql-20261101/header-listeners/isolated-wildcards.log |
| Fokussierte bestehende Relay-, Go-Symlink-, Envoy-/HAProxy-TLS- und normalisierte Redaktionskontrollen | 0 für korrigierte begrenzte Aufrufe | Acht bestehende Kontrollen bestehen; zusätzlich neun ungültige Auth-Suffixe und reine Musternamendiagnose bestanden | framework-codeql-20261101/counterevidence/focused-control-summary.json |
| Fünf exakte SSL-Konstruktorproben; sechs begrenzte MemoryBIO-Handshake-Kontrollen | 0 für abgeschlossene Proben | Tatsächliche Einstellungen erfasst; TLS 1.0/1.1 verworfen, TLS-1.2-Kontrollen erfolgreich | framework-codeql-20261101/counterevidence/tls-context-probe.json; tls-legacy-handshake-probe.json |
| `rtk bypass git diff --check` nach Header-/Listener-Implementierung | 0 | Keine Whitespace-Fehler | framework-codeql-20261101/header-listeners/result.md |
| `rtk make check-documentation check-canonical-common-pins check-canonical-python-pins check-canonical-workflow-pins check-canonical-crs-contract-pins PYTHON=${PYTHON} FRAMEWORK_ROOT=${FRAMEWORK_ROOT} BUILD_ROOT=${RUN_ROOT}/build` | 0 | Dokumentation, Links, Pfade und Nachweise bestehen; 356 Sprachpaare | framework-codeql-20261101 |
| `rtk bypass actionlint .github/workflows/ci-findings-regressions.yml`; `rtk bypass ${PYTHON} ci/checks/security/check-ci-security-contract.py` | 0 | Bestehender Workflow und CI-Sicherheitsvertrag bestehen | framework-codeql-20261101 |
| `rtk bypass env TEST_ROOT=${FRAMEWORK_ROOT} CONNECTOR_ROOT=${CONNECTOR_ROOT} CONNECTOR_REVISION=2abad408cae7e5a103d12a9a9e432129bfe0468f PYTHONPATH=${FRAMEWORK_ROOT}:${FRAMEWORK_ROOT}/connector_suite PYTHONDONTWRITEBYTECODE=1 ${PYTHON} connector_suite/modsecurity_connector_ci/tools/update-inventory-bindings.py --apply`, danach `--check`; `update-test-archive.py`, danach `--check`; `build-migration-map.py`, danach `--check` aus demselben Tools-Verzeichnis mit gleichem Umgebungspräfix | 0 | Eine Quellbindung aktualisiert; native Archiv-/Map-Erzeugung und Frischeprüfungen bestehen | framework-codeql-20261101 |
| `rtk bypass env PYTHONPATH=${FRAMEWORK_ROOT}:${FRAMEWORK_ROOT}/connector_suite TMPDIR=${RUN_ROOT} PYTHONDONTWRITEBYTECODE=1 ${PYTHON} -P -m modsecurity_test_framework.connector --connector-root ${CONNECTOR_ROOT} --connector-revision 2abad408cae7e5a103d12a9a9e432129bfe0468f --test-root ${FRAMEWORK_ROOT} --profile codeql-boundaries --output-root ${RUN_ROOT}/admission --check` | 0 | Nur Zulassungsprüfung: 100 Standard-/2.586 optionale Fälle; keine Tests ausgeführt | framework-codeql-20261101 |
| Syntaxkompilierung sechs geänderter/neuer Python-Quellen; exakter CI-Runner mit sieben Selektoren im genehmigten Hostkontext | 0 | Syntax besteht; sieben Methoden bestehen ohne Skips | framework-codeql-20261101 |
| Kontrollierte Importprobe mit privatem Verzeichnis; exakter Runner mit sieben Selektoren durch die äußere User-Namespace mit Eigentümerabbildung | 0 | Alte Root-Abbildung scheitert am Import aus fremdem Privatverzeichnis; Eigentümerabbildung besteht äußeren und verschachtelten Import. Alle sieben echten Methoden bestehen durch den korrigierten Launcher ohne Skips | framework-codeql-20261101/namespace-import-probe.py; ci-selected-regressions.py |
| Zwei Ausnahme-Tests der privaten Netzwerk-Guards nach Sonar-S5778-Korrektur | 0 | Beide Methoden bestehen; nur der Guard-Aufruf bleibt innerhalb von assertRaises, der Decorator wird vorher aufgebaut | framework-codeql-20261101; unabhängige Folgeprüfung ohne abgeschwächte Assertion |

Der Test fehlerhafter Header scheiterte vor dem Fix in allen drei Untertests und bestand danach. Erste Gegenevidenzversuche mit fehlendem Connector-Kontext, falschem Testklassenselektor, unpassender Vor-Body-Assertion für auth_proxy und angenommener Mindestversions-Eigenschaft scheiterten; korrigierte begrenzte Prüfungen oben unterscheiden tatsächlichen Schutz von Annahmen. Kein fehlgeschlagener Versuch wird als Erfolg gezählt.

## Sicherheitsauswirkung

Backend-Traversal konnte Request- und Response-Artefakte außerhalb des Backend-Roots überschreiben. Gemeinsame frühe Target-Zulassung schließt beide Senken vor Body-Zugriffen, auch für alternative normalisierte/rohe Targets sowie Suffix-/Kodierungsvarianten. Headerreflexion gab zuvor obsolete Faltung, SOH und DEL aus; beobachtete Faltung belegt fortgesetzte Headerausgabe, keine beliebige neue Headerinjektion. Ungültige Werte liefern jetzt 400 ohne Reflexion. Echte Wildcard-Tests erhalten Kernelverhalten und begrenzen die Ausführung auf nachgewiesene isolierte Namespaces; ungeeignete Kontexte überspringen ausdrücklich als BLOCKED.

Für die übrigen Meldungen gilt die jeweils einzeln genannte Gegenevidenz; keine pauschalen Verwerfungen. Für TLS #17–#21 weicht tatsächlich verwendetes Python **3.14.4** vom Pin **3.14.8** ab. Alle fünf Kontexte melden `minimum_version=MINIMUM_SUPPORTED`, `maximum_version=MAXIMUM_SUPPORTED`, OpenSSL **3.5.5**, Sicherheitsstufe **2** und keine expliziten OP_NO_TLSv1/OP_NO_TLSv1_1-Bits. Echte Standard-Client-/Server-MemoryBIO-Handshakes verwerfen TLS 1.0/1.1 mit UNSUPPORTED_PROTOCOL und akzeptieren TLS-1.2-Kontrollen. Dies belegt die wirksame Richtlinie des aktuellen Hosts, keine beobachtete TLSv1_2-Mindesteigenschaft oder universelle Plattformgarantie. Die [offizielle Python-SSL-Dokumentation](https://docs.python.org/3.14/library/ssl.html#ssl.SSLContext) beschreibt Standardwerte und Plattformabhängigkeit. Keine spekulativen TLS-Änderungen.

## Dokumentation und Runtime-Evidenz

Dieses vollständige englisch/deutsche Change-Record-Paar dokumentiert Framework-Umfang. Evidenz sind begrenzte Unit-/Parser-/Loopback-/Kernel-/TLS-Gegenprüfungen unter dem externen Run-Root. Keine Connector-Host-/Profilqualifizierung oder Promotion-Evidenz erhoben. Parent-Pin unverändert; MRTS schreibgeschützt behandelt. Keine GitHub-Meldungsstatusänderungen, kein Merge, keine Änderungen an PR #150.

## Nicht ausgeführte Prüfungen

Zum lokalen Commit stehen Hosted-CI/CodeQL/Sonar des aktuellen Heads noch aus; deren Ergebnisse werden in PR-Beschreibung und externer Lifecycle-Evidenz nachgeführt. Der vorherige Head 9ddac92 bestand alle anwendbaren GitHub-Jobs einschließlich aller CodeQL-Sprachen, Backend 5/5 und Header/Isolation 7/7 ohne Skips. Sonar ordnete genau diesem Commit ein Quality Gate OK, null Bugs/Sicherheitslücken/Hotspots sowie zwei S5778-Wartbarkeitshinweise in Tests zu. Diese zwei Tests bauen den dekorierten Aufruf jetzt außerhalb von assertRaises auf; nur der tatsächliche Guard-Aufruf kann die Ausnahme-Assertion erfüllen. Beide Tests bestehen; unabhängige Prüfung fand keine abgeschwächte Assertion. Frühere Importfehler verschachtelter Namespaces wurden durch Abbildung von Namespace-Root auf den Runner-Dateisystemeigentümer korrigiert. Die lokale Sonar-Prüfung vor Dateilesen wurde ausdrücklich vom Nutzer aufgehoben; Hosted-Scanner und Quality Gates bleiben erforderlich. Normale Sandbox-Namespace-Ausführung war blockiert; genehmigte Host- und Hosted-CI-Ausführung liefern getrennte Laufzeitevidenz.

## Einschränkungen und Restrisiko

Benachbarte Auth-Prüfung: 23 von 24 Methoden bestehen; ein vorbestehender Migrationsfehler löst das zentrale Manifest unter Parent statt Framework auf. `prepare.py` wurde unverändert wiederhergestellt. Eine weitergehende Pfadkorrektur berührt das versiegelte Traefik-Profil und bleibt außerhalb dieses Fixes; keine Aktualisierung versiegelter Hashes oder Abschwächung von Guards.

Echte Wildcard-Literale bleiben für CodeQL sichtbar; Isolationsevidenz beweist keine automatische Meldungsschließung. TLS-Evidenz hängt vom tatsächlichen Interpreter/OpenSSL ab und validiert nicht den gepinnten Interpreter. CI muss bei fehlenden Namespaces ausdrückliche BLOCKED-Semantik erhalten. Die begrenzte Backend-Grammatik erlaubt sichere Namen zusätzlich zum aktuellen endlichen Katalog. Keine Rohbodys, Zugangsdaten, Secret-Treffer oder vollständigen Logs in diesem Nachweis.

## Finaler Diff- und Review-Status

Koordinierter Quellenreview und unabhängige Prüfung fanden keine konkrete verbleibende Umgehung der geänderten Grenzen. EN/DE-Paar, alle 26 ID-Zeilen, generierte Artefakte und Whitespace wurden abgeglichen; Dokumentationsprüfung besteht mit 356 Sprachpaaren. Neun unabhängig geprüfte Methoden bestehen mit drei ausdrücklich isolationsbedingt übersprungenen Fällen; die sieben verpflichtenden CI-Selektoren bestehen separat im genehmigten Hostkontext ohne Skips. Hosted-Ergebnisse bleiben bis zur Prüfung des tatsächlichen PR-Heads offen. Keine Meldungsstatusänderung oder Merge.
