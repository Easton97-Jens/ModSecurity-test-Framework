# Envoy-I12-Hostevidenz

**Sprache:** [English](README.md) | Deutsch

Für die folgenden aktuellen Quellcheckout-Befehle beide Checkouts, einen
kompatiblen Interpreter und vorhandenen freigegebenen externen Speicher explizit
wählen. Diese Beispielpfade durch tatsächliche physische Pfade ersetzen;
Quellvorbereitung verlangt weiterhin die beschriebene unabhängige Zulassung und
autorisiert keinen Hostlauf.

```sh
export CONNECTOR_ROOT="/absolute/product/checkout"
export CONNECTOR_REVISION="$(git -C "$CONNECTOR_ROOT" rev-parse HEAD)"
export TEST_ROOT="/absolute/framework/checkout"
export FRAMEWORK_ROOT="$TEST_ROOT"
export FRAMEWORK_PYTHON="/absolute/framework-venv/bin/python"
export CODEX_TEMP_ROOT="/absolute/approved/external/storage"
export I12_TEST_ROOT="$CODEX_TEMP_ROOT"
export CONNECTOR_TEST_OUTPUT_ROOT="$CODEX_TEMP_ROOT"
export PYTHONSAFEPATH=1
export PYTHONPATH="$TEST_ROOT:$TEST_ROOT/connector_suite"
```

Diese reine Envoy-Testerweiterung nutzt die vorhandene Capture-Variante `envoy`
und den gemeinsamen nativen Observer. Der [kompakte Abschluss von PR #410](https://github.com/Easton97-Jens/ModSecurity-conector/blob/master/docs/pr-410-i12-closeout-20261024.de.md)
ist **PARTIAL**: 284 Original-IDs bleiben erhalten. Vier neu freigegebene ext_proc-
Nachweispakete erhöhen den aktuellen Lifecycle-PASS-Bestand auf sieben;
118 ursprüngliche Oracles bleiben offen. Die zentrale Baseline bleibt
unverändert. Synthetische Hostproben qualifizieren Original-IDs nicht automatisch.

Alle 125 Original-Oracles haben einzelne Quellreviews. Die 33 neuen
Fixture-gebundenen Quellvorschläge bleiben von kanonischer Auflösung und
Hostabnahme getrennt.

## Grenze für gepflegte Parser und Veröffentlichung

Aktuelle Verbraucher importieren die gepflegten Module
`host_log_observations.py` und `grpc_stream_observations.py` aus diesem
Verzeichnis. `--helpers` wählt ausschließlich erhaltene Herkunftsdaten:
Beide historischen Helperhashes müssen dem Capture-Manifest entsprechen;
kein Helper-Verzeichnis wird dem Python-Importpfad hinzugefügt. Der
Objektspeicher erhält die exakten historischen Helperbytes als verlustfreie
JSON-Zeilendaten. Neue physische Reviews verwenden `current_parser_sha256`
für die gepflegten Module und `helper_sha256` für historische Herkunft.
Neue Originalfallpakete verwenden `current_parser_sha256` und
`historical_helper_sha256`; beide Identitäten werden bei Reproduktion erneut
geprüft. Eine historische Helperidentität kann die aktuelle Parseridentität
nicht ersetzen. Archivierte Reviews, Pakete und Ergebnisse behalten ihre
ursprüngliche Revisionsbindung und werden durch diese Änderung nicht erneuert.

Der gepflegte Hostparser verwendet einen eindeutigen Scan des Taginhalts,
auch bei nicht abgeschlossenen Tags. Die Ausgabe von Transport, physischen
Reviews, Current-Base-Supplementen und Reconciliation verwendet neue,
deskriptorbasierte Dateien innerhalb konfigurierter Runtime-Wurzeln. Der Runner
prüft Matrixlabels und sämtliche unterschiedlichen Logziele vor Controllerstart,
erstellt private Logs einmalig und ersetzt nur seinen zugelassenen Checkpoint
atomar. Quellwurzeln, Traversierung, Symlink-Eltern und fremde Ziele werden durch
die gemeinsame Grenze `ci/lib/i12_path_safety.py` zurückgewiesen. Die normalen
CLI-Optionen bleiben unverändert; eine Ausgabe außerhalb konfigurierten
Runtime-Speichers ist ein Fehler.

Der Quellobserver-Adapter akzeptiert zusätzlich den expliziten C-Nachfolger
`5038d0068cef52f7cf4f2013355cf1b828648061993dd89c51d14f5439cfe387`
unter `i12.envoy.preserve-source-observer.v2`. Sein Beleg erfasst den
tatsächlichen archivierten C-Hash; der vorhandene Pfad `0d903fc5…` behält seinen
ursprünglichen v1-Vertrag und seine Nachweismetadaten. Das historische
Envoy-Capture-Profil und seine Ergebnisidentitäten bleiben unverändert. Eine
akzeptierte Eingabeidentität liefert keinen Runtime-Nachweis.

## Aktueller Abnahmestand

| Route | Lifecycle-PASS / Original-IDs | Offene Original-Oracles |
| --- | ---: | ---: |
| `envoy-ext-proc` | 5 / 117 | 46 |
| `envoy-ext-authz-request` | 1 / 94 | 39 |
| `envoy-ext-authz-response-companion` | 1 / 73 | 33 |

Von 277 IDs ohne vollständige Lifecycle-Abnahme sind 8 reine
Konfigurations-PASS und 269 unqualifiziert. Die 86 echten Hostmessungen umfassen
37 Retakes unter 33 exakten Original-IDs. Die vier neuen Einzelfreigaben sind:

- `I12::envoy-ext-proc::NEED-request-streaming`
- `I12::envoy-ext-proc::NEED-response-streaming`
- `I12::envoy-ext-proc::NEED-client-response-bytes`
- `I12::envoy-ext-proc::NEED-client-exit-signal`

Vier zuvor vorgeschlagene Qualifikationen sind ausgeschlossen: bei Request-
Autorisierung `NEED-complete-sample`, `NEED-request-multiple-chunks` und
`NEED-client-response-bytes` sowie beim Companion `NEED-allow`. Ihre
Authorization-Trailer tragen keine Zuordnung zum jeweiligen Stream; der
Remote-gRPC-Status bleibt unbekannt und erfolgreicher Abschluss bleibt falsch.
Die physischen Host-, Client- und Backendbeobachtungen bleiben erhalten, ohne
diese IDs zu qualifizieren. Mehrere Client-Schreibvorgänge bedeuten keine
mehreren nativen Authorization-Callbacks.

## Producer

| Producer | Evidenzgrenze |
| --- | --- |
| `reconcile.py` | Prüft ursprüngliche Oracle-Quellen und physisches Ledger erneut; erhält alle 284 exakten Envoy-IDs |
| `prepare_native.py` | Git-freie aktuelle Quellkopie, unveränderte Capture-Overlays, native/CGo-Build, Go/Race/Vet und Observer-Kontrollen |
| `source_inventory.py` | Rekonstruiert sämtliche Buildeingaben aus dem hashgebundenen Gitarchiv und den expliziten Capture-Ergänzungen |
| `evidence_io.py` | Begrenzt physische Lesezugriffe auf erlaubte, besitzgeprüfte Pfade; sperrt Symlinks, private Konfiguration und Änderungen beim Lesen |
| `validate_oracles.py` | Prüft alle 125 Original-ID-Reviews und physischen Referenzen; erhält kanonische Ergebnisse |
| `host_scenarios.py` | Versiegelte unabhängige Fixtures, TLS-Eingaben, Binary-/Quellbindung und privater Controller; startet keine Hosts |
| `fault_scenarios.py` | Versiegelte Response-EOS-Fehlerfixture mit separatem Testproxy; realer Lauf `fault-host-v1` bleibt Runner77/Controller1/Client1, unqualifiziert und ohne neuen PASS |
| `bind_originals.py` | Versiegelt neue Retakes geprüfter Fixtures unter exakten Original-IDs mit sämtlichen Eingaben innerhalb des aktuellen privaten Laufs |
| `run_host.py` | Begrenzte Starts mit dem bestehenden nonroot Controller; Exitcodes bleiben Beobachtungen |
| `review_runs.py` | Physische Hashes, geladene Images, Client-/Backendbytes, native/Hostcallbacks, Cleanup und Transportfakten |
| `current_base_evidence.py` | Bindet das separate native/Host-Supplement der aktuellen Base sowie verworfene und ersetzte Versuche; ergänzt keine Original-ID-Qualifikation |
| `transport.py` | Unterscheidet tatsächlichen lokalen HTTP/2-Reset von explizitem Remote-gRPC-Erfolg |
| `host_log_observations.py` | Gepflegte Extraktion tatsächlicher, über Nonce abgegrenzter Hostlogger-Zeilen |
| `grpc_stream_observations.py` | Gepflegte Extraktion eindeutig abgegrenzter Process-Reset- und HTTP/2-Abschlussfakten |
| `qualify_originals.py` | Bereitet ausgewählte Originalfälle vor; Einzelfreigabe verlangt exakte Fixturegleichheit, frische Reproduktion aller 35 Nachweisfelder und den gemeinsamen Validator |
| `write_report.py` | Erzeugt nur den eigenen EN/DE-Taskbericht und das exakte ID-JSON; ändert keine gemeinsamen Generatoren oder Ledger |

Ein neuer Companion-NEED-allow-Retake bindet vor Ausführung ein separates ergänzendes Quellreview. Seine frühe Backend-Request-Line-Erfassung belegt genau einen Ziel- und einen Nachbarrequest; alte Receipts mit unterer Zählgrenze bleiben unverändert.

## Validierung

Mit der obigen expliziten Quellcheckout-Umgebung ausführen:

```sh
ON_DEMAND_TESTS=1 rtk proxy "$FRAMEWORK_PYTHON" -P -B -m unittest discover -s "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/i12/envoy" -p 'test_*.py' -v
rtk proxy "$FRAMEWORK_PYTHON" -P -B "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/i12/capture_sources.py" verify
```

Die vollständige aktuelle Envoy-Suite hat 257 PASS und 0 Skips. Beleg: `ci/final-envoy-controls-257-sonar-v3.json`. Die fokussierten Fehlerproben-Kontrollen haben 16 PASS, die separaten Go-Testproxy-Kontrollen 10 PASS. Diese Kontrollen qualifizieren den Hostlauf nicht automatisch.

Jeder Producer bietet `--help`. Native Vorbereitung benötigt eine neue
registrierte externe Laufwurzel, den aktuellen Checkout, den vorhandenen
Offline-Modulcache, das ausgewählte echte SDK und die gepatchte Go-Toolchain.
`--validate-existing` erhält fehlgeschlagene Setup-Evidenz und wiederholt
Prüfungen, ohne Binaries still neu zu bauen. Für UDS-Tests einen kurzen privaten
physischen Temporärpfad verwenden.

Hostvorbereitung benötigt außerdem die ausdrücklich hashgebundenen erhaltenen
v5-Controller-/Template-Eingaben und die passende native Build-Receipt. Diese
sind externe Voraussetzungen, keine mitgelieferten Binaries und keine Erlaubnis
zur Toolinstallation. Der Controller entfernt Capabilities, wechselt in private
Namespaces und lässt UID/GID 65534 mit NoNewPrivs zu, bevor Capture-Programme
laufen. Die Envoy-Kopie hält ihren positiv identifizierten PID-Namespace bis
nach Cleanup offen, damit Inode-Wiederverwendung keine fremden Prozesse
fehlzuordnet. Alle ursprünglichen Prüfungen bleiben aktiv; fehlgeschlagene
Ownership-Prüfungen bleiben Fehler.


Die Quellrevision der historisch qualifizierten nativen und Hostevidenz bleibt
`f27eb59b53beff6f65384fc2e5037881a3052c01`. Der exakte Base-Head
`a62296fb57263f9be18c6ac879e36e0ab2a9935c` wurde in
`dfb1a07a863530a53c0006ee204319453d66a2ad` gemergt. Ein separates
hashgebundenes Supplement `current-base-evidence-v1.json` bindet die historischen
finalen Receipts `current-base-a622-native-v3` und `current-base-a622-host-v3`.
Der Engine-Build nutzt das von der Base verlangte Go 1.27.2 und x/net 0.61.0;
das auf dem Host installierte Go 1.27.3 ist eine separate Umgebungsbeobachtung.
Das SDK ist ModSecurity 3.0.14, der Host Envoy 1.39.1. Alle 16 nativen
Prüfungen einschließlich Go/CGo, Race, Vet und 34 nativen Observer-Kontrollen
bestanden. Frühere Build-/Hostversuche mit Go 1.27.3 bleiben ersetzt. Ein Build
mit gemischter Toolchain scheiterte vor dem Hoststart und bleibt verworfene
Evidenz. Frühere Zulassungsfehler behalten Exit 77 ohne Cleanup-Aussage.

Alle drei finalen a622-Proben haben Runner-Exit 0, zwei vollständige
Backendrequests, physische Eventlogs und geprüftes Cleanup ohne Survivors oder
Mountleaks. Jede Route beobachtet Zielrequest/-response mit 95/96 Bytes sowie
unabhängigen Nachbarrequest/-response mit 6/7 Bytes. Ihre Verträge bleiben getrennt:

- ext_proc beobachtet Requestchunks 64+31+0 und Responsechunks 64+32+0 mit
  EOS, natives Finish/Logging/Free/Cleanup sowie lokalen Process-reset2.
  Der Remote-gRPC-Status von Process bleibt unbekannt.
- Request-Autorisierung liefert ein vollständiges natives 95-Byte-Sample unter
  Host-`max_request_bytes=4096` und nativem Limit 1024. Diese Probe prüft keine
  native Body-Limit-Entscheidung. Unzugeordnete Authorization-Trailer lassen den
  Remotestatus unbekannt; HTTP-/Backendbeobachtungen belegen keinen gRPC-Erfolg.
- Der Companion beobachtet eine korrelierte Transaction-Lease, P3 vor dem
  Common-Commit, danach Response-Bodycallbacks/P4, EOS und Cleanup. Sein Ziel empfängt eine
  vollständige HTTP-Entity mit anschließendem TCP-Reset errno104; der Nachbar
  beobachtet EOF. Die Remotestatus von Authorization und Process bleiben
  unbekannt. Eine Unterstützung von P4 Strict wird nicht behauptet.

Die folgenden vier Fälle bleiben unqualifiziert, weil die sichtbaren
Authorization-Trailer nicht streamgebunden sind und der Remote-gRPC-Status
unbekannt bleibt:

- `I12::envoy-ext-authz-request::NEED-complete-sample`
- `I12::envoy-ext-authz-request::NEED-request-multiple-chunks`
- `I12::envoy-ext-authz-request::NEED-client-response-bytes`
- `I12::envoy-ext-authz-response-companion::NEED-allow`

Das Supplement qualifiziert keine Original-ID und ergänzt keinen Oracle-
Fortschritt. Die historischen Messungs-/Retake-Zahlen bleiben unverändert.
Die erhaltene Baseline und physischen Quellen wurden mit aktuellen zentralen
Validatoren erneut geprüft; dieser Envoy-Task änderte keinen gemeinsamen
Validator. Begrenzte Dokumentationsevidenz: `ci/docs-sonar-v3.json`.

Die Base rückte danach auf `e4c872cde16eb73182de49c09a8ba8ee4219b417`
und `afaf6305bd55646073c3b40632b52fc4e5edf714` vor; beide wurden durch normale
Merges integriert. `current-base-e4-evidence-v2-sonar.json` erhält den nativen e4-PASS,
den ersten ext_proc-Timeout und den erfolgreichen Host-Retake.
`current-base-afaf-evidence-v3-sonar.json` bindet diese Historie an die frische Receipt
`current-base-afaf-native-v3` und
`current-base-afaf-host-v2/physical-review-sonar-v1.json`. Alle 16 nativen afaf-Schritte
einschließlich Go/CGo, Race und Vet bestehen. Engine-Go1.27.2,
Hostumgebungs-Go1.27.3, SDK3.0.14 und Envoy1.39.1 bleiben unabhängig identifiziert.
Alle 2.196 Buildquellen und die 155 Objekte/10 Profile der aktuellen Registry
sind ohne Änderung des gemeinsamen Manifests geprüft. Frühere afaf-Build- und
Admission-Fehler bleiben erhalten.

Die Delivery-Base rückte danach durch einen normalen Merge auf
`76672071c3f7665dfde3340bef9e64271d6f6e70` vor. Ihr geerbtes Delta ändert nur
zwei Parent-Testfixtures und deren eigenen EN/DE-Change-Record; Envoy-, Runtime-,
Capture-, Dependency- und Buildeingaben bleiben unverändert. afaf bleibt deshalb
die letzte Quellrevision echter nativer Envoy-/Hostevidenz. 766 erhält keine
neue Hostausführung, keinen Lifecycle-PASS und keinen Oracle-Fortschritt.

Die drei afaf-host-v2-Runner enden mit Exit0, jeweils mit Zielrequest/-response
95/96 Bytes, Nachbar 6/7 Bytes, zwei Backendrequests sowie physischem
Finish/Free/Cleanup ohne Survivors oder Mountleaks. ext_proc beobachtet P1–P4
und native Chunks 64/31/0-EOS sowie 64/32/0-EOS; sein Nachbar läuft sequenziell.
Authorization liefert ein vollständiges 95-Byte-Sample unter dem Hostbuffer-Vertrag
und prüft keinen Host-Reject, keine native Limitentscheidung, Intervention oder
technisches Runtimeversagen. Die Companion-Lease ist allocationsgebunden;
Wire-Token-Gleichheit bleibt unbelegt. P3 liegt vor Commit und das erste
Client-Entitybyte vor P4. P4-Strict-Unterstützung ist nicht belegt. Nicht
zugeordnete Authorization-Trailer und fehlende Remote-Process-Status bleiben
unbekannt, erfolgreicher Abschluss false. Diese ergänzenden Läufe erhöhen keine
Original-ID, Lifecycle-PASS oder Oracle-Fortschritte; 7 PASS/118 offen,
86 historische Hostmessungen und 37 Retakes für 33 IDs bleiben unverändert.

Die echte ext_proc-Fehlerprobe `fault-host-v1` verwirft ausschließlich den leeren Response-EOS-Callback und führt einen tatsächlichen Half-Close aus. Engine-API und dem Zielstream eindeutig zugeordneter Envoy-Trace melden gRPC-Status14. Der Client empfängt einen HTTP200-Präfix mit 96 Bodybytes in 64+32, jedoch keinen Nullchunk. Runner77/Controller1/Client1 bleiben unqualifiziert; neue PASS: 0. Am Ziel sind P1–P3 und P4=0, ein `runtime_finish`-Versuch mit Result0 sowie Logging/Free/Cleanup jeweils1 beobachtet. Der gesunde Nachbar hat P1–P4/Finish jeweils1; Survivors und Mountleaks fehlen. Der Proxy-Wirestatus bleibt unbeobachtet. Fehlender Status wird nicht als erfolgreicher Abschluss interpretiert.

## Aussagegrenzen

`max_request_bytes` ist Envoys Hostbuffer-Grenze. Authorization-Samples, native
Limits und technische gRPC-Fehler benötigen getrennte Beobachtungen. Begonnene
oder abgebrochene Backendrequests werden unabhängig von abgeschlossenen Receipts
gezählt. Mehrere Client-Schreibvorgänge allein belegen keine mehreren nativen
Bodycallbacks. Vollständiges HTTP-Framing, TCP-Reset, gRPC-Status, EOS, Finish
und Free sind getrennte Fakten. Fehlender Remote-gRPC-Status ist niemals
erfolgreicher Abschluss.

Verbleibende Lücken stehen im Taskbericht und im exakten ID-JSON. Über diese
Erweiterung keine gemeinsamen Manifeste, Originalkataloge, anderen Connectoren
oder Produktquellen ändern. Rohartefakte extern erhalten; nur geprüfte Metadaten
versionieren.
