# Vorbereitung der Protokollabnahme

**Sprache:** [English](protocol-acceptance-preparation.md) | Deutsch

Diese separat auswählbaren Adapter ergänzen native NGINX-Pfade für H2/H3/h2c
sowie Apache-, HAProxy-HTX/SPOP-Companion- und Envoy-ext_proc-H2-Pfade.
Die 100 Standardfälle bleiben unverändert.
Die Gesamtabnahme bleibt **NOT_RUN**. Dieses Dokument erklärt weder
`READY_FOR_FULL_ACCEPTANCE` noch eine Connector-Capability als erreicht.

## Umfang und Registrierung

Die geschlossene Registry ist `tests/runners/protocol_acceptance_contract.py:CASES`.
Sie enthält 25 stabile IDs. Für jeweils `h2` und `h3` lauten die Suffixe
`parallel_stream_transaction_isolation`, `parallel_cleanup_balanced`,
`first_byte_before_response_end`, `no_full_response_buffering`, `upstream_reset`,
`phase3_deny`, `phase4_safe` und `phase4_strict`. Die weiteren IDs sind:

| H2 | H3 |
| --- | --- |
| `h2_deny_does_not_abort_unrelated_stream` | `h3_deny_does_not_abort_unrelated_stream_preparation` |
| `h2_client_rst_stream` | `h3_client_stream_cancel` |
| `h2_server_rst_stream` | `h3_server_stream_reset` |

Die drei zusätzlichen IDs sind `h2c_prior_knowledge_preparation`,
`h3_reset_does_not_abort_unrelated_stream` und
`phase4_strict_http2_stream_reset`. Mehrere IDs können dasselbe Szenario
wählen; jede ausgewählte ID benötigt dennoch ein eigenes vollständiges
Nachweisbundle.

[Der bestehende native Executor](nginx-native-protocol-execution.de.md) und
seine kanonischen Fixtures/Assertions behalten ihren bisherigen Umfang.
Der separate Einstiegspunkt ist
`connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-protocol-acceptance.py`.
Er ist auf `native-nginx-http-module` begrenzt. Andere Profile verwenden
eigene Adapter und unabhängige native Nachweisleser. Ein fehlender
Pflichtpfad wird nicht durch eine Unsupported-Markierung geschlossen.
Ein Vorbereitungsergebnis bewirkt keine Framework-, Parent- oder MRTS-Promotion.

## Unabhängige Beobachtungen

Ein aus Quellen gebauter libcurl-Multi-Client erzwingt das gewählte Protokoll
und startet einen erlaubten Peer vor dem Ziel. Peer, Ziel und Folgerequest
müssen dieselbe Transportverbindung sowie verschiedene Streams und native
Transaktionen nutzen. Native Transaktionserzeugung/-bereinigung und Regel-/
Phasenereignisse binden jede Anfrage; eine eingereihte Clientanfrage belegt
noch kein aktives Multiplexing. H3-Accessrecords binden Streams über den
entfernten Transportendpunkt, da NGINX `$connection` dort pro Anfrage gilt.

Rohe Client-Debugbeobachtungen liefern Streamkennungen und gegebenenfalls
Client-ALPN. Fehlendes Client-ALPN bleibt fehlend; serverseitiges
`$ssl_alpn_protocol` bleibt eine separate Beobachtung. h2c verlangt HTTP/2
Prior Knowledge ohne TLS/ALPN. H3 benötigt zusätzlich bidirektionale
Loopback-QUIC-Paketmetadaten. Paketnutzlasten und rohe QUIC-Verbindungskennungen
werden nicht aufbewahrt. H1-Fallback, widersprüchliche Protokollidentität
oder fehlende Originalzeugen lassen die Prüfung scheitern.

Der kontrollierte Upstream pausiert vor EOS. Der Treiber gibt die Barriere erst
nach tatsächlich beobachteten Clientbytes oder dem erwarteten Abschluss des
blockierten Ziels frei. Der Reader prüft Byteanzahl und den Snapshot mit
pausiertem Upstream ohne EOS/Responseabschluss; reine Laufzeitvergleiche
belegen Streaming nicht. P3 prüft Deny vor Commit; P4 Safe verlangt Regelzeuge
und Log-only-Verhalten. Strict trennt die originale native Aktion
`abort_connection` vom clientseitig beobachteten Server-Streamreset: H2-Fehler
`0x2`, H3-Fehler `0x102`. Erforderlich sind der genau betroffene Stream, ein
erfolgreicher unabhängiger Peer und ein erfolgreicher Folgerequest über
dieselbe Verbindung. Clientabbruch und kontrollierter Upstreamreset besitzen
separate Szenarioerwartungen.

## Ausführung und Nachweise

Den vorhandenen zugelassenen Hostausführungskontext und die Framework-eigene
Python-Umgebung verwenden. Der Treiber führt den bestehenden Identitäts-/
Runtimepreflight im selben Kontext aus und besitzt anschließend Loopback-
NGINX-Host, Upstream, Ports und Client. Er erzeugt keine UDS. H3 benötigt die
bestehende `AF_PACKET`-Beobachtungsberechtigung. Fehlende Voraussetzungen
ergeben `BLOCKED`, niemals PASS. Keine globalen Rechte ändern oder
Abhängigkeiten installieren, um einen Lauf erfolgreich zu machen.

Vor der Ausführung `--help` über RTK und den gewählten Interpreter prüfen.
`--case-id`, `--nginx-binary`, `--module`, `--output-root`, `--run-id`,
`--parent-sha`, `--framework-sha`, `--mrts-sha`, `--framework-root`,
`--curl-prefix`, `--client-build-root` und gegebenenfalls `--library-dir`
angeben. Vollständige Quell-SHAs, zugelassene quellabgeglichene Binärartefakte,
ein aus Quellen gebautes curl-Präfix mit benötigten Protokollen und frische
absolute externe Ausgabe-/Buildpfade verwenden. Der Quellkontext muss
Frameworkwurzel und `connector_suite` auf `PYTHONPATH` verfügbar machen;
`TEST_ROOT` auf die Frameworkwurzel und `CONNECTOR_ROOT`/`CONNECTOR_REVISION`
auf die gewählte Parentquelle setzen. Der Runner installiert keine Software
und erhöht keine Berechtigungen.

`receipt.json` bindet Quellrevisionen, Quellhashes, Hashes der kopierten
Binärdateien/Module, tatsächliche Konfiguration/Regeln und originale Client-/
Access-/Native-/Upstream-/QUIC-/Rollen-/Cleanup-Nachweise. Der unabhängige Reader
`validate_bundle` öffnet diese Dateien erneut und prüft Hashes, geschlossene
Inventare, vollständige Requests, Writer-/Treiberfehler, Protokollidentität,
natives Cleanup und Listenerfreigabe. Fehlende Requests, unvollständiges JSONL,
null Beobachtungen, Manipulationen, falsche Runs/Streams/Transaktionen oder
fehlgeschlagenes Cleanup ergeben kein PASS. Originale native Eventbytes bleiben
erhalten. Eigene Schlüssel/Zertifikate und Kinder werden entfernt;
aufbewahrte Nachweise bleiben außerhalb des Checkouts.

`tests.no_crs.test_protocol_acceptance_contract` mit dem gewählten Framework-
Interpreter für positive und negative Vertragskontrollen ausführen. Diese
Unitprüfungen ersetzen keine Hostläufe. Bestehende Regressionen
`tests.no_crs.test_nginx_protocol_executor` und
`modsecurity_connector_tests.test_nginx_full_lifecycle_protocol_wiring`
beibehalten. Laufbezogene Befehle, Identitäten, Ergebnisse und offene Prüfungen
stehen im gepaarten [Change Record](../reports/audits/change-records/20261106-01-protocol-acceptance-preparation.de.md).
Lokales Sonar ist für diesen Auftrag ausgesetzt; bestehende GitHub-Sonar- und
CodeQL-Prüfungen bleiben erforderlich. Vorbereitung und spätere Gesamtabnahme
bleiben getrennte Nachweise.

## Separate Nicht-NGINX-H2-Registry

`tests/runners/non_nginx_h2_acceptance.py:CASES` registriert **32** zusätzliche
Opt-in-IDs, getrennt von den 25 NGINX-IDs und den 100 Standardfällen.
Jedes folgende Präfix hat acht Suffixe: `allow`, `phase1`, `phase2`, `phase3`,
`phase4_safe`, `phase4_strict`, `client_cancel`, `upstream_reset`.

| Präfix | Ausgewähltes Profil | Ausführbarer Framework-Adapter |
| --- | --- | --- |
| `apache_h2_` | Natives Apache-Modul | `connector_suite/adapters/apache/harness/apache_h2_acceptance.py` |
| `haproxy_htx_h2_` | Lokaler nativer HTX-Filter | `connector_suite/adapters/haproxy/harness/haproxy_h2_acceptance.py` |
| `haproxy_spop_htx_h2_` | SPOP-Requestphasen plus nativer HTX-Response-Companion | `connector_suite/adapters/haproxy/harness/haproxy_spop_h2_acceptance.py` |
| `envoy_h2_` | Natives gestreamtes ext_proc | `connector_suite/adapters/envoy/harness/envoy_h2_acceptance.py` |

`--help` jedes Adapters über RTK im oben beschriebenen expliziten Quellkontext
prüfen. Apache akzeptiert eine vollständige `--case-id`; die übrigen Adapter
akzeptieren ein Szenario über `--case`. Envoy Strict benötigt
`--late-action-policy strict --case phase4_strict`; seine Vorgabe führt die
sieben Safe-Szenarien aus. Jeder Adapter verlangt explizite externe Laufzeit-
und zugelassene Binär-/Buildeingaben. Die HAProxy-Buildhelfer
`ci/provisioning/prepare-haproxy-h2-test-build.py` und
`ci/provisioning/prepare-haproxy-spop-h2-test-build.py` bauen rein protokollierende
native Observer aus verifizierten Quellkopien. Produktquellbytes bleiben
unverändert. Die Manifeste erhalten historische Buildidentitäten, exakte
Transformation und Quell-/Archiv-/Bibliotheks-/Binärhashes; wiederverwendete
Ausgaben benötigen eine frische Quellenzulassung.

Ein TLS-1.3/ALPN-h2-verifizierender Rohframeclient hält Peer-Stream 1, während
Target-Stream 3 läuft, und verwendet Stream 5 für den Folgezugriff. Er dekodiert
native HPACK-Statusheader über die zugelassene libnghttp2-ABI und weist fehlende/
doppelte Statuswerte, H1-Fallback und fehlerhafte Frames zurück. P2 sendet einen
tatsächlichen begrenzten POST-Body. Native Access-Records, Common-Regel-/
Phasenentscheidungen und profilbezogenes Transaktionscleanup bleiben getrennte
Beobachtungen. Das Target muss bei offener TLS-Verbindung und weiter gehaltenem
Peer bereinigt sein; Hostshutdown kann diesen Nachweis nicht liefern. Apaches
Testmodul beobachtet die tatsächliche Freigabe des mod_security-Requestkontexts
in einem APR-Pool-Cleanup. HTX beobachtet seinen tatsächlichen Detach; SPOP
verknüpft zusätzlich nativen Handoff/Claim/Close über einen SHA-256-Handlezeugen,
ohne den rohen Responsehandle auszugeben. Frühe SPOP-P1/P2-Denys verlangen null
Phantomclaims. Die SPOP-Fixture sendet für leere H2-Requests explizit
`Content-Length: 0`, weil die aktuelle NOTIFY-ABI H2 END_STREAM nicht transportiert.
Dies ist eine sichtbare Produktgrenze, kein Nachweis sämtlicher H2-Bodyframings.

Jeder Fall prüft Allow/Block, anwendbare Request-/Responsephase und exakte Regel,
clientseitiges Targetergebnis, aktive Peer-Isolation, erfolgreichen Folgezugriff,
Readiness und eigenes Cleanup. Safe verlangt erste Bytes vor Upstream-EOS und
die tatsächliche Log-only-Entscheidung. Strict verlangt den tatsächlichen Reset
des betroffenen Streams mit profilbezogenem Fehlercode; Engineentscheidung oder
erfolgreicher gRPC-Send ersetzen ihn nicht. Negativkontrollen weisen fehlende,
doppelte, fremde oder falsch zugeordnete Nachweise, fehlerhaftes JSON, unsichere
Nachweisdateien, spätes Cleanup und Writerfehler zurück. Die Registry-Prüfung
weist null Ergebnisse, fehlende/doppelte/fremde IDs und jedes Ergebnis ohne
PASS zurück; sie ergänzt die unabhängigen Hostleser.

## Bewiesene H2-Resetursache und versionierte Korrektur

Die erhaltene Baseline reproduzierte alle vier Fehler bei Parent
`adf75d05ced37ccab066b8608aed1ce297be84e3` / Framework
`b5d8d9442d7751c04ee84f478f594fc84a236e3b`. Unabhängige verifizierte TLS/H2-
Frames zeigten Target-RST_STREAM ohne neue Eingabe erst nach etwa 12 Sekunden,
nach einem kontrollierten PING dagegen sofort mit gesundem Peer/Folgezugriff.
Damit ist ausstehende Serverausgabe statt verzögerter libcurl-Verarbeitung belegt.

NGINX reihte den Reset in `ngx_http_v2_close_stream` ein und kehrte bei einem
weiter aktiven Stream zurück, ohne das Schreibereignis der echten Verbindung
zu planen. `ci/provisioning/patches/nginx/h2-close-stream-flush.patch` plant das
vorhandene Schreibereignis bei ausstehender Ausgabe und nicht blockierter
Verbindung. Die native Vorbereitung wendet ihn ohne Fuzz auf verifizierte
angeheftete Quellen an; sein SHA bindet Provenienz und Cacheidentität. Er ruft
keinen rekursiven Flush auf und behält keinen Requestzeiger. Assertions und
Timeouts bleiben unverändert.

Frische native H2- und H3-Builds bestanden. Die vier erhaltenen Regressionen und
acht H2/H3-Nachbarn bestanden in gezielten Kandidatenläufen. Ein unabhängiger
Frameprobe ohne PING sah den Targetreset nach etwa 15 ms mit gesundem Peer/
Folgezugriff. Endgültige Commitpaar-Zahlen und aktuelle gehostete CI stehen im
laufbezogenen Bericht und gepaarten Change Record; Kandidatenläufe allein
belegen keine globale Bereitschaft. Die versiegelten früheren 21-PASS/4-FAIL-
Beobachtungen bleiben als Vorher-Nachweis erhalten.

Envoy Strict sendet nun eine späte ImmediateResponse über den angehefteten
nativen Host. Sein Filter-Manager setzt einen bereits committeten Downstream-
Stream zurück; der Dienst erfasst den erfolgreichen Send getrennt vom
clientseitig beobachteten Reset. Acht ext_proc-H2-Kandidatenfälle bestanden mit
rechtzeitigem Cleanup. Dies stuft weder ext_authz noch andere Versionen/Profile hoch.

## Übrige Profilgrenzen und Bereitschaft

Alle zehn logischen Profile behalten getrennte Aussagen. Die ausgewählten
Stock-/Patched-lighttpd-Verträge bleiben H1-only. Envoy ext_authz und Traefik
ForwardAuth benötigen eigene Response-Companions und erben keine direkten
ext_proc-/nativen Ergebnisse. Moderne Protokoll- und Strict-Pfade von Traefik
native benötigen weiterhin eigene Qualifizierung; diese Pflichten bleiben in
der Abschlussmatrix sichtbar. Neue Unsupported-Markierungen oder entfernte
Fälle schließen keinen fehlenden Pflichtpfad.

Der Vorbereitungsclient erlaubt nur eigene IPv4-Loopback-Origins, verifiziert CA,
Peer und Host, setzt die geprüfte TLS-1.3-Mindestversion vor Netzwerkzugriff und
verwendet Klartext nur für die separat gewählte h2c-Fixture. Tatsächliche
TLS-1.2-Negativkontrollen verlangen abgelehnte Handshakes ohne HTTP-Bytes.
Callback-ABI, numerisches Streamlogging und begrenztes h2c werden je Sonar-
Vorkommen geprüft; lokale Prüfung bleibt getrennt von gehosteter Befundbewertung
und erforderlichem Gate. Lokales Sonar bleibt ausgesetzt. Die Gesamtabnahme
bleibt **NOT_RUN**. Bereitschaft wird erst im abgeglichenen Abschlussbericht
erklärt, wenn alle Pflichtvorbereitungen und erforderlichen aktuellen gehosteten
Checks erfolgreich sind.
