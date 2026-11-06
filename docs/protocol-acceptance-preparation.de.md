# Vorbereitung der Protokollabnahme

**Sprache:** [English](protocol-acceptance-preparation.md) | Deutsch

Dieser separat auswählbare Vorbereitungsläufer ergänzt ausführbare native
NGINX-Pfade für H2, H3 und h2c. Die 100 Standardfälle bleiben unverändert.
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
Er ist auf `native-nginx-http-module` begrenzt. Die übrigen neun logischen
Profile behalten ihre eigenen Capability- und Runnerlücken. Ein fehlender
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

## Beobachtetes Vorbereitungsergebnis

Die gezielte Hostkampagne `trial4` wertete alle 25 registrierten IDs aus:
**21 PASS, 4 FAIL**. Die fehlgeschlagenen IDs sind `h2_phase4_strict`,
`h2_server_rst_stream`, `h2_upstream_reset` und
`phase4_strict_http2_stream_reset`. Alle 25 Bundles bestätigten Cleanup eigener
Prozesse und Listener. Originale Fehlerbeobachtungen bleiben in externen
`host/trial4`-Nachweisen erhalten; Erwartungen und fehlgeschlagene Regressionen
bleiben unverändert. Die Vorbereitung ist **NOT_READY**; die Gesamtabnahme ist
**NOT_RUN**.

H3 Strict bestand mit einem nach den Headern bis zum tatsächlichen Zielreset
gehaltenen Peer sowie anschließend gesundem Peer und Folgerequest derselben
Verbindung. Bei H2 erschien das native Abortereignis sofort; der Client sah
den Reset jedoch erst etwa 12 Sekunden später beim Timeout der Peerbarriere.
Der Peer scheiterte danach. Ein H2-Build ohne QUIC reproduzierte sowohl Strict-
als auch Upstreamresetfehler. Die Quellhypothese lautet, dass NGINX HTTP/2 RST
in `close_stream` einreiht und zurückkehrt, solange ein anderer Peer verarbeitet
wird. Dies ist eine Hypothese zum beobachteten Produktpfad, kein abgeschlossener
Ursachennachweis oder eine Behebung. Produktänderungen liegen außerhalb dieser
Vorbereitungsänderung.

Weiter erforderliche moderne Pfade umfassen Apache H2, HAProxy HTX H2 samt
SPOE-Begleiter für H2-Streamshutdown sowie Envoy ext_proc H2. Dieser NGINX-Runner
schließt diese Lücken nicht. Die ausgewählten stock- und gepatchten lighttpd-
Profile besitzen einen bestehenden H1-Vertrag; moderne Protokolle sind darüber
ausgeschlossen, ohne neue Unsupported-Deklaration. Alle zehn logischen Profile
behalten getrennte Abnahmeaussagen.

Die acht angrenzenden bestehenden echten Hostfälle bestanden ebenfalls:
`protocol_h2_negotiated`, `h2_phase2_deny`, `h2_phase3_deny`, `h2_phase4_safe`,
`protocol_h3_negotiated`, `h3_phase2_deny`, `h3_phase3_deny`, `h3_phase4_safe`.
Die vollständige Ausführungsquittung bleibt extern als
`host/adjacent/executions.json` erhalten, mit Frameworkbasis
`62b411e073551ef0fef22ab3d372e2489f2ae168` und Parentquelle
`a5f697c35acb5386d2037f91dfed10ad4b469cd9`. Diese erfolgreichen angrenzenden
Pfade schließen die vier fehlgeschlagenen neuen H2-Fälle nicht.
