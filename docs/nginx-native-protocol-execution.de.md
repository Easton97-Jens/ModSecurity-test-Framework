# Native NGINX-H2/H3-Ausführung

[English](nginx-native-protocol-execution.md)

Der native Protokollexecutor verbindet die bestehenden TLS-H2- und QUIC-H3-
Katalogverträge mit einem isolierten NGINX-Master/Worker, einem Loopback-Upstream
und einem erzwungenen curl-Client. `full-lifecycle-nginx` mit
`NGINX_DOWNSTREAM_PROTOCOL=h2` beziehungsweise `h3` führt die unterstützten
Protokollfälle über diesen Executor aus. Gewöhnliche H1-Operationen erhalten
kein modernes Protokollergebnis; sie bleiben unausgeführt und der
Auswahlnennwert bleibt unverändert. Ein erweitertes Buildprofil wählt allein
weiterhin H1.

Unterstützt sind Aushandlung, kein Fallback, P1/P2/P3-Deny, P4-Safe-Log-only,
die bestehende H2-Transportprobe und H3-Alt-Svc. Jeder Fall sendet zusätzlich
einen eigenständigen Allowrequest. Reset, strikte Streambeendigung,
Multiplex-Transaktionsisolation, moderne First-Byte- und h2c-Verträge bleiben
außerhalb des implementierten Executors. Produktcapabilities und ehrliche
Nichtausführung bleiben maßgeblich; kein Skip zählt als Erfolg.

Benötigt wird ein zugelassenes aktuelles NGINX-Binär-/Modulpaar aus `h1-h2`
für H2 beziehungsweise `h1-h2-h3-quic` für H3. Framework-Interpreter und explizite
Produkt-/Testcheckout-Identitäten auswählen. Der Aufrufer übergibt Bibliothek,
geeigneten curl-Client, begrenzte Run-ID, alle drei Quellrevisionen und ein
frisches privates externes Ausgabeverzeichnis. Der Executor führt den
vorhandenen Runtimepreflight vor dem Hoststart im selben Launcher aus. H3
benötigt zusätzlich die Berechtigung zur Loopback-Paketbeobachtung über einen
`AF_PACKET`-Socket. Fehlende Identitäts- oder Clientvoraussetzungen ergeben
`BLOCKED`, niemals PASS.

Für einen begrenzten Einzelfall
`connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-nginx-protocol-cases.py`
über RTK und den ausgewählten Interpreter aufrufen. `--help` nennt die
geschlossenen Fall-IDs und erforderlichen Argumente `--nginx-binary`, `--module`,
`--output-root`, `--run-id`, `--parent-sha`, `--framework-sha`, `--mrts-sha`,
`--framework-root` sowie optional `--library-dir` und `--curl`. Der Executor
installiert keine Pakete und erhöht keine Berechtigungen selbstständig.

H2 verwendet `--http2-prior-knowledge` über TLS, H3 `--http3-only`. Ein
erfolgreicher HTTP-Transfer reicht nicht: tatsächliche HTTP-Version und
Streamöffnung aus curl müssen übereinstimmen. Beide nativen Accessrecords
müssen unabhängig das gewünschte Protokoll und akzeptiertes ALPN über
`$ssl_alpn_protocol` zeigen und Allow- und
Vertragsrequest an unterschiedliche native Transaktionen binden. Native
Rule-/Phasen-/URI-/Transaktionszeugen belegen Deny oder Safe-Aktion. H3 verlangt
zusätzlich bidirektionale portgebundene QUIC-/UDP-Longheader auf Loopback.
Gespeichert werden nur Paketgrößen, Richtung, Version und gehashte
Verbindungskennungen; keine Paketnutzlasten oder rohen Verbindungskennungen.

Einige QUIC-TLS-Backends von curl melden akzeptiertes ALPN nicht im Trace.
Der Clientparser erhält dieses Fehlen; er leitet ALPN weder aus HTTP/3 ab noch
kopiert er den Serverwert in eine Clientbeobachtung. Das vollständige Bundle
verlangt weiterhin passendes Server-ALPN in **beiden** originalen Accessrecords.
Ein ausdrücklich widersprüchliches Client-ALPN scheitert immer.
`alpn_source=nginx_access_ssl_alpn_protocol` benennt die unabhängig geprüfte
Serverquelle; `client_alpn_observed` und `client_alpn` erhalten, ob und welchen
ALPN-Wert der Client tatsächlich meldete. Fehlendes oder falsches Server-ALPN
verhindert PASS auch bei erfolgreichem HTTP/3-Transfer, Stream- und QUIC-Nachweis.

`tests/runners/nginx_protocol.py` öffnet das private Nachweisbundle erneut und
prüft Originalhashes, Quellverträge, Run-/Revisionsidentitäten,
Request-/Accesskorrelation, native Zeugen und Cleanup. Kanonische Sammlung und
Übernahme verwenden denselben Reader und prüfen PASS unabhängig erneut.
Originale native Eventbytes bleiben unverändert. `protocol_evidence_mapping`
trennt tatsächlich native Felder von unabhängigen Client-/Access-/QUIC-Fakten;
ALPN und Stream-IDs werden nicht in Common-Events eingefügt.

Der Executor verwendet das bestehende pidfd-gebundene Cleanup eigener Kinder,
prüft TCP-/UDP-Portfreigabe, beendet Upstream und Paketbeobachter und entfernt
temporären TLS-Schlüssel/Zertifikat auch bei Fehlern. Metadatennachweise bleiben
im Taskausgabepfad. Ein gezielt bestandener Lauf belegt nur sein genaues
Quell-/Artefaktpaar und seine ausgewählte Operation. Gesamtprotokollabnahme,
nicht unterstützte Produktfähigkeiten und geschützter Broker bleiben separat.

Die On-demand-Regressionen mit dem Framework-Interpreter über
`python -m unittest tests.no_crs.test_nginx_protocol_executor` und das migrierte
Modul `modsecurity_connector_tests.test_nginx_full_lifecycle_protocol_wiring`
ausführen. Sie prüfen Parser, Fallbackablehnung, Paketmetadaten, Manipulation,
fremde Requests/Runs, Cleanup, kanonische Nachprüfung und echte Make-Auswahl/Init.
Diese Selbsttests starten keinen Protokollhost und qualifizieren keinen
Runtimeverkehr. Die 100-Fälle-Standardauswahl wird nicht erweitert.
