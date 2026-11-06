# Change Record zur Vorbereitung der Protokollabnahme

**Sprache:** [English](20261106-01-protocol-acceptance-preparation.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261106-01-protocol-acceptance-preparation |
| UTC-Datum | 2026-11-06 |
| Framework-Basisrevision | `62b411e073551ef0fef22ab3d372e2489f2ae168` |
| Issue oder Pull Request | [Framework PR #169](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/169); exakte Auslieferungs-SHAs und CI-Belege extern |

## Motivation und Problemstellung

Der bestehende native NGINX-Executor schließt Reset/Abbruch, aktive Multiplex-
Isolation, modernes Streaming, h2c und strikte Streambeendigung bewusst aus.
Diese Änderung ergänzt eine separate ausführbare Vorbereitungsoberfläche ohne
Änderung bestehender Assertions oder der 100 Standardfälle. Die Gesamtabnahme
bleibt NOT_RUN.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework besitzt Treiber, libcurl-Client, Regeln, unabhängigen Nachweisreader,
Unitkontrollen und gepaarte Dokumentation. Native Connectorimplementierung,
Capabilities und Promotion bleiben Parent-eigen. Der Parent-Gitlink bleibt
durch diese Frameworkänderung unverändert; MRTS bleibt schreibgeschützt.
Aufbewahrte Nachweise sind privat, begrenzt, hashgebunden und außerhalb des Checkouts.

## Akzeptanzkriterien

Die separate Registry mit 25 IDs muss reale NGINX-/Clientszenarien ausführen;
unabhängige Request-/Verbindungs-/Stream-/Transaktions-/Regelzeugen, tatsächlich
aktives Multiplexing, Bytes vor EOS und isolierte Resets verlangen; unvollständige/
manipulierte Bundles und Writerfehler ablehnen; alten Executor und Standardinventar
erhalten; sowie ehrliche gezielte Host-/Cleanup-Nachweise und zweisprachige
Dokumentation bewahren. Alle 25 gezielten Hostfälle wurden ausgewertet; vier verpflichtende H2-
Reseterwartungen scheitern weiterhin. Das Vorbereitungsergebnis ist NOT_READY;
READY_FOR_FULL_ACCEPTANCE ist nicht belegt.

## Untersuchte Alternativen

Eine Standarderweiterung würde das feste Inventar verletzen. Fehlende Pflichtpfade
als unsupported umzuetikettieren würde Vorbereitungslücken verdecken. Reine Mocks
belegen keine Hostsemantik. Der separate Runner erhält den bestehenden Executor
und ergänzt unabhängige Hostnachweise mit negativen Unitkontrollen.

## Implementierungsentscheidung

Aus Quellen gebauten libcurl-Multi-Client sowie bestehenden Preflight im selben
Kontext und Cleanup eigener Prozesse verwenden. Peer vor Ziel starten, verschiedene
aktive Streams derselben Verbindung beobachten und natives Transaktionscleanup
bewahren. Client-Debug/ALPN, Serveraccess und QUIC getrennt halten. Die pausierte
Upstreambarriere verlangt beobachtete Bytes vor EOS. Strict mit nativem
`abort_connection` bleibt vom clientseitig beobachteten H2-`0x2`-/H3-`0x102`-
Streamreset mit gesundem Peer/Folgerequest getrennt. Vollständiges hashgebundenes
Bundle vor PASS erneut öffnen.

## Geänderte Dateien und Tests

- `connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-protocol-acceptance.py`
- `tests/runners/protocol_acceptance_contract.py`
- `tests/runners/protocol_acceptance_client.py` und `protocol_acceptance_client.c`
- `tests/rules/protocol-acceptance.conf`
- `tests/no_crs/test_protocol_acceptance_contract.py`
- `docs/protocol-acceptance-preparation.md` / `.de.md`, Querverweise im bestehenden
  nativen Ausführungsdokumentationspaar und dieses Change-Record-Paar.

Vertragstests prüfen alle Szenarioerwartungen und beschädigte unabhängige Zeugen,
Quell-/Hash-/Revisionsbindung, h2c-ALPN, bidirektionales QUIC, Strict-Streamreset-
Identität, gleichzeitige native Transaktionen und Upstreamabbruch.

## Befehle und Ergebnisse

Befehlskontext: `F` = Framework-Taskworktree, `P` = gewählter Parentcheckout,
`PYTHON` = gewählter vorhandener Framework-eigener Interpreter.
Absolute Hostpfade bleiben gemäß dem Dokumentationspfadvertrag des Repositorys
in externen Tasknachweisen erhalten.
Die gewählte bestehende Frameworkumgebung nutzt Python 3.15.2; die Abweichung
zur konfigurierten 3.14.4-Umgebung ist dokumentiert. Keine Abhängigkeiten installiert.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk bypass env ON_DEMAND_TESTS=1 PYTHONPATH="$F:$F/connector_suite" TEST_ROOT="$F" CONNECTOR_ROOT="$P" CONNECTOR_REVISION=a5f697c35acb5386d2037f91dfed10ad4b469cd9 "$PYTHON" -m unittest tests.no_crs.test_nginx_protocol_executor modsecurity_connector_tests.test_nginx_full_lifecycle_protocol_wiring -q` | 0 | 29 angrenzende Regressionstests bestanden | Taskausführungsnachweise |
| `rtk make check-documentation PYTHON="$PYTHON"` | 0 | Links, Sprachparität, Repositorypfade und Change-Record-Vertrag bestanden; initialer Exit 2 wegen lokaler Pfade durch externe Ablage absoluter Pfade behoben | Taskdokumentationsprüfung |
| `rtk bypass git diff --check` | 0 | Keine Whitespacefehler | Taskdokumentationsprüfung |

Frische gezielte Verifikation bestand außerdem 15 Vertragsunitmethoden,
21 negative Manipulationen kopierter echter Beobachtungen (alle abgelehnt),
strikten C17-Clientbuild, negative CLI-/Cache-/Writerkontrollen und einen
begrenzten Cleanupprobe nach akzeptierter partieller HTTP-Anfrage (2-Sekunden-
Grenze). Exakte ausgeführte Befehle, Werkzeugversionen, Quell-/Artefaktidentitäten
und Rohergebnisse bleiben in externen Tasknachweisen erhalten.

Das gezielte Verfahren `trial4` rief jede registrierte ID gegen realen Host und
aus Quellen gebauten Client auf: 21 PASS / 4 FAIL; Cleanup 25/25 bestätigt.
Fehler: `h2_phase4_strict`, `h2_server_rst_stream`, `h2_upstream_reset`,
`phase4_strict_http2_stream_reset`. Separate Reproduktion mit H2-Build ohne QUIC
verfehlte ebenfalls Strict- und Upstreamreseterwartungen. Diese fehlgeschlagenen
Produktpfadregressionen bleiben erhalten; Erwartungen und Produktcode wurden
nicht geändert.

Die acht angrenzenden bestehenden echten Hostfälle bestanden ebenfalls:
`protocol_h2_negotiated`, `h2_phase2_deny`, `h2_phase3_deny`, `h2_phase4_safe`,
`protocol_h3_negotiated`, `h3_phase2_deny`, `h3_phase3_deny`, `h3_phase4_safe`.
Die vollständige Ausführungsquittung bleibt extern als
`host/adjacent/executions.json` erhalten, mit Frameworkbasis
`62b411e073551ef0fef22ab3d372e2489f2ae168` und Parentquelle
`a5f697c35acb5386d2037f91dfed10ad4b469cd9`. Diese erfolgreichen angrenzenden
Pfade schließen die vier fehlgeschlagenen neuen H2-Fälle nicht.

## Sicherheitsauswirkung

Keine Produkt-Security-Remediation. Die neue Validierung lehnt fehlende oder
widersprüchliche Protokoll-/Transaktionszeugen und unvollständige Schreibvorgänge
ab. Rohe native Eventfelder bleiben erhalten. Globale Rechte, Authentifizierung,
Capabilitydeklarationen und Prüfpflichten werden nicht abgeschwächt;
Zugangsdaten werden nicht aufbewahrt.

## Dokumentation und Runtime-Evidenz

Neue Vorbereitungsdokumentation und dieser Record haben vollständige EN/DE-
Begleiter; die bestehende native Executordokumentation verlinkt den separaten
Runner. Der gepaarte Leitfaden dokumentiert die echten `trial4`-Ergebnisse und den
H2-Fehlermechanismus. H3 Strict beobachtete unabhängig einen Zielreset, während
der Peer nach den Headern bis zum Reset gehalten wurde, danach gesunden Peer/
Folgerequest derselben Verbindung. H2-Reset wurde erst nach etwa 12 Sekunden
Peerbarrierentimeout mit anschließendem Peerfehler beobachtet, obwohl das native
Abortereignis sofort erschien. Quellhypothese ist das Einreihen von RST in NGINX
HTTP/2 `close_stream`, während ein anderer Peer verarbeitet wird; Ursachennachweis
und Behebung bleiben separate Arbeit. Originale `host/trial4`-Bundles und alle
absoluten Pfade bleiben in externen Tasknachweisen. Die Gesamtabnahme bleibt
NOT_RUN; die Vorbereitung ist NOT_READY.

## Nicht ausgeführte Prüfungen

Gesamtabnahme: NOT_RUN, vom Benutzer ausdrücklich aufgeschoben. Lokales Sonar:
nicht ausgeführt, ausdrücklich ausgesetzt; keine lokale Installation/Start/
Authentifizierung. GitHub-Sonar, CodeQL und PR-Prüfungen: laufen oder werden untersucht; Ergebnisse extern.
Profilübergreifende Hostqualifikation: vom NGINX-spezifischen Runner nicht
durchgeführt. Kein Produktfix; fehlgeschlagene H2-Erwartungen bleiben Pflicht.

## Einschränkungen und Restrisiko

Der neue Runner bedient nur `native-nginx-http-module`; alle zehn logischen
Profile bleiben getrennte Aussagen. Apache H2, HAProxy HTX H2/SPOE-Begleiter-H2-Streamshutdown sowie Envoy
ext_proc H2 bleiben offene Pflichtpfade. Ausgewählte stock-/gepatchte lighttpd-
Profile behalten ihren bestehenden H1-Vertrag ohne neue Unsupported-Deklaration. Ein passendes Build allein beweist keine Runtime.
Unitkontrollen ersetzen keine echten Hostnachweise. Fehlgeschlagene Harnessläufe
müssen erhalten bleiben und dürfen Produkterwartungen nicht ändern.
Globale Vorbereitungsbereitschaft wird nicht behauptet.

## Finaler Diff- und Review-Status

Der ausdrücklich freigegebene Framework-[PR #169](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/169)
und Parent-[PR #445](https://github.com/Easton97-Jens/ModSecurity-conector/pull/445)
existieren. Neue Benutzerfreigabe ersetzte die frühere Pushablehnung; beide
ursprünglichen Commits wurden gepusht. GitHub-CI wird weiter ausgewertet;
finale Ergebnisse am exakten Head bleiben extern dokumentiert. Kein Merge.

Alle 33 gezielten Hostwiederholungen wurden an Parent
`5093a7aa349372279fb2c76974da6423de511332` / Framework
`fa444236fa3b00c91ba94de49f69f52101087087` / MRTS
`ee2174431c4edf97e66afe32558ce8454deb2397` abgeschlossen: neue Fälle
21 PASS / 4 FAIL, angrenzende Fälle 8 PASS; alle 33 Cleanups bestätigt. Diese
Ergebnisse qualifizieren genau dieses Paar und seine zugelassenen Artefakte.
Vier H2-Pflichten und weitere moderne Profilpfade bleiben offen; NOT_READY und
Gesamtabnahme NOT_RUN bleiben unverändert.

Parent-CI deckte eine ausgelassene generierte Testarchivprojektion auf: Natives
`update-test-archive --check` scheiterte in Lint-, Quick-, NGINX- und Commonprüfungen.
Der native Frameworkgenerator ergänzt ausschließlich die neue Testquelldatei
mit 15 Methoden im Archiv; der Bestand steigt von 8096 auf 8111. Diese Folgeänderung
betrifft Archivprojektion und Dokumentation ohne Runtimecode- oder
Erwartungsänderung. Die Verifikation eines späteren Commitpaars bleibt separat;
sie wird nicht aus den 5093/fa-Hostläufen abgeleitet. Exakte Folge-SHAs und
CI-Belege bleiben extern erhalten.

Die Framework-PR-CI lehnte danach den neu versionierten C-Client vor dem
Scannerstart ab: Seine Quelle fehlte im geschlossenen nativen Compileinventar.
Ausschließlich `tests/runners/protocol_acceptance_client.c` in die geprüften
Rezepte aufnehmen und die exakte Offlineinventarassertion von 81 auf 82 Einheiten
anpassen. Vollständige Mengengleichheit, Warnflags, Zugangsdatenabgrenzung und
alle Analysegates bleiben erhalten. Generiertes Spezialtestarchiv wegen der
geänderten Offlinetestquelle aktualisieren. Kein lokaler Scanner, keine
Sonarinstallation oder Authentifizierung. Finale Folge-SHAs, gezielte
Hostwiederholungen und aktuelle Head-CI-Ergebnisse bleiben extern dokumentiert.

Der native Inventarbindungsaktualisierer erneuert die zwei bestehenden
Quelldigestslots für das geprüfte Compilerezept und seinen Offlinetest. Alle
100 Standardfälle, Ausführungsselektoren und Offlineausnahmen bleiben identisch.
Der Inventardigest ändert sich ausschließlich wegen dieser geprüften Quellbytes;
das abhängige generierte Archiv wird nativ aktualisiert. Die Parentprüfung setzt
den Frameworkroot explizit als Makeargument gegen geerbte Hostcheckoutwerte.

Die erste vollständige entfernte Frameworkanalyse kompilierte den neuen Client,
verfehlte aber den Security-Gate für neuen Code. Die Folgekorrektur setzt das
Clientminimum auf TLS 1.3, begrenzt Clientorigins auf `127.0.0.1` mit explizitem gültigem
Port, entfernt quadratisches Listener-Regexparsing und zerlegt die drei neuen
Runtime-/Nachweismodule in begrenzte Helfer. Sämtliche Protokoll-, Barrieren-,
Korrelations-, Outputfehler- und Cleanuperwartungen bleiben Pflicht. Explizites
Klartext-h2c gehört weiter zum Loopbacktestvertrag; numerische Stream-IDs werden
mit fest typisierter JSON-Ausgabe geschrieben. Keine Sonarunterdrückung,
Befunddisposition, Exklusion oder Gateabschwächung. Gezielte Unit-/Äquivalenz-/CLI-/
Barrierekontrollen bestehen; frische Hostwiederholungen am eingecheckten Paar
und die maßgebliche entfernte Headanalyse bleiben extern dokumentiert.
