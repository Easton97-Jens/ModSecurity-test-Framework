# Abnahmevorbereitung für natives Traefik-HTTP/2

`traefik_native_h2_acceptance.py` ist ein expliziter Host-Läufer für die native
UDS-Middleware des Repositorys im Yaegi-Interpreter des gepinnten Traefik.
Er führt sieben Safe-Szenarien und ein separates Strict-Szenario aus: Allow,
P1-/P2-/P3-Sperre, spätes Safe-P4, spätes Strict-P4, Client-Abbruch und
Upstream-Reset. Das Standardinventar des Projekts bleibt unverändert.

`CONNECTOR_ROOT`, die exakte `CONNECTOR_REVISION`, Framework-`TEST_ROOT` und
dessen kompatible Python-Umgebung/PYTHONPATH müssen ausgewählt sein. Erforderlich
sind `--root`, `--traefik`, `--modsecurity-prefix`, `--socket-parent` und
`--mode safe|strict`. Der endgültige Auslieferungsnachweis verwendet zusätzlich
`--require-clean`, `--expect-parent` und `--expect-framework`. Jeder Ausgabepfad
muss frisch, privat und unterhalb der konfigurierten externen Runtime-Wurzel
liegen. Die beiden Modi benötigen unterschiedliche Wurzeln.

Jedes Szenario verwendet einen verifizierten TLS1.3-/ALPN-H2-Socket und drei
echte Streams. Ein antwortender Peer bleibt bis zur nativen Zielfreigabe aktiv;
eine spätere Allow-Anfrage nutzt denselben physischen Socket. Native Zugriffslogs
belegen HTTP/2, TLS, Pfad, Antwort und physische Verbindungsidentität unabhängig.
Es gibt keinen H1-Fallback und keine Speicherung von Antwortinhalten. First-Byte-
und gehaltene EOS-Barrieren prüfen spätes P4, Abbruch und Reset. Strict verlangt
den echten serverseitigen RST_STREAM mit Code2.

Die native Middleware streamt Request-Bodies. Die P2-Qualifikation verlangt die
tatsächliche POST-Entity, passende native Regel-/URI-/Body-Byte-Nachweise und
Client-403; Upstream-Request-Header können vor der Body-Entscheidung bereits
vorliegen. Dieser Pfad behauptet keine Vorautorisierungsgrenze von ForwardAuth.
Allow, Safe und Strict verlangen tatsächliches Upstream-Ziel-EOS ohne einen
verfälschenden Reset.

Der C-Link-Beobachter des Frameworks aktiviert Common-Entscheidungs- und
Freigabedatensätze nach nativer Freigabe über die vorhandene Trusted-Provenance-
API. Seine Run-Kennung stammt ausschließlich aus der validierten Launcher-
Umgebung; die feste Verbindungskennung bezeichnet den Engine-Beobachterbereich,
mit Wiederverwendung false. HTTP-Header werden niemals als vertrauenswürdige
Provenienz übernommen; die physische Verbindung wird damit nicht behauptet.
Diesen Nachweis liefern Wire-Socket und natives Zugriffslog unabhängig.
Quellabschluss und Artefakthashes kennzeichnen die instrumentierte Engine
getrennt von Produktartefakten. Das P4-Inspektions-EOS der Engine kann vor einem
Strict-Reset liegen und belegt kein Client-END_STREAM. Die Middleware erfasst
den angeforderten Abbruch ohne erfundene Bestätigung eines abgeschlossenen
Abbruchs an Common.

PASS wird erst nach allen ausgewählten Fällen, nativen Zugriffszahlen,
Quellprüfung und Prozess-/Socket-/Fixture-Bereinigung veröffentlicht. Fehlender
Verkehr, keine/doppelte Freigabe, falsche Regel/Protokoll/Reset, unvollständige
native Datensätze und verlorene Peer-Isolation schlagen fehl. Compiler-,
Service- und frühere Fehlerlogs bleiben in ihren ursprünglichen Run-Verzeichnissen.
Dies sind Vorbereitungsnachweise, keine vollständige Abnahmekampagne und keine
globale Hochstufung von Fähigkeiten.

`--fault-event-writer` aktiviert eine explizite fputs-Fehlerinjektion im Test-Link;
sie muss ohne Abnahme-PASS fehlschlagen und eigene Ressourcen dennoch bereinigen.
