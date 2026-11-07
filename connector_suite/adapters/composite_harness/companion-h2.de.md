# HTTP/2-Vorbereitung für Autorisierung und Response-Companion

`companion_h2_acceptance.py` führt das vollständige logische Profil
`envoy-ext-authz` oder `traefik-forwardauth` aus. Je Profil gibt es acht
ausdrücklich gewählte Zusatzfälle: Allow, P1/P2/P3-Deny, spätes P4 Safe/Strict,
Client-Abbruch und Upstream-Reset. Das automatische Standardinventar bleibt
unverändert.

Auszuwählen sind `--adapter envoy_ext_authz_h2` oder
`--adapter traefik_forwardauth_h2`, ein `--case`, beide Quellverzeichnisse und
vollständigen Revisionen, ein frisches externes Laufverzeichnis, der native
Host samt unabhängig zugelassenem `--host-sha256` sowie der frisch gebaute
native Composite-`--service` mit `--build-receipt`. `--require-clean` lehnt
veränderte finale Quellstände ab. Der Beleg enthält den nativen Build-Exitcode,
die exakten Hashes aller kompilierten Quellen vor/nach dem Build sowie die
Service- und libModSecurity-Hashes. Nach dem Verkehr wird erneut geprüft.

Der Client prüft TLS 1.3, die Fixture-CA und ALPN `h2`; es gibt keinen
Protokoll-Fallback. Stream 1 bleibt aktiv, während Zielstream 3 läuft und seine
native gehaltene Transaktion schließt. Stream 5 prüft danach dieselbe lebende
Verbindung. Angehaltene Response-Fälle verlangen tatsächliche DATA vor der
Freigabe des Upstream-EOS. P2 nutzt den tatsächlichen begrenzten POST-Inhalt.
Native Host-Zugriffe, Request-Hash, serverseitige Transaktionsidentität, Regel
und Lebenszyklusbelege müssen zusammenpassen. Envoy-Stream-UUIDs und
Traefik-Request-Zähler unterscheiden sich von Wire-Streamnummern; eindeutige
Request-Metadaten ordnen sie auf derselben Verbindung einander zu.

Beide Composite-Modi verwenden dasselbe Common-CGo-Engine-Backend; rohe
Common-Ereignisse nennen `envoy`/`ext_proc`. Das logische Profil wird unabhängig
durch den nativen Host und die gehaltene Autorisierungs-/Response-Übergabe
belegt. Der Backend-Name qualifiziert keines der logischen Profile als ext_proc.

Safe erhält die vollständige bereits begonnene Antwort und protokolliert
Log-only. Explizites Strict verlangt die passende native Laufzeitpolicy und
fordert einen Host-Abbruch an. Nur unabhängig beobachtete RST_STREAM belegen
das Ergebnis. Die Anforderung bleibt von einem Common-bestätigten tatsächlichen
Host-Ergebnis getrennt. Eine beobachtete unvollständige Companion-Verbindung
erzeugt einen typisierten Protokollabschluss, niemals erfundenes Response-EOS
oder eine unbelegte Zuordnung zu Client-/Upstream-Abbruch.

`--completion-writer-fault` begrenzt ausschließlich reguläre Dateischreibvorgänge
des gewählten Service und injiziert einen echten Lebenszyklus-Schreibfehler.
Dieser Negativtest muss scheitern und trotzdem den eigenen Host, Service und
die Fixture beenden. Berichte verlangen vorhandene, vollständige, eindeutige
Ergebnisse und geprüfte Bereinigung von Prozessen, Ports, privaten TLS-Dateien
und privatem UDS. Fehlender Verkehr, vertauschte Identitäten, fehlende Phasen
oder Schreibfehler dürfen kein PASS erzeugen.

Die gezielten Reader-Kontrollen laufen mit:

```sh
python -m unittest connector_suite.adapters.composite_harness.test_companion_h2_acceptance
```

Die nutzlastfreien Metadaten-Fixtures stammen aus tatsächlichen Allow-,
Strict- und Cancel-Vorbereitungsläufen. Sie sind Unit-Test-Eingaben und keine
Laufzeitbelege für das finale Commit-Paar. Vor einer Vorbereitungsfreigabe ist dessen frischer Lauf
weiterhin erforderlich.
