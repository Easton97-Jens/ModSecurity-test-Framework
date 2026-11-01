# Native Connector-Regressionstests

Dieses Paket besitzt die nativen Selbsttestdefinitionen, die aus den
Produkt-Übersetzungseinheiten des Connectors ausgelagert wurden.
`extraction-manifest.json` verzeichnet die ursprünglichen Funktionsdigests.
Definitionen und Assertions blieben bei der Auslagerung erhalten. Die
Produktprogramme bieten ihre Service-, Konfigurations- und Metadatenbefehle an;
sie führen diesen Testbestand nicht mehr über `--self-test` aus.

Dies sind ausdrücklich ausgewählte Spezialtests. Sie vergrößern das automatisch
ausgewählte Standardinventar nicht. Ein bestandener nativer Selbsttest ist kein
Nachweis eines Connector-Laufs im Host. Der Runner verlangt
`ON_DEMAND_TESTS=1` oder eine durch das Inventar zugelassene Ausführung.

```sh
ON_DEMAND_TESTS=1 python connector_native_tests/run.py \
  --connector-root /absolute/Connector \
  --connector-revision FULL_40_CHARACTER_CONNECTOR_HEAD \
  --test-root /absolute/Framework/connector_native_tests \
  --profile native-selftest \
  --target envoy-bridge \
  --output-root /absolute/existing/external/output
```

| Target | Erhaltene Prüfungen |
| --- | --- |
| `envoy-bridge` | Allow, Header-Deny und URI-Deny |
| `lighttpd-bridge` | Starter-Capability und nicht promotender Probevertrag |
| `traefik-decision-service` | Allow, URI-Deny und Header-Deny |
| `haproxy-spoa-starter` | Allow, lokales Deny und ungültiger Request |
| `traefik-engine` | Protokollparsing und Eigentum des privaten Listeners |
| `haproxy-modsecurity-binding` | Native Regeln, Request-/Body- und Lifecycle-Prüfungen |
| `haproxy-spop-runtime` | SPOP-Framing, Queue, Fehler, Deadlines und Cleanup |

`traefik-engine` benötigt zusätzlich `--socket-parent` mit einem vorhandenen
kurzen externen Elternverzeichnis. Der Runner erzeugt dort ein eigenes privates
Unterverzeichnis. `haproxy-modsecurity-binding` verlangt entweder
`--argument=--self-test --argument=/absolute/lifecycle-rules.conf` oder
`--argument=--self-test-crs --argument=/absolute/crs-preamble.conf`.
Komplexe Targets benötigen ein kompatibles natives ModSecurity-SDK samt
Bibliothek. Explizite `--modsecurity-include` und `--modsecurity-lib` wählen
vorhandene Installationen aus.

Das Framework erzeugt eine private externe Übersetzungseinheit, welche den
expliziten Produktquellcode und die Definitionen des Frameworks einbindet. So
bleibt der Zugriff auf private C-Helfer erhalten, ohne die Produktprogramme vom
Framework abhängig zu machen. Die Kompilierung behält C17,
`-Wall -Wextra -Werror` und pthread-Unterstützung bei. Jeder Aufruf besitzt
zeitlich begrenzte Compiler-/Testprozessgruppen und getrennte Ausgaben.

`result.json` verzeichnet beide Repositoryrevisionen, das Profil, den tatsächlichen
Exitstatus, lokale Produktänderungen und einen Digest von `input-bindings.json`.
Diese Datei bindet die tatsächlich verwendeten Produkt-/Testeingaben; nach dem
Lauf erfolgt eine erneute Prüfung. Geänderte Eingaben lassen den Aufruf scheitern.
`--build-only` dokumentiert ausschließlich die Kompilierung. Fehlgeschlagene
Spezialtests bleiben fehlgeschlagen und behalten ihre Diagnoseausgaben.
