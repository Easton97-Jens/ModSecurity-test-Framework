# Regression für Traefik-Native-Informationsantworten

**Sprache:** Deutsch | [English](traefik-native-informational.md)

Das Framework besitzt die Regression für das externe Connector-Finding
`SEC-TRAEFIK-NATIVE-001`. Die Produktquelle verbleibt im Connector-Repository.
Die Suite prüft, dass 100, 102 und 103 weder P3 noch Commit-Metadaten der finalen
Antwort oder das Request-Body-EOS verbrauchen. Status 101 behält den bestehenden
terminalen Upgrade-/Hijack-Vertrag.

Die Standardauswahl enthält weiterhin genau 100 expandierte Fälle. Diese
zusätzlichen Spezialisten verlangen ausdrücklich `--on-demand` und
`ON_DEMAND_TESTS=1`; das Inventar erlaubt nur die benannten Selektoren mit
geprüften Quellbindungen. Ein Quellen- oder Paket-Seam-Ergebnis belegt keinen
realen Traefik-/libmodsecurity-Lauf.

| Ausführungssuffix nach `specialist.sec-traefik-native-001.` | Expandierte Fälle | Beobachtbarer Vertrag |
| --- | ---: | --- |
| `final-decision` | 13 | Echter HTTP-Server/-Client; `httptrace.Got1xxResponse`; 100/102/103, wiederholte 1xx, final 200/201/401/403, ausschließlich finaler Schutzheader, P3-Allow/-Deny/-Redirect und Kontrollen, Keepalive-Folgezugriff, einmaliges Cleanup |
| `request-eos` | 3 | 1xx liest keine Requestbytes vorzeitig und führt kein Request-EOS aus |
| `implicit-final` | 10 | Write, leeres Write, Flush, ReadFrom und Handler-Rückkehr erhalten finales P3-Allow/-Deny |
| `streaming` | 1 | Client erhält erste Bytes vor Upstream-EOS; begrenzte P4-Chunks und einmaliges EOS/Cleanup |
| `upgrade` | 1 | 101 bleibt terminal; Hijack erfindet kein P4/EOS; einmaliges Cleanup |
| `header-bounds` | 3 | Ungültiger Name sowie Headeranzahl- und Byteüberschreitung scheitern vor Informationsweitergabe/P3 |
| `host` | 4 | Realer gepinnter Traefik-/Plugin-/privater UDS-/libmodsecurity-Pfad: 103-Deny, Deny ohne 103, 103-Allow und legitimer Folgezugriff |

Die Deny-Prüfungen unterscheiden geschützte Upstreambytes vom eigenen
`request rejected`-Antwortbody der Middleware. Die Go-Tests verwenden echten
HTTP-Transport für die Semantik von Informationsantworten; der Recorder dient
nur Zustands- und Fehlerpfaden ohne weitergegebene Informationsantwort.

Setze `CONNECTOR_ROOT`, die exakte `CONNECTOR_REVISION`, `TEST_ROOT` auf diesen
Framework-Checkout und `CONNECTOR_TEST_OUTPUT_ROOT` auf ein eigenes externes
Verzeichnis. Auch Python-/Go-Caches und temporäre Pfade bleiben extern. Rufe den
Framework-Einstieg über RTK auf, beispielsweise:

```sh
rtk bypass env ON_DEMAND_TESTS=1 "$PYTHON" -P -m modsecurity_test_framework.connector \
  --connector-root "$CONNECTOR_ROOT" --connector-revision "$CONNECTOR_REVISION" \
  --test-root "$TEST_ROOT" --output-root "$CONNECTOR_TEST_OUTPUT_ROOT" \
  --profile traefik-native --on-demand --strict-skips \
  --execution specialist.sec-traefik-native-001.final-decision
```

Verwende die übrigen exakten Ausführungssuffixe separat oder wiederhole
`--execution`. Wähle für drei unabhängige reale Hostwiederholungen `host` in drei
getrennten Aufrufen und bewahre alle Ausgabeverzeichnisse auf. Der Hostadapter
verlangt die vorhandenen nativen Laufzeitvoraussetzungen sowie Identitäts- und
Isolationsprüfungen. Eine fehlende Voraussetzung ist ein Blocker und erlaubt
keine Abschwächung dieser Prüfungen.

Das Go-Quelloverlay protokolliert die gewählten Quelldigests. Bis Commits
vorliegen, müssen die exakte lokale Quelldifferenz und die Basisrevisionen
gemeinsam geprüft werden. Framework-Tests müssen verfügbar sein, bevor eine
Connector-Änderung den Framework-Pin aktualisiert; Merge und Pinänderungen
benötigen jeweils eigene Autorisierung.
