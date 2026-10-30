# Traefik-Harness

**Sprache:** [English](README.md) | Deutsch

Status: minimal_runtime_smoke für den Connector-eigenen ForwardAuth-Anforderungspfad
Laufzeitstatus: Breiteres Connector-Verhalten bleibt nicht überprüft/Connector-Lücke

`run_traefik_smoke.sh` bleibt der Framework-orientierte Kompatibilitätseinstiegspunkt.
Der Connector-eigene Dienstpfad wird direkt von ausgeübt
`scripts/runtime-smoke.sh`, das die erstellte Common-Runtime-Backed startet
ForwardAuth-Dienst, ein minimaler Upstream und Traefik mit einer temporären Datei
Anbieterkonfiguration.

Aktueller lokaler Selbsttest:

- `make -C connectors/traefik self-test-decision-service`

Der Selbsttest deckt nur die speicherinterne Entscheidungslogik zum Zulassen/Blockieren ab. Das ist nicht der Fall
Nachweis einer Traefik `forwardAuth`-Bereitstellung, HTTP-Dienstverhalten, CRS-Ausführung,
libmodsecurity-Integration oder Traefik-Verkehrsverarbeitung.

Getrennte Real-Service-Stufen:

```sh
make -C connectors/traefik build-connector
make -C connectors/traefik check-config
make -C connectors/traefik start-smoke
make -C connectors/traefik runtime-smoke
```

Nur `runtime-smoke` sendet Anfragen. Es erfordert 200 für die zulässige Anfrage und
403 für `X-Modsec-Smoke: block`; Behobene Laufzeitfehler sind eher FAIL als
GESPERRT. Die Verarbeitung des Antworttextes wird von `forwardAuth` weiterhin nicht unterstützt.

Framework-Runtime-Smoke-Einstiegspunkt:

```sh
make smoke-traefik
```

Der auf das Framework gerichtete Einstiegspunkt führt keine Starter-Selbsttests für Entscheidungsdienste aus
als Laufzeitbeweis. Fehlende explizit lokale Laufzeitabhängigkeiten bleiben bestehen
GESPERRT/77.

Der Full-Lifecycle-Dispatcher verwendet diese `forwardAuth`-Kompatibilität nicht wieder
Einstiegspunkt. Es ruft `runtime-smoke-traefik-native` auf
`full-lifecycle-traefik-native`, das `native_middleware/` in einem bereitstellt
Isolierter angehefteter Traefik-Lokal-Plugin-Arbeitsbereich, erstellt/startet einen persistenten
private UDS Common/libmodsecurity-Engine und überprüft das Ziel P1–P4-sicher
Wirtsverhalten. Es lädt `MSCONNECTOR_RULES_FILE`, wenn es geliefert wird, also das Original
Ereignisse verwenden die Framework-Regel-IDs. Diese Beweise bleiben nicht gefördert und
kann nicht für die Fähigkeits- oder Produktionsüberprüfung eintreten; P4 bleibt streng
`NOT EXECUTED`.

Zukünftige Harnessarbeiten müssen Folgendes dokumentieren:

- Traefik-Binär-, Container- oder Quell-Build, der vom Harness verwendet wird
- Traefik-Konfigurationsdatei
- Ausgewählter ModSecurity-Integrationspunkt
- `forwardAuth`, Plugin-, Middleware-, Sidecar- oder benutzerdefinierte Modulkonfiguration, wenn
  dieser Pfad ist ausgewählt
- Entscheidungsdienst-Endpunkt, wenn ein externer Entscheidungsdienst ausgewählt ist
- Vom Harness geschriebene Beweispfade
- Ergebnis-JSON-Pfad
- PASS/FAIL/BLOCKED-Zählungen
- No-CRS- und With-CRS-Trennung
- RESPONSE_BODY, Negativ-/Pass-Through- und Audit-/Protokollnachweise bei der Auswertung

Es wird kein Laufzeitergebnis beansprucht, bis der Connector-eigene Laufzeitrauch erfolgreich ist
Der aktuelle Commit und seine externen Beweise bleiben erhalten.
