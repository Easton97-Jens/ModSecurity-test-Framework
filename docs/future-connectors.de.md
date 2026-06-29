# Zukünftige Connector

**Sprache:** [English](future-connectors.md) | Deutsch

In diesem Stabilisierungsschritt wird kein neuer Konnektor implementiert. Jede Zukunft
Der Connector muss zunächst einen realen Harness bereitstellen, der Apache und entspricht
NGINX.

## HAProxy

- Erwartetes Modell: SPOE oder nativer Erweiterungspfad müssen Metadaten manuell anfordern und
  Körperdaten in der richtigen Phase an libmodsecurity übergeben.
- Schwierige Bereiche: Pufferung, Antwortinspektion, Überwachungsprotokollbesitz und
  Zuordnung von ModSecurity-Eingriffen zu HAProxy-Aktionen.
- Wahrscheinlich übertragbare erste Fälle: `REQUEST_HEADERS`, `ARGS`, einfacher Anfragetext.
- Wahrscheinliche Connector-spezifische Fälle: Streaming, Backend-Antwortverarbeitung, SPOE
  Fehlerpfade.

## Gesandter

- Erwartetes Modell: HTTP Filter oder externer Verarbeitungsfluss.
- Schwierige Bereiche: asynchrone Körperpufferung, Filterreihenfolge, Header-Mutation und
  Zuordnung von Interventionen zu Envoy-Antworten.
- Wahrscheinlich portable erste Fälle: Header, Abfrageargumente, roher JSON-Körper.
- Wahrscheinliche Connector-spezifische Fälle: HTTP/2, gRPC, Streaming, Filterkette
  Konfiguration.

## Lighttpd

- Erwartetes Modell: native Plugin-Hook-Integration oder dokumentiertes Skript
  Modulpfad.
- Schwierige Bereiche: Verfügbarkeit des Anforderungskörpers, Antwortfilter-Hooks und Stabilität
  Modul-Build-Verpackung.
- Wahrscheinlich portable erste Fälle: Header und Abfrageargumente.
- Wahrscheinlich Connector-spezifische Fälle: Plugin-Lebenszyklus und Serverkonfigurationsanalyse.

## Traefik

- Erwartetes Modell: plugin/middleware Pfad muss vor jedem Connector nachgewiesen werden
  Ansprüche.
- Schwierige Bereiche: Plugin-Sandbox-Einschränkungen, Anforderungskörperpufferung, Antwort
  Mutation und das Verteilen von libmodsecurity.
- Wahrscheinlich portierbare erste Fälle: Header und Abfrageargumente, sofern die Middleware dies kann
  Rufen Sie libmodsecurity sicher auf.
- Wahrscheinlich Connector-spezifische Fälle: dynamisches Neuladen der Konfiguration und anbieterspezifisch
  Middleware-Verkabelung.

## Gemeinsame Anforderung

Jeder Connector muss eine Zusammenfassung JSON mit „connector_path“ erstellen:
"real-world"`, `validation_mode: "real-world-connector-path"`, stabil
`pass/fail/blocked`-Semantik und keine generierten Artefakte außerhalb von `BUILD_ROOT`.
