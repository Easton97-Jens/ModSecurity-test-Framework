# Connector-Integration

**Sprache:** [English](connector-integration.md) | Deutsch

Das Framework liefert wiederverwendbare Fälle, Runner, Normalizer,
Katalogchecks und Report-Generierung. Ein Connector-Repository besitzt seinen
Host-Adapter, Build-Integration, Runtime-Konfiguration, ausführbaren Harness
und kanonische Host-Evidence.

## Ownership-Grenze

| Bereich | Eigentümer |
|---|---|
| YAML-Fallschema, Auswahl und Normalisierung | Framework |
| Host-Hooks, Filter, Plugins und Direktiven | Connector-Repository |
| Host-Build und Runtime-Konfiguration | Connector-Repository |
| Connector-Capabilities und Integrationsmodus | Connector-Repository |
| Kanonische Runtime-Artefakte und Promotion-Entscheidung | Connector-Repository |
| Generierte Cross-Case-Sicht | Framework-Generator mit deklarierten Eingaben |

Das Framework kann `BLOCKED` melden, wenn ein benötigter
Connector-eigener Harness fehlt. Ein Framework-Starter- oder Self-Test-PASS
beweist niemals einen Host-Lifecycle.

## Adaptervertrag

Ein Adapter muss seine Grenze explizit machen, statt Host-Objekte an Shared
Code weiterzugeben. Das normale Runner-Modell deckt Vorbereitung, Start,
Stopp, Reload, Konfigurations- und Regelanwendung, Endpoint-Ermittlung,
Request-Ausführung, Artefaktsammlung und Cleanup ab. Ein Connector kann eine
gleichwertige host-spezifische Form implementieren, muss aber die
Evidence-Grenze bewahren: Nur beobachtetes Verhalten wird Runtime-Evidence.

Host-spezifische Phasenreihenfolge, Request- und Response-Body-Zustellung,
Interventionsverhalten, Logging, Connection-Handling und
Konfigurations-Merge-Regeln bleiben Connector-eigen. Das Framework macht aus
einer deklarierten Capability keinen Implementierungsclaim.

## Gepflegte Provenienz

Die folgenden Quellfakten bleiben absichtlich hier erhalten, weil
Adapter-Metadaten-Driftchecks sie validieren.

| Komponente | Upstream | Branch | Commit | Version | Lizenz | Adapter-eigener Pfad |
|---|---|---|---|---|---|---|
| ModSecurity-apache | https://github.com/owasp-modsecurity/ModSecurity-apache | master | `0488c77f69669584324b70460614a382224b4883` | `v0.0.9-beta1-26-g0488c77` | Apache-2.0 | `connectors/apache` |
| ModSecurity-nginx | https://github.com/owasp-modsecurity/ModSecurity-nginx | master | `9eb44fd9ab0988756e1ab8ce5aa5548ddbe57846` | `v1.0.4-14-g9eb44fd` | Apache-2.0 | `connectors/nginx` |
| ModSecurity v3 | https://github.com/owasp-modsecurity/ModSecurity | v3/master | `0fb4aff98b4980cf6426697d5605c424e3d5bb60` | `v3.0.15` | Apache-2.0 | Konfigurierte Engine-Quelle |
| ModSecurity v2 | https://github.com/owasp-modsecurity/ModSecurity | v2/master | `02eed22d74667b32091eece088a8ebdf64b6ba67` | `v2.9.13` | Apache-2.0 | Historische Semantikreferenz |

Produktive Apache- und NGINX-Adapterquellen sind absichtlich
connector-spezifisch. Ihre Attribution, Lizenz, Origin und Source-Maps bleiben
auch im Connector-Repository. Das Framework validiert Dokumentationsmetadaten,
ohne C-Code des Connectors zu linken.

## Sechs-Connector-Grenze

| Connector | Framework-Rolle | Erforderliche Evidence-Quelle |
|---|---|---|
| Apache | Anwendbare Fälle auswählen und materialisieren | Connector-eigener Apache-Host-Harness und Artefakte |
| NGINX | Anwendbare Fälle auswählen und materialisieren | Connector-eigener NGINX-Host-Harness und Artefakte |
| HAProxy | Anwendbare Fälle auswählen und normalisieren | Connector-eigener Harness des gewählten Integrationsmodus und Artefakte |
| Envoy | Anwendbare Fälle auswählen und normalisieren | Connector-eigener Harness des gewählten Integrationsmodus und Artefakte |
| Traefik | Anwendbare Fälle auswählen und normalisieren | Connector-eigener Harness des gewählten Integrationsmodus und Artefakte |
| lighttpd | Anwendbare Fälle auswählen und normalisieren | Connector-eigener Harness des gewählten Integrationsmodus und Artefakte |

Der gewählte Integrationsmodus, das Capability-Manifest, die
Konfigurationsreferenz und das Lifecycle-Ergebnis gehören zum
Connector-Repository. Dadurch wird Dokumentations-, Compatibility- oder
Prototyp-Material nicht als native Runtime-Implementierung behandelt.

## Compatibility-Pfade

Historische HAProxy-SPOE/SPOA-Discovery-, Disabled-Key-, Report-Schema- und
Readiness-Notizen beschrieben nur eine mögliche Compatibility-Richtung. Sie
implementierten keinen Framework-Connector-Key und bewiesen keine
Host-Runtime. Aktuelle Arbeit muss den im Connector-Repository deklarierten
Integrationsmodus und kanonische Evidence verwenden; kein historischer
Planungstext erzeugt eine Capability oder Promotion.

Dieselbe Regel gilt für importierte Apache-, NGINX-, v2-, v3- und
MRTS-Referenzen: Ihr Code oder ihre Tests sind Eingaben für Review und
Ableitung, aber kein ausführbarer Beweis in einem anderen Connector.

## Eine Integration aktualisieren

1. Adapter-Metadaten und Connector-Origin-Datensätze mit der Adapter-Quelle
   ausrichten.
2. Integrationsmodus und Capability-Grenze im Connector-Repository deklarieren.
3. Einen echten Host-Harness bereitstellen, bevor Runtime-Unterstützung
   behauptet wird.
4. Begrenzte Artefakte normalisieren und über den anwendbaren Evidence-Vertrag
   validieren.
5. Framework-Berichte erst regenerieren, nachdem ihre Input-Evidence aktuell ist.

## Historischer Kontext

Getrennte Importanalysen, Connectorpläne und HAProxy-SPOE/SPOA-Dokumente wurden
hier zusammengeführt. Git bewahrt die detaillierte Migrationshistorie; dieses
Dokument bewahrt den aktuellen Ownership- und Attribution-Vertrag.
