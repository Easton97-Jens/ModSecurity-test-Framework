# Architektur

**Sprache:** [English](architecture.md) | Deutsch

Das Framework ist eine wiederverwendbare Test-, Normalisierungs- und
Evidence-Schicht für ModSecurity-Connector-Projekte. Es ist kein Server,
Proxy oder Connector-Implementierung.

## Repository-Grenze

| Ebene | Verantwortung |
|---|---|
| Framework | YAML-Fälle, Runner, Normalizer, Katalogchecks, Report-Generatoren und begrenzte Evidence-Validierung |
| Gemeinsamer Connector-Code | Connector-neutrale Datenformen, soweit das Connector-Repository sie bereitstellt |
| Host-Adapter | Host-Hooks, Filter, Plugins, Direktiven, Konfigurations-Merge und Interventionsübersetzung |
| Connector-Evidence | Capability-Deklaration, beobachtete Artefakte und Promotion-Entscheidung |

Gemeinsamer Framework-Code darf keine Host-SDK-Objekte, Serverkonfiguration
oder ungeprüfte Payload-Daten besitzen. Ein Connector-Adapter übersetzt seinen
Host-Zustand in die gewählten Test- und Evidence-Verträge und übersetzt
beobachtete Ergebnisse zurück in host-spezifisches Verhalten.

## Transaktions- und Lifecycle-Modell

Das Framework repräsentiert eine Transaktion über Fallmetadaten und begrenzte
Artefakte. Der Host-Adapter besitzt die tatsächliche Reihenfolge und darf nur
beobachtete Phasen melden.

| Lifecycle-Bereich | Framework-Anliegen | Connector-Verantwortung |
|---|---|---|
| P1 Request-Start | Fallauswahl und Request-Metadaten | Connection-, URI- und Request-Header-Zustellung |
| P2 Request-Body | Body-Fixture und begrenzte Assertions | Inkrementelle Body-Zustellung, Limits und Interventionsverhalten |
| P3 Response-Header | Response-Header-Fixture und Assertions | Header-Zustellung und Host-Response-Handling |
| P4 Response-Body und Logging | Nicht-Promotion- und Privacy-Grenzen | Streaming, Late Intervention, Final-Logging und Host-sicheres Verhalten |

P1–P4-Namen machen aus einer deklarierten Phase keinen Implementierungsclaim.
Insbesondere müssen ein Phase-4-Log, eine Pass-Through-Response oder ein
Post-Commit-Connection-Ergebnis der konfigurierten Evidence-Policy folgen und
dürfen nicht als Pre-Commit-Response-Body-Blocking dargestellt werden.

## Engine- und Host-Trennung

Öffentliche libmodsecurity-APIs, Regeln und Transaktionszustand gehören zur
Engine-Seite. Der Host-Adapter steuert, wann diese APIs aufgerufen werden und
ob ein Host eine Intervention sicher anwenden kann. Connector-spezifische
Konfiguration, Body-Limits, Content-Type-Handling, Logging und
Connection-Verhalten lassen sich nicht verallgemeinern, nur weil das Framework
gemeinsame YAML-Dateien verwendet.

Der connector-freie v3-API-Smoke ist eine begrenzte Engine-Sonde. Er ist keine
Apache-, NGINX-, HAProxy-, Envoy-, Traefik- oder lighttpd-Runtime-Evidence.

## Capability- und Statusmodell

Capabilities kennzeichnen getestetes Verhalten; sie überspringen, promoten oder
zertifizieren keinen Fall automatisch. Der Ergebnisstatus unterscheidet
beobachtete PASS und FAIL von BLOCKED, NOT_EXECUTABLE, mapped-only, pending,
future, connector-gap und runtime-difference.

`RESPONSE_BODY` bleibt nicht verifiziert und nicht hochgestuft, bis der
anwendbare Connector-Evidence-Vertrag stabile Belege akzeptiert. First-Byte-
Timing, No-Full-Response-Buffering, Body-Limits, Event-Privacy und
Evidence-Promotion werden ebenfalls aus expliziten Artefakten validiert, nicht
aus einem Bericht oder Exit-Status abgeleitet.

## Daten, Events und Privacy

Kanonische Result- und Event-Eingaben verwenden begrenzte, normalisierte
Metadaten. Sie dürfen geprüfte Identifikatoren, Phase, Aktion oder Entscheidung,
Status, HTTP-Status, Version, Größe, Hash, Trunkierung und vom Schema
zugelassene Redaktionsfakten enthalten. Sie dürfen keine rohen Request- oder
Response-Bodies, Credentials oder ungeprüfte Host-Logs enthalten.

Hash-Chain-Daten können Tamper-Detection auf Smoke-Ebene unterstützen. Ohne
Connector-eigene sichere Schlüsselbehandlung und Storage bieten sie keine
dauerhafte Integrität.

## Build- und Cache-Grenze

Quellkopien, Build-Ausgaben, Logs, temporäre Daten und Evidence liegen unter
expliziten Pfaden außerhalb des Git-Worktrees. Das Framework verwendet keinen
Parent-Workspace still wieder und schreibt keine Source-Checkouts um.
Cache-Reuse ersetzt keine aktuelle Konfigurations-, Start-, Runtime- oder
Evidence-Validierung.

## Verwandte Dokumente

- [Katalog und Fälle](catalog-and-cases.de.md)
- [Testing und Evidence](testing-and-evidence.de.md)
- [Connector-Integration](connector-integration.de.md)
- [Entwicklung](development.de.md)
- [Variablen und Platzhalter](reference/variables.de.md)
