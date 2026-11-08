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

## Nativer Repository-Architekturvertrag

Das strikte [Repository-Architekturmodell](../connector_suite/config/testing/repository-architecture.json)
definiert drei verpflichtende Abhängigkeitsregeln aus diesem Dokument und den
versionierten Architektur- und Testzuständigkeitsverträgen des gewählten
Connectors:

- Common-C-Familienquellen müssen Host-SDK-Includes in den Adaptern belassen.
  Lokale Common-Includes werden rekursiv aufgelöst; fehlende lokale und nicht
  literale Include-Operanden schlagen fehl. Bekannte SDK-Headersignaturen für
  Apache, NGINX, HAProxy, Envoy, lighttpd und Traefik werden abgewiesen. Externe
  Standardbibliotheks- und `modsecurity/`-Engine-Header bleiben zulässig und werden
  nicht als lokale Quellen durchlaufen.
- Produktquellen, Bibliotheken und produktive Launcher dürfen nicht von der
  Framework-Testinfrastruktur abhängen. Der Checker untersucht literale
  Include-/Ladeoperanden der C-Familie, Python-Imports und ausgewählte literale
  Ladeaufrufe, Go-Imports und ausgewählte Lade-/Linkeroperanden, direkte
  Shellbefehle und native Build-Eingaben. Make-Quell-/Linkvariablen,
  Include-Direktiven, Voraussetzungen und bekannte Compile-/Linkbefehle werden
  getrennt von reiner Testdelegation geprüft. Framework-Testrunner,
  Harness-/Smoke-/Check-Einstiege, Lock-/Regeldaten, dünne Parent-Testdelegation
  und explizit gebundene Framework-Leser von Produktquellen bleiben zulässig.
  Eine datenähnliche Endung befreit keine bekannte Linker- oder Compiler-Eingabe.
- Das Framework darf keinen Parent-Gitlink einführen. Die explizite
  Framework-Wurzel muss dessen Git-Top-Level sein. Kanonische Parent-Repository-
  URLs und lokale/file-URLs auf das gewählte Produktrepository einschließlich
  alternativer Worktrees desselben Git-Repositorys werden ohne Abruf entfernter
  Repositorys geprüft.

Der ausgewählte Quellumfang ist `common/` und `connectors/`: C/C++-Header und
Quellen, Python, Go, Shell, `.in`-Templates mit Shebang, `.mk`, `.m4`, `go.mod`,
Makefiles, `Makefile.am`, `configure.ac`, NGINX-`config`, CMake-, meson- und
BUILD-Dateien. Dies ist eine begrenzte literale Prüfung, kein Compiler,
POSIX-Shell- oder Make-Auswerter. Berechnete Befehle/Imports, beliebige entfernte
Repository-Aliase, vollständige transitive Sprachgraphen, Binärinhalte und
Objektlebenszeiten benötigen gesondertes Review sowie native Build-/Runtime-
Evidenz. Harmlose Erklärungs- und Logstrings bilden in den unterstützten
Sprachformen keine Abhängigkeit.

Das Parent-Ziel `check-repository-architecture` gehört zum delegierten Lint.
Der direkte Check benötigt explizite Wurzeln:

```sh
"$PYTHON" "$FRAMEWORK_ROOT/connector_suite/modsecurity_connector_ci/checks/common/check-repository-architecture.py" \
  --connector-root "$CONNECTOR_ROOT" --framework-root "$FRAMEWORK_ROOT"
```

Exit `0` bedeutet `PASS`, `1` einen erkannten Vertragsverstoß und `2` eine
ungültige oder unvollständige Prüfung. Fehlende/leere Modelle und erforderliche
Quellumfänge können nicht bestehen. Das explizite On-Demand-Modul
`test_repository_architecture.py` prüft zulässige Eingaben und absichtliche
Verstöße, ohne Standardfälle des Connectors hinzuzufügen. Diese native Prüfung
aktiviert keinen Sonar-Architektursensor und behauptet keinen Lauf einer
inaktiven Grenzprüfung.

Die Migrationsherkunft unterscheidet gesondert ursprüngliche Produktquellen von
explizit registrierten späteren Framework-Erstaufnahmen. Eine registrierte
Erstaufnahme muss ihrer Source-Map-Route, ihrem Git-Erstaufnahmecommit/-Blob,
der Framework-Abstammung und der Abwesenheit in beiden unveränderlichen
Produktbaselines entsprechen. Aktuelle Quellen müssen regulär sein, innerhalb
der Framework-Wurzel bleiben und dürfen keine symlinkenden Vorfahren besitzen.
Unbekannte fehlende historische Quellen und Git-Fehler bleiben Fehler; eine
Registrierung erklärt sie nicht zu späteren Ergänzungen.

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

Seine Multipart-Zeilenumbruchregression prüft bytegenau die Formwerte
`A\\r\\nB` und `A\\nB` sowie eine `AB`-Allow-Kontrolle über die öffentliche
C-API. Eine passende Engine-Intervention belegt keine vom Connector
ausgelieferte Backend- oder clientseitig sichtbare Wirkung; die Fälle bleiben
daher ohne kontrollierte Host-Evidence nicht hochgestuft.

Der öffentliche C-API-Smoke enthält zusätzlich eine Exakt-Darstellungskontrolle
für AB: Ein AB-Formwert muss die konfigurierte Phase-2-Deny-Intervention
auslösen, statt nur der Zeilenumbruchregel nicht zu entsprechen.

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
