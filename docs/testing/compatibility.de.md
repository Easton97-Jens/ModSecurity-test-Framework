# Kompatibilität

**Sprache:** [English](compatibility.md) | Deutsch

Status: eingerüstet

## Versionsposition

Das Gerüst zielt auf öffentliche APIs von libmodsecurity v3 ab. v2-Artefakte werden nicht als verwendet
Architektur für neue Connector.

## Aktuelle Kompatibilitätsmatrix

| Bereich | Status | Notizen |
| --- | --- | --- |
| Gemeinsame Überschriften | umgesetzt | Nur Connector-neutrale C-kompatible Datenformen |
| libmodsecurity v3 API Zuordnung | geplant | Öffentliche API-Sequenz dokumentiert, nicht verpackt |
| Apache-Connector | eingerüstet | Der neueste von einer lokalen Quelle erzeugte Smoke hat die aktiven Laufzeitfälle 48/48 bestanden |
| NGINX-Connector | eingerüstet | Der neueste von der lokalen Quelle erstellte Smoke hat 54/54 aktive Laufzeitfälle nach der Behebung der NGINX Harness-Berechtigung bestanden |
| Apache-Verbindungspfad für die reale Welt | umgesetzt | Smoke-Zusammenfassungen zeichnen im Quellcode erstellte httpd-, `mod_security3.so`-, libmodsecurity- und verifizierte Variablen auf |
| NGINX realer Connector-Pfad | umgesetzt | Smoke-Zusammenfassungen zeichnen im Quellcode erstellte NGINX, dynamische Module, libmodsecurity und verifizierte Variablen auf |
| HAProxy-Connector | unbekannt | SPOE/Lua/native Optionen dokumentiert, Implementierung unentschlossen |
| Envoy-Connector | unbekannt | HTTP filter/ext_authz/Wasm Optionen dokumentiert, Implementierung unentschlossen |
| Lighttpd-Connector | unbekannt | Native Plugin- und mod_magnet-Optionen dokumentiert, Implementierung noch unklar |
| Traefik-Connector | unbekannt | Yaegi/Wasm Plugin-Optionen dokumentiert, Implementierung noch unklar |
| Wiederverwendung der v2-Regression | geplant | Nur portable rule/engine-Semantik darf `docs/imports/common/` eingeben |
| Von v2 abgeleitete gemeinsame Importe | umgesetzt | Blockierende operator/transformation-Fälle und der `t:urlDecode`-No-Match-Pass-Through-Fall werden lokal auf Apache und NGINX weitergeleitet. |
| Von v3 abgeleitete gemeinsame Importe | umgesetzt | Blockierende multipart/FILES/XML/operator/action/collection/audit-Fälle und No-Match-Pass-Through-Fälle für cookies/header names/ARGS_NAMES werden lokal auf Apache und NGINX weitergeleitet. |
| Von der Quelle abgeleiteter Apache/NGINX Testimport | umgesetzt | Importierte YAML-Fälle werden abgeleitet und nicht kopiert; Herkunft und Portabilität werden dokumentiert |

## Fähigkeitsregel

Tests und Connector-Dokumente müssen die erforderlichen Funktionen benennen. Wenn ein Verhalten davon abhängt
On-Hook-Timing, Pufferung, Streaming, Protokollartefakte, Neuladesemantik oder Server
Konfiguration ist es Connector-spezifisch, sofern es sich nicht als portabel erwiesen hat.

## Geteilte Minimalfälle

Die Dateien unter `$FRAMEWORK_ROOT/tests/cases/` sind portierbar
rule/request Modelle, die von `ModSecurity-test-Framework` bereitgestellt werden.
Bis dahin sind sie kein Nachweis dafür, dass ein Connector das Verhalten unterstützt
Der Laufzeitkabelbaum des Connectors beobachtet die erwartete HTTP-Antwort.

Lokal beobachtet am 15.05.2026 mit expliziter externer `BUILD_ROOT`:

| Fall | Fähigkeitsbereich | Apache | NGINX |
| --- | --- | --- | --- |
| `audit_log_phase1_block.yaml` | Abfrageargumente, Phase 1, Prüfprotokoll | bestanden, HTTP 403 plus Prüffelder | bestanden, HTTP 403 plus Prüffelder |
| `phase1_header_block.yaml` | Anforderungsheader, Phase 1 | bestanden, HTTP 403 | bestanden, HTTP 403 |
| `phase2_args_block.yaml` | Abfrageargumente, Phase 2 | bestanden, HTTP 403 | bestanden, HTTP 403 |
| `phase2_args_pass.yaml` | Abfrageargumente, Phase 2, Passthrough | bestanden, HTTP 200 plus Ursprungskörper | bestanden, HTTP 200 plus Ursprungskörper |
| `request_body_json_block.yaml` | Anfragetext, JSON Inhaltstyp, Rohtextübereinstimmung | bestanden, HTTP 403 | bestanden, HTTP 403 |
| `request_body_urlencoded_block.yaml` | Formularkörper, `ARGS_POST` | bestanden, HTTP 403 | bestanden, HTTP 403 |
| `response_header_basic.yaml` | Antwortheader, Phase 3 | bestanden, HTTP 403 | bestanden, HTTP 403 |

Dies beweist nur diese PoC-Verhaltensweisen in diesem Arbeitsbereich, nicht den vollständigen Connector
Kompatibilität, CRS Unterstützung, Multipart-Handhabung, Streaming-Verhalten, HTTP/2, oder
vollständiges Reaktionskörperverhalten.

## Importierte Fallumfänge

| Umfang | Standort | Bedeutung der Kompatibilität |
| --- | --- | --- |
| häufig minimal | `$FRAMEWORK_ROOT/tests/cases/` | Vor dem Importschritt bereits lokal für beide PoCs nachgewiesen |
| allgemein importiert | `$FRAMEWORK_ROOT/tests/cases/` | Übertragbare Kandidaten, abgeleitet aus Apache/NGINX-Tests; Die Kompatibilität wird erst dann beansprucht, wenn der Smoke beider Anschlüsse vorüber ist |
| v2 importiert | `$FRAMEWORK_ROOT/tests/cases/` | Tragbare v2-Semantikkandidaten, angepasst an das HTTP-Verhalten und bewährt auf beiden Connector-PoCs |
| v3 importiert | `$FRAMEWORK_ROOT/tests/cases/` | Tragbare v3-Regressionskandidaten, angepasst an das HTTP-Verhalten und bewährt auf beiden Connector-PoCs |
| Apache importiert | `tests/cases/connector-specific/apache/` | Nur Apache, bis ein gemeinsames Äquivalent nachgewiesen ist |
| NGINX importiert | `tests/cases/connector-specific/nginx/` | Nur NGINX, bis ein gemeinsames Äquivalent nachgewiesen ist |

Nur zugeordnete Kategorien umfassen HTTP/2, Proxy, mehrteilige Parser-Randfälle,
Blockierung des Antworttextes, Operatoren für externe Dateien, Debug-Protokolle und Connector
Konfigurationsvererbung.

Frühere lokale Ausführungen importierten häufige Fälle nach Apache- und NGINX-Nachweisen. A
2026-05-20 lokaler NGINX-Lauf hat einen Harness-Berechtigungsblocker offengelegt, bei dem 11
erwartet - 200 pass-through/phase-4 Fälle haben 403 zurückgegeben, weil NGINX dies nicht konnte
Lesen Sie generierte `htdocs/index.html` unterhalb eines privaten übergeordneten Verzeichnisses. Der
21.05.2026 Wiederholung, nachdem der Harness-Berechtigungs-Fix alle 54 aktiven NGINX bestanden hat
Fälle; siehe `docs/testing/nginx-runtime-failure-classification.md`.

## Gehäuse- und Filterkompatibilität

| Fall oder Kategorie | Apache | NGINX | Status |
| --- | --- | --- | --- |
| `json_request_body_block.yaml` | bestanden, HTTP 403 | bestanden, HTTP 403 | vollständig importiert-gemeinsam |
| `multipart_basic_block.yaml` | bestanden, HTTP 403 | bestanden, HTTP 403 | vollständig importiert-gemeinsam |
| `response_body_pass.yaml` | Durchgang, HTTP 200 | Pass-Through, HTTP 200 Nachweis | RESPONSE_BODY non-verified/non-promoted |
| `response_body_basic_block` | fehlschlagen, HTTP 200 | fehlschlagen, HTTP 200 | ehemalige expected-failure/mapped-only |
| PR #377 minimal/safe Nur-Protokoll-Prüfungen der Phase 4 | n/a | Pass, HTTP 200 im letzten NGINX Smoke | NGINX-spezifische Nur-Protokoll-Nachweise; nicht RESPONSE_BODY Hochstufung |
| PR #377 Inhaltstyp außerhalb des Gültigkeitsbereichs Phase-4-Probe | n/a | Pass, HTTP 200 im letzten NGINX Smoke | NGINX-spezifische Nur-Protokoll-Nachweise; nicht RESPONSE_BODY Hochstufung |

Die Antwortkörperblockreihe ist absichtlich kein aktiver Smoke. Die NGINX
Referenztest markiert das Verhalten TODO und ModSecurity-nginx PR #377 Quelle
Änderungen werden nur als Belege auf Quellenebene behandelt. Eine lokale Sonde mit drei Wiederholungen
hat auf keinem der Connectors stabile HTTP 403 erzeugt, also dieses Repository
dokumentiert die Nachweise, ohne Anspruch auf Connector-Parität zu erheben.

## V2/V3-Derived Kompatibilität

Lokal beobachtet am 15.05.2026 mit expliziter externer `BUILD_ROOT`:

| Fallgruppe | Apache | NGINX | Status |
| --- | --- | --- | --- |
| V2 Operatorsemantik (`@streq`, `@contains`, `@beginsWith`, `@endsWith`, `@pm`, `@containsWord`) | bestanden, HTTP 403 | bestanden, HTTP 403 | vollständig importiert-gemeinsam |
| V2 Transformationssemantik (`t:lowercase`, `t:trim`, `t:urlDecode`, `t:htmlEntityDecode`) | bestanden, HTTP 403 | bestanden, HTTP 403 | Fully-imported-common zum Blockieren von Zweigen; `t:urlDecode` No-Match-Pass-Through wird jetzt im letzten NGINX-Lauf durchgeführt |
| V3 mehrteilige FILES Variablen | bestanden, HTTP 403 | bestanden, HTTP 403 | vollständig importiert-gemeinsam |
| V3 XML Hauptfall des Körperprozessors | bestanden, HTTP 403 | bestanden, HTTP 403 | vollständig importiert-gemeinsam |
| V3 `@rx`, trimmen und `SecAction` Grundlagen | bestanden, HTTP 403 | bestanden, HTTP 403 | vollständig importiert-gemeinsam |
| V3 `@pm`, Cookies, Header-Namen, ARGS_NAMES und Grundlagen der seriellen Prüfung | passieren | Pass für blockierende Zweige und die neueste nicht übereinstimmende Pass-Through-Teilmenge | vollständig importiert, gemeinsam für aktive Smokezweige; Weitere Randfälle bleiben mapped/former erwarteter Fehler |
| V3 `nolog,pass` Prüfungsabwesenheit (`issue-2196`) | Lokal übergeben, Audit-Protokoll leeren | Lokal übergeben, Audit-Protokoll leeren | Früherer erwarteter Fehler, da GitHub Actions ein nicht leeres Überwachungsprotokoll festgestellt hat |

Die aktiven Fälle beweisen nur die minimalen YAML-Szenarien. V2 Perlgeschirr
Interna, v3-API-nur-Fälle, XML schema/DTD Validierung, fehlerhafte Mehrteiligkeit,
NUL/binary Transformationszweige, Streaming, HTTP/2 und optionale Bibliothek
Betreiber bleiben zugeordnet, bis dedizierte Unterstützung hinzugefügt wird.

## Realer Verbindungspfad

`real-world-connector-path` ist der Kompatibilitätsnachweismodus für Apache und
NGINX:

```text
HTTP client -> server process -> connector module -> libmodsecurity -> rule variables -> HTTP response
```

Der direkte v3 API Smoke bleibt getrennt und ist nicht steckersicher. Connector
Zusammenfassung JSON Datensätze `connector_path`, `validation_mode`, `server_binary`,
`module`, `libmodsecurity` und `verified_variables`. Dort erscheint eine Variable
nur, wenn mindestens ein aktiver Passgeber dies über den realen Server ausübt
Laufzeit.

Aktuelle aktive Passing-Fälle verifizieren `ARGS`, `ARGS_NAMES`, `REQUEST_COOKIES`,
`REQUEST_HEADERS`, `REQUEST_URI`, `REQUEST_BODY`, `FILES`, `XML`, `AUDIT_LOG`,
und `RESPONSE_HEADERS` sowohl über Apache als auch über die NGINX-Laufzeit in diesem Arbeitsbereich.
`RESPONSE_BODY` bleibt mapped/former erwarteter Fehler, bis ein aktiver Antworttext vorliegt
variable/blocking case übergibt beide Konnektoren.

## Neueste NGINX Laufzeitklassifizierung (21.05.2026)

`make smoke-nginx` hat 54 aktive Laufzeitfälle gegen frisch erstellte ausgeführt
Source-Build-Artefakte: 54 PASS, 0 FAIL, 0 BLOCKIERT. Diese Wiederholung wurde verwendet
Vom Arbeiter lesbare generierte Laufzeitdateien unter dem NGINX-Harness-Arbeitsstammverzeichnis, also
Die vorherige `htdocs/index.html`-Berechtigungsverweigerung blockiert nicht mehr „expected-200“.
Pass-Through- und Phase-4-Log-Only-Fälle.

Die 11 zuvor blockierten Fälle sind jetzt aktuelle lokale NGINX Laufzeit PASS
Nachweise. `response_body_pass` bleibt nur ein Durchgangsbeweis; das ist es nicht
RESPONSE_BODY Verifizierung, kein Nachweis für die Blockierung des Antworttextes und keine vollständige
Anspruch auf Kompatibilität mit Phase 4. Siehe
`docs/testing/nginx-runtime-failure-classification.md` für die Falltabelle.

`v3_action_nolog_pass_no_audit` wird vorerst auch als ehemalige expected-failure/mapped klassifiziert:
Lokale Ausführungen in diesem Arbeitsbereich erzeugten HTTP 200 und leere Überwachungsprotokolle, aber die
aktuelle Ausführung der GitHub-Aktionen gemeldet `expected audit log to be absent or empty`.
Es wird nicht als stabiler gemeinsamer PASS gezählt, bis lokaler Apache, lokaler NGINX und
GitHub Actions stimmen zu.

## Reproduzierbare lokale Einrichtung (Smoke + Lint)

Das smoke/lint-Tool hat explizite Voraussetzungen und meldet fehlende Laufzeiteingaben als **BLOCKED**.

Die Standardeinstellungen für Shell-Helfer sind in `modules/ModSecurity-test-Framework/ci/lib/common.sh` zentralisiert. Überschreiben Sie Variablen in
die Umgebung, anstatt Skripte zu bearbeiten:

```bash
BUILD_ROOT=$HOME/.local/state/ModSecurity-conector-build
SOURCE_ROOT=$BUILD_ROOT/sources
MODSECURITY_GIT_REF=v3/master
MODSECURITY_SOURCE_DIR=$SOURCE_ROOT/ModSecurity_V3
MODSECURITY_V3_SOURCE_DIR=$SOURCE_ROOT/ModSecurity_V3
MODSECURITY_V3_ROOT=$SOURCE_ROOT/ModSecurity_V3
MODSECURITY_APACHE_SOURCE_DIR=$PWD/connectors/apache
MODSECURITY_NGINX_SOURCE_DIR=$PWD/connectors/nginx
APACHE_BIN=/path/to/apache2
APACHECTL_BIN=/path/to/apachectl
APXS_BIN=/path/to/apxs
NGINX_BIN=/path/to/nginx
MODSECURITY_PKG_CONFIG=modsecurity
MODSECURITY_LIB_DIR=/path/to/lib
MODSECURITY_INCLUDE_DIR=/path/to/include
HTTPD_VERSION=2.4.67
APR_VERSION=1.7.6
APR_UTIL_VERSION=1.6.3
PCRE2_VERSION=10.47
NGINX_SOURCE_REPO_URL=https://github.com/nginx/nginx
NGINX_RELEASE_TAG=latest
```

`modules/ModSecurity-test-Framework/ci/lib/common.sh` ist passiv und führt keine Prüfungen durch, ruft keine Quellen ab und erstellt keine Dateien
Artefakte für sich. Die Connector-Quelle ist standardmäßig repo-lokal; extern
Apache/NGINX Connector-Repositorys erfordern eine explizite Zustimmung und sind keine Laufzeit
Standardwerte.

### Python-Abhängigkeiten

Installieren Sie Entwicklungsabhängigkeiten, bevor Sie `make lint` ausführen:

```bash
python3 -m pip install -r requirements-dev.txt
```

Derzeit erforderlich für Linthelfer:

- `PyYAML>=6,<7` (verwendet von `modules/ModSecurity-test-Framework/ci/checks/documentation/check-workflow-yaml.py`)

Wenn es fehlt, gibt Lint anstelle eines Python-Tracebacks eine klare Blockierungsmeldung und einen Installationshinweis aus.


### Entwickler-Bootstrap mit einem Befehl

Erstellen Sie eine isolierte virtuelle Umgebung und installieren Sie Dev Deps:

```bash
make setup-dev
# make now auto-prefers .venv/bin/python when present
source .venv/bin/activate
```

Äquivalente Zielnamen:

- `make install-dev-deps`
- `make setup-dev`

### Umweltarzt

Überprüfen Sie die Python-Abhängigkeiten und die Pfaderkennung von ModSecurity v3:

```bash
make doctor
```

Die Doctor-Ausgabe trennt die Quell-Build-Bereitschaft von der optionalen Installation
Bereitschaft. Die Quell-Build-Bereitschaft verwendet die konfigurierten Quell-Aliase von
`modules/ModSecurity-test-Framework/ci/lib/common.sh`; Die installierte Apache/NGINX/libmodsecurity-Erkennung ist diagnostisch
nur und macht Systeminstallationen nicht zur Standardvoraussetzung. Wenn nein
ModSecurity v3-Quellbaum ist verfügbar, Doctor beendet BLOCKED und druckt den
genauer Export oder `make fetch-deps` Sanierungsbefehl.


### Optionaler GitHub-Laufzeitabruf

Um echte externe Laufzeitvoraussetzungen explizit zu booten:

```bash
make fetch-deps
```

Dies verwendet `modules/ModSecurity-test-Framework/ci/provisioning/fetch-smoke-sources.sh` und ruft die ModSecurity-Kern-Engine ab
Quelle aus den konfigurierten `MODSECURITY_REPO_URL` / `MODSECURITY_GIT_REF` (siehe
`docs/testing/bootstrap.md`). Die Apache- und NGINX-Connector-Quelle bleibt erhalten
standardmäßig repo-local.
Durch `make setup-dev`, `make lint`, `make doctor` oder `make smoke-all` wird kein Netzwerkabruf automatisch ausgelöst.

Wenn Sie zunächst nur die Abhängigkeitsdiagnose ausführen möchten:

```bash
make doctor
```

### Laufzeitvoraussetzungen für Connector Smokes

`make smoke-all` erfordert einen ModSecurity v3-Quellbaumpfad. Das Tragbare
Der Source-Build-Standardwert ist abgeleitet von:

- `SOURCE_ROOT=$BUILD_ROOT/sources`
- `MODSECURITY_SOURCE_DIR=$SOURCE_ROOT/ModSecurity_V3`

Außerkraftsetzen in tragbaren Umgebungen:

```bash
export BUILD_ROOT=/absolute/path/for/build-artifacts
export MODSECURITY_SOURCE_DIR=$BUILD_ROOT/sources/ModSecurity_V3
make smoke-all
```

Wenn Voraussetzungen fehlen, geben Smoke-Skripte jetzt explizite blockierte Anweisungen aus, die Folgendes umfassen:

- Fehlender Voraussetzungspfad
- Name der betroffenen Umgebungsvariable
- Abhilfe command/env Hinweis
- explizite Anweisung, dass das Ergebnis **BLOCKED** ist, nicht **FAIL**

### Statusbedeutung

- **PASS**: erwartetes Verhalten, das über den realen Connector-Pfad beobachtet wird.
- **FAIL**: Harness wurde ausgeführt und unerwartetes Verhalten oder Ausführungsfehler beobachtet.
- **BLOCKED**: Voraussetzungen (Abhängigkeiten, Quellpfade, build/runtime Anforderungen) fehlen, daher konnte die Ausführung nicht zuverlässig gestartet werden.


### Empfohlener Fluss in frischer Umgebung

```bash
make setup-dev
make lint
make fetch-deps
make doctor
make smoke-all
```

Verwenden Sie einen einzigen konsistenten `BUILD_ROOT` für `fetch-deps`, `doctor` und `smoke-all`.


Siehe auch: `docs/testing/fast-checks.md` für quick/full Grenzen prüfen.


Schnelle lokale Entwicklerprüfungen können `make doctor-quick` und `make quick-all` verwenden;
Hierbei handelt es sich nicht um einen vollständigen Ersatz und es kann sein, dass zur Laufzeit BLOCKED zurückgegeben wird
Voraussetzungen fehlen. GitHub/Codex CI nutzt das Feuerzeug
`make cloud-quick-check` framework/generator Pfad und vermeidet ihn absichtlich
Laufzeitsonden.

## Hinweis zur inkrementellen Abdeckung (19.05.2026)

Von der Quelle abgeleitete negative/pass-through häufige Fälle hinzugefügt für:

- `REQUEST_COOKIES_NAMES` (`v3_request_cookies_names_pass_no_match`)
- `ARGS_NAMES` (`v3_args_names_get_pass_no_match`)
- `REQUEST_URI` mit `t:urlDecode` No-Match-Zweig (`v2_transformation_url_decode_pass_no_match`)

Diese Ergänzungen verbessern die matrix/documented-Abdeckung, werden jedoch nicht als neuer stabiler allgemeiner PASS-Nachweis beansprucht, bis Smoke (`make smoke-all`) zur vollständigen Laufzeit mit allen Voraussetzungen ausgeführt wird.


## Installierte Laufzeiterkennung (nicht autorisierend)

`make doctor` und `make smoke-installed` / `make installed-readiness` melden die Bereitschaft installierter Komponenten mithilfe alternativer Binärnamen und expliziter ModSecurity-Erkennung. Dies ist eine optionale Diagnoseausgabe und keine erforderliche Quell-Build-Voraussetzung.

Unterstützte Erkennungsaliase:

- Apache: `apache2` / `httpd` / `apachectl`
- APXS: `apxs` / `apxs2`
- NGINX: `nginx`
- ModSecurity: `pkg-config` (`modsecurity` oder `libmodsecurity`) oder Dateisystembeweis (`libmodsecurity.so*` plus `modsecurity/modsecurity.h`)

Unterstützte Override-Variablen:

- `APACHE_BIN`, `APXS_BIN`, `NGINX_BIN`
- `APACHECTL_BIN`
- `MODSECURITY_PKG_CONFIG`, `MODSECURITY_LIB_DIR`, `MODSECURITY_INCLUDE_DIR`
- `CI_APACHE_BIN_CANDIDATES`, `CI_APXS_BIN_CANDIDATES`,
  `CI_NGINX_BIN_CANDIDATES`
- `CI_INSTALLED_LIB_SEARCH_DIRS`, `CI_INSTALLED_INCLUDE_SEARCH_DIRS`

Diese Bereitschaft für den installierten Pfad ist informativ für eine schnelle Diagnose. Vollständiger Kompatibilitätsnachweis bleibt der Source-Build-Full-Smoke-Pfad (`make smoke-all`).


## Cloud/GitHub Leichter Pfad

Für Codex Cloud-/GitHub-Aktionen: `.github/workflows/quick-framework-check.yml`
führt leichtes Framework, Lint, Generator und Dokumentationskonsistenz aus
Schecks. Der Connector Runtime-Smokes, Quellabrufe und die Installation werden nicht ausgeführt
Laufzeitsonden.

Dieser Weg unterscheidet:

- Framework-Korrektheitsfehler (rot): lint/schema/python/generated-doc/diff-Probleme.
- Nachweis der Laufzeitkompatibilität: Nur lokal über Smoke-Ziele mit vollständigem Connector.

Es ersetzt nicht den maßgeblichen lokalen Full-Source-Build-Smoke
(`make smoke-all`).

## Erweiterte ausstehende Kompatibilitätsabdeckung (19.05.2026)

Es wurde ein größerer, von der Quelle abgeleiteter früherer expected-failure/pending-Satz für Connector-Gap-, Runtime-Difference- und Future-Compatibility-Ziele hinzugefügt. Dies erweitert die langfristige Kompatibilitätsverfolgung, ohne die aktuell verifizierte PASS-Semantik zu ändern.

Insbesondere bleibt RESPONSE_BODY ungeprüft und wird nicht hochgestuft; Der Nachweis für die Blockierung des Antwortkörpers bleibt bestehen expected-failure/mapped-only, bis ein stabiler Cross-Connector-HTTP 403-Nachweis vorliegt.

## Ausstehende operator/transformation/phase-Abdeckung (19.05.2026)

Die Kompatibilitätsmatrix enthält jetzt zusätzliche aus der Quelle abgeleitete frühere erwartete Fehlerziele für Operatoren, Transformationen, Phasenreihenfolgeannahmen und parser/edge-Verhalten. Hierbei handelt es sich um eine Abdeckung im Roadmap-Stil, nicht um eine aktiv verifizierte Connector-Parität.

Die Klassifizierung nach `RESPONSE_BODY` bleibt unverändert (bisherige expected-failure/mapped-only, nicht verifiziert).

## Audit/normalization/parser ausstehende Berichterstattung (19.05.2026)

Die Kompatibilitätsverfolgung umfasst jetzt zusätzliche aus der Quelle abgeleitete frühere erwartete Fehlerziele für das Audit-Log-Verhalten, die duplicate/normalization-Behandlung, Parser-Teilkörperkanten und Transformationsketteninteraktionen. Hierbei handelt es sich um Roadmap-Prüfungen und nicht um aktive PASS-Paritätsansprüche.

## Multipart/files/unicode/parser ausstehende Berichterstattung (19.05.2026)

Die Kompatibilitätsverfolgung umfasst jetzt zusätzliche frühere Prüfpunkte für erwartete Fehler für FILES/multipart-Analyse, Unicode/encoding-Normalisierung, tiefere JSON/XML-Strukturen und harmlose XSS-like/SQLi-like-Transformationsinteraktionen. Dabei handelt es sich weiterhin um eine nicht verifizierte Roadmap-Abdeckung.

## Outbound-Phase (3/4) bis zur Berichterstattung (19.05.2026)

Die Abdeckung umfasst jetzt explizite Phase-3-Antwort-Header und Phase-4-outbound/response-body-Probes als frühere expected-failure/connector-gap/runtime-difference/future-Ziele. Dies verbessert die langfristige Kompatibilitätsverfolgung, während RESPONSE_BODY nicht überprüft wird.

## Zusätzliche ausgehende Folgeuntersuchungen (19.05.2026)

Eine Folgewelle erweitert phase-3/4 ausgehende Abdeckung für Antwort-Header-Normalisierung und ausgehende Prüfannahmen. RESPONSE_BODY bleibt ausdrücklich nicht verifiziert und nicht hochgestuft.

## Berichterstattung über die Abdeckungsmatrix

Für aktuelle Berichte zur Repository-Abdeckung verwenden Sie:

- `docs/testing/test-coverage-overview.md`
- `docs/testing/generated/case-matrix.generated.md`
- `docs/testing/generated/coverage-summary.generated.md`
- `docs/testing/generated/xfail-summary.generated.md`
- `docs/testing/generated/connector-gap-summary.generated.md`
- `docs/testing/generated/phase-coverage.generated.md`

Generation/check Arbeitsablauf:

```sh
make generate-test-matrix
make check-test-matrix
```

Diese Artefakte fassen deklarierte Fallmetadaten und den Importstatus zusammen. Das tun sie nicht
Gewährleistung der vollständigen Laufzeitkompatibilität; `make smoke-all` bleibt maßgebend
Lokaler Laufzeitnachweispfad.
