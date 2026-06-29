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
| Apache-Connector | eingerüstet | Der von der lokalen Quelle erstellte PoC beobachtete das erwartete HTTP-Verhalten für alle aktuell gemeinsam genutzten Minimalfälle |
| NGINX-Connector | eingerüstet | Der von der lokalen Quelle erstellte PoC beobachtete das erwartete HTTP-Verhalten für alle aktuell gemeinsam genutzten Minimalfälle |
| Apache-Verbindungspfad für die reale Welt | umgesetzt | Smoke-Zusammenfassungen zeichnen im Quellcode erstellte httpd-, `mod_security3.so`-, libmodsecurity- und verifizierte Variablen auf |
| NGINX realer Connector-Pfad | umgesetzt | Smoke-Zusammenfassungen zeichnen im Quellcode erstellte NGINX, dynamische Module, libmodsecurity und verifizierte Variablen auf |
| HAProxy-Connector | unbekannt | SPOE/Lua/native Optionen dokumentiert, Implementierung unentschlossen |
| Envoy-Connector | unbekannt | HTTP filter/ext_authz/Wasm Optionen dokumentiert, Implementierung unentschlossen |
| Lighttpd-Connector | unbekannt | Native Plugin- und mod_magnet-Optionen dokumentiert, Implementierung noch unklar |
| Traefik-Connector | unbekannt | Yaegi/Wasm Plugin-Optionen dokumentiert, Implementierung noch unklar |
| Wiederverwendung der v2-Regression | geplant | Nur portable rule/engine-Semantik darf `docs/imports/common/` eingeben |
| Von v2 abgeleitete gemeinsame Importe | umgesetzt | Operator- und Transformationsfälle einschließlich `@streq`, `@contains`, `@beginsWith`, `@endsWith`, `@pm`, `@containsWord`, `t:lowercase`, `t:trim`, `t:urlDecode` und `t:htmlEntityDecode` werden lokal übergeben auf Apache und NGINX |
| Von v3 abgeleitete gemeinsame Importe | umgesetzt | Mehrteiliger FILES, XML Körperprozessor, Operator, Transformation, Aktion, cookie/header-name/ARGS_NAMES und stabile Prüffälle werden lokal auf Apache und NGINX übergeben |
| Von der Quelle abgeleiteter Apache/NGINX Testimport | umgesetzt | Importierte YAML-Fälle werden abgeleitet und nicht kopiert; Herkunft und Portabilität werden dokumentiert |

## Fähigkeitsregel

Tests und Connector-Dokumente müssen die erforderlichen Funktionen benennen. Wenn ein Verhalten davon abhängt
On-Hook-Timing, Pufferung, Streaming, Protokollartefakte, Neuladesemantik oder Server
Konfiguration ist es Connector-spezifisch, sofern es sich nicht als portabel erwiesen hat.

## Geteilte Minimalfälle

Die Dateien unter `tests/cases/` sind portable rule/request-Modelle.
Bis dahin sind sie kein Nachweis dafür, dass ein Connector das Verhalten unterstützt
Der Laufzeitkabelbaum des Connectors beobachtet die erwartete HTTP-Antwort.

Lokal beobachtet am 15.05.2026 mit `BUILD_ROOT=/src/ModSecurity-test-Framework-build`:

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
| häufig minimal | `tests/cases/` | Vor dem Importschritt bereits lokal für beide PoCs nachgewiesen |
| allgemein importiert | `tests/cases/` | Übertragbare Kandidaten, abgeleitet aus Apache/NGINX-Tests; Die Kompatibilität wird erst dann beansprucht, wenn der Smoke beider Anschlüsse vorüber ist |
| v2 importiert | `tests/cases/` | Tragbare v2-Semantikkandidaten, angepasst an das HTTP-Verhalten und bewährt auf beiden Connector-PoCs |
| v3 importiert | `tests/cases/` | Tragbare v3-Regressionskandidaten, angepasst an das HTTP-Verhalten und bewährt auf beiden Connector-PoCs |
| Apache importiert | `tests/cases/connector-specific/apache/` | Nur Apache, bis ein gemeinsames Äquivalent nachgewiesen ist |
| NGINX importiert | `tests/cases/connector-specific/nginx/` | Nur NGINX, bis ein gemeinsames Äquivalent nachgewiesen ist |

Nur zugeordnete Kategorien umfassen HTTP/2, Proxy, mehrteilige Parser-Randfälle,
Blockierung des Antworttextes, Operatoren für externe Dateien, Debug-Protokolle und Connector
Konfigurationsvererbung.

Lokal beobachtet am 15.05.2026, wurden die aktuell importierten häufigen Fälle alle weitergegeben
Apache und NGINX bis `make smoke-all`; die NGINX-spezifischen importierten Fälle
nur an NGINX übergeben und bleiben `portable: false`.

## Gehäuse- und Filterkompatibilität

| Fall oder Kategorie | Apache | NGINX | Status |
| --- | --- | --- | --- |
| `json_request_body_block.yaml` | bestanden, HTTP 403 | bestanden, HTTP 403 | vollständig importiert-gemeinsam |
| `multipart_basic_block.yaml` | bestanden, HTTP 403 | bestanden, HTTP 403 | vollständig importiert-gemeinsam |
| `response_body_pass.yaml` | Durchgang, HTTP 200 | Durchgang, HTTP 200 | RESPONSE_BODY non-verified/non-promoted |
| `response_body_basic_block` | fehlgeschlagen, HTTP 200 und kein Audit-Treffer | fehlgeschlagen, `RESPONSE_BODY` audit/error getroffen, aber der Client hat eine leere `000` Antwort beobachtet | non-promoted/mapped-only |

Die Antwortkörperblockreihe ist absichtlich kein aktiver Smoke. Die NGINX
Referenztest markiert das Verhalten TODO. Bei einer lokalen Sonde mit drei Wiederholungen war dies nicht der Fall
Erzeugen Sie stabile HTTP 403 auf beiden Connectors, daher dokumentiert dieses Repository die
Nachweise ohne Anspruch auf Connectorparität.

## V2/V3-Derived Kompatibilität

Lokal beobachtet am 15.05.2026 mit `BUILD_ROOT=/src/ModSecurity-test-Framework-build`:

| Fallgruppe | Apache | NGINX | Status |
| --- | --- | --- | --- |
| V2 Operatorsemantik (`@streq`, `@contains`, `@beginsWith`, `@endsWith`, `@pm`, `@containsWord`) | bestanden, HTTP 403 | bestanden, HTTP 403 | vollständig importiert-gemeinsam |
| V2 Transformationssemantik (`t:lowercase`, `t:trim`, `t:urlDecode`, `t:htmlEntityDecode`) | bestanden, HTTP 403 | bestanden, HTTP 403 | vollständig importiert-gemeinsam |
| V3 mehrteilige FILES Variablen | bestanden, HTTP 403 | bestanden, HTTP 403 | vollständig importiert-gemeinsam |
| V3 XML Hauptfall des Körperprozessors | bestanden, HTTP 403 | bestanden, HTTP 403 | vollständig importiert-gemeinsam |
| V3 `@rx`, trimmen und `SecAction` Grundlagen | bestanden, HTTP 403 | bestanden, HTTP 403 | vollständig importiert-gemeinsam |
| V3 `@pm`, Cookies, Header-Namen, ARGS_NAMES und Grundlagen der seriellen Prüfung | passieren | passieren | vollständig importiert-gemeinsam |
| V3 `nolog,pass` Prüfungsabwesenheit (`issue-2196`) | Lokal übergeben, Audit-Protokoll leeren | Lokal übergeben, Audit-Protokoll leeren | früherer Verlauf erwarteter Fehler, da GitHub Actions ein nicht leeres Überwachungsprotokoll festgestellt hat |
| PR #3564 RAW Argumentsammlungen | Wird in der aktuellen lokalen v3-Quelle nicht unterstützt | Wird in der aktuellen lokalen v3-Quelle nicht unterstützt | mapped-only/unsupported-local-source |

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
und `RESPONSE_HEADERS` über Apache und NGINX in diesem Arbeitsbereich.
`RESPONSE_BODY` bleibt non-promoted/mapped-only bis ein aktiver Antworttext vorliegt
variable/blocking case übergibt beide Konnektoren.

## RAW Argumentsammlungen

ModSecurity PR #3564 führt `ARGS_RAW`, `ARGS_GET_RAW`, `ARGS_POST_RAW` ein,
`ARGS_NAMES_RAW`, `ARGS_GET_NAMES_RAW` und `ARGS_POST_NAMES_RAW`.

Die aktuelle lokale Checkout `<workspace>/ModSecurity_V3` enthält das nicht
RAW Sammlungsimplementierung oder ihre Regressionsdatei, also markiert dieses Repository
RAW Argumente als `mapped-only/unsupported-local-source`. Sie dürfen nicht in erscheinen
aktive PASS-Zusammenfassungen, bis eine konfigurierte v3-Quelle die PR und beide enthält
Apache und NGINX übergeben reale Connector-Smokes für von der Quelle abgeleitete RAW-Fälle.

`v3_action_nolog_pass_no_audit` behält vorerst auch frühere Metadaten zu erwarteten Fehlern bei:
Lokale Ausführungen in diesem Arbeitsbereich erzeugten HTTP 200 und leere Überwachungsprotokolle, aber die
aktuelle Ausführung der GitHub-Aktionen gemeldet `expected audit log to be absent or empty`.
Es wird nicht als stabiler gemeinsamer PASS gezählt, bis lokaler Apache, lokaler NGINX und
GitHub Actions stimmen zu.
