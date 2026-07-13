# Framework-Glossar

**Sprache:** [English](glossary.md) | Deutsch

Dieses Glossar definiert Framework-Begriffe. Ein Einsteigerdokument soll einen
Begriff beim ersten Auftreten zusätzlich kurz lokal erklären.

| Begriff | Bedeutung in diesem Framework |
|---|---|
| ABI | Application Binary Interface: der Binär-Aufruf- und Layoutvertrag zwischen kompilierten Komponenten. |
| ALPN | Application-Layer Protocol Negotiation; die TLS-Erweiterung zur Auswahl eines Anwendungsprotokolls. |
| API | Application Programming Interface: ein expliziter Programm-zu-Programm-Vertrag. |
| APXS | Apache eXtenSion-Werkzeug, üblicherweise zum Bauen oder Installieren eines Apache-Moduls. |
| CRS | OWASP Core Rule Set. `no-crs` lässt es weg; `with-crs` lädt es vor lokalen Fallregeln. |
| EOS | End of stream: der Zeitpunkt, zu dem der Antwortstrom beendet ist. |
| Evidence | Payload-sichere, zuordenbare Artefakte, die eine Laufbeobachtung festhalten; Evidence ist keine automatische PASS-Promotion. |
| ext_authz | Envoy-Filter/Integrationsmodus für externe Autorisierung. |
| ext_proc | Envoy-Filter/Integrationsmodus für externe Verarbeitung. |
| Full Lifecycle | Ein kausal verknüpfter P1–P4-Connector-Lauf mit erforderlicher Evidence und Validierung, nicht nur ein Build- oder Starter-Check. |
| HTX | Interne HAProxy-HTTP-Repräsentation, die kompatible Filter verwenden. |
| Late Intervention | Eine Entscheidung nach früherer Request- oder Response-Verarbeitung; ohne kausale Phase-Evidence darf sie nicht behauptet werden. |
| No-CRS | Testmodus, der nur lokale Fallregeln ohne OWASP CRS lädt. |
| P1 / P2 / P3 / P4 | Request-Header, Request-Body, Response-Header und Response-Body / späte Response-Verarbeitung im Framework-Katalog. |
| Promotion | Eine validierte Änderung von einer beobachteten Evidence-Klasse zu einem stärkeren bewiesenen Status. Promotion wird durch Richtlinien kontrolliert. |
| QUIC | UDP-basierter sicherer Transport für HTTP/3. Bei einer Behauptung braucht er explizite Beobachtungs-Evidence. |
| SPOE / SPOA / SPOP | HAProxy Stream Processing Offload Engine, ihr Agent und ihr Protokoll. |
| TTFB | Time to first byte: Zeit bis das erste Response-Byte beobachtbar wird. |
| UDS | Unix domain socket: lokaler IPC-Endpunkt, der durch einen Dateisystempfad repräsentiert wird. |
| Upstream | Dienst oder Server hinter Proxy/Connector, der die ursprüngliche Response liefert. |
| Wire Body | Auf dem Transport beobachtete Bytes; dies kann sich von einem dekodierten oder normalisierten Body unterscheiden. |
| Entity Body | HTTP-Nachrichtenkörper nach der anwendbaren Transfer-/Content-Interpretation. |
| First Byte Before EOS | Evidence, dass ein Response-Byte vor dem Stream-Ende beobachtet wurde; sie schließt eine Behauptung vollständigen Response-Wartens aus. |
| No Full Response Buffering | Evidence, dass die Integration nicht den vollständigen Response-Body sammeln musste, bevor sie ein Response-Byte weiterleiten konnte. |

## Statusvokabular

`PASS` bedeutet, dass die aufgerufene Validierung die erwartete Bedingung
beobachtet hat. `FAIL` bedeutet, dass sie eine gegenteilige Bedingung beobachtet
hat. `BLOCKED` bedeutet, dass eine benannte Voraussetzung fehlte.
`NOT EXECUTED`, `NOT APPLICABLE` und `UNSUPPORTED` behalten jeweils ihre
Grenze; keiner dieser Zustände bedeutet implizit PASS.

## Referenzgrenzen

Katalogbegriffe beschreiben Auswahl und erwartetes Verhalten.
Connector-eigene Runtime-Evidence beschreibt eine konkrete Ausführung.
Generierte Berichte fassen Eingaben zusammen; sie ersetzen keine
Evidence-Validierung. Anpassbare Befehlswerte stehen unter
[Variablen](variables.de.md).
