# Allgemeine Fallreferenz

**Sprache:** [English](cases.md) | Deutsch

Status: eingerüstet

Das Laufzeitkorpus YAML befindet sich jetzt unter `tests/cases/` und wird von organisiert
Thema. Dieses Verzeichnis wird für allgemeine Fallreferenznotizen und den Import beibehalten
Nur Geschichte.

Nur übertragbare engine/rule/behavior-Fälle gehören zu den allgemeinen Fallmetadaten.

Fügen Sie keine Fälle hinzu, die eine bestimmte server/proxy-Laufzeit erfordern.

`tests/cases/phases/phase2/phase2_args_block.yaml` ist ein tragbares Gerät
rule/request/expectation Modell.
Es wird nur dann zu einem Connector-Durchlauf, wenn ein Connector-spezifischer Harness ihn ausführt
und beobachtet das erwartete Ergebnis.

Importiert, von v2 abgeleitet, von v3 abgeleitet, früherer erwarteter Fehler, ausstehend, zukünftig, Connector-Lücke und
Laufzeitdifferenzklassifizierungen werden durch YAML-Metadaten und getragen
Connector-eigene `config/testing/import-status.json`, nicht nach Statusordnern.

Unterstützte Anforderungsformen sind absichtlich klein: `GET`, `POST`, Header,
einfache Körper und deterministische mehrteilige Formkörper. Multipart-Parser-Edge
Fälle, Streaming, HTTP/2 und konnektorspezifische Serverkonfiguration bleiben außen vor
der häufigsten Fälle, bis beide Connectorstränge das Verhalten beweisen.

Hier kann der Response-Body-Pass-Through bestehen, wenn beide Konnektoren passieren. Antwort
Das Blockieren des Körpers wird als früherer erwarteter Fehler abgebildet, bis Apache und NGINX beide stabile HTTP zurückgeben.
403 für denselben YAML-Fall.
