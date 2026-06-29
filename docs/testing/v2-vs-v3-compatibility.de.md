# v2 vs. v3 Kompatibilität

**Sprache:** [English](v2-vs-v3-compatibility.md) | Deutsch

Status: umgesetzt

## Architektur

v2 ist eine Apache-zentrierte Codebasis. Viele Engines, Connectors, Parser und Anfragen
Handhabungsbedenken finden Sie unter `apache2/`.

v3 ist libmodsecurity: eine Connector-neutrale Engine mit öffentlichen C- und C++-APIs.
Connectors sind separate Adapter, die Transaktionsphasen in die Engine einspeisen.

Entscheidung: Die neue Connector-Architektur folgt nur v3.

## API

Interne Funktionen und Strukturen der Version 2 sind kein Connector API für dieses Repository.
Öffentliche APIs der Version 3 unter `headers/modsecurity/` bilden die nutzbare Connector-Grenze.

Kompatible v3 API-Konzepte:

- Motorlebenszyklus
- Regelsatz-Lebenszyklus
- Transaktionsphasenaufrufe
- Interventionsabfrage
- Protokollieren Sie die Rückrufregistrierung

Inkompatible v2-Konzepte:

- Direkte Verwendung von Apache-Anforderungsdatensätzen als Engine-Status
- APR-eigene Transaktionsstrukturen
- direkte Aufrufe in v2-interne parser/operator-Funktionen
- Apache-spezifische v2-Modul-Hooks als portabler Lebenszyklus

## Protokollierung

v2-Regressionstests stimmen häufig mit error/debug/audit-Protokolltext im Apache-Stil überein.
v3 stellt einen Protokollrückruf bereit und verfügt über eine eigene audit/debug-Implementierung.

Entscheidung: Protokolltests müssen vor der Durchführung normalisiert und mit einer Fähigkeitsmarkierung versehen werden
gelten als tragbar. Rohe v2-Protokolltexterwartungen sind standardmäßig nicht portierbar.

## Transaktionslebenszyklus

Der v2-Lebenszyklus wird durch die Phasen des Apache-Moduls geprägt. Der v3-Lebenszyklus wird geprägt von
libmodsecurity-Transaktions-APIs:

- Verbindung
- URI
- Anforderungsheader
- Anfragetext
- Antwortheader
- Antwortkörper
- Protokollierung

Connector-Adapter entscheiden, wo diese Aufrufe in die einzelnen server/proxy passen und müssen
Dokument fehlt oder ist verspätet.

## Connector-Modell

v2 definiert kein allgemeines Connector-Modell für dieses Monorepo. v3-Anschlüsse
sollten dünne Übersetzer zwischen server/proxy Hooks und libmodsecurity public sein
APIs.

## Testen Sie die Wiederverwendung

| Testart | Portable zu v3-Anschlüssen? | Platzierung |
| --- | --- | --- |
| Operatorsemantik | Vielleicht | `docs/imports/common/` nur nach Fähigkeitsprüfung |
| Transformationen | Vielleicht | `docs/imports/common/` nur nach v3-Paritätsprüfung |
| Regelanalyse | Vielleicht | `docs/imports/common/` wenn keine Connector-Laufzeit erforderlich ist |
| Body-Parsing anfordern | Teilweise | Nur üblich, wenn die Körperlieferung nur über den Motor erfolgt; ansonsten Connector-spezifisch |
| Inspektion der Einsatzstelle | Teilweise | Fähigkeitsabhängig |
| Audit/error Protokollieren Sie den genauen Text | Partial/no | Normalisiert und funktionsgekennzeichnet, oft Connector-spezifisch |
| Verhalten des Apache-Harnesss | Nein | `tests/cases/connector-specific/apache/` oder nur historische Dokumente |
