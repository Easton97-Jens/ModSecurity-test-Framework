# Reale Connector-Validierung

**Sprache:** [English](real-world-connector-validation.md) | Deutsch

Status: umgesetzt

`real-world-connector-path` bedeutet, dass das Smokeergebnis von diesem Pfad stammt:

```text
HTTP client
  -> real Apache or NGINX process
  -> real ModSecurity connector module
  -> libmodsecurity
  -> rule variables
  -> real HTTP response
```

Dies unterscheidet sich von der konnektorfreien libmodsecurity API Smoke unten
`src/v3-api-smoke/`. Der API Smoke beweist einen öffentlichen libmodsecurity C API Pfad,
aber es beweist nicht, dass ein Server-Connector dieselben Variablen gefüllt hat,
hat dieselben Körper gepuffert, dieselben Prüfartefakte geschrieben oder denselben Hook ausgeführt
Phase.

## Warum das existiert

Direkte API-Tests prüfen kein Server- und Connector-Verhalten. Die
Der reale Connector-Pfad erkennt Probleme wie:

- Serverspezifische Normalisierung des Abfragearguments, bevor `ARGS` erreicht wird
  libmodsecurity;
- Header werden nicht wie erwartet an `REQUEST_HEADERS` übergeben;
- Anforderungstexte werden für Phase:2-Regeln nicht früh genug gelesen;
- roher JSON-Body-Inhalt ist für `REQUEST_BODY` nicht verfügbar;
- Mehrteilige Uploads füllen `FILES`, `FILES_NAMES` nicht aus,
  `FILES_COMBINED_SIZE` oder `MULTIPART_FILENAME`;
- Audit-Log-Artefakte werden von einer Connector-Laufzeit unterschiedlich geschrieben;
- Das Verhalten des Antwortfilters weicht von den direkten API Erwartungen ab.

Wenn der Server startet und das Modul geladen wird, eine erwartete Variable jedoch nicht
Erreiche libmodsecurity und die YAML-Erwartung schlägt fehl, also `fail`, nicht
`blocked`. `blocked` ist für fehlende Quellen, Downloads, Build-Tools,
Modulartefakte, Bibliotheken oder Laufzeitvoraussetzungen.

## Aktuelle Nachweisfälle

Die YAML-Fälle sind die einzige Quelle für Regeln, Wünsche und Erwartungen. Die
Verbindungskabelbäume materialisieren sie und senden echte HTTP-Anfragen.

Die aktuelle lokale Standardzusammenfassung des Connector-Repositorys kann Variablen auflisten
Familien in `verified_variables`, wenn die entsprechenden realen Fälle bestehen.
Dies ist evidenzbezogen und fördert keine Force-All-Fehler, die nur zugeordnet werden können
Inventar, frühere Tests auf erwartete Fehler, zukünftige Fälle, Connectorlückenfälle, Laufzeitunterschiede
Fälle oder `RESPONSE_BODY`.

| Verifizierte Variable | Beispiele für aktive Fälle | Status |
| --- | --- | --- |
| `ARGS` | `phase2_args_block`, `collection_args_get_block`, V2 operator/transform Fälle | Evidenzbasiert; gezählt nur aus bestandenen realen Connectorfällen |
| `REQUEST_HEADERS` | `phase1_header_block` | Evidenzbasiert; gezählt nur aus bestandenen realen Connectorfällen |
| `REQUEST_BODY` | `request_body_json_block`, `request_body_raw_text_block`, `json_request_body_block` | Evidenzbasiert; gezählt nur aus bestandenen realen Connectorfällen |
| `FILES` | `multipart_files_value_block`, `multipart_files_names_block`, `multipart_files_combined_size`, `multipart_filename_block` | Evidenzbasiert; gezählt nur aus bestandenen realen Connectorfällen |
| `XML` | `xml_request_body_block` | Evidenzbasiert; gezählt nur aus bestandenen realen Connectorfällen |
| `AUDIT_LOG` | `audit_log_phase1_block` | Evidenzbasiert; `audit_behavior` ist möglicherweise immer noch instabil |
| `RESPONSE_HEADERS` | `response_header_basic` | Evidenzbasiert; gezählt nur aus bestandenen realen Connectorfällen |

`RESPONSE_BODY` wird bewusst nicht als verifiziert aufgeführt. Der Aktive
`response_body_pass` Fall beweist Passthrough mit aktiviertem Antworttextzugriff,
Die Blockierung der Antwortkörper-Regelvariablen bleibt jedoch non-promoted/mapped-only bestehen, bis beide
Konnektoren geben stabile HTTP 403 für denselben YAML-Fall zurück.

## Ergebnismetadaten

Jede Connector-Zusammenfassung unter `$BUILD_ROOT/results/` zeichnet Folgendes auf:

```json
{
  "connector_path": "real-world",
  "validation_mode": "real-world-connector-path",
  "server": "apache",
  "server_binary": "...",
  "module": "...",
  "libmodsecurity": "...",
  "verified_variables": ["ARGS", "REQUEST_BODY"]
}
```

`verified_variables` wird nur aus aktiven Fällen berechnet, deren Ergebnis ist
`pass`. Nur zugeordnete, früher erwartete Fehler, blockierte und fehlgeschlagene Fälle fügen keine Variablen hinzu.

## Aktueller Connector-Status

Der aktuelle Connector-Status muss aus dem Connector-Repository gelesen werden
`$BUILD_ROOT/results/connector-summary.json`, verfolgter Laufzeit-Snapshot und
generierte Berichte. Ab den Connector-Berichten vom 24.05.2026 standardmäßige lokale Zusammenfassung
Daten und Force-All-Laufzeitmatrixdaten sind separate Nachweisklassen:

| Nachweisklasse | Apache | NGINX |
| --- | --- | --- |
| Zusammenfassung des standardmäßigen lokalen Connectors | PASS-Zählungen können nur aus der aktuellen Connector-Zusammenfassungsdatei beansprucht werden | PASS-Zählungen können nur aus der aktuellen Connector-Zusammenfassungsdatei beansprucht werden |
| Snapshot der Force-All-Laufzeitmatrix | Enthält erwartete FAIL-Klassen; keine Decke PASS | Enthält erwartete FAIL-Klassen; keine Decke PASS |
| Nur API-Smoke | Nicht steckerfest | Nicht steckerfest |

In anderen Umgebungen müssen die gleichen Smoke-Ziele verwendet werden, bevor die Prüfung bestanden werden kann.

## Zukünftige Connector

HAProxy, Envoy, Lighttpd und Traefik benötigen vor jeder Laufzeit einen analogen Nachweis
Es wird behauptet:

- echter server/proxy Prozess;
- echtes Integrationsmodul, Plugin, Filter, SPOE-Dienst oder Middleware;
- libmodsecurity oder dokumentierter gleichwertiger Integrationspfad;
- aktive YAML-Fälle, die als HTTP-Verkehr gesendet werden;
- Ergebniszusammenfassung mit echten Server-binary/module-Metadaten und verifiziert
  Variablen, die nur aus vorübergehenden Fällen abgeleitet sind.
