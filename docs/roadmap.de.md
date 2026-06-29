# Roadmap

**Sprache:** [English](roadmap.md) | Deutsch

Status: aktueller Schnappschuss der evidenzbasierten Framework-Roadmap

Diese Framework-Roadmap verfolgt wiederverwendbare YAML-Fälle, Runner, Normalisierer usw
Meldeverhalten. Connector-pass/stability-Ansprüche gehören zum Connector
Repositorys und müssen durch reale Connector-Zusammenfassungen unterstützt werden.

## Aktueller Fokus

- Behalten Sie YAML Fallerkennung, Fähigkeitsmetadaten und generierte Berichte bei
  abgestimmt auf Connector-eigene Laufzeitzusammenfassungen.
- Behalten Sie die strikte Trennung zwischen reinen API-Nachweisen und Standard-Connectoren bei
  Smokebeweise, Force-All-Laufzeitmatrixbeweise, nur kartiertes Inventar,
  frühere Untersuchungen zu erwartetem Scheitern und blockierte Fälle.
- Behalten Sie `RESPONSE_BODY` non-verified/non-promoted bei, bis sowohl Apache als auch NGINX
  Nachweisen Sie eine stabile echte HTTP-Blockierung für denselben YAML-Fall.
- Behalten Sie die Zuordnung von RAW-Argumentsammlungsfällen nur bis zur lokalen ModSecurity v3 bei
  Quellunterstützung für PR #3564 ist vorhanden und beide Konnektoren bestehen.

## Umgesetzt

- YAML Gehäusekorpus, Runner-Kern, steckerseitiger CLI, Normalisierer und
  generierte Berichtsskripte.
- Fähigkeit validation/normalization für mehrteilige Dateien, XML, JSON,
  Antworttext, Prüfprotokoll, Sammlungen, Operatoren, Transformationen, Aktionen,
  Regelparser, Transaktionslebenszyklus und Pass-Through-Metadaten.
- Laufzeitstatusmodell, das `pass`, `fail`, `blocked`,
  `not_executable` und `skipped` unterscheiden sich vom Status import/classification.
- Reale Connector-Metadatenfelder für Apache- und NGINX-Zusammenfassungen:
  `status_model`, `origin_model`, `intervention_model`, `connector_path`,
`validation_mode`, `audit_behavior` und `verified_variables`.
- Generierte Abdeckungsberichte für 140 YAML Fälle, 80 frühere Fälle mit erwartetem Ausfall, 10 nur zugeordnete Fälle
  Inventareinträge importieren, 11 Connector-Gap-Fälle, 13 Laufzeitunterschied
  Fälle und 24 `RESPONSE_BODY` Fälle.
- Fallmatrix, Laufzeitmatrix, früherer erwarteter Fehler, Connectorlücke, Phasenabdeckung und
  Erstellung einer Abdeckungszusammenfassung.
- Connector-freie libmodsecurity v3 API Smokequelle und Dokumentation, aufbewahrt
  getrennt vom Connectorschutz.
- Framework-Dokumente für YAML Schemaform, gemeinsam genutzte Fixtures, Fallmatrix, schnell
  Prüfungen, Kompatibilitätsnachweise, Blockierung des Antworttexts, PR #377 und
  PR #3564 RAW Argumentbeweis.

## Nächste Meilensteine

- Fördern Sie die dokumentierte Form YAML in ein maschinenlesbares Schema nach dem
  aktuelle Feldsatz- und Connector-spezifische Erweiterungsregeln festlegen.
- Unterstützung für tragbare Geräte für externe Dateien und schema/DTD/XML-Assets hinzufügen.
  dateigestützte Operatoren, binary/NUL-Nutzlasten und größere Antwortvorrichtungen.
- Verbessern Sie die stabile Analyse von Prüfprotokollen und abschnittsbezogene Behauptungen und vermeiden Sie gleichzeitig
  volatile Werte.
- `make runtime-matrix-all`-Nachweise sichtbar halten, ohne frühere erwartete Fehler automatisch hervorzuheben,
  Future, Connector-Gap, Runtime-Difference oder Response-Body-Pass-Through
  Fälle.
- Fügen Sie eine klarere Unterstützung für Connector-Konfigurationstestfälle hinzu, die nicht ausgedrückt werden können
  wie schlicht HTTP raucht.

## Später / Aufgeschoben

- HAProxy, Envoy, Lighttpd und Traefik bleiben für Connector-Projekte zurückgestellt
bis die allgemeinen Metadaten und das Nutzverhalten stabil sind.
- HTTP/2, Streaming, großer body/response, CRS Vergleich, Leistung und
  Graceful-Restart-Szenarien bleiben spätere Abdeckungsarbeiten.
- Die dedizierte Nur-API-Smoke-Zielerweiterung bleibt vom Connector getrennt
  Nachweis.

## Blockiert/Wartend

- `RESPONSE_BODY` Blockierung wartet auf stabilen Apache und NGINX reale Welt HTTP 403
  Verhalten für die gleiche YAML-Probe.
- RAW Argumentsammlung wartet auf PR #3564 Unterstützung in der konfigurierten lokalen v3
  Quelle plus Apache- und NGINX-Connector-Durchgänge.
- XML schema/DTD, fehlerhafter mehrteiliger, dateigestützter Operator, binary/NUL, HTTP/2,
  und Streaming-Fälle erfordern explizite Installations- und Transportunterstützung.
- `v3_action_nolog_pass_no_audit` behält den früheren Verlauf erwarteter Fehler bei lokalen und GitHub-Aktionen bei
  Das Verhalten des Überwachungsprotokolls ist unterschiedlich.

## Unbekannte / Designentscheidungen

- Ob das maschinenlesbare YAML-Schema das JSON-Schema sein soll, ein Benutzerdefiniert
  Validator oder beides.
- So modellieren Sie Connector-spezifische YAML-Erweiterungen, ohne Common zu verunreinigen
  Fälle.
- So stellen Sie leere Antworten, bereits gesendete Header und verspätete Antworttexte dar
  Eingriffe in stabile Ergebnisaussagen.
- Welche Audit-Log-Felder können über lokale und GitHub-Aktionen hinweg stabilisiert werden?
  Umgebungen.

## Empfohlene nächste Aktionen

- Führen Sie anschließend die Connector-eigenen `make lint`, `make summary` und `make case-matrix` aus
Fall- oder Metadatenänderungen.
- Führen Sie steckereigene Smoke-Ziele aus, bevor Sie PASS/FAIL die Sprache ändern
  Connector-Statusdokumente.
- Behalten Sie vom Connector generierte Berichte und das Framework-eigene Stammverzeichnis bei
  `TEST-COVERAGE-SUMMARY.md` über den Connector aktualisiert
  `make generate-test-matrix` / `make check-test-matrix` Fluss.
- Behalten Sie `RESPONSE_BODY`, RAW-ARGS, nur zugeordnet, früherer erwarteter Fehler, blockiert, Connector-Lücke,
  und Laufzeitdifferenzfälle sichtbar getrennt in Zusammenfassungen.
