# HAProxy SPOE/SPOA Framework Contract

**Language:** English | [Deutsch](haproxy-spoe-framework-contract.de.md)

## Status
contract_status: draft
implementation_status: not_started
runner_support: false
runtime_verified: false
report_schema_complete: false
connector_repo_tests_allowed: false

## Zweck
Dieses Dokument beschreibt den geplanten Vertrag zwischen dem zentralen ModSecurity-test-Framework und einem späteren HAProxy SPOE/SPOA-PoC im Connector-Repository.
Es implementiert keine Tests und keinen Runner.

## Grundsatz
- Alle Tests liegen im ModSecurity-test-Framework.
- Das Connector-Repository enthält keine Tests.
- Das Connector-Repository kann nur Artefakte, Beispielkonfigurationen, Doku und Schnittstellen bereitstellen.
- Runtime-Evidence darf nur durch dieses Framework erzeugt werden.
- Reports dürfen nur durch dieses Framework erzeugt oder kontrolliert zurückgeschrieben werden.

Begründung aus dem aktuellen Framework-Stand:
- Das Repository definiert sich als zentrales Test-, Runtime-, Coverage- und Reporting-Framework, nicht als Connector-Implementierungsrepo.
- Connector-Projekte liefern Connector-Quellcode, Harness-Entrypoints, Adapter-Metadaten und connector-lokale Runtime-Evidence.
- Die gemeinsame YAML-Case-Basis liegt im Framework (`tests/cases/`).

## Aktueller Stand im Framework

| Fähigkeit | Aktueller Stand | Beleg | Grenze |
|---|---|---|---|
| Connector-Auswahl | Connector-Auswahl im Runner ist aktuell Apache/NGINX-zentriert. | `tests/runners/case_cli.py` (`choices=("apache", "nginx")` in relevanten Subcommands). | HAProxy ist dort aktuell nicht auswählbar. |
| Adapter-Hook-Vertrag | Der generische Adapter-Vertrag ist dokumentiert (`prepare`, `start`, `stop`, `reload`, `apply_rules`, `materialize_case`, `send_request`, `collect_logs`, `summarize_results`, `cleanup`). | `docs/connector-adapter-interface.md`. | Für HAProxy/SPOE/SPOA nicht implementiert. |
| Summary-/Report-Modell | Ein Summary-/Report-Modell existiert im Runner-Modell mit Feldern wie `connector_path`, `validation_mode`, `summary`, `cases`, `origin`. | `tests/runners/msconnector_models.py`. | `runtime_verified` ist kein vollständiges vorhandenes Schemafeld; `integration_model` ist kein vollständiges vorhandenes Schemafeld; `evidence`/`open_questions` sind nicht vollständig als Schemafelder vorhanden. |
| Runtime-Smoke-Orchestrierung | Runtime-Smoke-Orchestrierung existiert für Apache/NGINX. | `ci/runtime/run-connector-smokes.sh` ruft `run-apache-smoke.sh` und `run-nginx-smoke.sh`; `Makefile` enthält Smoke-Targets für Apache/NGINX. | Keine belegte HAProxy-Orchestrierung im aktuellen Repository. |
| HAProxy/SPOE-Status | HAProxy wird als zukünftiger Connector-Pfad beschrieben. | `docs/future-connectors.md`. | HAProxy/SPOE ist nicht implementiert. |
| Runtime-Verifikation | Laufzeit-Evidence-Semantik und lokale Smoke-Autorität sind beschrieben. | `README.md` (Evidence-Semantik, lokale Smokes als Autorität). | Konkrete HAProxy Runtime-Evidence: Nicht belegbar aus dem aktuellen Repository. |

## Geplanter HAProxy Connector-Key

Vorschlag (keine Implementierung):

- `connector: haproxy`
- `integration_model: spoe_spoa`
- `validation_mode: poc`

Status:
- planned only

Offen:
- Runner-CLI-Unterstützung
- Artefakt-Discovery
- Report-Schema-Erweiterung
- Runtime-Orchestrierung

## Geplanter Framework-Vertrag

| Vertragsfeld / Hook | Bedeutung | Status | Beleg/Grenze |
|---|---|---|---|
| `connector` | Eindeutiger Connector-Key im Report/Run-Kontext. | planned only | Aktuell kein eigenständiges Feld im vorhandenen Summary-Objekt (Connector liegt aktuell als Top-Level-Key). |
| `integration_model` | Integrationspfad (hier: `spoe_spoa`). | planned only | Nicht belegbar aus dem aktuellen Repository. |
| `validation_mode` | Betriebsmodus für Validierung (`poc`, `real-world-connector-path`, etc.). | repo documented | In `SummaryContext`/CLI vorhanden. |
| `connector_root` | Wurzel des Connector-Repositories für Artefakte/Quellen. | repo documented | In README/CI-Flows als expliziter Pfad genutzt. |
| `artifact_root` | Pfad zu PoC-/Runtime-Artefakten innerhalb Connector-Kontext. | planned only | Im Connector-Repository zu belegen. |
| `prepare` | Voraussetzungen prüfen, Laufzeitverzeichnisse vorbereiten. | repo documented | Als Hook im Adapter-Vertrag dokumentiert. |
| `start` | Serverprozess mit Connector starten. | repo documented | Als Hook im Adapter-Vertrag dokumentiert. |
| `send_request` | Reale HTTP-Anfrage je YAML-Case ausführen. | repo documented | Als Hook im Adapter-Vertrag dokumentiert. |
| `collect_logs` | Server-/Connector-/Audit-/Access-Logs sammeln/verweisen. | repo documented | Als Hook im Adapter-Vertrag dokumentiert. |
| `stop` | Serverprozess kontrolliert stoppen. | repo documented | Als Hook im Adapter-Vertrag dokumentiert. |
| `cleanup` | Runtime-Artefakte bereinigen/isolation unter BUILD_ROOT. | repo documented | Als Hook im Adapter-Vertrag dokumentiert. |
| `generate_report` | Report aus Runner-Ergebnissen erzeugen. | planned only | Aktuell existiert `summarize_results`; ein expliziter Hook `generate_report` ist so nicht benannt. |
| `runtime_verified` | Explizite Kennzeichnung, ob Runtime-Verifikation erfolgreich erbracht ist. | planned only | Im aktuellen Summary-Schema nicht als Feld vorhanden. |
| `evidence` | Strukturierte Evidenzliste je Test/Anforderung. | planned only | Im aktuellen Summary-Schema nicht als Feld vorhanden. |
| `open_questions` | Offene Punkte/Grenzen maschinenlesbar erfassen. | planned only | Im aktuellen Summary-Schema nicht als Feld vorhanden. |
| `response_body_scope` | Dokumentierter Gültigkeitsbereich für Response-Body-Bewertungen. | planned only | RESPONSE_BODY-Semantik ist dokumentiert, aber dieses Feld existiert aktuell nicht. |

## Verantwortlichkeiten

| Verantwortung | ModSecurity-test-Framework | ModSecurity-conector | Status |
|---|---|---|---|
| Testfall-Definition | Verantwortlich (`tests/cases/`) | Nicht verantwortlich | repo documented |
| Testausführung | Verantwortlich (Runner/Harness-Integration im Framework) | Liefert nur Connector-seitige Runtime-Anbindung/Artefakte | repo documented |
| Runner | Verantwortlich (`tests/runners/`) | Nicht verantwortlich | repo documented |
| Assertions | Verantwortlich (shared Assertions im Runner-Core/CLI) | Nicht verantwortlich | repo documented |
| Report-Erzeugung | Verantwortlich (Summary-/Matrix-Generierung) | Kann Ziel für kontrollierte Ausgabe sein | repo documented |
| Runtime-Evidence | Verantwortlich (durch Framework-Smokes/Matrix) | Liefert nur ausführbare Connector-Basis | repo documented |
| Connector-Artefakte | Nicht verantwortlich für Implementierung | Verantwortlich | repo documented |
| Beispielkonfigurationen | Kann Referenz nutzen, nicht primäre Ownership | Verantwortlich | Im Connector-Repository zu belegen. |
| Agent-/Harness-Design | Rahmenvertrag/Hook-Modell im Framework | Konkrete Connector-Harness-Umsetzung je Connector | repo documented |
| Produktiver Connector-Code | Nicht verantwortlich | Verantwortlich | Im Connector-Repository zu belegen. |

## Minimaler HAProxy/SPOE-PoC aus Framework-Sicht

Nur Anforderungen, keine Implementierung.

| Anforderung | Status | Wo zu belegen |
|---|---|---|
| HAProxy-Konfigurationssyntax prüfbar | planned only | Im Connector-Repository zu belegen. |
| HAProxy startbar | planned only | Im Connector-Repository zu belegen. |
| SPOA-Komponente startbar | planned only | Im Connector-Repository zu belegen. |
| benign request allowed | planned only | Durch Framework-Runner mit HAProxy-Adapter später zu belegen. |
| malicious request block-signal | planned only | Durch Framework-Runner mit HAProxy-Adapter später zu belegen. |
| Logs sammelbar | planned only | Im Connector-Repository zu belegen. |
| Report erzeugbar | planned only | Durch Framework-Summary/Matrix nach Schema-Erweiterung zu belegen. |
| Response-Body-Scope dokumentierbar | planned only | Extern zu verifizieren. |

## Geplantes Report-Zielmodell

Proposed schema (nicht implementiert):

```json
{
  "connector": "haproxy",
  "integration_model": "spoe_spoa",
  "validation_mode": "poc",
  "runtime_verified": false,
  "tests": [],
  "evidence": [],
  "open_questions": [],
  "response_body_scope": "unknown"
}
```

Hinweis:
- Dieses Zielmodell ist ein Vertragsvorschlag für spätere Erweiterung.
- Eine vollständige Feldabdeckung im aktuellen Framework ist Nicht belegbar aus dem aktuellen Repository.
