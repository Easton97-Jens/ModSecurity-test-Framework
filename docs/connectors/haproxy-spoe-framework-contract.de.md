# HAProxy SPOE/SPOA Rahmenvertrag

**Sprache:** [English](haproxy-spoe-framework-contract.md) | Deutsch

## Status
Vertragsstatus: Entwurf
Implementierungsstatus: nicht_gestartet
runner_support: false
runtime_verified: false
report_schema_complete: false
Connector_repo_tests_allowed: false

## Zweck
Dieses Dokument beschreibt den geplanten Vertrag zwischen dem zentralen ModSecurity-Test-Framework und einem späteren HAProxy SPOE/SPOA-PoC im Connector-Repository.
Es sind keine Tests und kein Runner implementiert.

## Grundsatz
- Alle Tests liegen im ModSecurity-Test-Framework.
- Das Connector-Repository enthält keine Tests.
- Das Connector-Repository kann nur Artefakte, Beispielkonfigurationen, Dokumentation und Schnittstellen bereitstellen.
- Runtime-Evidence darf nur durch dieses Framework erzeugt werden.
- Berichte dürfen nur durch dieses Framework erzeugt oder kontrolliert zurückgeschrieben werden.

Begründung aus dem aktuellen Framework-Stand:
- Das Repository definiert sich als zentrales Test-, Runtime-, Coverage- und Reporting-Framework, nicht als Connector-Implementierungsrepo.
- Connector-Projekte liefern Connector-Quellcode, Harness-Entrypoints, Adapter-Metadaten und Connector-lokale Runtime-Evidence.
- Die gemeinsame YAML-Case-Basis liegt im Framework (`tests/cases/`).

## Aktueller Stand im Framework

| Fähigkeit. Fähigkeit | Aktueller Stand | Beleg | Grenze |
|---|---|---|---|
| Connector-Auswahl | Connector-Auswahl im Runner ist aktuell Apache/NGINX-zentriert. | `tests/runners/case_cli.py` (`choices=("apache", "nginx")` in relevanten Unterbefehlen). | HAProxy ist dort aktuell nicht auswählbar. |
| Adapter-Haken-Vertrag | Der generische Adapter-Vertrag ist dokumentiert (`prepare`, `start`, `stop`, `reload`, `apply_rules`, `materialize_case`, `send_request`, `collect_logs`, `summarize_results`, `cleanup`). | `docs/connector-adapter-interface.md`. | Für HAProxy/SPOE/SPOA nicht implementiert. |
| Summary-/Report-Modell | Ein Summary-/Report-Modell existiert im Runner-Modell mit Feldern wie `connector_path`, `validation_mode`, `summary`, `cases`, `origin`. | `tests/runners/msconnector_models.py`. | `runtime_verified` ist kein vollständiges Schemafeld; `integration_model` ist kein vollständiges Schemafeld; `evidence`/`open_questions` sind nicht vollständig als Schemafelder vorhanden. |
| Runtime-Smoke-Orchestrierung | Runtime-Smoke-Orchestrierung existiert für Apache/NGINX. | `ci/run-connector-smokes.sh` ruft `run-apache-smoke.sh` und `run-nginx-smoke.sh`; `Makefile` enthält Smoke-Targets für Apache/NGINX. | Keine belegte HAProxy-Orchestrierung im aktuellen Repository. |
| HAProxy/SPOE-Status | HAProxy wird als zukünftiger Connector-Pfad beschrieben. | `docs/future-connectors.md`. | HAProxy/SPOE ist nicht implementiert. |
| Laufzeit-Verifikation | Laufzeit-Evidence-Semantik und lokale Smoke-Autorität sind beschrieben. | `README.md` (Evidence-Semantik, lokale Smokes als Autorität). | Konkrete HAProxy Runtime-Evidence: Nicht belegbar aus dem aktuellen Repository. |

## Geplanter HAProxy Connector-Key

Vorschlag (keine Implementierung):

- `connector: haproxy`
- `integration_model: spoe_spoa`
- `validation_mode: poc`

Status:
- nur geplant

Offen:
- Runner-CLI-Unterstützung
- Artefakt-Entdeckung
- Report-Schema-Erweiterung
- Laufzeit-Orchestrierung

## Geplanter Framework-Vertrag

| Vertragsfeld / Hook | Bedeutung | Status | Beleg/Grenze |
|---|---|---|---|
| `connector` | Eindeutiger Connector-Key im Report/Run-Kontext. | nur geplant | Aktuell kein eigenständiges Feld im vorhandenen Summary-Objekt (Connector liegt aktuell als Top-Level-Key). |
| `integration_model` | Integrationspfad (hier: `spoe_spoa`). | nur geplant | Nicht belegbar aus dem aktuellen Repository. |
| `validation_mode` | Betriebsmodus für Validierung (`poc`, `real-world-connector-path` usw.). | Repo dokumentiert | In `SummaryContext`/CLI vorhanden. |
| `connector_root` | Wurzel des Connector-Repositories für Artefakte/Quellen. | Repo dokumentiert | In README/CI-Flows als expliziter Pfad genutzt. |
| `artifact_root` | Pfad zu PoC-/Runtime-Artefakten innerhalb Connector-Kontext. | nur geplant | Im Connector-Repository zu belegen. |
| `prepare` | Voraussetzungen prüfen, Laufzeitverzeichnisse vorbereiten. | Repo dokumentiert | Als Hook im Adapter-Vertrag dokumentiert. |
| `start` | Serverprozess mit Connector starten. | Repo dokumentiert | Als Hook im Adapter-Vertrag dokumentiert. |
| `send_request` | Echte HTTP-Anfrage je YAML-Case ausführen. | Repo dokumentiert | Als Hook im Adapter-Vertrag dokumentiert. |
| `collect_logs` | Server-/Connector-/Audit-/Access-Logs sammeln/verweisen. | Repo dokumentiert | Als Hook im Adapter-Vertrag dokumentiert. |
| `stop` | Serverprozess kontrolliert gestoppt. | Repo dokumentiert | Als Hook im Adapter-Vertrag dokumentiert. |
| `cleanup` | Runtime-Artefakte bereinigen/isolation unter BUILD_ROOT. | Repo dokumentiert | Als Hook im Adapter-Vertrag dokumentiert. |
| `generate_report` | Reportage aus Runner-Ergebnissen erzeugen. | nur geplant | Aktuell existiert `summarize_results`; ein expliziter Hook `generate_report` ist so nicht benannt. |
| `runtime_verified` | Explizite Kennzeichnung, ob Runtime-Verifikation erfolgreich durchgeführt ist. | nur geplant | Im aktuellen Summary-Schema ist nicht als Feld vorhanden. |
| `evidence` | Strukturierte Evidenzliste je Test/Anforderung. | nur geplant | Im aktuellen Summary-Schema ist nicht als Feld vorhanden. |
| `open_questions` | Offene Punkte/Grenzen maschinenlesbar erfassen. | nur geplant | Im aktuellen Summary-Schema ist nicht als Feld vorhanden. |
| `response_body_scope` | Dokumentierter Gültigkeitsbereich für Response-Body-Bewertungen. | nur geplant | RESPONSE_BODY-Semantik ist dokumentiert, aber dieses Feld existiert aktuell nicht. |

## Verantwortlichkeiten

| Verantwortung | ModSecurity-Test-Framework | ModSecurity-Anschluss | Status |
|---|---|---|---|
| Testfall-Definition | Verantwortlich (`tests/cases/`) | Nicht verantwortlich | Repo dokumentiert |
| Testausführung | Verantwortlich (Runner/Harness-Integration im Rahmenwerk) | Liefert nur Connector-seitige Runtime-Anbindung/Artefakte | Repo dokumentiert |
| Runner | Verantwortlich (`tests/runners/`) | Nicht verantwortlich | Repo dokumentiert |
| Behauptungen | Verantwortlich (gemeinsame Behauptungen im Runner-Core/CLI) | Nicht verantwortlich | Repo dokumentiert |
| Report-Erzeugung | Verantwortlich (Summary-/Matrix-Generierung) | Kann Ziel für kontrollierte Ausgabe sein | Repo dokumentiert |
| Laufzeitbeweis | Verantwortlich (durch Framework-Smokes/Matrix) | Liefert nur ausführbare Connector-Basis | Repo dokumentiert |
| Connector-Artefakte | Nicht verantwortlich für die Implementierung | Verantwortlich | Repo dokumentiert |
| Beispielkonfigurationen | Kann Referenz nutzen, nicht primäre Ownership | Verantwortlich | Im Connector-Repository zu belegen. |
| Agent-/Harness-Design | Rahmenvertrag/Hook-Modell im Framework | Konkrete Connector-Harness-Umsetzung je Connector | Repo dokumentiert |
| Produktiver Connector-Code | Nicht verantwortlich | Verantwortlich | Im Connector-Repository zu belegen. |

## Minimaler HAProxy/SPOE-PoC aus Framework-Sicht

Nur Anforderungen, keine Implementierung.

| Anforderung | Status | Wo zu belegen |
|---|---|---|
| HAProxy-Konfigurationssyntax prüfbar | nur geplant | Im Connector-Repository zu belegen. |
| HAProxy-Startleiste | nur geplant | Im Connector-Repository zu belegen. |
| SPOA-Komponente startbar | nur geplant | Im Connector-Repository zu belegen. |
| harmlose Anfrage erlaubt | nur geplant | Durch Framework-Runner mit HAProxy-Adapter später zu belegen. |
| böswilliges Anforderungsblockierungssignal | nur geplant | Durch Framework-Runner mit HAProxy-Adapter später zu belegen. |
| Protokolle sammelbar | nur geplant | Im Connector-Repository zu belegen. |
| Bericht erzeugbar | nur geplant | Durch Framework-Summary/Matrix nach Schema-Erweiterung zu belegen. |
| Response-Body-Scope dokumentierbar | nur geplant | Extern zu verifizieren. |

## Geplantes Report-Zielmodell

Vorgeschlagenes Schema (nicht implementiert):

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
- Dieses Zielmodell ist ein Vertragsvorschlag für spätere Erweiterungen.
- Eine vollständige Feldabdeckung im aktuellen Framework ist nicht belegbar aus dem aktuellen Repository.
