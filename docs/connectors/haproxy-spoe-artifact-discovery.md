# HAProxy SPOE/SPOA Artifact Discovery (Documentation-Only)

**Language:** English | [Deutsch](haproxy-spoe-artifact-discovery.de.md)

## Status
contract_status: draft
implementation_status: not_started
runner_support: false
runtime_verified: false
artifact_discovery_implemented: false

## Zweck
Dieses Dokument beschreibt eine vorgeschlagene, dokumentarische Artifact-Discovery für einen späteren HAProxy/SPOE/SPOA-PoC.
Es implementiert keine Discovery-Logik, keinen Runner und keine Tests.

## Grundsatz
- Tests, Testfälle, Runner, Reports und Runtime-Evidence gehören ausschließlich in das ModSecurity-test-Framework.
- Das Connector-Repository liefert nur Artefakte, Beispielkonfigurationen, Doku und Schnittstellenbeschreibungen.
- Artifact-Discovery darf nur als Eingabe für Framework-Ausführung dienen.

## Aktueller belegbarer Stand
| Bereich | Stand | Beleg | Grenze |
|---|---|---|---|
| Pfadtrennung Framework/Connector | Explizite Pfade (`FRAMEWORK_ROOT`, `CONNECTOR_ROOT`) sind dokumentiert. | `README.md` | HAProxy-spezifische Discovery-Regeln fehlen. |
| Adapter-Vertrag | Hook-Vertrag (`prepare/start/send_request/collect_logs/...`) ist dokumentiert. | `docs/connector-adapter-interface.md` | Keine HAProxy-Implementierung. |
| Laufende Connector-Smokes | Apache/NGINX-Orchestrierung vorhanden. | `ci/runtime/run-connector-smokes.sh` | HAProxy nicht orchestriert. |
| Runner-Connector-Auswahl | `apache`/`nginx` sind auswählbar. | `tests/runners/case_cli.py` | `haproxy` nicht auswählbar. |

## Proposed Discovery Inputs (planned only)
- `connector_root`: Root des Connector-Repositories.
- `connector`: Erwartet `haproxy`.
- `integration_model`: Erwartet `spoe_spoa`.
- `artifact_root`: Basisverzeichnis für PoC-Artefakte im Connector-Repository.
- `haproxy_config_path`: Hauptkonfiguration des HAProxy-PoC.
- `spoa_entrypoint_path`: Startpunkt/Startskript der SPOA-Komponente.
- `artifact_manifest_path`: Optionales Manifest für referenzierte Artefakte.

Status aller Felder: planned only.

## Proposed Discovery Outputs (planned only)
- Aufgelöste Artefaktpfade für spätere `prepare`/`start`-Hooks.
- Validierungsstatus „referenzierbar ja/nein" (nur dokumentarisch, keine Implementierung).
- Offene Fragenliste (`open_questions`) bei unklaren/vermissten Artefakten.

## Nachweisführung je Input
| Input | Nachweisquelle | Status |
|---|---|---|
| `artifact_root` | Im Connector-Repository zu belegen. | planned only |
| `haproxy_config_path` | Im Connector-Repository zu belegen. | planned only |
| `spoa_entrypoint_path` | Im Connector-Repository zu belegen. | planned only |
| `artifact_manifest_path` | Im Connector-Repository zu belegen. | planned only |
| Port-/Netzwerkannahmen | Extern zu verifizieren. | planned only |

## Nicht-Ziele
- Keine Validierung durch ausführbares JSON-Schema.
- Keine Anpassung von CI/Build/Runner.
- Keine Erzeugung von Runtime-Evidence.
