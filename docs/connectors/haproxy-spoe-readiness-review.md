# HAProxy SPOE/SPOA Readiness Review (Documentation-Only)

## Kurzfazit
Das Framework ist teilweise vorbereitet, aber es fehlen noch zentrale Verträge/Runner/Schemas.

## Scope
Dieses Review ist dokumentarisch und implementation-free.
Es erzeugt keine Tests, keine Runner, keine Reports und keine Runtime-Evidence.

## Belege aus dem aktuellen Repository
| Datei/Pfad | Aussage | Bewertung |
|---|---|---|
| `README.md` | Zentrales Test-/Runner-/Reporting-Framework; Connector-Code bleibt getrennt. | stark |
| `docs/connector-adapter-interface.md` | Generischer Hook-Vertrag ist dokumentiert. | stark |
| `tests/runners/case_cli.py` | Runner-CLI kennt nur `apache`/`nginx` als Connector-Auswahl. | stark |
| `tests/runners/msconnector_models.py` | Summary-Modell vorhanden, aber nicht mit vollständigem HAProxy-Ziel-Feldset. | stark |
| `ci/run-connector-smokes.sh` | Runtime-Orchestrierung nur für Apache/NGINX. | stark |
| `.github/workflows/test-common.yml` | CI prüft Framework-Materialisierung, nicht HAProxy Runtime-Integration. | mittel |
| `docs/future-connectors.md` | HAProxy nur als Zukunftspfad beschrieben. | mittel |

## Fähigkeitsmatrix
| Fähigkeit | Vorhanden? | Stand | Grenze |
|---|---|---|---|
| Connector-Auswahl | Teilweise | Apache/NGINX vorhanden. | HAProxy fehlt. |
| Generische Hooks | Ja (dokumentiert) | `prepare/start/send_request/collect_logs/stop/cleanup` sind vertraglich beschrieben. | Nicht implementiert für HAProxy/SPOE. |
| Request-Runner | Ja | Shared YAML-Materialisierung und Status-Assertion vorhanden. | Keine HAProxy-Ausführung. |
| Log-Sammlung | Teilweise | Hook vertraglich definiert. | HAProxy/SPOA-Logpfade: Im Connector-Repository zu belegen. |
| Report-Erzeugung | Teilweise | Summary-Mechanik vorhanden. | Zielschema-Felder (`runtime_verified`, `evidence`, `open_questions`) nicht vollständig vorhanden. |
| Runtime-Evidence | Teilweise | Evidence-Semantik dokumentiert. | HAProxy Runtime-Evidence: Nicht belegbar aus dem aktuellen Repository. |
| CI-Orchestrierung | Teilweise | Framework/Apache/NGINX fokussiert. | Externe HAProxy-Artefakt-Orchestrierung fehlt. |

## Offene Punkte für die Doku-Phase
- Report-Zielmodell formalisiert als vorgeschlagenes Dokument (`haproxy-spoe-report-schema.md`).
- Artifact-Discovery als reiner Vertragsentwurf (`haproxy-spoe-artifact-discovery.md`).
- Keine Ableitung einer vorhandenen HAProxy-Unterstützung aus der Doku-Phase.

## Aussagen mit Nachweisgrenze
- Eine produktive HAProxy/SPOE/SPOA-Laufzeitintegration ist Nicht belegbar aus dem aktuellen Repository.
- Konkrete PoC-Artefaktstruktur und Startkommandos sind Im Connector-Repository zu belegen.
- Externe Betriebsannahmen (z. B. Hostnetz, Ports, Prozessmodelle) sind Extern zu verifizieren.
