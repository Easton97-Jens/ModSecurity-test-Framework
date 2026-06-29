# HAProxy SPOE/SPOA Bereitschaftsüberprüfung (nur Dokumentation)

**Sprache:** [English](haproxy-spoe-readiness-review.md) | Deutsch

## Kurzfazit
Das Framework ist teilweise vorbereitet, es fehlen jedoch noch zentrale Verträge/Runner/Schemas.

## Umfang
Diese Rezension ist dokumentarisch und umsetzungsfrei.
Es werden keine Tests, keine Runner, keine Reports und keine Runtime-Evidence generiert.

## Belege aus dem aktuellen Repository
| Datei/Pfad | Aussage | Bewertung |
|---|---|---|
| `README.md` | Zentrales Test-/Runner-/Reporting-Framework; Connector-Code bleibt getrennt. | krass |
| `docs/connector-adapter-interface.md` | Generischer Hook-Vertrag ist dokumentiert. | krass |
| `tests/runners/case_cli.py` | Runner-CLI kennt nur `apache`/`nginx` als Connector-Auswahl. | krass |
| `tests/runners/msconnector_models.py` | Zusammenfassungsmodell vorhanden, aber nicht mit vollständigem HAProxy-Ziel-Feldset. | krass |
| `ci/run-connector-smokes.sh` | Runtime-Orchestrierung nur für Apache/NGINX. | krass |
| `.github/workflows/test-common.yml` | CI prüft Framework-Materialisierung, nicht HAProxy Runtime-Integration. | mittel |
| `docs/future-connectors.md` | HAProxy nur als Zukunftspfad beschrieben. | mittel |

## Fähigkeitsmatrix
| Fähigkeit. Fähigkeit | Vorhanden? | Stehen | Grenze |
|---|---|---|---|
| Connector-Auswahl | Teilweise | Apache/NGINX vorhanden. | HAProxy fehlt. |
| Allgemeine Haken | Ja (dokumentiert) | `prepare/start/send_request/collect_logs/stop/cleanup` sind vertraglich beschrieben. | Nicht implementiert für HAProxy/SPOE. |
| Request-Runner | Ja | Shared YAML-Materialisierung und Status-Assertion vorhanden. | Keine HAProxy-Ausführung. |
| Log-Sammlung | Teilweise | Hook vertraglich definiert. | HAProxy/SPOA-Logpfade: Im Connector-Repository zu belegen. |
| Report-Erzeugung | Teilweise | Zusammenfassung-Mechanik vorhanden. | Zielschema-Felder (`runtime_verified`, `evidence`, `open_questions`) nicht vollständig vorhanden. |
| Laufzeitbeweis | Teilweise | Evidenz-Semantik dokumentiert. | HAProxy Runtime-Evidence: Nicht belegbar aus dem aktuellen Repository. |
| CI-Orchestrierung | Teilweise | Framework/Apache/NGINX konzentriert. | Externe HAProxy-Artefakt-Orchestrierung fehlt. |

## Offene Punkte für die Doku-Phase
- Report-Zielmodell formalisiert als vorgeschlagenes Dokument (`haproxy-spoe-report-schema.md`).
- Artifact-Discovery als reiner Vertragsentwurf (`haproxy-spoe-artifact-discovery.md`).
- Keine Ableitung einer vorhandenen HAProxy-Unterstützung aus der Doku-Phase.

## Aussagen mit Nachweisgrenze
- Eine produktive HAProxy/SPOE/SPOA-Laufzeitintegration ist nicht belegbar aus dem aktuellen Repository.
- Konkrete PoC-Artefaktstruktur und Startkommandos sind im Connector-Repository zu belegen.
- Externe Betriebsannahmen (z. B. Hostnetz, Ports, Prozessmodelle) sind Extern zu verifizieren.
