# HAProxy SPOE/SPOA Disabled Connector Key Implementation Plan

**Language:** English | [Deutsch](haproxy-spoe-disabled-key-implementation-plan.de.md)

## Status
plan_status: draft
implementation_status: not_started
runner_support: false
tests_implemented: false
runtime_verified: false
dry_run_only: true
connector_enabled: false

## Zweck
Dieses Dokument beschreibt nur, wie ein HAProxy connector key später als disabled/dry-run/planned key eingeführt werden könnte.
Es implementiert nichts.

## Ziel des ersten Implementierungsschritts
Der erste spätere Code-Schritt soll nur ermöglichen:
- `haproxy` als bekannten, aber deaktivierten Connector-Key zu erkennen,
- klar zu melden, dass HAProxy/SPOE noch nicht unterstützt wird,
- keine Runtime-Ausführung zu starten,
- keine Tests auszuführen,
- `runtime_verified` niemals auf `true` zu setzen.

## Nicht-Ziele
- Kein HAProxy Runner.
- Keine SPOA-Komponente.
- Keine Runtime-Orchestrierung.
- Keine Testausführung.
- Keine CI-Integration.
- Keine Report-Evidence.
- Keine Unterstützung als produktiver Connector.

## Aktuelle Code-Berührungspunkte

| Datei | Aktueller Stand | Mögliche spätere Änderung | Risiko |
|---|---|---|---|
| `tests/runners/case_cli.py` | Connector-Argumente sind in relevanten Subcommands auf `apache`/`nginx` begrenzt. | Optional: `haproxy` als bekannter disabled/planned Key in Auswahl und Fehlermeldungspfad ergänzen (ohne Runtime-Pfad). | Falsche Aktivierung eines nicht implementierten Connectors. |
| `tests/runners/msconnector_models.py` | Summary-Modell enthält kein dediziertes Feld `runtime_verified`; bestehende Struktur fokussiert auf vorhandene Connector-Summaries. | Optional: metadata-only Kennzeichnung für disabled/not_run dokumentieren, ohne Runtime-Evidence-Felder als erfüllt auszugeben. | Missverständliche Reports könnten Support suggerieren. |
| `ci/run-connector-smokes.sh` | Orchestriert nur Apache/NGINX-Smokes. | Keine Änderung im ersten Schritt; HAProxy bleibt außerhalb der Runtime-Orchestrierung. | Unbeabsichtigte CI/Smoke-Erweiterung ohne Runner. |
| `docs/connector-adapter-interface.md` | Hook-Vertrag ist allgemein dokumentiert (`prepare/start/send_request/collect_logs/...`). | Dokumentationsverweis: HAProxy bleibt planned, bis Hook-Implementierungen real vorliegen. | Vertrag könnte fälschlich als Implementierungsnachweis gelesen werden. |

## Geplantes Verhalten

| Aktion | Erwartetes Verhalten | Status |
|---|---|---|
| `connector=apache` | Bleibt unverändert. | planned |
| `connector=nginx` | Bleibt unverändert. | planned |
| `connector=haproxy` | Wird erkannt, aber als disabled/planned gemeldet. | planned |
| `connector=haproxy` Runtime | Startet keine Runtime. | planned |
| `connector=haproxy` Tests | Führt keine Tests aus. | planned |
| `connector=haproxy` Runtime-Evidence | Erzeugt keine Runtime-Evidence. | planned |
| `connector=haproxy` Output | Darf höchstens dry-run/metadata/readiness Output liefern, falls überhaupt. | planned |

## Fehlermeldung / User-Facing Message

Proposed only:

`HAProxy/SPOE is documented as planned support but is not implemented. No tests were run. runtime_verified=false.`

## Report-Verhalten im disabled Zustand
- Kein echter Runtime-Report.
- Falls ein metadata-only Ergebnis erzeugt wird, muss es klar als `not_run` / `disabled` / `runtime_verified=false` markiert sein.
- `evidence[]` muss leer bleiben.
- `tests[]` dürfen nur `planned`/`not_run` enthalten.
- `open_questions[]` darf offene Punkte listen.

Hinweis zur Beleglage:
- Das konkrete Feldset (`runtime_verified`, `evidence`, `tests`, `open_questions`) im HAProxy-Format ist Nicht belegbar aus dem aktuellen Repository.
- Das Connector-Artefaktmodell für HAProxy/SPOE ist Im Connector-Repository zu belegen.

## Sicherheitsregeln
- `runtime_verified` darf im disabled key niemals `true` sein.
- HAProxy darf nicht als supported beworben werden.
- Keine Tests im Connector-Repo.
- Keine Runtime-Ausführung ohne explizite spätere Implementierung.
- Keine stillen Fallbacks auf Apache/NGINX.

## Akzeptanzkriterien für spätere Codeänderung
Eine spätere Codeänderung ist akzeptabel, wenn:
- Apache/NGINX-Verhalten unverändert bleibt.
- HAProxy nur als disabled/planned erkannt wird.
- klare Fehlermeldung oder disabled-Ausgabe erfolgt.
- keine Runtime gestartet wird.
- keine Tests ausgeführt werden.
- keine Reports mit Runtime-Evidence erzeugt werden.
- unit/structure checks für bestehendes Framework weiterhin grün bleiben.

## Risiken

| Risiko | Status | Gegenmaßnahme |
|---|---|---|
| HAProxy wird versehentlich als supported angezeigt. | offen | Klare disabled-Meldung und Review-Gate für wording. |
| `runtime_verified` wird falsch gesetzt. | offen | Harte Regel: im disabled-Zustand immer `false`. |
| CLI choices aktivieren HAProxy, obwohl kein Runner existiert. | offen | Falls Key aufgenommen wird: nur mit immediate disabled-abort Pfad. |
| Tests erwarten HAProxy-Runtime. | offen | Test-Discovery/Docs klar als not_run für HAProxy markieren. |
| CI versucht HAProxy-Smokes auszuführen. | offen | Keine CI-Orchestrierung für HAProxy bis Runner implementiert ist. |
| Connector-Repo wird wieder mit Tests vermischt. | offen | Ownership-Regel in Docs/Review strikt beibehalten. |

## Empfohlene spätere Mini-PR
Nur als Plan:
Eine kleine PR, die:
- HAProxy als disabled/planned key dokumentiert oder in Metadata sichtbar macht,
- bei Nutzung klar abbricht,
- keine Runtime startet,
- keine Tests hinzufügt.

## Nächster Schritt
Nach Review dieses Plans eine minimale Codeänderung für einen disabled/dry-run HAProxy connector key vorbereiten.

## Nachweis- und Abgrenzungshinweise
- Aktive HAProxy/SPOE-Unterstützung: Nicht belegbar aus dem aktuellen Repository.
- HAProxy/SPOA-Laufzeitartefakte und Startpfade: Im Connector-Repository zu belegen.
- Externe Laufzeitannahmen (Netzwerk/Ports/Prozessmodell): Extern zu verifizieren.
