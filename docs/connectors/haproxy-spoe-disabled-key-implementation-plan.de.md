# HAProxy SPOE/SPOA Implementierungsplan für Connector-Schlüssel deaktiviert

**Sprache:** [English](haproxy-spoe-disabled-key-implementation-plan.md) | Deutsch

## Status
plan_status: Entwurf
Implementierungsstatus: nicht_gestartet
runner_support: false
tests_implemented: false
runtime_verified: false
dry_run_only: wahr
Connector_enabled: falsch

## Zweck
Dieses Dokument beschreibt nur, wie ein HAProxy Connector Key später als disabled/dry-run/planned Key eingeführt werden könnte.
Es ist nichts implementiert.

## Ziel des ersten Implementierungsschritts
Der erste spätere Code-Schritt soll nur ermöglichen:
- `haproxy` als bekannt, aber deaktivierten Connector-Key zu erkennen,
- klar zu melden, dass HAProxy/SPOE noch nicht unterstützt wird,
- keine Runtime-Ausführung zu starten,
- keine Tests durchführen,
- `runtime_verified` niemals auf `true` setzen.

## Nicht-Ziele
- Kein HAProxy Runner.
- Keine SPOA-Komponente.
- Keine Runtime-Orchestrierung.
- Keine Testausführung.
- Keine CI-Integration.
- Kein Bericht-Nachweis.
- Keine Unterstützung als produktiver Connector.

## Aktuelle Code-Berührungspunkte

| Datei | Aktueller Stand | Mögliche spätere Änderung | Risiko |
|---|---|---|---|
| `tests/runners/case_cli.py` | Connector-Argumente sind in relevanten Subcommands auf `apache`/`nginx` begrenzt. | Optional: `haproxy` als bekannter disabled/planned Key in Auswahl und Fehlermeldungspfad ergänzen (ohne Runtime-Pfad). | Falsche Aktivierung eines nicht implementierten Connectors. |
| `tests/runners/msconnector_models.py` | Summary-Modell enthält kein dediziertes Feld `runtime_verified`; Die bestehende Struktur konzentriert sich auf diese Connector-Zusammenfassungen. | Optional: Metadata-only Kennzeichnung für disabled/not_run dokumentieren, ohne Runtime-Evidence-Felder als erfüllt auszugeben. | Unverständliche Berichte könnten vom Support vorgeschlagen werden. |
| `ci/runtime/run-connector-smokes.sh` | Orchestriert nur Apache/NGINX-Smokes. | Keine Änderung im ersten Schritt; HAProxy bleibt außerhalb der Runtime-Orchestrierung. | Unbeabsichtigte CI/Smoke-Erweiterung ohne Runner. |
| `docs/connector-adapter-interface.md` | Hook-Vertrag ist allgemein dokumentiert (`prepare/start/send_request/collect_logs/...`). | Dokumentationsbericht: HAProxy bleibt geplant, bis Hook-Implementierungen real vorliegen. | Vertrag könnte fälschlicherweise als Implementierungsnachweis gelesen werden. |

## Geplantes Verhalten

| Aktion | Erwartetes Verhalten | Status |
|---|---|---|
| `connector=apache` | Bleibt unverändert. | geplant |
| `connector=nginx` | Bleibt unverändert. | geplant |
| `connector=haproxy` | Wird erkannt, aber als disabled/planned gemeldet. | geplant |
| `connector=haproxy` Laufzeit | Startet keine Runtime. | geplant |
| `connector=haproxy` Tests | Führt keine Tests aus. | geplant |
| `connector=haproxy` Laufzeitnachweis | Erzeugt keine Runtime-Evidence. | geplant |
| `connector=haproxy` Ausgabe | Darf höchstens dry-run/metadata/readiness Output liefern, fällt überhaupt. | geplant |

## Fehlermeldung / benutzerbezogene Meldung

Nur vorgeschlagen:

`HAProxy/SPOE is documented as planned support but is not implemented. No tests were run. runtime_verified=false.`

## Report-Verhalten im behinderten Zustand
- Kein echter Runtime-Report.
- Falls ein metadata-only Ergebnis erzeugt wird, muss es klar als `not_run` / `disabled` / `runtime_verified=false` markiert sein.
- `evidence[]` muss leer bleiben.
- `tests[]` dürfen nur `planned`/`not_run` enthalten.
- `open_questions[]` darf offene Punkte hören.

Hinweis zur Beleglage:
- Das konkrete Feldset (`runtime_verified`, `evidence`, `tests`, `open_questions`) im HAProxy-Format ist nicht aus dem aktuellen Repository belegbar.
- Das Connector-Artefaktmodell für HAProxy/SPOE ist im Connector-Repository zu belegen.

## Sicherheitsregeln
- `runtime_verified` darf im deaktivierten Schlüssel niemals `true` sein.
- HAProxy darf nicht als unterstützt verwendet werden.
- Keine Tests im Connector-Repo.
- Keine Runtime-Ausführung ohne explizite spätere Implementierung.
- Keine stillen Fallbacks auf Apache/NGINX.

## Akzeptanzkriterien für spätere Codeänderungen
Eine spätere Codeänderung ist akzeptabel, wenn:
- Apache/NGINX-Verhalten bleibt unverändert.
- HAProxy wird nur als disabled/planned erkannt.
- Es erfolgt eine klare Fehlermeldung oder eine deaktivierte Ausgabe.
- Es wird keine Runtime gestartet.
- Es werden keine Tests durchgeführt.
- Es werden keine Reports mit Runtime-Evidence erzeugt.
- unit/structure Prüfungen für bestehendes Framework bleiben weiterhin grün.

## Risiken

| Risiko | Status | Gegenmaßnahme |
|---|---|---|
| HAProxy wird standardmäßig als unterstützt angezeigt. | offen | Klare Disabled-Meldung und Review-Gate für Wording. |
| `runtime_verified` wird falsch gesetzt. | offen | Harte Regel: im invalid-Zustand immer `false`. |
| CLI Auswahlmöglichkeiten aktivieren HAProxy, obwohl kein Runner existiert. | offen | Falls Key aufgenommen wird: nur mit sofortigem Disabled-Abort Pfad. |
| Tests erwarten HAProxy-Runtime. | offen | Test-Discovery/Docs klar als not_run für HAProxy markieren. |
| CI versucht HAProxy-Smokes auszuführen. | offen | Es ist keine CI-Orchestrierung für HAProxy bis Runner implementiert. |
| Connector-Repo wird wieder mit Tests vermischt. | offen | Eigentums-Regel in Docs/Review strikt beibehalten. |

## Empfohlene spätere Mini-PR
Nur als Plan:
Eine kleine PR, die:
- HAProxy als disabled/planned key dokumentiert oder in Metadata sichtbar macht,
- bei Nutzung klar abbricht,
- keine Runtime gestartet,
- keine Tests hinzufügt.

## Nächster Schritt
Nach Überprüfung dieses Plans eine minimale Codeänderung für einen disabled/dry-run HAProxy Connector Key vorbereiten.

## Nachweis- und Abgrenzungshinweise
- Aktive HAProxy/SPOE-Unterstützung: Nicht belegbar aus dem aktuellen Repository.
- HAProxy/SPOA-Laufzeitartefakte und Startpfade: Im Connector-Repository zu belegen.
- Externe Laufzeitannahmen (Netzwerk/Ports/Prozessmodell): Extern zu verifizieren.
