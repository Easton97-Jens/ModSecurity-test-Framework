# NGINX-Verträge für feste native Event-Grenzen

**Sprache:** Deutsch | [English](20261008-23-nginx-event-boundaries.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20261008-23-nginx-event-boundaries` |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | `93154133105fbeb2144ca02f6957282a1fc3b808` |
| Issue oder Pull Request | Framework-PR-#137-Folgearbeit; nur lokal |

## Motivation und Problemstellung

Zwei Required-IDs benötigen echte Phase1-Regel-Callbacks mit begrenzten projizierten Metadaten statt erfundener Log-only-Events oder konfigurierbarer Writer-Direktiven.

## Betroffene Komponenten und Sicherheitsgrenzen

Neuer eigenständiger Input-/Raw-Validator und Unit-Tests. Katalog/Schema/Auswahl bleiben Root-Verantwortung; Parent-Runtime und URI-Produzent sind separate Abhängigkeiten.

## Akzeptanzkriterien

Echtes natives request_rule_match/pass/Regel1100402, HTTP200, exakte projizierte URI-/Truncated-/Redacted-Flags, keine Body-/Query-Payload und JSONL unter tatsächlichem NGX4096-Puffer. Fester URI256-Vertrag benötigt unabhängige At255-/Over256-Kindläufe/Receipts.

## Untersuchte Alternativen

Driver-Summaries oder HTTP200 allein beweisen keinen nativen Callback/Truncation. Konfigurierbare Produkt-Event-Limit-Direktive existiert nicht; feste Source-Verträge müssen explizit sein.

## Implementierungsentscheidung

Geschlossene Eingaben erzeugen nicht sensible Long-query-/At255-/Over256-Requests. Raw-Validierung bindet tatsächliche Bytes/Hashes an eine native TX pro Kind und Same-run-Root/nobody-Cleanup. Übergeordnetes Receipt versiegelt Kind-Basename-/Lauf-/Revisionsidentität und exakte Receipt-Bytes. Query-Marker bleibt bei langen/escaped Präfixen erhalten; Common-Prüfung anderer Felder bleibt unverändert.

## Geänderte Dateien und Tests

tests/runners/nginx_event_boundary_operations.py, tests/no_crs/test_nginx_event_boundaries.py und dieses EN/DE-Paar. Vorhandene reine Pointer-Rollen-/MIME-Wire-Helfer werden wiederverwendet und von Parent als explizite Input-Abhängigkeiten authentifiziert.

## Befehle und Ergebnisse

Framework-Python über RTK: Event-Helfer5 und gemischte Event-/MIME-/Pointer16-Tests bestanden, Exit0. Absichtliche Akzeptanz einer ungültigen Truncatedfalse-Unit-Fixture erzeugte erwarteten Assertion-RED Exit1; korrekte Negativ-Suite GREEN. Synthetische Unit-Kontrollen, keine Runtime-Beobachtungen. Repository-/Dokumentationsresultate stehen im externen Handoff.

## Sicherheitsauswirkung

Keine Required-Verkleinerung, erfundene Regel, Common-Validator-Abschwächung oder MRTS-Schreibzugriffe. Falsche native Regel/Aktion/TX/Flags, Payload, übergroßes JSON, Receipt-Siegel, Cleanup und Identitäten werden abgelehnt.

## Dokumentation und Runtime-Evidenz

Tatsächlicher Root-Source-Callback ist MSCONN_EVENT_RULE_MATCHED/request_rule_match/pass mit Regel1100402. Source-URI-Puffer256, NGX-Writer4096; Generator255/256 ist explizit sourcegebunden. Kein nativer Lauf/Build für diesen Anteil.

## Nicht ausgeführte Prüfungen

Neue native Callback-/URI-Projektion, aktuelle Modul-/Artefaktidentität, integriertes Canonical97 und Remote-CI/Sonar warten auf Root-Runtime-Integration.

## Einschränkungen und Restrisiko

Canonical-Reader muss rohe Kinder sicher öffnen und echte Build-/Produzenten-/Prozessidentität authentifizieren. Hashes allein beweisen diese Ebenen nicht. Gemeinsame Runtime-Request-Header-/Callback-Hooks werden vor nativem Aufruf benötigt.

## Finaler Diff- und Review-Status

Nur eigenständige delegierte Framework-Dateien; lokaler Commit ohne Push/Gitlink/Merge/MRTS. Gesamte Runtime-Akzeptanz bleibt partial.
