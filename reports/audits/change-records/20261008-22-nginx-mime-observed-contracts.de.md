# NGINX-Verträge für beobachtete MIME-Operationen

**Sprache:** Deutsch | [English](20261008-22-nginx-mime-observed-contracts.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20261008-22-nginx-mime-observed-contracts` |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | `e94ed33` |
| Issue oder Pull Request | Framework-PR-#137-Folgearbeit; nur lokal |

## Motivation und Problemstellung

HTTP200 und ein fehlendes Regel-Event beweisen weder nativen MIME-Ausschluss noch Completion. Vier vorhandene Required-MIME-Fixtures benötigen eine Beobachtungsprüfung tatsächlicher Wire-Header und Engine-Retention.

## Betroffene Komponenten und Sicherheitsgrenzen

Eigenständiger Runner-Helfer und Tests; Katalog, Schema, Auswahl, Collector und Runtime-Produzenten bleiben externe Abhängigkeiten des Koordinators. Parent- und MRTS-Source bleiben durch diesen Framework-Anteil unverändert.

## Akzeptanzkriterien

Aufbewahrte Raw-Hashes, vollständige Client-Antwort, exakter tatsächlicher Content-Type oder dessen Fehlen, geschlossene Backend-Fixture, echte MIME-Konfiguration und native Append-/Completion-Fakten müssen übereinstimmen. In-Scope und Charset benötigen echte Regel1100301 mit safe/log-only; Out/Missing benötigen Completion mit tatsächlich retained0 ohne erfundene Regel.

## Untersuchte Alternativen

Fixture-Deklaration, HTTP-Status oder leere Phase4-Logs allein beweisen keine native Ausführung. MIME-Reset verändert das Engine-Merge-Verhalten der vorhandenen Fixture.

## Implementierungsentscheidung

`validate_mime_operation(case_id, receipt, raw_artifacts)` prüft vier geschlossene IDs. Native `phase4_append`- und `phase4_completion`-JSONL verwenden dieselben begrenzten Reason-Formate wie der Phase4-Operationshelfer. Übergebene Bytes behalten Commons Inspected-Byte-Bedeutung; tatsächlich durch die Engine behaltene Bytes werden separat geführt. Append-Anzahlen werden beobachtet und dürfen mehrere native Chunks abbilden. Out/Missing mit Append-Return1/Retained0 folgt echten Engine-MIME-Prüfungen vor Append-Schreiben und Regelauswertung.

## Geänderte Dateien und Tests

`tests/runners/nginx_mime_operations.py`, `tests/no_crs/test_nginx_mime_operations.py` und dieses EN/DE-Paar.

## Befehle und Ergebnisse

Framework-Python über RTK: sieben MIME-Fokustests und dreizehn kombinierte Pointer-/MIME-/Fixture-Tests bestanden, Exit0. Negative Kontrollen prüfen fehlende Append/Completion, falschen nativen Return/Retention/TX/Regel/EOS, boolesche Bytes, falschen Wire-Typ/Body/Framing, Raw-Hash-Manipulation, Fixture-Abweichung und doppelte native Schlüssel; Readiness-Beobachtungen bleiben separat. Natives `make test-no-crs-contract` bestand218 Tests vor den letzten zwei kleinen Unit-Ergänzungen; neuester Fokus13 bestand danach. Korrigiertes `make check-documentation` bestand, Exit0; zuvor hatte es einen lokalen Entwicklerpfad im Input-Fault-Nachweis beanstandet. Framework-Ruff konnte mangels Modul in seiner eigenen Umgebung nicht laufen; keine Pakete installiert.

## Sicherheitsauswirkung

Keine Required-Verkleinerung, synthetischen Events, Validator-Abschwächung oder MRTS-Änderungen. Hash-Prüfung bindet hier übergebene Bytes ans Receipt; der übergeordnete Canonical-Reader muss sicheren Zugriff auf aufbewahrte Dateien, zusammengehörige Source/Build-Identität, echten Produzenten, Prozessrollen und Cleanup authentifizieren.

## Dokumentation und Runtime-Evidenz

Alte In-/Charset-Diagnoseläufe besitzen echte native Regel1100301/Log-only-Events. Out/Missing haben leere native Logs und bleiben unzureichend. Für diesen Helfer wurden weder neues Modul gebaut noch Runtime ausgeführt. Missing-Type-Akzeptanz benötigt fehlenden finalen Wire-Header; Backend-Omission allein reicht nicht.

## Nicht ausgeführte Prüfungen

Finale integrierte native Runtime, neu gebautes Modul für alle vier Operationen, Canonical97-Prüfung und Remote-CI/Sonar wurden nicht ausgeführt.

## Einschränkungen und Restrisiko

Koordinator muss Receipt-/Raw-API und nativen Completion-Produzenten verdrahten und tatsächliche Artefaktidentitäten prüfen. Raw-Konfiguration erwartet exakte eigenständige native Driver-Konfiguration mit einer effektiven Safe-/Default-Type-/Types-Deklaration; Include-Produzenten müssen ihre tatsächliche Include-Kette erhalten und prüfen.

## Finaler Diff- und Review-Status

Nur eigenständiger Framework-Helfer, Tests und EN/DE-Nachweis; lokaler Commit ohne Push, Gitlink-Update oder Merge. Native Runtime-Completion bleibt ungeprüft.
