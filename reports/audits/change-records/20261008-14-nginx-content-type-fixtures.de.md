# NGINX-Fixtures für Response-Content-Type

**Sprache:** Deutsch | [English](20261008-14-nginx-content-type-fixtures.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20261008-14-nginx-content-type-fixtures` |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | `11e1d20990d4ecbbcf18641782b04f0bb6369c69` |
| Issue oder Pull Request | Framework-PR-#137-Folgearbeit; nicht veröffentlicht |

## Motivation und Problemstellung

Vier Required-MIME-Cases hatten keine ausführbaren Case-Fixtures.

## Betroffene Komponenten und Sicherheitsgrenzen

Nur Case-YAML, Fokustests und dieser zweisprachige Nachweis ändern sich.
Native Common-Producer und Canonical-Validator integriert der Koordinator.

## Akzeptanzkriterien

Getrennte echte Requests, Engine-MIME-Policy, sichtbarer SAFE-HTTP-Status 200
und explizite begrenzte Content-Type-Auslassung beim Missing-Header-Case.

## Untersuchte Alternativen

Keine Wiederherstellung der entfernten Connector-MIME-Datei-API und keine
synthetischen Scope-Events.

## Implementierungsentscheidung

Baseline-Regel 1100301 und echte text/plain-, Charset-, image/png- oder fehlende
Content-Type-Header verwenden. Kein gemeinsames Löschen und Neufüllen der MIME-
Typen im Rules-Load: Der geprüfte Engine-Merge löscht auch folgende Werte.
SAFE-Late-Deny bleibt sichtbar 200, kein erfundener nachträglicher 403.
Missing verwendet `omit_headers: [Content-Type]` und leeren NGINX-Default-Type.

## Geänderte Dateien und Tests

Vier Case-Fixtures und `tests/no_crs/test_nginx_content_type_cases.py` prüfen
echte Materializer-Ausgaben und exakte Case-Semantik.

## Befehle und Ergebnisse

Fehlende Dateien: RED Exit 1; zwei Fokustests: GREEN Exit 0. Vollständige
No-CRS-Contract-Suite Exit 0. Vier isolierte Diagnose-Harness-Aufrufe lieferten
Exit 0 und HTTP 200; In-Scope und Charset haben native Regel-1100301/log_only-Logs.

## Sicherheitsauswirkung

Keine Required-Verkleinerung, Validator-, MRTS-, Policy- oder Guardrail-Abschwächung.

## Dokumentation und Runtime-Evidenz

Externes Task-Verzeichnis `nginx-all-required-20261008T124555Z/stream-a-r4` hält
Config, Requests, Root-Master/nobody-Worker, Artefakt-Maps und Cleanup fest.
Der alte geprüfte native Build ist Diagnose, kein aktueller Exact Head.
Leere Out-of-Scope-/Missing-Logs beweisen keinen Abschluss. Der Harness hält
keine Wire-Header fest; separate Backend-Wire-Tests beweisen die Auslassung
nur auf dieser Ebene. Native Completion-/Scope-Evidence bleibt erforderlich.

## Nicht ausgeführte Prüfungen

Finaler integrierter Canonical-Lauf, vollständiger Lint, Remote-CI und Sonar fehlen.

## Einschränkungen und Restrisiko

Fixture-Deklarationen und HTTP-Erfolg beweisen keine Canonical-Coverage.

## Finaler Diff- und Review-Status

Nur gezielte Änderungen. Kein Push, Gitlink-Update, Merge oder Full-E2E-PASS.
