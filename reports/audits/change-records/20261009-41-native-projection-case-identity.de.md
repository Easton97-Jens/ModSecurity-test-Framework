# Change record

**Sprache:** [English](20261009-41-native-projection-case-identity.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261009-41-native-projection-case-identity |
| UTC-Datum | 2026-10-09 |
| Framework-Basisrevision | 7db219af6b6e911b73de8b437f82e63efdb06bde |
| Issue oder Pull Request | Keine |

## Motivation und Problemstellung

Gemeinsame Run-IDs benötigen unterschiedliche Case-gebundene Projection-Kinder.

## Betroffene Komponenten und Sicherheitsgrenzen

Reader und authentische Receipt-/Config-Bindung; Authority und Seals unverändert.

## Akzeptanzkriterien

Exakter Hash; alte Namen, falscher Case/Run/Parent/Config werden abgelehnt.

## Untersuchte Alternativen

Kein Legacy-Fallback: dieser würde Kollisionen erneut zulassen.

## Implementierungsentscheidung

phase4- plus24 SHA256-Hexzeichen aus tatsächlicher run_id:case_id; E-Child-Run-IDs bleiben gebunden.

## Geänderte Dateien und Tests

Neuer Identitätstest; vorhandene decorate_phase4-Fixture exakt angepasst.

## Befehle und Ergebnisse

Framework-Python Unittest:28 Tests, Exit0. Original:18 Fehler und1 roter Negativtest, Exit1.

## Sicherheitsauswirkung

Keine Lockerung von Quelle, Receipt, Schema, Status oder Payload.

## Dokumentation und Runtime-Evidenz

EN/DE-Record; keine Native-Runtime-Evidenz.

## Nicht ausgeführte Prüfungen

Native-Build/Runtime/Veröffentlichung nicht autorisiert.

## Einschränkungen und Restrisiko

Root integriert Producer und Reader gemeinsam;97 Required unverändert.

## Finaler Diff- und Review-Status

Enger unstaged Diff geprüft; keine Git-Schreibaktionen.
