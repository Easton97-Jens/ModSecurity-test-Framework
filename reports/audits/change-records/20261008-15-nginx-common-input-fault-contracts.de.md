# NGINX-Common-Input-Fault-Verträge

**Sprache:** Deutsch | [English](20261008-15-nginx-common-input-fault-contracts.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20261008-15-nginx-common-input-fault-contracts` |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | `210a33c44c8620d42db7393524083294cf052cf5` |
| Issue oder Pull Request | Framework-PR-#137-Folgearbeit; nicht veröffentlicht |

## Motivation und Problemstellung

Zwei Required-Input-Faults benötigen tatsächliche native Common-Validierung statt Driver-Events.

## Betroffene Komponenten und Sicherheitsgrenzen

Nur neuer Runner-Helfer, Fokuskontrollen und dieses EN/DE-Paar; Katalog/Schema bleiben beim Koordinator.

## Akzeptanzkriterien

Echter Worker-/Transaktions-/URI-Guard-Fault, Mapper-Return0, HTTP400 und nativer Phase1-Protokollfehler ohne Regel; an denselben Lauf/Prozess gebundenes Cleanup und Wrong-Target-Kontrollen.

## Untersuchte Alternativen

Keine erfundene Phase2-Completion oder generische HTTP500-Deutung des vorhandenen NGINX-Mapper-Boundarys.

## Implementierungsentscheidung

Geschlossene NGINX-spezifische Phase1/400/mapping_error-Verträge; generische Katalog-Semantik anderer Connectoren bleibt erhalten. Rohes Protocol-Event über echte Transaktion an Guard-Ledger und Access binden.

## Geänderte Dateien und Tests

tests/runners/nginx_common_input_faults.py und tests/no_crs/test_nginx_common_input_faults.py; EN/DE-Nachweise.

## Befehle und Ergebnisse

Vier fokussierte Unit-Tests bestanden nach Fortsetzung, einschließlich falscher Transaktion/Prozesse/Läufe, Guard-Return1 oder booleschem false, fehlendem/doppeltem/fremdem Event, Regel-Ersatz, HTTP405 und boolescher Phase. Framework-Interpreter: `rtk proxy env PYTHONNOUSERSITE=1 PIP_REQUIRE_VIRTUALENV=true PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1 "${FRAMEWORK_PYTHON}" -m unittest tests.no_crs.test_nginx_common_input_faults -v`, Exit0; der exakte umgebungseigene Interpreterpfad steht im externen Task-Handoff. Natives `make test-no-crs-contract` mit explizitem Framework-Python und externen Wurzeln bestand213 Tests, Exit0; die erste `make check-documentation`-Prüfung bestand, Exit0. Spätere Dokumentationsprüfung beanstandete einen lokalen Entwicklerpfad in diesem Nachweis; der Beispielbefehl nutzt jetzt einen portablen Platzhalter. Alle Befehle liefen über RTK.

## Sicherheitsauswirkung

Keine Required-Verkleinerung, synthetischen Events, Validator-Abschwächung oder MRTS-Änderungen.

## Dokumentation und Runtime-Evidenz

Alter Cache: Header echt400/Commonreturn0/nativ protocol_error und Driver0; WrongTX Driver1/405 ohne Event. Alter Body-Guard Return1/405 bleibt RED bis neu gebaut. Echter Common-event_jsonl-Protocol-View liefert protocol_error statt phase1_error; exakter Validator und frischer Header-Retry folgen dieser Source. Rohdaten/Maps/Root/nobody/Cleanup extern; Unit-Beobachtungen sind keine Runtime-Records.

## Nicht ausgeführte Prüfungen

Vollständiger integrierter E2E, Remote-CI/Sonar und finale Canonical-Validierung fehlen.

## Einschränkungen und Restrisiko

Koordinator muss geschlossene rohe Artefakt-Receipt-Zuordnungen und echte Build-Identität unabhängig prüfen. Der reine Beobachtungshelfer authentifiziert keine Receipt-Hashes oder Revisionen. Rollen und Cleanup binden nun exakten Lauf und beobachtete Master-/Worker-PIDs.

## Finaler Diff- und Review-Status

Nur Fokusdateien; separater lokaler Commit nach begrenzter Diagnose; kein Push/Gitlink/Merge/PASS. Neu gebauter Body-Positivlauf und finale Exact-Source-Validierung fehlen weiterhin.
