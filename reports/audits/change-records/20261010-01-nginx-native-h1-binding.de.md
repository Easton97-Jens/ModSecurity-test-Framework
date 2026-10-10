# Change record

**Sprache:** Deutsch | [English](20261010-01-nginx-native-h1-binding.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261010-01-nginx-native-h1-binding |
| UTC-Datum | 2026-10-10 |
| Framework-Basis | 4c6c21e8622840b4c218d8ea5520dd0b10b3fac9 |
| PR | Framework137; Parent-Integration396 separat |

## Motivation und Problemstellung

Native Strict-H1-Beobachtungen waren echt vorhanden; Canonical-Protokollfelder und passendes Event fehlten.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-Koordinator, Schema und Tests; Source-/Receipt-/Byte-Autorität erhalten. MRTS und Produkt unverändert.

## Akzeptanzkriterien

H1 verlangt tatsächliche Version11 und passende URI/TX/Case/Run/Phase/Rule; Mismatches bleiben FAIL.

## Untersuchte Alternativen

Defaults, erfundene Evidence und Validator-Abschwächungen verworfen.

## Implementierungsentscheidung

Reopened Reader-Beobachtung wird protokollgebunden projiziert. Originalevents bleiben unverändert. Retained Bytes erneut prüfen, case-gebundenes Canonical-Event ergänzen und versiegeln. Finale und Offline-Prüfung verlangen passendes Event.

## Geänderte Dateien und Tests

ci/checks/catalog/no_crs_baseline.py, tests/no_crs/test_nginx_native_h1_projection.py und dieses Paar.

## Befehle und Ergebnisse

RTK + Framework Python3.14.7: Arbeits-Overlay auf Basis4c6c21e8: unittest C/D14 Tests Exit0; unittest discover -s tests/no_crs -p test*.py:413 Tests Exit0. Committete Revision0c7f224731cda059decee026c7bd32e58bf9aa21: natives make test-no-crs-contract,413 Tests, keine SKIPs, Exit0. D RED zwei Subtests/vier Enumfehler; GREEN acht Negativkontrollen je MIME. C Offline-Pipeline: Eventlöschung und sechs Canonical-Manipulationen abgelehnt. Gesamt-Producer-Replay schema-valid, Gesamtstatus weiterhin FAIL.

## Sicherheitsauswirkung

Keine H2/H3-Umetikettierung, Required-Verkleinerung oder Herkunftsumgehung.

## Dokumentation und Runtime-Evidenz

HISTORICAL INPUT / CURRENT VALIDATOR REPLAY / NOT A NEW RUNTIME RUN. Originale unverändert; erfolgreiche lokale externe Logs framework-cd/c-historical-replay-v3.log und framework-cd/d-historical-replay.log; Log der committeten Suite framework-quality/no-crs-suite.log, im externen Task nginx-full97-followup-20261010T084822Z. Frühere fehlgeschlagene Replay-Versuche bleiben separat erhalten. Diese lokalen Dateien sind keine veröffentlichten Downloads.

## Nicht ausgeführte Prüfungen

Echte begrenzte H1-/MIME-Fokusprobe, integrierte saubere SHAs und frische CI/Sonar separat. Vollständiger nativer Lint auf0c7f2247 endete Exit2, weil der Aufruf einen externen Report-Lese-OUTPUT_ROOT übergab; zuvor604 Testausführungen erfolgreich. Der bestehende lesende Report-Pfadvertrag bleibt unverändert; korrigierter nativer Lint weiterhin erforderlich. Full97/Protected nicht freigegeben.

## Einschränkungen und Restrisiko

Lokale Python3.14.7 ist nicht exakte Framework-CI3.14.8. Historische Replay-Authority verwendet ausdrücklich unveränderte gleich-SHA-Checkouts.

## Finaler Diff- und Review-Status

Nur zugewiesene Dateien; git diff --check Exit0. Koordinator reviewt, committet Ursachen separat und aktualisiert Parent-Gitlink.
