# Change record

**Sprache:** Deutsch | [English](20261010-02-nginx-mime-aggregate-schema.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261010-02-nginx-mime-aggregate-schema |
| UTC-Datum | 2026-10-10 |
| Framework-Basis | e8a8f98a4c24958616b15b98aadedcc73345a786 |
| PR | Framework137; Parent-Integration396 separat |

## Motivation und Problemstellung

Zwei MIME-Allow-Case-PASS verursachten vier verschachtelte Schema-Enumfehler.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-Koordinator, Schema und Tests; Source-/Receipt-/Byte-Autorität erhalten. MRTS und Produkt unverändert.

## Akzeptanzkriterien

allow/allow nur für exakte zwei Case-/Result-Paare ohne Rule, späte Intervention oder Abbruch.

## Untersuchte Alternativen

Defaults, erfundene Evidence und Validator-Abschwächungen verworfen.

## Implementierungsentscheidung

Aggregate-Projektor unverändert. Enge anyOf-Schemaform für bestehende MIME-Nichtintervention. Null/completed-Transport bleibt erhalten.

## Geänderte Dateien und Tests

tests/schemas/no-crs-baseline/result.schema.json, tests/no_crs/test_nginx_native_canonical_binding.py und dieses Paar.

## Befehle und Ergebnisse

RTK + Framework Python3.14.7, Arbeits-Overlay auf der ursprünglichen 4c6c21e8622840b4c218d8ea5520dd0b10b3fac9: unittest C/D14 Tests Exit0; unittest discover -s tests/no_crs -p test*.py:413 Tests Exit0. D RED zwei Subtests/vier Enumfehler; GREEN acht Negativkontrollen je MIME. C Offline-Pipeline: Eventlöschung und sechs Canonical-Manipulationen abgelehnt. Gesamt-Producer-Replay schema-valid, Gesamtstatus weiterhin FAIL. Clean-Commit- und frische Runtime-Prüfungen sind separate Integrationsevidence.

## Sicherheitsauswirkung

Keine H2/H3-Umetikettierung, Required-Verkleinerung oder Herkunftsumgehung.

## Dokumentation und Runtime-Evidenz

HISTORICAL INPUT / CURRENT VALIDATOR REPLAY / NOT A NEW RUNTIME RUN. Originale unverändert; lokale externe Logs c-historical-replay-v3.log, d-historical-replay.log und no-crs-suite.log.

## Nicht ausgeführte Prüfungen

Echte begrenzte H1-/MIME-Fokusprobe, integrierte saubere SHAs, vollständiger Lint und frische CI/Sonar separat. Full97/Protected nicht freigegeben.

## Einschränkungen und Restrisiko

Lokale Python3.14.7 ist nicht exakte Framework-CI3.14.8. Historische Replay-Authority verwendet ausdrücklich unveränderte gleich-SHA-Checkouts.

## Finaler Diff- und Review-Status

Nur zugewiesene Dateien; git diff --check Exit0. Koordinator reviewt, committet Ursachen separat und aktualisiert Parent-Gitlink.
