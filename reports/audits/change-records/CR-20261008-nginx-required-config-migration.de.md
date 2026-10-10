# Änderungsnachweis

**Sprache:** Deutsch | [English](CR-20261008-nginx-required-config-migration.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change ID | CR-20261008-nginx-required-config-migration |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | `385046a` |

## Motivation und Problemstellung

Drei bestehende Required-Case-IDs bleiben erforderlich und erhalten einen
expliziten nativen Konfigurationsaufruf. `invalid_status` prüft die bestehende
Ablehnung von `status:not-a-number` durch den Engine-Parser. Die beiden
Scope-Datei-Cases prüfen die Ablehnung der entfernten API
`modsecurity_phase4_content_types_file` mit ihren tatsächlichen, kontrollierten
Source-Fixtures. Sie behaupten weder eine erfundene MIME-Ablehnung der Engine
noch einen ausgeführten HTTP-Request.

## Betroffene Komponenten und Sicherheitsgrenzen

Geschlossener Katalog/Schema, kontrollierte Config-Fixture-Projektion und strikter kanonischer Config-Bundle-Reader. Parent-Treiber und MRTS werden durch diesen Framework-Teil nicht geändert.

## Akzeptanzkriterien

Der kanonische Reader verlangt exakte Fixture-Bytes, private reguläre Dateien
mit einem Link, exakte Konfigurations- und Diagnosepfade, beobachteten Exit 1,
aufbewahrte Binary-/Modul-/Config-/Stdout-/Stderr-Prüfsummen sowie passende
Run-/Source-Identitäten. Fehlende, ersetzte oder fremde Artefakte, neu gehashte
falsche Fixtures und die Verwendung einer Receipt für HTTP-Cases bleiben Fehler.

## Untersuchte Alternativen

Required-IDs zu entfernen oder akzeptierte MIME-Konfiguration als Ablehnung auszugeben, würde den Scope ändern oder Evidence erfinden.

## Implementierungsentscheidung

Alle drei IDs bleiben Required und erhalten die ausdrücklich freigegebenen nativen Config-Verträge mit exakten kontrollierten Fixture-Bytes.

## Geänderte Dateien und Tests

Katalog/Schema, Config-Bundle-Reader, Migration/Wiring und bestehende Receipt-Kontrollen; zweisprachiger Nachweis.

## Befehle und Ergebnisse

Validierung: 14 Unit-Tests für Migration, Wiring und bestehende Config-Receipts
bestanden im Integrations-Worktree. Drei frühere echte Configtests bestanden
ihre einzelnen strikten kanonischen Prüfungen mit ausdrücklich älterer
Build-Provenienz. Dies ist kein frischer integrierter Exact-Head-E2E-Nachweis.
Alle 97 selektierten Required-IDs bleiben erforderlich; abschließende Runtime,
vollständige Suites und aktuelle Remote-Qualitätsprüfungen stehen noch aus.

## Sicherheitsauswirkung

Strikte Byte-, Ownership-, Identitäts-, Digest- und negative Mismatch-Kontrollen bleiben erhalten. Keine Requests oder Events synthetisieren.

## Dokumentation und Runtime-Evidenz

Die drei früheren echten Configtests besitzen alte Build-Provenienz und sind nur einzelne Diagnose-Records.

## Nicht ausgeführte Prüfungen

Frischer integrierter Build, vollständige Framework-/Parent-Suites, Full Lifecycle und Remote-CI/Sonar.

## Einschränkungen und Restrisiko

Source-Deklarationen und gezielte Tests schließen die finale Required-Coverage nicht.

## Finaler Diff- und Review-Status

Gezielte Konfigurationsmigration. Gitlinks und Required-Auswahl unverändert.
