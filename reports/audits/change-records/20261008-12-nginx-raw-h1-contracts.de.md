# Änderungsnachweis

**Sprache:** Deutsch | [English](20261008-12-nginx-raw-h1-contracts.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change ID | 20261008-12-nginx-raw-h1-contracts |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | `178c10d` |

## Motivation und Problemstellung

Vier erforderliche fehlerhafte H1-Eingaben werden von NGINX vor der Connector-Zulassung abgelehnt. Ein HTTP-Status allein beweist weder die beabsichtigte Parser-Ablehnung noch eine Engine-Transaktion.

## Betroffene Komponenten und Sicherheitsgrenzen

Geschlossener Framework-Eingabe-/Beobachtungshelfer und gezielte Tests. Parent-Ausführung, Normalisierung, Katalog, MRTS und Gitlinks bleiben unverändert.

## Akzeptanzkriterien

Case-/Run-Identitäten und echte Wire-Bytes begrenzen; vollständige eindeutige HTTP400-Antwort, exakte native Access-Identität und native Parser-Diagnose verlangen. Fehlende, abgeschnittene oder widersprüchliche Beobachtungen scheitern.

## Untersuchte Alternativen

Szenario-Erfolg allein aus HTTP400 abzuleiten oder vor Connector-Zulassung ein Engine-Event zu erzeugen, würde Evidence erfinden.

## Implementierungsentscheidung

Vier exakte fehlerhafte Header und unabhängige gültige Kontrolleingaben registrieren. Vollständiges Content-Length-Framing, echte Methode/URI/Status und quellenspezifische native Diagnose prüfen. Keine allgemeine Raw-Request-Injektionsschnittstelle ergänzen.

## Geänderte Dateien und Tests

`tests/runners/nginx_raw_h1.py`, vier Kontrollen in `tests/no_crs/test_nginx_raw_h1.py` und dieser zweisprachige Nachweis.

## Befehle und Ergebnisse

Die vier gezielten Unit-Tests bestehen. Sie prüfen kontrollierte Byte-Beobachtungen, keinen neuen NGINX-Runtime-Lauf.

## Sicherheitsauswirkung

Unbekannte Cases, Pfad-/Steuerzeichen-Identitäten, doppeltes oder unvollständiges Framing, falsche Access-Identität und fehlende Diagnosen bleiben abgewiesen. Keine synthetische Transaktion, Regel oder Events erzeugen.

## Dokumentation und Runtime-Evidenz

Dieser Nachweis beschreibt nur den begrenzten Source-Vertrag. Vorhandene Diagnose-Requests mit alten Artefakten sind keine neue Exact-Head-Evidence.

## Nicht ausgeführte Prüfungen

Native Ausführung mit neuen Artefakten und integrierte finale Canonical-Validierung stehen aus.

## Einschränkungen und Restrisiko

Der Helfer authentifiziert weder Artefakt-Ownership noch Source-Identität oder Root-/Worker-Rollen; diese muss der integrierte Bundle-Reader separat beweisen.

## Finaler Diff- und Review-Status

Gezielter Helfer-/Test-/Nachweisumfang. Keine Required-Scope-Verkleinerung oder Validator-Abschwächung.
