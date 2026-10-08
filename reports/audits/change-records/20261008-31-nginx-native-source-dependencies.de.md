# Change record

**Sprache:** [English](20261008-31-nginx-native-source-dependencies.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261008-31-nginx-native-source-dependencies |
| UTC-Datum | 2026-10-08 |
| Framework-Basis-Revision | `4745d853fbc6b11d2137385e7a887762e44e98f9` |
| Issue oder Pull Request | Framework-PR137; koordinierte All-required-Integration |

## Motivation und Problemstellung

Originale Native-Envelopes versiegelten die neuen Fakt-Projector-/Contract-/Authority-Module, ihre unbedingten Helper-Abhängigkeiten, Canonical-Koordinator/Schema/Modell und den tatsächlichen Parent-Collector-/Caller-Pfad nicht. Frei aus Receipts übernommene Pfade dürfen diese Lücke nicht schließen.

## Betroffene Komponenten und Sicherheitsgrenzen

Nur die geschlossene42-Source-Whitelist, eine fokussierte Kontrolle und dieses EN/DE-Record. Source-Bytes werden weiterhin unabhängig unter expliziten Owned-Roots erneut gelesen. Binary-/Modul-/Fault-Artefaktautorität und Build-Provenance bleiben getrennt.

## Akzeptanzkriterien

Jede native Route enthält die tatsächlich verwendeten Normalisierungs-/Mapping-/Caller-Abhängigkeiten. Exakte geschlossene Pfadgleichheit sowie Datei-/Owner-/Größen-/Hash-Prüfungen erhalten. Im bestehenden64-Source-Schemalimit bleiben; keine beliebigen Dateien oder ganzen Produktbäume aufnehmen.

## Untersuchte Alternativen

Aus Envelopes übernommene Pfade ermöglichen Source-Austausch. Pauschale Source-Inventare vermischen unbeteiligte Imports mit ausgeführten Verträgen. Ein Source-Hash beweist weder ausgeführte Bytes noch einen neuen nativen Build.

## Implementierungsentscheidung

Die nachgewiesenen Framework-Projector-, Faktvertrag-, Authority-, Framing-/Sequence-/Phase4-Helper, Statusmodell, Koordinator, Katalog und sechs direkt verwendeten Schemas gemeinsam versiegeln. Parent-Collector/Native-Collection/Authority und Baseline-/Selected-Host-/Stage-Caller ergänzen. Case-Driver, Fixtures und Rule-Seals bleiben erhalten; keine Sicherheitsprüfung entfällt.

## Geänderte Dateien und Tests

`tests/runners/nginx_native_operation_bundle.py`, `tests/no_crs/test_nginx_native_source_dependencies.py` und dieses Paar. Die fokussierte Kontrolle prüft alle42 exakten Routen und das bestehende64-Source-Maximum.

## Befehle und Ergebnisse

Initiale Abhängigkeitskontrolle:42 rote Subtests (Exit1), extern in `root-native-dependency-red.log`. Nach Ergänzung61 Reader-/Projector-/Contract-/Canonical-Kontrollen grün (Exit0,9.274s), `root-native-dependency-green-r2.log`. Ein früherer Aufruf benannte ein nicht vorhandenes optionales Testmodul: Exit1,45 tatsächliche Tests bestanden; als Befehlsfehler erfasst, nicht als Source-PASS. Die eigenständige Source-Kontrolle sowie Dokumentations-/Whitespace-Prüfungen werden vor dem Commit erneut ausgeführt.

## Sicherheitsauswirkung

Strengere Abhängigkeitsidentität, keine behauptete Sicherheitsbehebung. Explizite Source-/Run-/Artefakt-Autoritäten, stabile No-follow-Lesevorgänge und exakte Schema-Gleichheit bleiben Pflicht. Keine beliebigen Helper- oder Artefaktpfade akzeptieren.

## Dokumentation und Runtime-Evidenz

EN/DE-Paar. Unit-Kontrollen sind keine Runtime-Evidenz. Required97 bleibt unverändert, die45 finalen Lücken bleiben offen. Kein neuer Head-Build oder nativer Request wird behauptet.

## Nicht ausgeführte Prüfungen

Nativer Build/vollständiger E2E, Remote-CI/Sonar und geschützte administrative Verifikation bleiben Voraussetzungen des Koordinators. Vollständiger Lint ist nicht zertifiziert.

## Einschränkungen und Restrisiko

Der verschachtelte Live-Framing-Import des erfassten Sequence-Helpers benötigt einen separaten Loader-Fix für ausgeführte Bytes. Das Source-Seal behebt diesen Unterschied allein nicht. Finaler sauberer Tupelstand und originale Runtime-Artefakte bleiben erforderlich.

## Finaler Diff- und Review-Status

Nur vier begrenzte Dateien; zentrale Canonical-/Schema-Arbeit bleibt bewusst außerhalb dieses separaten Ursachen-Commits. Die exakte Abhängigkeitsliste wurde vom Worker unabhängig verfolgt und vom Koordinator geprüft. Keine MRTS-/Gitlink-Änderung oder Historienumschreibung.
