# Change Record

**Sprache:** [English](20261008-02-nginx-ordered-duplicate-headers.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261008-02-nginx-ordered-duplicate-headers |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | `dc41bd22c335156cae02d9049098b92af65b7c57` |
| Issue oder Pull Request | Freigegebener Folgebranch `fix/nginx-seven-contracts-20261008`; externe Parent PR #396 bleibt Draft. |

## Motivation und Problemstellung

`duplicate_header_names` fehlte eine ausführbare Fixture. Ein Header-Modell
allein aus Mappings kann zwei Felder gleichen Namens nicht verlustfrei abbilden.

## Betroffene Komponenten und Sicherheitsgrenzen

`tests/runners/runner_core.py`, No-CRS-Fixture/-Katalog und fokussierte
Runner-Tests. Parent-H1-Transport und echte Connector-Beobachtungen bleiben
externe Runtime-Grenzen. Request-Smuggling-, H2/H3- oder Product-Source-Arbeit
wird nicht ergänzt.

## Akzeptanzkriterien

Geordnete Name/Wert-Einträge erhalten Wiederholungen, verschiedene und leere
Werte sowie die relevante Reihenfolge. Bestehende einfache Mappings bleiben
kompatibel. Fehlerhafte Einträge und unerlaubte Steuerzeichen bleiben
abgewiesen. Ein einzelner oder zusammengeführter Header darf den spezifischen
nativen Duplicate-Nachweis nicht erfüllen.

## Untersuchte Alternativen

Dictionary-Überschreiben, Set-Deduplizierung, Sortierung und Zusammenführung mit
Kommas verlieren die geforderte Repräsentation. Stattdessen bleibt die
Listenrepräsentation des bestehenden Parsers durch Validierung und
Materialisierung erhalten.

## Implementierungsentscheidung

Die Fixture sendet `X-No-Crs-Duplicate` zweimal mit `one` und danach `two`.
Eine eigene Phase-1-Regel `1100504` verlangt Anzahl `2` und beide Werte. HTTP
`200` allein reicht nicht: Echte native Regel-Evidence ist vorgeschrieben.
Dies prüft Transportreihenfolge und native Anzahl-/Wertbeobachtung, keine
undokumentierte Engine-Iterationsreihenfolge. Der Parent-Driver muss sein
tatsächliches H1-Mehrfachfeldverhalten erhalten.

## Geänderte Dateien und Tests

`tests/runners/runner_core.py`,
`tests/cases/no-crs-baseline/duplicate_header_names.yaml`,
`tests/cases/no-crs-baseline/catalog.json`,
`tests/no_crs/test_duplicate_header_runner.py`; dieses EN/DE-Paar.

## Befehle und Ergebnisse

Fokuslogs unter
`nginx-seven-contracts-20261008T080604Z` (externe Analysis-Run-ID):
`framework-headers-red.log` belegt den Fehler vor dem Fix;
`framework-headers-green.log` belegt 31 bestandene Tests. Abgleich des exakten
Befehls sowie abschließender Katalog-/Suite-Ergebnisse bleiben
Integrationsarbeit. Diese Tests beweisen nicht, dass ein nativer Host die
Fixture erhalten hat.

## Sicherheitsauswirkung

Header-Name-/Wertvalidierung bleibt vorgeschrieben; native Events werden nicht
aus Payload-Wissen synthetisiert. Selection und Required werden nicht
verkleinert. Es wird weder Security-Remediation noch Zertifizierung einer
geschützten Runtime behauptet.

## Dokumentation und Runtime-Evidenz

Dieses EN/DE-Paar dokumentiert ausschließlich Framework-Verhalten. Frische
echte H1-Invocation, Root-Master/nobody-Worker-Identität, korreliertes natives
Regel-Event, negative Single-Header-Kontrolle und Cleanup bleiben notwendige
externe Integrationsnachweise. Hier wird keine solche New-Head-Runtime-Coverage
behauptet.

## Nicht ausgeführte Prüfungen

Vollständige Framework-Lint/API-/Canonical-Regressionen, frischer integrierter
Hostlauf und CI/Sonar am späteren Delivery-SHA sind bei Erstellung noch nicht
abgeschlossen.

## Einschränkungen und Restrisiko

Client-Argumente allein reichen nicht. Unzugehöriges `200`, Regel, Phase,
Transaktion oder Run dürfen nicht bestehen. Engine-interne
Iterationsreihenfolge wird nicht behauptet. Weitere Required-Coverage-Lücken
bleiben außerhalb dieser Änderung.

## Finaler Diff- und Review-Status

Implementierungsrecord vor dem abschließenden Abgleich von Diff, vollständiger
Suite, Runtime und Delivery. Das Paar enthält keine Secrets, Raw-Bodies oder
eingebetteten ungeprüften Logs.
