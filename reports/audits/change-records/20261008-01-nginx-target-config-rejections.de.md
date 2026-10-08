# Change Record

**Sprache:** [English](20261008-01-nginx-target-config-rejections.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261008-01-nginx-target-config-rejections |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | `dc41bd22c335156cae02d9049098b92af65b7c57` |
| Issue oder Pull Request | Freigegebener Folgebranch `fix/nginx-seven-contracts-20261008`; Parent PR #396 ist eine externe Integrationsabhängigkeit und bleibt Draft. |

## Motivation und Problemstellung

Vier selektierten Konfigurationsrecords fehlten explizite ausführbare
NGINX-Verträge: `missing_rules_file`, `invalid_rule_syntax`,
`unknown_config_key` und `unsafe_event_path`. Ein beliebiger nonzero Exit
identifiziert ihre vorgeschriebenen Ablehnungsgrenzen nicht.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-Katalog, Configtest-Receipt-Schema, Normalisierung, Artefaktretention
und No-CRS-Regressionstests. Parent-Ausführung ist eine externe Abhängigkeit.
MRTS, Common-Produktsemantik, Protocol-Selection und geschützte Infrastruktur
bleiben unverändert.

## Akzeptanzkriterien

Jeder Fall besitzt einen expliziten geschlossenen Configtest-Deskriptor, Exit
`1`, seine genaue Diagnose und gebundene Raw-Konfigurations-/Binary-/Modul-/
Ausgabeartefakte. Falscher Case, Operation, Run, Modul, Grund, fehlendes Artefakt
oder manipulierte Bytes dürfen nicht bestehen. Bestehende Boolean-/Size-
Configtests bleiben kompatibel; Selection und Required-Status werden nicht
verkleinert.

## Untersuchte Alternativen

Weder beliebiger nonzero Erfolg noch die Anpassung erwarteter Ablehnung an
Akzeptanz sind zulässig. Die bestehende strikte Receipt-Architektur wird
erweitert, statt ein unabhängiges Evidence-System einzuführen.

## Implementierungsentscheidung

Die fehlende Datei ist ein kontrollierter nicht vorhandener Leaf; ungültige
Syntax verwendet festes Inline-`SecRule REQUEST_URI`; der unbekannte Key ist
die NGINX-Directive `modsecurity_unknown_config_key`, kein Ersatz aus der
Engine-Regelsprache. Das unsichere Event-Ziel ist ein eigenes Directory-Leaf,
das die private Dateigrenze von NGINX `modsecurity_phase4_log` ablehnt.
Geschlossene Fixture-Metadaten und Prüfungen des erhaltenen Fixture-Zustands
unterscheiden die beiden Pfadfälle. Configtest-only belegt weder Worker,
Request, Reload noch natives Event.

## Geänderte Dateien und Tests

`ci/checks/catalog/no_crs_baseline.py`,
`tests/cases/no-crs-baseline/catalog.json`,
`tests/schemas/no-crs-baseline/configtest-receipt.schema.json` und
`tests/no_crs/test_configtest_target_rejections.py`; dieses EN/DE-Paar.

## Befehle und Ergebnisse

Die fokussierten roten und grünen Ausführungslogs liegen unter
`nginx-seven-contracts-20261008T080604Z` (externe Analysis-Run-ID).
`framework-config-red.log` belegt den Regressionsfehler vor dem Fix;
`framework-config-green.log` belegt 52 bestandene Tests. Dies sind Unit-/
Contract-Ergebnisse, keine Runtime-Coverage. Abgleich der exakten Invocations
und abschließende native Suite-Ergebnisse gehören noch zum Integrationsreview.

## Sicherheitsauswirkung

Pfad-, Ownership-, Symlink-, Artefaktintegritäts-, Operationsidentitäts- und
Provenance-Prüfungen bleiben vorgeschrieben. Validatoren, Required-Records und
Statusvorrang werden nicht abgeschwächt. Es wird weder Security-Remediation
noch Zertifizierung einer geschützten Runtime behauptet.

## Dokumentation und Runtime-Evidenz

Dieser vollständige EN/DE-Record dokumentiert ausschließlich den
Framework-Vertrag. Discovery-Proben mit einem historischen Modul halfen bei
der Diagnoseformulierung, sind aber keine New-Head-Coverage. Frische
artefaktgebundene Host-Ausführung und Canonical-Auswertung bleiben notwendige
externe Integrationsnachweise.

## Nicht ausgeführte Prüfungen

Vollständiger Framework-Lint/API-/Canonical-Suite und integrierter
Standard-Hostlauf sind für diesen Arbeitsstand noch nicht abgeschlossen.
CI/Sonar eines später veröffentlichten Commits liegen bei Erstellung noch
nicht vor.

## Einschränkungen und Restrisiko

`PRODUCT DECISION REQUIRED — invalid_status`: Engine-Statusaktion und
Common-/Adapter-Default-Statusfeld haben unterschiedliche Owner und
Ablehnungssemantik. Es werden weder Wertebereich noch Directive erfunden;
dieser Record bleibt Required und unerfüllt. `valid_rules_file` benötigt einen
separaten erfolgreichen Lade- sowie echten Regelausführungsnachweis. Die
anderen historischen Coverage-Lücken werden hier nicht behoben.

## Finaler Diff- und Review-Status

Dies ist ein Übergaberecord im Implementierungsstadium. Finaler Source-Diff,
vollständige Suite, Runtime-Evidence, Delivery-SHA und unabhängiges Review
müssen vor Abschluss abgeglichen werden. Keine Secrets, Raw-Bodies oder
ungeprüften Logs sind eingebettet.
