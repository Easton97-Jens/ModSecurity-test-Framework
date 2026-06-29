# Importanalyse: ModSecurity Apache Connector

**Sprache:** [English](import-analysis-apache.md) | Deutsch

Status: umgesetzt

Lokaler Bezug: `/root/conecter/ModSecurity-apache`
Upstream-Quelle: https://github.com/owasp-modsecurity/ModSecurity-apache
Beobachtete Referenz: `master`, `v0.0.9-beta1-26-g0488c77`

## Rolle

Dieses Repository ist ein Apache-Connector für libmodsecurity v3. Sein Anschluss
Quell- und Autotools/APXS-Build-Eingaben sind jetzt im Besitz des Adapters unter
`connectors/apache/`, mit produktiven C-Dateien unter `connectors/apache/src/`.
Der frühere `connectors/apache/upstream/`-Import war
nach erfolgter Bau- und Smokedichtheit entfernt. Dateien bleiben bestehen
Apache-spezifisch und in `connectors/apache/ORIGIN.md` und dokumentiert
`connectors/apache/SOURCE_MAP.json`.

## Build-System

Beobachtete Dateien:

- `configure.ac`
- `Makefile.am`
- `build/apxs-wrapper.in`
- `build/find_apxs.m4`
- `build/find_libmodsec.m4`

Build verwendet Autotools und `apxs` bis build/install ein Apache-Modul.

## Testsystem

Beobachtete Tests:

- `t/TEST`
- `t/load-modsec.t`
- `t/simple-block.t`
- `t/very-simple-test.t`
- `tests/run-regression-tests.pl.in`

Diese Tests sind Apache-spezifisch, da sie von Apache::Test und httpd abhängen
Konfiguration.

## libmodsecurity v3 Verwendung

Zu den beobachteten öffentlichen C API-Anrufen gehören:

- `msc_init`, `msc_set_connector_info`, `msc_set_log_cb`, `msc_cleanup`
- `msc_create_rules_set`, `msc_rules_add`, `msc_rules_add_file`,
  `msc_rules_add_remote`
- `msc_new_transaction`, `msc_new_transaction_with_id`
- Transaktionsphasenaufrufe und `msc_intervention`

## Apache-Hooks

Beobachtete Hook-Konzepte:

- pre/post Konfigurationsinitialisierung
- Anfrage early/late Verarbeitung
- input/output Filter für Körper
- Log-Transaktions-Hook
- Konfiguration und Zusammenführung pro Verzeichnis

Dies sind `connector-specific` und gehören nur unter `connectors/apache/`.

## Wiederverwendungsklassifizierung

| Konzept | Quelle | Umfang | Kompatibilität | Entscheidung |
| --- | --- | --- | --- | --- |
| v3 C API Phasenfolge | v3 über Connector | motorspezifisch | kompatibel | Dokumentieren und anpassen |
| Apache-Hook-Registrierung | Connector | Connector-spezifisch | kompatibel nur für Apache | Verfolgt in `docs/roadmap/todo-inventory.md` |
| Apache::Test Dateien | Connector | Connector-spezifisch | teilweise | Zu `tests/cases/connector-specific/apache/` zuordnen |
| Quellcodedateien | Connector | Connector-spezifisch | kompatibel nur für Apache | Adapterbesitz gemäß `connectors/apache/src/` |

## Importentscheidung

Der Import wird bewusst von `common/` getrennt. Apache-Hook-Registrierung,
input/output Filter, Anforderungskonfiguration und APXS/Autotools Build-Logik bleiben erhalten
unter `connectors/apache/`. Zukünftige gemeinsame Extraktion erfordert einen separaten Nachweis über
reale Apache- und NGINX-Smoketests.
