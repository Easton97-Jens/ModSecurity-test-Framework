# Connector-Vertragstests

**Sprache:** [English](README.md) | Deutsch

## Ownership

Dieses Framework-Paket enthält die früheren Python-Unit-/Vertragstests des
Connector-Repositories. Sämtliche Tests gehören ins Framework, einschließlich
Prüfungen von Produkt-Build/-Konfiguration, Hostadaptern, Workflows, Makefiles,
Quellpfaden, Provisionierung, Artefakten, Sicherheit und Evidence. Produktcode
bleibt im explizit ausgewählten Connector-Checkout.

Der eindeutige Namespace ist `modsecurity_connector_tests`; Testorchestrierung
nutzt `modsecurity_connector_ci`, Host-Testadapter `connector_suite.adapters`.
Siehe [Schnittstelle](../../docs/connector-test-suite.de.md),
[Quellmapping](../source-map.json) und [Fallmapping](../test-map.tsv).

## Auswahl

[Das Inventar](../config/testing/active-cases.json) bewahrt die ursprünglichen
100 Standardfälle / 80 Ausführungen und 1893 On-demand-Fälle / 839 Ausführungen.
Neue Migrationsregressionen bleiben gesondert zu diesen Basiszahlen auf Abruf.
Standard-Discovery und automatische Gruppen wählen nur zugelassene Standards;
mehr als 100 expandierte Standards verhindern Zulassung statt Kürzung der Auswahl.
Erhaltene Spezialmodule verlangen `ON_DEMAND_TESTS=1`; der öffentliche
Inventaradapter verlangt `--on-demand` plus genauen Gruppen-/Fall-/Ausführungsselektor.

Neues automatisch ausgewähltes Verhalten braucht stabile ID, Zweck, Profil und
quellgebundenen ausführbaren Selektor. Bei voller Kapazität ersetztes oder wirklich
konsolidiertes Verhalten und verlorene Abdeckung benennen. Definitionen,
Subtestvarianten, Ausführungen, Versuche und unterschiedliche Fälle sind andere
Zählgrößen. Ein Retry erzeugt keinen zusätzlichen unterschiedlichen Fall.
Verschieben einer Datei aktiviert keine archivierte Kampagne.

## Sichere Ausführung

Connector-Tests verlangen expliziten Produktroot/-revision, Framework-Root,
Profil und vorhandenen externen Ausgabeparent. Framework-eigene Fixturetests
verlangen keinen impliziten Parent-Checkout. Framework-eigenen Interpreter und
`PYTHONSAFEPATH=1`, Python `-P` sowie
`PYTHONPATH="$FRAMEWORK_ROOT:$FRAMEWORK_ROOT/connector_suite"` nutzen. Produktquellen
werden über begrenzte explizite Schnittstellen statt globalem Produktimportpfad
geladen. Der öffentliche Adapter ist eine Quellcheckout-Schnittstelle;
Abdeckung des installierbaren Pakets ist ein getrennter Vertrag.

Fixtures bleiben portabel, eigenständig und ohne Secrets. Runtime-Ausgabe,
Bytecode, Build-/Cachedaten, Downloads, Zugangsdaten oder Payload-Evidence nicht
einchecken. Unit-/Vertrags-PASS belegt nur das geprüfte Verhalten; weder gehostetes
H1 noch CRS-Vollständigkeit, HTTP/2, HTTP/3, Produktionsreife oder vollständige
Matrix. Der [Archivgenerator](../modsecurity_connector_ci/tools/update-test-archive.py)
erfasst Verfügbarkeit, ohne Definitionen als ausgeführte Evidence zu behandeln.
