# NGINX-Konfigurationsmigrationsverträge

**Sprache:** Deutsch | [English](20261008-13-nginx-config-migration-contracts.md)

## Identität

Change ID: `20261008-13-nginx-config-migration-contracts`. UTC-Datum: 2026-10-08.
Framework-Basis: `11e1d20990d4ecbbcf18641782b04f0bb6369c69`.
Folgekontext: Framework-PR #137; dieser Worktree ist nicht veröffentlicht.

## Motivation und Implementierung

Drei Required-Konfigurationscases besaßen bisher keine expliziten Hostoperationen.
Der Benutzer wählte für `invalid_status` den bestehenden lexikalischen
Engine-Parservertrag: ungültiges `status:not-a-number`, keine neu erfundene
numerische Range oder Common-Default-Status-Direktive. Zwei Scope-Dateicases
prüfen ausdrücklich die Ablehnung der entfernten Adapter-API
`modsecurity_phase4_content_types_file`. Sie behaupten keine Verarbeitung oder
Ablehnung ihrer MIME-Dateiinhalte durch die Engine.

`ci/lib/nginx_migration_config_contracts.py` deklariert genau diese drei
geschlossenen Operationen und liefert unabhängige Kopien. Der Koordinator muss
sie in Katalog, strikte Receipt-Validierung und echten Parent-Dispatcher
integrieren; Deklarationen allein sind keine kanonische Runtime-Evidence.

## Tests und Runtime-Evidence

Die RTK-umhüllte Framework-Python-Unittest-Discovery für
`test_nginx_migration_config_contracts.py` endete zunächst mit Exit 1, weil der
Helper fehlte; danach endeten vier Tests mit Exit 0. Sie schützen die
lexikalische Statusidentität, den exakten Removed-Directive-Grund, die
geschlossene Casemenge und voneinander unabhängige Mutationen.

Separate echte diagnostische NGINX-1.31.6-Configtests beobachteten Exit 1 mit
`Expecting an action, got:  status:not-a-number` sowie zweimal Exit 1 mit dem
Removed-Directive-Grund. Rohkonfigurationen, Fixture-Bytes, Captures und
Artefaktdigests liegen im externen Task-Run
`nginx-all-required-20261008T124555Z`. Diese Diagnoseoperationen verwenden die
unveränderten committeten nativen Artefakte und sind kein neuer integrierter
Exact-Head- oder kanonischer PASS-Nachweis.

## Sicherheit, Kompatibilität und Grenzen

Keine Änderung an Validatoren, Selection, Required-Records, Produkt-API,
numerischer Statuspolitik, MRTS-Source oder geschützter Infrastruktur.
Beliebige Nonzero-Exits erfüllen diese Verträge nicht. Parent-Dispatch, Receipts
und Schema-Integration bleiben beim Koordinator. Vollständiger Framework-Lint,
integrierte Runtime und Remote-CI/Sonar müssen nach Integration laufen.
Die englischen und deutschen Records beschreiben denselben Umfang.

## Prüfung und Lieferung

Nur neuer Helper, fokussierte Tests und dieses Dokumentationspaar gehören zu
dieser Konfigurationsvertragsscheibe. Dieser Workstream führt keinen Push,
Gitlink-Update oder Merge aus. Die finale integrierte Abnahme bleibt offen.
