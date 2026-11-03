# Änderungsprotokoll

**Sprache:** Deutsch | [English](20261103-02-protected-caller-projection.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261103-02-protected-caller-projection |
| UTC-Datum | 2026-11-03 |
| Framework-Basis | `bb6c7580208a05c17d6d6674571731b6a71028cb` |
| Lieferung | Prüfbare isolierte Taskarbeit; Koordinator besitzt Lieferung |

## Motivation und Problemstellung

Dem delegierten Parent-Caller fehlen Concurrency und fünf Jobs des unveränderlichen
geschützten Brokervertrags. Frameworks kanonischer Caller besitzt die benötigte
Inlineform bereits; die Migration änderte den Ablageort ohne kompatible
Parentprojektion.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework besitzt Callerquelle, Generator, Tests und historische inerte Fixture.
Parent besitzt generierten Workflow und typisierte Pin-/Datenprojektion. MRTS
unverändert. Diese Tests autorisieren keinen privilegierten Broker/Publisher/Admin.

## Akzeptanzkriterien

Tatsächlicher unveränderlicher Parser akzeptiert die aktuelle Generierung und
verwirft Originaldelegation, schwächeres Gate, Schreibrechte und falsche/veränderliche
geschützte Pins. Generator und Parentprojektion stimmen exakt überein. Quellbezug,
feste Allowlist, transaktionale Updates und geschützte Identitäten bleiben
erzwungen. 100 Standardfälle unverändert; neue Tests On-demand.

## Untersuchte Alternativen

Den unveränderlichen Parser umzuschreiben würde den historischen Vertrag ändern.
Neue Brokerveröffentlichung ist unnötig, wenn die bestehende kanonische Inlinequelle
akzeptiert wird. Erfundenes Referenzkommentar würde den Zieltypfehler nur verbergen.

## Implementierungsentscheidung

Exakte geprüfte Framework-Gitquelle nach Parent projizieren; nur Trigger ändern
und Provenienzkommentare ergänzen. Parents eigener Inline-Callertyp liest begrenzte
feste Kandidaten-Gitdaten und fordert geprüften Quell-SHA-256; Kandidaten-Python
wird nicht importiert. Originalgenerierung muss exakt stimmen; nur eingefrorene
exakte Delegation erlaubt Migration. Historische Ablehnung an inerte Fixture
binden, damit der reparierte Livecaller nicht weiter fälschlich scheitern muss.

## Geänderte Dateien und Tests

`modsecurity_test_framework/protected_nginx_caller.py`, feste CLI,
`tests/ci_security/test_protected_nginx_caller_projection.py`, historische Caller-
Fixture/-Test, Framework-SHA- und Synchronisiererfixtureanpassungen;
gepaarter Leitfaden und Protokoll. Externe Abhängigkeit: Parentworkflow und
typisierte Synchronisiereränderung werden getrennt in Parent geliefert.

## Befehle und Ergebnisse

Nachweise unter externer Speicherwurzel des aufrufenden Projekts:
`runs/20261103T115937Z-runtime-readiness/broker`.
RTK-Framework-3.15.2-Aufruf `python -m unittest -v
tests.ci_security.test_protected_nginx_caller_projection`: neun Tests bestanden,
einschließlich echtem unveränderlichem Parser, Parentrenderer und atomarer CLI
(`immutable-typed-projection-final.log`). Originaldelegation wird vom Originalparser
abgelehnt; exakte Generierung mit fünf Jobs besteht. Brokercode wird aus Git
gelesen und vor dem Laden per SHA-256 geprüft. Sechs bestehende ausgewählte
Fixture-/CLI-/Pinprüfungen bestehen (`typed-pin-fixtures.log`); echte Parent-
Projektionsprüfung `--check` meldet `changed=[]` (`parent-projections-check.log`).
`make check-documentation` und Whitespaceprüfungen beider Repositories bestehen.
Exakte Befehle liegen in der Taskübergabe.

## Sicherheitsauswirkung

Callerkompatibilität ohne Erweiterung privilegierter Aktionen oder Berechtigungen
wiederherstellen. Broker `8ae707d72f1a8acb25d239e55e28a73cbc7522b1` und geschütztes
Framework `99a7985c1be92a2297b1b59208f64df6768f2cbf` erhalten. Keine Geheimnisse,
Ersatzscanner, schwächeren gehosteten Gates oder automatische Administration.

## Dokumentation und Runtime-Evidenz

Gepaarter Leitfaden definiert Generierung, geprüfte Quellidentität, Updategrenzen
und spätere Protected-Master-Nachweise. Parser-PASS bleibt vom gewöhnlichen
Hosted-NGINX-Smoke und geschützter Rootruntime getrennt. Lokale Sonar-Vorprüfung
bleibt ausdrücklich durch Benutzeranweisung ausgesetzt.

## Nicht ausgeführte Prüfungen

Keine geschützte Broker-/Rootruntime, Publisher-/Adminaktion oder Vollkampagne.
Finale integrierte Framework-/Parentrevisionen und gehostete Prüfungen gehören dem
Lieferkoordinator. Keine neue Brokerveröffentlichung für Callerform erforderlich.

## Einschränkungen und Restrisiko

Künftige Callerquelländerungen erfordern semantische Prüfung vor Vertragspflege.
Finale saubere Projektion muss gelieferte Frameworkrevision binden. Tatsächlicher
Protected-Master-Dispatch und Runtime bleiben gesondert zu autorisieren.

## Finaler Diff- und Review-Status

Prüfbare Änderungen erhalten Repositorygrenzen. Gemeinsamer aktiver Katalog,
Quellbindungen sowie finale Parentpins/PR-Integration gehören dem Koordinator.
Kein Workercommit/-push/-PR; Originalcheckouts/MRTS unverändert.
