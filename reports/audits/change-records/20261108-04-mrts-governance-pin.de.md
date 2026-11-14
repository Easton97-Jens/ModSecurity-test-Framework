# Geprüfte MRTS-Governance-Metadaten pinnen

**Sprache:** Deutsch | [English](20261108-04-mrts-governance-pin.md)

## Identität

| Field | Value |
| --- | --- |
| Change-ID | 20261108-04-mrts-governance-pin |
| UTC | 2026-11-08 |

Framework-Quellbasis: `9cf786ab99057880028b8db7b56709e5d1e2e3e2`. Dieser Datensatz bereitet die Framework-eigene Gitlink-Übergabe für Draft-PR #169 vor.

## Motivation und Problemstellung

Die geprüften Parent-Befehls-/Architekturpolicys erforderten passende MRTS-Vererbungsmetadaten. Der externe [MRTS-Draft-PR #7](https://github.com/Easton97-Jens/MRTS/pull/7) veröffentlicht genau eine Governance-Manifeständerung mit zwei geprüften Hashes ohne Produkt- oder Teständerungen. Das Framework muss diesen separat ausgelieferten Commit pinnen, bevor Parent eine konsistente verschachtelte Kette veröffentlichen kann.

## Betroffene Komponenten und Sicherheitsgrenzen

`tools/MRTS` und dieses EN/DE-Paar gehören dem Framework. Vorgesehen ist MRTS-Revision `9a855b092645733ea8ff73a512aff7bfe916407e` statt `ee2174431c4edf97e66afe32558ce8454deb2397`. Submodul-URL und MRTS-Produkt-/Testquellen bleiben gleich. Parent besitzt seinen separaten Framework-Gitlink, Versionslock und Workflow-Projektionen.

## Akzeptanzkriterien

Exakten geprüften MRTS-Commit, vollständige separate Secrets-Abdeckung und nativen Framework-Quick-Check am gestagten Kandidaten verlangen. Standardauswahl mit 100 Fällen und sämtliche negativen Evidenzkontrollen erhalten. Die spätere Parent-Veröffentlichung muss beide Revisionsidentitäten und native Projektionen synchronisieren; dieser Datensatz zertifiziert diese künftige eingecheckte Kette nicht.

## Untersuchte Alternativen

Blinde Hashersetzung, fachfremde MRTS-Änderungen, Merge, Hook-Umgehung, zusätzliche Integration, gelockerte native Prüfungen oder umetikettierte historische Ergebnisse würden den Auftrag verletzen. Eine aktuelle Betreiberänderung ist nur für den vorhandenen Parent-Gitlink-Dispatcher erforderlich.

## Implementierungsentscheidung

Die bereits veröffentlichte reine Governance-Revision wird über den regulären Framework-Gitlink ausgewählt. Ursprüngliche Arbeitsbäume und historische Nachweise bleiben erhalten. Aktuelle Metadaten bestätigen im Framework-Git-Common-Verzeichnis fehlende pre-commit/pre-push-Dispatcher und keinen konfigurierten Hooks-Path-Override; kein Hook wird installiert, entfernt oder umgeleitet. Separate manuelle Secrets-Ergebnisse bleiben deshalb ausdrücklich ausgewiesen; ein regulärer Framework-Commit ist kein automatischer Hookbeleg.

## Geänderte Dateien und Tests

Nur der Framework-Gitlink und dieses Dokumentenpaar gehören zur Übergabe. Der MRTS-Manifest-Postimage-SHA256 lautet `fe3a2b31ecc2ffd2869bc67524ea95bd3d920f49fd9f97676f72da422698c676`. Diese Metadatenänderung führt keine Framework-Testmethode, keinen Selektor und keine Produktfähigkeit ein.

## Befehle und Ergebnisse

Der separate MRTS-Nachweis erfasst alle 472 Git-Blobs: 431 reguläre Dateien und 41 Link-Blobs, einschließlich exakter Rahmung, Längen, SHA256 und Gitobjektidentitäten. Alle 41 Links und Zielidentitäten bleiben gegenüber dem vorherigen MRTS-Commit gleich und sind innerhalb seines Git-Baums auflösbar.

Externe MRTS-Validierung am ausgewählten Commit umfasst den tatsächlichen Policy-Root-Validator und 41 lokale Standardbibliothekstests mit Python 3.14.4. Die vorhandene gehostete Python-3.14.6-Governance-Prüfung bestand separat; sie validiert ihre eigene Fixture, während die tatsächliche Policy-Root-Prüfung ein separater lokaler Befund ist.

Framework-Quellprüfungen mit Python 3.15.2 bestanden 48 Workflow-Methoden und 222 Subtest-Ausführungen sowie den FIFO-Vertragsblock mit 29 Methoden und expliziten Positiv-/Fehlerkontrollen. Zwei frühere vollständige native Fehlerläufe bleiben dokumentiert: die korrigierte FIFO-Startbeobachtung und ein Runner-Umask-Konflikt in CRS-Fixtures. Beide zuvor fehlgeschlagenen CRS-Methoden und vorhandene Modus-Negativkontrollen bestehen mit ausschließlich kindseitiger Umask 0022; private Runner-/Evidenzverzeichnisse behalten 0077/0700-Isolation. Ein frischer vollständiger nativer Lauf nach diesem Datensatz bleibt erforderlich.

## Sicherheitsauswirkung

Die ausgewählte MRTS-Differenz ändert nur geprüfte Governance-Hashes. Für die separate Parent-Übergabe bleiben rootgeschützte Betreiberbelege, vollständige gestagte Indexbindung und native Pin-Prüfungen erforderlich. Reguläre Secrets-Prüfungen, exakte Modi und Symlink-Ablehnung werden nicht abgeschwächt.

## Dokumentation und Runtime-Evidenz

Quellgebundene Belege liegen unter `$EVIDENCE_ROOT/inheritance/`, `$EVIDENCE_ROOT/hook/parent-only-current/`, `$EVIDENCE_ROOT/quick-check/umask-context-controls/` sowie der separaten MRTS-Evidenzwurzel. Der Koordinator erfasst dort tatsächliche Befehle, Endergebnisse und unveränderliche Commitidentitäten. Keine neue Runtime-Abnahmekampagne wird gestartet.

## Nicht ausgeführte Prüfungen

Endgültige veröffentlichte Kettenregression, Parent-Gitlink-Zulassung und umfassende Abnahmekampagne bleiben hier **NOT_RUN**. Ein neuer vollständiger Framework-Quick-Check und gehosteter Readback am exakten Head sind koordinierte Auslieferungsschritte.

## Einschränkungen und Restrisiko

Externe MRTS-CI und separate Secrets-Abdeckung belegen weder den endgültigen eingecheckten Parent-Pin noch Runtime-Abnahme. Historische Forderungen einer neuen Framework-zu-MRTS-Hookinstallation beschreiben die aktuelle Topologie nicht. Der vorhandene Parent-Dispatcher bleibt betreiberverwaltet; diese Übergabe umgeht ihn nicht.

## Finaler Diff- und Review-Status

Der Koordinator prüft gestagte MRTS-Identität, Dokumentenpaar und native Prüfungen vor regulärer Auslieferung. Alle PRs bleiben Draft. Dieser Datensatz erklärt weder Merge-Fähigkeit noch Gesamtbereitschaft.
