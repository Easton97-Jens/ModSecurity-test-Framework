# Change Record: explizit nicht materialisierbare Security-Data-Flow-Deskriptoren

**Sprache:** [English](20260726-03-fix-security-data-flow-case-schema.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260726-03-fix-security-data-flow-case-schema |
| UTC-Datum | 2026-07-26 |
| Framework-Basisrevision | `a7ebf5a1d9cad2b0a65a7603476a1434fdb16cf6` |
| Issue oder Pull Request | Framework-Draft-PR [#51](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/51); zunächst bei `70b5a74c32fcb924e97b6f02a2079cad8ccbc848` veröffentlicht; entblockt Parent-PR-#74-Exact-Head-Validierung nach unabhängiger Integration |

## Motivation und Problemstellung

Die gehostete Runtime-Matrix von Parent-PR #74 baute die Apache- und
NGINX-Adapter, scheiterte danach aber bei der Framework-Falldiscovery: 15
connector-neutrale Security-Data-Flow-Deskriptoren wurden als ausführbare
YAML-Tests behandelt. Sie besitzen keine connector-eigenen ModSecurity-Regeln,
und ihre deklarierte Capability `security_data_flow` war dem Runner-Schema
nicht bekannt.

## Betroffene Komponenten und Sicherheitsgrenzen

- `tests/cases/security-data-flow/**`: nur connector-neutrale Deskriptoren.
- `tests/runners/runner_core.py` und `tests/runners/case_cli.py`: Auswahl- und
  Materialisierungsgrenze.
- `ci/reporting/generate-case-matrix.py`: Grenze des generierten
  Runtime-Inventars.

Die Sicherheitsgrenze verhindert, dass ein nicht unterstützter Deskriptor in
eine Connector-Runtime gezwungen, als ausführbar berichtet oder zu PASS
hochgestuft wird. Dieser Record behauptet kein Connector-Verhalten für
Body-Limits, Log-Sicherheit oder Transaction-IDs.

## Akzeptanzkriterien

1. Jeder betroffene Deskriptor ist explizit nicht materialisierbar und unter
   dem Framework-Metadatenvertrag gültig.
2. Force-All-Discovery schließt nur diese Deskriptoren aus; direkte
   Materialisierung weist sie ab.
3. Der Vertrag verlangt `connector-gap`, `former_xfail: true` und
   `capabilities.runtime_verified: false`; ein aktiver Fall kann ihn nicht
   verwenden.
4. Berichte zeigen die Deskriptoren als nicht ausführbar und nicht
   hochstufbar.

## Untersuchte Alternativen

- Platzhalterregeln würden YAML parsen lassen, aber Runtime-Verhalten erfinden
  und können eine Security-Lücke zu einem irreführenden Ergebnis machen.
- Eine Umklassifizierung zu `mapped-only` würde das sichtbare
  Connector-Gap-Inventar verlieren.
- Die gewählte explizite Metadatenlösung erhält das Inventar und blockiert die
  Ausführung, bis eine connector-eigene Implementierung Regeln und Live-Evidence
  liefert.

## Implementierungsentscheidung

`runtime_materializable: false` ist eine eng begrenzte, validierte Ausnahme von
der normalen Forderung nach nichtleeren `rules`. Sie wird nur für
Former-XFAIL-Connector-Gap-Deskriptoren mit `runtime_verified: false` akzeptiert;
für alle materialisierbaren Fälle bleibt die Regelanforderung bestehen.
Force-All-Auswahl und direkte Materialisierung erzwingen diese Grenze, und der
Report-Generator hält den Zustand als `NOT_EXECUTABLE` bzw. nicht hochstufbar
fest.

## Geänderte Dateien und Tests

- Runner-Schema/Auswahl und Schutz der direkten Materialisierung.
- Berechnung des ausführbaren Zustands im Report.
- Die 15 Framework-eigenen `security-data-flow`-Deskriptoren.
- Englische/deutsche Fallkatalog-Dokumentation.
- Fokussierte Runner-/CLI- sowie Report-Generator-Regressionen.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Parent Exact-PR-#74-`report-governance`-Lauf `30205593649` | 1 | Ursprüngliches `case requires rules` nach erfolgreicher nativer Adaptervorbereitung reproduziert | GitHub-Actions-Lauf 30205593649 |
| `FORCE_ALL_CASES=1 ... case_cli.py list-cases` vor der Reparatur | 1 | Schema-Ablehnung wegen fehlender Regeln reproduziert | Parent-PR-#74-Remediation-Evidence |
| `python3 -m unittest tests.security_regression.test_security_data_flow_case_schema tests.security_regression.test_generate_case_matrix_sonar -v` | 0 | 22 Runner-, CLI- und Report-Generator-Kontrollen bestanden | Lokaler Framework-Worktree |
| `FORCE_ALL_CASES=1 ... case_cli.py list-cases` nach der Reparatur | 0 | Falldiscovery abgeschlossen und die 15 Deskriptoren ausgeschlossen | Lokaler Framework-Worktree |
| `python3 -m py_compile` für die geänderten Python-Module | 0 | Syntax-Kompilierung bestand; Bytecode wurde in den registrierten externen Evidenzbereich geleitet | Lokaler Framework-Worktree |
| `make check-security-data-flow-cases` | 0 | Alle 15 Deskriptorfälle validiert | Lokaler Framework-Worktree |
| `make check-doc-links check-bilingual-docs check-change-records` | 0 | Dokumentationslinks, zweisprachige Dokumentation und Change-Record-Contract bestanden | Lokaler Framework-Worktree |
| `make generate-test-matrix ... MODSECURITY_MRTS_VARIANT=no-mrts` | 0 | Generator-Smoketest beendet, seine nicht-kanonische Ausgabe wurde wegen des unvollständigen No-MRTS-Inputinventars absichtlich verworfen | Lokaler Framework-Worktree |

## Sicherheitsauswirkung

Der ursprüngliche Discovery-Pfad wurde mit dem Force-All-Control erneut
geprüft und behandelt die Deskriptoren nicht mehr als Runtime-Fälle. Die
direkte Materialisierungsumgehung wird explizit abgewiesen. Ein Versuch, einen
aktiven Fall umzuklassifizieren, wird vom fokussierten Test abgewiesen. Kein
Security-Ergebnis wird hochgestuft und kein Test oder Gate geschwächt.

## Dokumentation und Runtime-Evidenz

`docs/catalog-and-cases.md` und die deutsche Begleitdatei dokumentieren das
neue Feld. Die Report-Generator-Kontrolle beweist die Klassifikation als
`NOT_EXECUTABLE` / nicht hochstufbar auch bei Force-All-Input. Der isolierte
No-MRTS-Generator-Smoketest lieferte keine kanonischen Report-Inputs (das
Import-Status-Inventar fehlt), daher wurden seine generierten Ausgaben bewusst
wiederhergestellt und nicht Teil dieser Änderung. Die beobachtete gehostete
Evidence beweist die native Adaptervorbereitung, aber keinen vollständigen
Connector-Runtime-Erfolg; nach unabhängig geprüfter Framework-Integration
bleibt ein frischer Parent-Exact-Head-Lauf erforderlich.

## Nicht ausgeführte Prüfungen

- Vollständige Framework-Connector-Matrix: lokal nicht ausgeführt, da sie
  externe Native-Komponenten erfordert und nach Framework-Integration durch
  den Parent-Exact-Head-Producer unabhängig ausgeführt wird.
- Ruff/Pyright: nicht ausgeführt, weil keines der Executables lokal verfügbar
  ist; es wurde kein Tool installiert.
- Gehostete Framework-CI, SonarQube Cloud, Reviews und Threads: bis zum
  separaten Draft-Framework-PR ausstehend.

## Einschränkungen und Restrisiko

Die 15 Fälle bleiben Connector-Gap-Inventar; diese Reparatur implementiert ihr
vorgesehenes Security-Verhalten nicht. Parent-PR #74 bleibt blockiert, bis der
Framework-PR gemergt und seine exakte Revision bewusst übernommen wurde.

## Finaler Diff- und Review-Status

Die versionierte Implementierung wurde normal als
`70b5a74c32fcb924e97b6f02a2079cad8ccbc848` committed und wird von
Framework-Draft-PR #51 präsentiert. Dieser Record wird durch einen normalen
Follow-up-Commit ohne History-Rewrite an den PR gebunden. Fokustests,
Syntax-Kompilierung, Deskriptorvalidierung, Dokumentationsprüfungen,
Whitespace-Review und Staging-Review bestanden; der exakte finale PR-Head
benötigt vor Framework-Integration noch eigene Hosted-CI-, SonarQube-Cloud- und
Review-Evidence.
