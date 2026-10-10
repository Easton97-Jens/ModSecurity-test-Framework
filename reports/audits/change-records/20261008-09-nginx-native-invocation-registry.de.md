# Änderungsnachweis

**Sprache:** Deutsch | [English](20261008-09-nginx-native-invocation-registry.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change ID | 20261008-09-nginx-native-invocation-registry |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | `5d19a0ef91f50c57c05cc1c40873f8d9ca4ab873` |

## Motivation und Problemstellung

42 nicht-konfigurationsbezogene Required-NGX-Fälle benötigen explizite native Dispatch-Identitäten. Generische Request-Fixtures oder Quellaliasnamen belegen keine native Ausführung.

## Betroffene Komponenten und Sicherheitsgrenzen

Nur Framework-Katalog, Fallkatalog-Schema und neue Katalogkontrollen. Root besitzt separat Auswahl, kanonische Normalisierung und Prüfung aufbewahrter Evidenz. Native Parent-Produzenten und MRTS bleiben in diesem Slice unverändert.

## Akzeptanzkriterien

Genau 42 bestehende Fall-IDs registrieren, generische Erwartungen und Capabilities erhalten, jeden NGX-Vertrag an seine eigene ID binden, nur die zwei expliziten Phase-4-Quellaliasnamen zulassen und fehlende, fremde oder erweiterte Deskriptoren ablehnen.

## Untersuchte Alternativen

Generische Erwartungsänderungen beträfen andere Connectoren. Freie Operationsnamen oder Quellaliasnamen ermöglichten Fallsubstitution. Geschlossene connectorlokale Deskriptoren vermeiden beides.

## Implementierungsentscheidung

`native_invocations.nginx` enthält Operation und contract_case_id; source_record_id erscheint nur bei EOS-zu-Split und begrenzte-Metadaten-zu-Over-Limit. Die fünf geschlossenen Gruppen umfassen Parser 4, Common-Mapper 2, Phase-4/MIME 12, Request-Sequenz 22 und Ereignisgrenze 2 Fälle. Ereignis-Untervarianten bleiben beim geschlossenen Helper.

Neun exakte NGX-lokale expected_overrides erhalten generische Verträge: Mapper-Fehler verwenden sichtbar400; die veraltete Minimal-ID verwendet explizit bestehendes SAFE/sichtbar200; unmittelbares Engine-Reject hat sichtbar200, nativ403, keine Regel und body_limit; post-response Finish-Fehler behalten sichtbar200; Timeout vor/nach Commit verwendet sichtbar504/200, nativ504, keine Regel und engine_timeout; außerhalb des MIME-Bereichs/fehlender MIME-Typ hat explizit sichtbar200/keine Regel. Nativer Status und Engine-Fehlerklasse sind vom sichtbaren HTTP getrennt.

Das Schema schließt Connector-, Deskriptor- und Override-Felder und bindet jeden vollständigen Deskriptor an seinen bestehenden Fall. Registrierungen sind für die 42 geschlossenen IDs verpflichtend. Hier entstehen weder synthetische Ereignisse noch Ableitungen inspizierter Bytes.

## Geänderte Dateien und Tests

Katalog und Fallkatalog-Schema; neue test_nginx_native_invocation_catalog.py; dieser Begleitnachweis. Alle generischen Fallfelder, Required-IDs, Capabilities und Protokollfälle bleiben unverändert.

## Befehle und Ergebnisse

RTK-gekapselte Kontrollen mit Framework-eigenem Python zeigten zunächst 11 Registrierungs-/Schemafehler. Abschließend bestanden sieben fokussierte Tests und zwei bestehende Prerequisite-Kontrollen. Die Helper-Registry-Kontrolle bestand zusätzlich read-only gegen die sechs tatsächlichen Helper-Module des Koordinators. Das JSONschema-Paket fehlt; Tests verwenden ohne Installation den vorhandenen JSON-Schema-Prüfer des Repositorys.

## Sicherheitsauswirkung

Unbekannte Operationen, falsche Vertrags-IDs, fremde Aliasnamen, veränderte Overrides, fehlende Registrierungen und Zusatzfelder scheitern geschlossen. Registrierungen sind niemals native Evidenz oder PASS.

## Dokumentation und Runtime-Evidenz

Dieser zweisprachige Nachweis dokumentiert ausschließlich Dispatch-Eingaben. Aufbewahrte native Ereignisse, Wire-Bytes, Prozessidentitäten, Quellauthentifizierung und Cleanup bleiben verpflichtende zentrale Evidenzgrenzen.

## Nicht ausgeführte Prüfungen

Integrierte 97-Fälle-H1-Auswahl, zentrale Normalisierung, native Runtime/Build und abschließende CI bleiben beim Koordinator.

## Einschränkungen und Restrisiko

Der eigenständige Worktree enthält nur den C-Helper; integrierte Helper-Kompatibilität wurde separat gegen den Koordinator-Worktree geprüft. Das native Engine-Budget bleibt ein Post-Return-Vertrag ausgewählter Prozessaufrufe und kein harter Abbruch.

## Finaler Diff- und Review-Status

Nur fokussierter Framework-Slice; keine Root-Worktree-Änderung, Veröffentlichung, Parent-Gitlink-Aktualisierung oder MRTS-Mutation.
