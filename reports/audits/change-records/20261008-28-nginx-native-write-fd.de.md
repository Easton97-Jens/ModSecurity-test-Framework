# Change Record

**Sprache:** [English](20261008-28-nginx-native-write-fd.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261008-28-nginx-native-write-fd |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | `41035763109e6f3acf5073d7bff07def3c351fd2` |
| Issue oder Pull Request | Begrenztes koordinatorgenehmigtes Follow-up des Source-Whitelist-Audits |

## Motivation und Problemstellung

Der tatsächliche Parent-Observation-Writer nginx_write_fault.c schreibt sieben Schlüssel einschließlich Integer-fd. Der Sechs-Schlüssel-Vertrag des neuen Faktenmappers lehnte dadurch echte Short-Write-/Would-Block-Zeilen ab. Source-Review fand den Widerspruch; keine Runtime wurde abgeleitet.

## Betroffene Komponenten und Sicherheitsgrenzen

Nur eigener Write-Result-Zweig des nativen Faktenvertrags, fokussierte Tests und dieses Paar. Parent-Producer, strikter Reader, zentrale Normalisierung, Schemas, Katalog, MRTS und Gitlinks bleiben unverändert.

## Akzeptanzkriterien

Exakt die sieben tatsächlichen payloadfreien Source-Schlüssel akzeptieren: pid, fd, peer_port, requested_bytes, returned_bytes, errno, fault_triggered. fd muss exakter Integer im nichtnegativen signed32-C-int-Bereich sein. Worker-/Peer-/Fault-/Resume-Prüfungen erhalten; Bool, Float, String, Null, negative Werte, Overflow, fehlende oder zusätzliche Felder ablehnen.

## Untersuchte Alternativen

fd aus aufbewahrten Observations zu entfernen, würde native Evidenz umschreiben. Beliebige Zusatzfelder würden den geschlossenen payloadfreien Vertrag lockern. Beides wird nicht verwendet.

## Implementierungsentscheidung

Nur fd zur exakten Schlüsselmenge hinzufügen und Typ/Bereich prüfen. Dasselbe tatsächliche Resume-Ergebnis und Original-Observation-SHA-Origin bleiben erhalten; kein Event oder nativer Record wird umgeschrieben. Bereichsprüfung beschreibt den Descriptor-Skalar des Source-Writers, nicht den Nachweis eines weiterhin geöffneten Live-Descriptors.

## Geänderte Dateien und Tests

Bestehende tests/runners/nginx_native_operation_contract.py und tests/no_crs/test_nginx_native_operation_contract.py sowie dieses Paar. Zwei neue kontrollierte Tests decken beide tatsächlichen Source-förmigen Sieben-Feld-Write-Varianten und falsche/fehlende/zusätzliche fd-Kontrollen ab. Die Fixtures sind kein nativer Runtime-Proof.

## Befehle und Ergebnisse

Test-first `rtk proxy env PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 python -m unittest tests.no_crs.test_nginx_native_operation_contract.NativeContractTests.test_source_shaped_seven_field_write_rows_keep_fd_and_prove_resume tests.no_crs.test_nginx_native_operation_contract.NativeContractTests.test_write_fd_exact_type_range_and_closed_source_fields -v` endete mit Exit1: Beide echten Sieben-Schlüssel-Varianten wurden abgelehnt.

Nach Korrektur bestand `rtk proxy env TMPDIR=<external-task-runs> PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 python -m unittest tests.no_crs.test_nginx_native_operation_contract tests.no_crs.test_nginx_native_operation_projection tests.no_crs.test_nginx_native_operation_bundle -v` mit48 Tests und Exit0 im Framework-eigenen Interpreter. `make check-documentation PYTHON=<framework-python>` bestand mit Exit0 über RTK; Staged-Whitespace-Prüfungen bestanden. Kein nativer Producer/Build wurde ausgeführt.

## Sicherheitsauswirkung

Keine Produkt-Security-Remediation. Exakte Sieben-Schlüssel-Closure verhindert Metadaten-/Payload-Erweiterung; exakter fd-Typ schließt Bool-als-Int und Overflow aus. Echte Worker-, Peer-, Fault- und nachfolgende positive Resume-Write-Prüfungen bleiben erforderlich.

## Dokumentation und Runtime-Evidenz

Gepaartes EN/DE-Record. Nur reine Source-förmige Unit-Fixtures; kein Canonical-PASS-, aktueller Runtime- oder All-required-Abschlussclaim.

## Nicht ausgeführte Prüfungen

Nativer Build/Runtime/vollständige E2E und Remote-Scans liegen außerhalb dieses begrenzten Follow-ups. Keine Tools installiert.

## Einschränkungen und Restrisiko

Root muss den separaten Korrekturcommit integrieren und strikte Bundle-Autorität/Offline-Revalidierung erhalten. Der vorherige vollständige Contract-Suite-Lauf beweist diese neu hinzugefügten fd-Kontrollen nicht; frische fokussierte Ergebnisse werden separat berichtet.

## Finaler Diff- und Review-Status

Vier begrenzte Dateien; Originalartefaktbytes unverändert, keine zentralen Edits. Normaler Commit nach Prüfungen an Koordinator.
