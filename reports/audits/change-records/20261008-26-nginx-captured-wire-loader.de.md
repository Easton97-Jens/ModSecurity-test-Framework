# Change Record

**Sprache:** [English](20261008-26-nginx-captured-wire-loader.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261008-26-nginx-captured-wire-loader |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | f22f03cc30253d6e5839a0a2272b22f209fc4b13 |
| Issue oder Pull Request | Parent-koordinierter begrenzter Native-Reader-Fix; kein eigenständiges Issue |

## Motivation und Problemstellung

Der strikte Reader erfasste und authentifizierte den Framing-Parser; der
Sequence-Helper öffnete jedoch seine aktuelle Nachbardatei über `__file__` erneut.
Abweichende oder fehlende Live-Bytes konnten so den ausgeführten Prüfhelper nach
der Source-Erfassung verändern.

## Betroffene Komponenten und Sicherheitsgrenzen

Nur Framework-Helper-Laden im Native-Bundle-Reader und Sequence-Parser-Initialisierung.
Die Ausführungsgrenze erfasster Source-Bytes ist sicherheitsrelevant. Source-Whitelist,
erneutes Öffnen der Source, Artefaktautorität, zentrale Normalisierung und Schemas
bleiben unverändert.

## Akzeptanzkriterien

Erfasstes Parsing ignoriert fremde oder fehlende Live-Nachbardateien; fehlende
erfasste Parser-Bytes werden abgewiesen. Erfolgreiche und fehlgeschlagene
Helper-Ausführung stellt begrenzte Module wieder her. Normales Driver-Laden
behält striktes Parsing gültiger und ungültiger Antworten bei.

## Untersuchte Alternativen

Erneutes Öffnen und Hashen der Nachbardatei ließe weiterhin eine Ausführungs-Race
zu. Globale Importpfadänderungen würden die Autorität ausweiten. Der Reader führt
stattdessen die bestehende erfasste Abhängigkeit aus und injiziert privat genau
dieses Modul.

## Implementierungsentscheidung

`load_helpers` kompiliert die erfasste Framing-Abhängigkeit unter bestehendem Lock
und Wiederherstellungsblock und übergibt `_AUTHENTICATED_WIRE` vor der Ausführung
an den Sequence-Helper. Dessen Initialisierung nutzt es, wenn vorhanden; normale
Driver behalten ihren Nachbardatei-Loader. Eine fehlende erfasste Abhängigkeit
führt zu einem expliziten Fehler.

## Geänderte Dateien und Tests

- `tests/runners/nginx_native_operation_bundle.py`: nur `load_helpers` geändert.
- `tests/runners/nginx_lifecycle_sequence.py`: begrenzte Initialisierungsschnittstelle.
- `tests/no_crs/test_nginx_captured_wire_loader.py`: fünf kontrollierte Loader-Tests.
- Dieses englisch/deutsche Record-Paar.

## Befehle und Ergebnisse

Die Befehle nutzen den vom Koordinator ausgewählten vorhandenen Framework-Interpreter;
Befehle verwenden RTK, `PYTHONNOUSERSITE=1` und externe Temp-/Cache-Verzeichnisse.
Logs liegen in der externen All-required-Task-Analyse. Lokale Interpreter-/Storage-Pfade
bleiben in Task-Evidence, nicht in versionierter leserbezogener Dokumentation.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk proxy env … python -m unittest -v tests.no_crs.test_nginx_captured_wire_loader` vor Fix | 1 | Fünf Kontrollen: ein Fehlschlag, drei Fehler; normaler Fallback erfolgreich | stream-c-captured-wire-red.log |
| Erster kombinierter unittest-Aufruf | 1 | 31 erfolgreiche Prüfungen; falscher Sequence-Testpfad unter `tests.runners` verursachte einen Importfehler | stream-c-captured-wire-green.log |
| `rtk proxy env … python -m unittest -v tests.no_crs.test_nginx_captured_wire_loader tests.no_crs.test_nginx_native_operation_bundle tests.no_crs.test_nginx_lifecycle_sequence tests.no_crs.test_nginx_http11_framing` | 0 | 52 Tests erfolgreich | stream-c-captured-wire-regressions.log |
| `rtk proxy env … python -m py_compile` für die drei geänderten Python-Dateien | 0 | Syntax erfolgreich | Externer Bytecode-Cache |
| Aktuelles `check-change-records.py` / fokussiertes `record_errors` für dieses Paar | 1 / 0 | Globaler Checker nur durch unveränderte historische Sequence-Record-Überschriften blockiert; dieses Paar erfolgreich | stream-c-captured-wire-docs.log |
| Aktuelles `check-doc-links.py` und `check-variable-documentation.py` | 0 / 0 | Links und zweisprachige Dokumentation erfolgreich | stream-c-captured-wire-links.log; stream-c-captured-wire-bilingual.log |
| `rtk git diff --check` | 0 | Keine Whitespace-Fehler | Fokussierter Worktree |

## Sicherheitsauswirkung

Kontrollierte Tests blockieren den ursprünglichen Live-Datei-Ausführungspfad und
den alternativen Fallback bei fehlender erfasster Abhängigkeit. Bestehende
Autoritätsprüfungen und Namespace-Wiederherstellung bleiben erhalten; keine
pauschalen Imports oder Validierungsausnahmen werden hinzugefügt.

## Dokumentation und Runtime-Evidenz

Dieses englisch/deutsche Record-Paar dokumentiert die Änderung. Nur reine
Source-Loader-Tests wurden ausgeführt; keine native Connector-Runtime- oder
Lifecycle-Abdeckung wird behauptet.

## Nicht ausgeführte Prüfungen

Native Build/Runtime, E2E und vollständiges Repository-Lint liegen außerhalb
dieser begrenzten Änderung. Root muss seine unabhängig erweiterte
Abhängigkeits-Whitelist bei der Integration prüfen.
Der vollständige Change-Record-Checker wurde ausgeführt, bleibt aber durch die
historischen Überschriften des unveränderten Paares
`20261008-04-nginx-native-sequence-observations` blockiert; diese Dateien außerhalb
des Scopes wurden nicht geändert.

## Einschränkungen und Restrisiko

Die bestehende Reader-Autorität liefert weiterhin authentifizierte Source-Bytes.
Die Änderung authentifiziert weder normales Driver-Laden noch Build-Vertrauen.
Parent-Gitlink bleibt unverändert; MRTS bleibt read-only.

## Finaler Diff- und Review-Status

Fokussierter Diff auf Scope, Whitespace, Secrets und Cleanup-Verhalten geprüft.
Nur die beiden begrenzten Source-Schnittstellen, neue Tests und das Record-Paar
werden geliefert. Normaler Framework-Commit geht an den Parent-Koordinator;
kein Push oder Gitlink-Update.
