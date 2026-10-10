# Änderungsnachweis

**Sprache:** Deutsch | [English](20261008-04-nginx-native-sequence-observations.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261008-04-nginx-native-sequence-observations |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | `11e1d20990d4ecbbcf18641782b04f0bb6369c69` |
| Issue oder Pull Request | Framework-Draft-PR #137; integrierte Ausführung bleibt beim Koordinator. |

## Motivation und Problemstellung

Selektierte Lifecycle- und Transportfälle brauchen echte Sequenzen mit passenden nativen Beobachtungen. Neuverbindung, HTTP 200 allein oder Wissen über einen angeforderten Fault beweisen sie nicht.

## Betroffene Komponenten und Sicherheitsgrenzen

Der neue Helfer `tests/runners/nginx_lifecycle_sequence.py` und dedizierte No-CRS-Tests prüfen beobachtete Operationen. Katalogauswahl, kanonische Aggregation, Produktcode und MRTS bleiben unverändert.

## Akzeptanzkriterien

Exakter Fall/Lauf, H1, Request-Anzahl/Status, native Request-/Transaktions-/Verbindungsidentitäten, steigende Keep-alive-Zähler, Root/nobody-Rollen und verifiziertes Cleanup sind erforderlich. Late Intervention braucht zusätzlich echte Header-/Marker-Synchronisation und passende native Rule 1100301. Write-Resume braucht beobachtetes natives Short-Write/EAGAIN, spätere positive Writes, vollständiges Client-Framing und einmalige native Body-Verarbeitung.

## Untersuchte Alternativen

Implizite Neuverbindung, vom Driver erzeugte Events und als Engine-Timeout umetikettierte Upstream-Verzögerung werden abgelehnt. Der Helfer macht einen nicht unterstützten Fault-Fall nicht erfolgreich.

## Implementierungsentscheidung

Geschlossene Operationstabelle und strikte unabhängige Beobachtungsprüfung verwenden. Host-Operationsgültigkeit ist nicht Canonical PASS: bestehende Transport-Event-Felder und Prüfung aufbewahrter Artefakte bleiben für den zentralen Normalizer verpflichtend.

## Geänderte Dateien und Tests

`tests/runners/nginx_lifecycle_sequence.py`, `tests/no_crs/test_nginx_lifecycle_sequence.py` und dieses EN/DE-Paar. Kontrollen prüfen Neuverbindung, doppelte Transaktionen, falschen Deny-Status, fremde Identität, fehlendes Cleanup, falschen Fault-Grund, fehlendes natives Late-Event, vollständige Antwort statt Abbruch und neu gestarteten Worker.

## Befehle und Ergebnisse

Framework-Python über RTK führte die dedizierten Tests aus: erste Regressionen für fehlende Operationen schlugen fehl; anschließend bestanden 14 Prüfungen. Echte diagnostische Operationen liegen unter externer Lauf-ID `nginx-all-required-20261008T124555Z`: 13 Sequenz-/Fault-/Late-Operationen, eine Short-Write- und eine tatsächliche EAGAIN-Resume-Probe bestanden die Host-Prüfung. Ein falsch zugeordneter Begin-Fault blieb abgelehnt. Die native Short-Write-Fixture wurde mit C17 und Warnings-as-Errors kompiliert.

## Sicherheitsauswirkung

Keine Required-, Pfad-, Ownership-, Freshness-, Identitäts-, Event- oder Artefaktprüfung wird gelockert. Test-Faults sind auf eigenen Worker/Request/Socket begrenzt; keine globale Ressourcenmanipulation oder synthetischen Events.

## Dokumentation und Runtime-Evidenz

Dieses EN/DE-Paar beschreibt ausschließlich Framework-Prüfverhalten. Parent besitzt echte Host-Operationen. Entwicklungs-Fokus verwendet verifizierte bestehende Artefakte und separat gehashte Entwicklungshilfen; das ist keine finale committed Exact-Head-Coverage.

## Nicht ausgeführte Prüfungen

Die ausgewählte Framework-Python-Umgebung enthält kein Ruff-Modul; fokussierte Ruff-Checks konnten nicht laufen, und Paket/Umgebung wurde nicht geändert. Der native `make check-documentation` bestand. Common-Phase-Completion wird zusätzlich aus `timed_phase_completed=0` im tatsächlichen Cleanup-Ledger geprüft, abgeleitet aus der Completed-Phase-Maske des Vertrags statt allein aus dem Grundtext.

Vollständige integrierte Framework-Suite, finaler Standard-Lifecycle und revisionsgebundene Remote-CI/Sonar bleiben Koordinator-Prüfungen.

## Einschränkungen und Restrisiko

Native Transportmetadaten brauchen weiterhin zentrale Producer-/Wiring-Integration. Freigegebenes Finish-Verhalten erhält die bereits sichtbare Antwort; der Engine-Timeout-Vertrag misst ein standardmäßig deaktiviertes synchrones Soft-Budget nach API-Rückkehr. Neue integrierte Host-Evidence bleibt erforderlich. Bestehende Required-Records bleiben sichtbar und unverändert.

## Finaler Diff- und Review-Status

Zwei Framing-Fälle verlangen tatsächliche rohe Downstream-HTTP/1.1-Captures bis EOF. Das neue `tests/runners/nginx_http11_framing.py` parst unabhängig begrenzte Status-/Header-/Chunkbytes, lehnt mehrdeutige CL/TE oder doppelte Framing-Header, unvollständige Bodys/Chunks/Enddelimiter und nachfolgende Bytes ab und dekodiert den exakten 22-Byte-Body `transport fixture body`. Der Sequenzhelfer lehnt reine Client-Framing-Metadaten, Origin-Substitution, falsche dekodierte Bodys und fremde native Identitäten ab. Chunked-Upstream-Provenance bleibt getrennt vom Downstream-Beleg.

Beide Fälle verlangen tatsächliches natives `phase4_completion` / `MSCONN_PHASE4_COMPLETE`, exakte Response-Body-Phase/TX/URI, EOS, tatsächlich supplied/retained22 Bytes und begrenzte Append-Anzahl sowie späteres echtes `transaction_cleanup` / `MSCONN_TRANSACTION_CLEANUP` mit exaktem `common_return=0;common_complete=1;native_cleanup_completed=1;error_class=none` und `cleanup_reason=normal`. Rule-ID und nativer API-Rückgabewert werden nicht erfunden. Root/nobody- und Prozess-/Listener-Cleanup-Checks bleiben aktiv. Acht dedizierte Parser-/Sequenztests bestanden nach fehlgeschlagenen Absent-Parser-Regressionen; der betroffene Framework-Fokus besteht mit 34 Tests. Dedizierte Tests sind `tests/no_crs/test_nginx_http11_framing.py` und `tests/no_crs/test_nginx_http11_sequence.py`. Native Modulausführung, Standardregistrierung und kanonische Artefakt-/Protokoll-Provenance-Validierung bleiben beim Koordinator.

Freigegebene Timeout-Folgearbeit: `observation_errors` unterstützt precommit504 und committed200 mit tatsächlich abgebrochenem Framing. `native_budget_errors` verlangt genau einen erfolgreichen delegierten Phase-1/Phase-4-API-Rückgabewert, exakten Worker/Transaktion, begrenzte monotone Messungen und strikt überschrittene Budgetdauer. Native Ereignisse müssen das flache `engine_timeout` / `MSCONN_EVENT_ENGINE_TIMEOUT` / kanonischen Grund `engine_timeout` mit flachem `engine_call_budget_exceeded` / `MSCONN_ENGINE_CALL_BUDGET` / exaktem payload-freiem `budget_ms=10;elapsed_ns=<actual>;native_return=1;common_completed=0` paaren. Bekannte Common-Ereigniskanonsierung bleibt erhalten. Beide Ereignisse verlangen keine Rule-ID, tatsächliche Sichtbarkeit und Phase/Stage-Identität. Phase4-EOS bleibt wahr, weil die tatsächliche terminale Engine-API zurückkehrte, während Common-Completion abgelehnt wurde. Der separate delegierte Cleanup-Ledger muss return0, complete1 und die tatsächliche erhaltene Timeout-Fehlerklasse4/Name `engine_timeout` zeigen.

RTK-umhülltes Framework-Python bestand 26 fokussierte Sequenz-/Transport-/Timeouttests, einschließlich fehlendem/doppeltem/fremdem Ereignis, falscher Rule-ID, Zeit am Budget, fehlgeschlagenem nativen Return, ungültiger Uhr, falscher Cleanup-Identität/Klasse sowie complete-wire/false-EOS-Negativkontrollen. Quellcode- und Fixture-Tests belegen keine native Laufzeit-Coverage. Neue Modulausführung, native disabled/under-budget/wrong-transaction-Kontrollen, kanonische Integration und aktuelle CI/Sonar bleiben beim Koordinator. Dedizierte Timeouttests sind `tests/no_crs/test_nginx_engine_budget_sequence.py`.

`transport_sequential_requests` verlangt nun eine native Verbindung und Zähler 1/2/3 gemäß dem vorhandenen Ein-Verbindungs-Vertrag im Katalog. Regressionen für neue Verbindung und zurückgesetzten Zähler schlugen vor der Korrektur fehl und bestehen danach beide. Die zwei dedizierten Transporttests liegen in `tests/no_crs/test_nginx_sequence_transport.py`; native Ereigniserzeugung gehört weiterhin dem Parent.

Freigegebene Post-Response-Finish-Folgearbeit:

Finish erhält den tatsächlichen HTTP-200-Status und den exakten Hash des 23-Byte-Fixture-Bodys. Erforderlich sind native Logging-Ablehnung (-1), delegiertes Cleanup (0), abgeschlossenes Cleanup und Erhalt des nativen Logging-Fehlers, gebunden an beobachteten Worker und Transaktion. Fehlende oder widersprüchliche Beobachtungen bleiben abgelehnt. Siebzehn Fokustests bestehen. Diagnose `stream-d-finish-r3` enthält positiven Exit 0 und falsche-Transaktion-Kontrolle Exit 1 mit verifiziertem Cleanup. Frühere Internal-Redirect-Fixtures bleiben erhaltene Fehlversuche; weder Evidence noch Validator wurden gelockert. Integrierte Canonical-Evidence bleibt Koordinator-Verantwortung.

Exklusive Dateien wurden auf Payload-Sicherheit und Negativkontrollen geprüft. Separater Framework-Commit/Handoff steht aus; hier erfolgen weder Merge, Force-Push noch Parent-Gitlink-Änderung.
