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

Vollständige integrierte Framework-Suite, finaler Standard-Lifecycle und revisionsgebundene Remote-CI/Sonar bleiben Koordinator-Prüfungen.

## Einschränkungen und Restrisiko

Native Transportmetadaten brauchen weiterhin zentrale Producer-/Wiring-Integration. Finish-Failure-Timing und Engine-Timeout-Semantik bleiben explizite Entscheidungen, keine erfundene Politik. Bestehende Required-Records bleiben sichtbar und unverändert.

## Finaler Diff- und Review-Status

## Freigegebene Post-Response-Finish-Folgearbeit

Finish erhält den tatsächlichen HTTP-200-Status und den exakten Hash des 23-Byte-Fixture-Bodys. Erforderlich sind native Logging-Ablehnung (-1), delegiertes Cleanup (0), abgeschlossenes Cleanup und Erhalt des nativen Logging-Fehlers, gebunden an beobachteten Worker und Transaktion. Fehlende oder widersprüchliche Beobachtungen bleiben abgelehnt. Siebzehn Fokustests bestehen. Diagnose `stream-d-finish-r3` enthält positiven Exit 0 und falsche-Transaktion-Kontrolle Exit 1 mit verifiziertem Cleanup. Frühere Internal-Redirect-Fixtures bleiben erhaltene Fehlversuche; weder Evidence noch Validator wurden gelockert. Integrierte Canonical-Evidence bleibt Koordinator-Verantwortung.

Exklusive Dateien wurden auf Payload-Sicherheit und Negativkontrollen geprüft. Separater Framework-Commit/Handoff steht aus; hier erfolgen weder Merge, Force-Push noch Parent-Gitlink-Änderung.
