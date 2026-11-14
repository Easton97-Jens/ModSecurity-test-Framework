# Change Record

**Sprache:** [English](20261114-02-nginx-review-runner-boundaries.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261114-02-nginx-review-runner-boundaries |
| UTC-Datum | 2026-11-14 |
| Framework-Basisrevision | Kandidaten-HEAD `6aaf2e153146fd2aa925666b42ed74985ca8543c`, eingehend `3ff8b75c9f4d2cb3614a4dcb7afd2e5360e074d8` |
| Issue oder Pull Request | Framework [#169](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/169); eingehender Runner aus [#171](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/171) |

## Motivation und Problemstellung

Der Review-Runner konnte Ausgaben in einem von den Umgebungswurzeln abweichenden CLI-Checkout samt Git-Metadaten verknüpfter Worktrees zulassen. SIGTERM oder ein bereits gereapter Master konnten außerdem eine weiterlaufende Servergruppe hinterlassen.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-Dateien `connector_suite/modsecurity_connector_tests/run_nginx_fzipi_review.py` und `connector_suite/modsecurity_connector_tests/test_nginx_fzipi_runner.py`: Ausgabezulassung und eigene Prozessgruppe des Runners. Parent- und MRTS-Quellcode bleiben außerhalb dieser Änderung.

## Akzeptanzkriterien

Ausgaben mit Überschneidung zum tatsächlichen CLI-Checkout, Git-Verzeichnis oder gemeinsamen Git-Verzeichnis vor Erstellung ablehnen; externe Geschwister erhalten. Abbruch muss die eigene Gruppe reapen, ihren Listener schließen, den Handler restaurieren und Exit 143 melden. Ursprüngliche 19 Methoden, Artefaktprüfungen und reguläre Cleanup-Receipt erhalten.

## Untersuchte Alternativen

Nur umgebungsgebundene Wurzeln und Warten nur auf den Master verfehlen die reproduzierten Pfade. SIGTERM-Blockierung über `Popen` riskiert eine vererbte Maske. Auch ein allein idempotenter Handler versagte beim ersten Signal während normalen Kontextendes.

## Implementierungsentscheidung

Die Zulassung erfasst kanonische CLI-/Git-Wurzeln vor der Runtime-Erstellung. Begrenzter vorgemerkter Abbruch deckt die Spawn-Übergabe ab; Cleanup-Zustand und geschachteltes `finally` schützen Shutdown und Handler-Restaurierung. Vorgemerkter Abbruch nach normalem Ende löst weiterhin 143 aus. Regulärem Master-SIGQUIT folgt begrenztes Gruppen-TERM/KILL, auch nach Master-Reaping. Kind-Signalmaske und Sichtbarkeit von Zombies bleiben erhalten.

## Geänderte Dateien und Tests

Geändert werden beide Python-Dateien und dieses EN/DE-Paar. Acht Methoden kommen hinzu: eine echte Regression mit regulärem/verknüpftem Git und sieben echte Prozesskontrollen. Alle ursprünglichen 19 Methoden bleiben unverändert; insgesamt 27. Kontrollen prüfen laufenden Abbruch, Spawn-Rückgabe, wiederholte Cleanup-Signale, bereits gereapten Master, TERM/KILL-Eskalation und wiederholtes/erstes SIGTERM unmittelbar vor SIG_IGN. Private prozesslokale Subreaper räumen auch fehlschlagende Negativkontrollen auf.

## Befehle und Ergebnisse

Die Befehle verwendeten ausgewähltes Framework-eigenes Python 3.15, explizite Quellwurzeln und externe temporäre/Cache-Wurzeln. Exakte Argumente und Hashes bleiben in privaten Receipts erhalten.

| Befehl oder Verfahren | Exit-Code | Ergebnis | Run-ID |
| --- | --- | --- | --- |
| Echte Git-Kontrolle gegen ursprünglichen Runner | 1 | Fünf erwartete fehlende Ablehnungen; externe Geschwisterkontrollen zugelassen | `runner171-fix-5408725399ea4aafa2a28d4d25a23eee` |
| Fünf echte Prozesskontrollen gegen ursprünglichen Runner | 1 | Fünf erwartete Fehler; Guardian entfernte jede Gruppe | `runner171-old-process-shadow-d40e78644403447fa2431623d1a55958` |
| Wiederholtes SIGTERM vor SIG_IGN gegen erste Korrektur | 1 | Erwartetes übersprungenes Cleanup und offener Listener | `runner171-before-ignore-shadow-17cef617e551443aaf98fba9a3508126` |
| Erstes SIGTERM beim normalen Ende gegen allein idempotenten Kandidaten | 1 | Erwartetes übersprungenes Cleanup; Guardian entfernte Gruppe | `runner171-normal-exit-shadow-8039fa69c9734abd93cec6f77ff25dad` |
| `rtk bypass "$PYTHON" -B -P -m unittest -v modsecurity_connector_tests.test_nginx_fzipi_runner` | 0 | 27 bestanden, keine Fehler/Skips; 39.918 Sekunden | `runner171-final27-controls-72c5c570c1ab4840854d5299b83199ed` |
| Python-`py_compile` für beide geänderten Dateien | 0 | Quelle unverändert; externer Bytecode-Cache | `runner171-python-qa-3fb91e9d36b24943904148b6d9c49a3b` |
| Framework-Python `-m ruff --version` und `-m pyright --version` | Je 1 | Beide Module fehlen; QA-Prüfungen NOT_RUN | `runner171-python-qa-3fb91e9d36b24943904148b6d9c49a3b` |

## Sicherheitsauswirkung

Ursprünglicher Bypass und Lifecycle-Pfade wurden reproduziert und bestanden anschließend mit der Korrektur. Erfolgreiche Prozesskontrollen verlangen keinen Guardian-Eingriff, abwesende Gruppen, geschlossenen Listener, Handler-Restaurierung und erwarteten Worker-Exit. Artefakt-/Provenienz-, Eigentümer-, Symlink-, Manifest-, Grammatik-, Hostzulassungs- und Quality-Gate-Kontrollen bleiben unverändert. Explizite Secrets-Qualifikation ist von unvollständigen automatischen Edit-Hook-Ereignissen getrennt.

## Dokumentation und Runtime-Evidenz

Dieser Record hat eine gleichwertige englische Begleitdatei. Echte Prozesse und Loopback-Listener waren kurzlebige Regressions-Fixtures. Native NGINX-/ModSecurity-Host-Szenarien, Connector-Matrix und umfassende Abnahme bleiben NOT_RUN.

## Nicht ausgeführte Prüfungen

Für lokale Ruff-/Pyright-Prüfungen fehlen bestehende Werkzeuge in ausgewählter Framework-Umgebung und registrierten ausführbaren Pfaden. Keine Installation oder Analyse-/Gate-Änderung erfolgte. Frische gehostete Prüfungen am späteren Framework-Commit bleiben erforderlich.

## Einschränkungen und Restrisiko

Prozesskontrollen benötigen Linux-Fork, prozesslokale Subreaper und Loopback-Sockets. Sie qualifizieren Runner-Grenzen; echte Connector-Artefakte/Runtime benötigen eigene Zulassung und Evidenz. Lokale Python-QA bleibt unvollständig.

## Finaler Diff- und Review-Status

Die gebundenen finalen Quellen bestanden alle 27 Methoden und Python-Syntaxkompilierung; unabhängiges statisches Review gab die Korrektur frei. Dieses Paar ist für Framework-Delivery vorbereitet. Native Aktualisierung generierter Ansichten, Dokumentationsprüfungen, Veröffentlichung und aktuelle gehostete Evidenz folgen beim Delivery-Verantwortlichen.
