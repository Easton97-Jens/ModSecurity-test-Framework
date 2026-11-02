# Traefik-Capture-Quellpfade und Zeitmessung der FIFO-Operation

**Sprache:** Deutsch | [English](20261102-01-auth-path-and-fifo-validation.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261102-01-auth-path-and-fifo-validation |
| UTC-Datum | 2026-11-02 |
| Framework-Basisrevision | 91145b7ba721bdec4e89af754cf40bf496fd2a08 |
| Issue oder Pull Request | Neun-Punkte-Master-Abgleich; Lieferung separat koordiniert |

## Motivation und Problemstellung

Die Traefik-Auth-Vorbereitung übergab weiterhin das entfernte Connector-Capture-Verzeichnis an die zentrale Registry und hashte den entfernten Manifestpfad. Die FIFO-Regression schloss einen frischen Interpreter und Imports in den Zwei-Sekunden-Timeout der Operation ein.

## Betroffene Komponenten und Sicherheitsgrenzen

Nur Framework-Auth-Vorbereitung und fokussierte Tests. Der Quellenexporter liest weiterhin eingecheckte Connector-Dateien. Capture-Quellpfade verwenden die geprüfte Framework-Zuordnung. Die FIFO-Beobachtungsimplementierung sowie `O_NONBLOCK`, `O_NOFOLLOW` und `fstat` bleiben unverändert.

## Akzeptanzkriterien

Quellpfadverdrahtung mit getrennten Framework- und Connector-Checkouts prüfen, versiegelte Capture-Ablehnung erhalten, genau 100 Standardfälle bewahren und FIFO-Ablehnung unabhängig vom Interpreter-/Importstart testen. Die vollständige Vorbereitung benötigt eine separate Auflösung des unten beschriebenen Registry-Blockers.

## Untersuchte Alternativen

Ein beliebig erhöhter Timeout, Skips, veränderte versiegelte Erwartungen und manuelles Umschreiben archivierter Objekte wurden verworfen. Für den Abgleich der veralteten Registry wurde kein vorhandener Archivgenerierungsbefehl gefunden.

## Implementierungsentscheidung

Capture-Verzeichnis und Receipt-Manifest über `source_path` auflösen. Ein zusätzlicher On-Demand-Test verwendet den echten Framework-Registry-Konstruktor; Quellenexport und Capture-Zulassung sind ausdrücklich gemockt, damit der Offline-Prozessguard erhalten bleibt. Er belegt ausschließlich Quellpfadverdrahtung und Argumente des Exportziels. Der FIFO-Test forkt nach dem Laden des Vertrags, erhält den Zwei-Sekunden-Watchdog für die Kindoperation, prüft die Ablehnungsdiagnose und beendet ein hängendes Kind beim Cleanup.

## Geänderte Dateien und Tests

`connector_suite/adapters/traefik/harness/i12_auth/prepare.py`, dessen Auth-Regressionsmodul, das aktive On-Demand-Inventar und `tests/no_crs/test_configtest_artifacts.py`. Quelldigests werden mit dem vorhandenen Inventarwerkzeug aktualisiert. Der neue Test ersetzt den bestehenden vollständigen Vorbereitungstest nicht.

## Befehle und Ergebnisse

Alle Projektbefehle laufen über RTK und den vorhandenen Framework-Interpreter. Die externe Task-Evidenz trägt die Run-ID `master-reconcile-20261102`, Umfang `framework`.

| Prüfung | Ergebnis |
| --- | --- |
| Ursprüngliche vollständige Auth-Vorbereitung | Fehler am entfernten Connector-Pfad `ci/runtime/lifecycle/i12/manifest.json` |
| Quellpfadregression mit getrennten Checkouts | PASS, ein Test; `split-offline-guarded-final.log` |
| Vollständige Auth-Kontrollen nach Pfadkorrektur | Sechs PASS, ein ERROR: `Sealed Traefik profile differs`; `auth-controls-final.log` |
| Artefakt-Regressionsmodul | PASS, neun Tests; `fifo-after.log` |
| Kaltcache-Regressionen für Artefakte, Receipts und Fixture-Qualität | PASS, 27 Tests; `fifo-cold-after.log` |
| Drei unabhängige Kaltcache-Messungen | Imports 0,82–0,88 Sekunden; FIFO-Ablehnung 0,00031–0,00035 Sekunden; `fifo-cold-measurements.json` |
| Inventar-Digestgenerator und Standardauswahl | PASS; Digests verifiziert und genau 100 aktive Fälle; `bindings-final-check.log`, `inventory-final-default.log` |

Der historische Timeout wurde auf diesem Host nicht reproduziert. Die Messungen bestätigen den dominierenden Interpreter-/Importanteil im bisherigen Watchdog; der neue Watchdog misst die Beobachtung in einem bereits geladenen Kind.

## Sicherheitsauswirkung

Alle Prüfungen versiegelter Profile, zentraler Implementierung, Registry-Objekte, vollständiger Quellenexporte und begrenzter Dateien bleiben fail-closed. Die neue Regression startet keinen Host. Keine Sicherheitsprüfung wurde für ein grünes Ergebnis abgeschwächt.

## Dokumentation und Runtime-Evidenz

Belegt sind ausschließlich Quellpfadverdrahtung und Dateisystem-Unit-Verhalten. Keine Host-, H2/H3- oder Runtime-Qualifikation wird behauptet. Die lokale ignorierte Framework-Konfiguration fehlte; eine minimale geheimnisfreie Einrichtung mit Framework-Interpreter und externem Taskcache ließ den tatsächlichen V3.2-Strukturvalidator bestehen. Sie ist keine versionierte Vorlage persönlicher Einstellungen.

## Nicht ausgeführte Prüfungen

Lokale Sonar-Secrets-Prüfung aufgrund ausdrücklicher Benutzeranweisung nicht ausgeführt. Keine Sonar-Anmelde-/Installationsreparatur und keine verpflichtende Ersatzprüfung eingeführt. Bestehende CI-Prüfungen bleiben unverändert. Kein Archivgenerator, keine native Hostkampagne und keine MRTS-Änderung ausgeführt.

## Einschränkungen und Restrisiko

Die vollständige Vorbereitung bleibt blockiert. Beide versiegelten Traefik-Profilpins stammen aus der Zeit vor der Observer-C-Eingangsbindung von `0d903fc5…` auf `5038d006…`; auch der zentrale Implementierungspin stammt aus der Zeit vor Migration/Refaktorierung. Eine Diagnose fand Abweichungen bei 10 von 19 historischen, repositorybasierten Registry-Objekten gegenüber aktuellen Quellen, einschließlich SDK-Accessor (`89ff282b…` erwartet, `a2205398…` aktuell). Diese Änderung enthält weder Pinaktualisierung noch Umschreiben archivierter Objekte. Vor erfolgreicher Gesamtvorbereitung werden ein unterstützter Archivgenerierungsweg und ein separat geprüfter vertrauenswürdiger Quellvertrag benötigt. `sealed-contract-review.diff` und `registry-repository-objects.json` enthalten die exakte Evidenz.

## Finaler Diff- und Review-Status

Framework-Lieferung, finale gemeinsame Inventarprüfung und Parent-Pinauswahl liegen beim Koordinator. Wartungs-PRs und MRTS-Quellen gehören nicht zu dieser Änderung. Der offene Fehler der vollständigen Vorbereitung bleibt ausdrücklich erhalten.
