# Reparaturen an Entwicklungs- und Testabläufen

**Sprache:** [English](20261122-01-development-test-repairs.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261122-01-development-test-repairs |
| UTC-Datum | 2026-11-22 |
| Framework-Basisrevision | bcf4ab233fcb6394c235ea7069d5cde8c06e34f6 |
| Issue oder Pull Request | Framework-Branch `codex/devtest-report-repairs-20261122`, Nacharbeit zu devtest-20261119T093840Z |

## Motivation und Problemstellung

Der Entwicklungslauf zeigte fehlende Bibliotheksbereitstellung in No-CRS,
fehlende Smoke-Test-Eingaben und eine fehlende Bindung von HAProxy-Testfällen an
Ereignisse. Er zeigte außerdem fehlende Opt-ins für lokale Bereitstellung und
einen gemeinsam genutzten Apache-Ausgabepfad.

## Betroffene Komponenten und Sicherheitsgrenzen

Das Framework verwaltet die Composite Action, die Test-Harnesses,
Evidenzmetadaten und die Auflösung lokaler Voraussetzungen. Das Veröffentlichen
von Evidenz erfordert weiterhin die vorhandenen Projektions- und Bindungsregeln.
Die lokale Bereitstellung nutzt die vorhandenen Build- und Download-Opt-ins und
die Herkunftsnachweise der gewählten Komponenten.

## Akzeptanzkriterien

Für jede festgelegte CI-Zeile einen vorbereiteten libModSecurity-Snapshot
verwenden. Den Envoy-Launcher im gewählten Parent auflösen. Beiden
Konfigurationsprüfungen ohne explizite Konfiguration eine nutzbare Fixture
bereitstellen. Erfolgreiche HAProxy-No-CRS-Ergebnisse an die beobachtete
Transaktion binden. Compiler-Ausgaben standardmäßig im gewählten Build-Pfad
halten und blockierte optionale Lint-Prüfungen eindeutig kennzeichnen.

## Untersuchte Alternativen

Die Framework-Action verwaltet Bereitstellung und Konfigurationsprüfung.
Ein Override im Parent-Workflow würde ihren Laufzeitkontext duplizieren.
Eine Änderung der Collector-Allowlist würde die Prüfung der Bindung von
Testfall und Ereignis untergraben.

## Implementierungsentscheidung

Die Action wählt das Provisionierungsziel für den Connector oder gemeinsame
Komponenten und exportiert Engine-Präfix, Header- und Bibliothekspfad. Die
Validierung bindet die exakten aktuellen Action-Bytes an die unveränderliche
Migrationsbasis. CI prüft einzeilige Build-Pfade vor dem Schreiben der
festgelegten Umgebungsvariablen. Der HAProxy-Harness bindet für einen erfolgreichen No-CRS-Testfall eine
beobachtete Kennung an das abgeschlossene Anfragefenster. Envoy und Traefik
beachten die explizite Konfiguration des Aufrufers. Optionales C17-Lint meldet
BLOCKED bei fehlendem SDK. Automatische lokale Bereitstellung erfordert beide
vorhandenen Opt-ins und ein auf den Bedarf begrenztes Ziel.

Die No-CRS-Action behandelt beide Default-Zweige ausdrücklich. Die
HAProxy-Helfer validieren und benennen ihre erforderlichen Argumente.

## Geänderte Dateien und Tests

- No-CRS Composite Action, exakte Quelländerungsbindung und gemeinsame Framework-CI-Bibliothek.
- Envoy- und HAProxy-Harnesses und Dispatch-Skript der Laufzeitstufen.
- Make-Lint-Rezepte und Apache-C-Standard-Prüfung.
- Regression zur Ergebnisidentität, Inventar-Digests und generiertes Spezialtestarchiv.
- Dieses englische und deutsche Change-Record-Paar.

## Befehle und Ergebnisse

| Befehl oder Prüfung | Exit-Code | Ergebnis |
| --- | --- | --- |
| `make check-apache-c17` | zweimal 0 | Compiler-Ausgabe am Standardpfad und expliziten Pfad geprüft |
| `sh -n` und `git diff --check` | 0 | Geänderte Shell-Skripte und Whitespace im Patch geprüft |
| No-CRS-Composite-Offline-Test mit kontrollierter Bereitstellung | 0 | Alle fünf Zeilen exportieren Engine-Eingaben. Ungültige oder fehlende Snapshots blockieren die Ausführung |
| Gezielter Unittest zur Ergebnisidentität | 0 | Erfasster Fall gebunden. Fremde und mehrdeutige Ereignisse abgelehnt |
| Dispatch der Konfigurationsstufen und native Konfigurationsparser | 0 | Regelauswahl und private Konfiguration geprüft. Envoy ext_authz, Envoy ext_proc und Traefik akzeptierten mit vorhandenen Binaries die Smoke-Regeln |
| `update-inventory-bindings.py --apply` und `update-test-archive.py` | 0 | Sieben Quell-Digests aktualisiert und Archiv neu generiert |
| `make check-active-inventory` | 0 | 100 aktive Fälle zugelassen. Das Spezialtestarchiv entspricht den Quellen |
| `make check-canonical-common-pins` und drei gezielte Action-Integritätstests | 0 | Exakte Action akzeptiert. Falsche Basis und veränderte Checkout-/Bootstrap-Prüfungen abgelehnt |
| Gezielte Prüfungen zur SonarCloud-Korrektur | 0 | Zizmor, Ruff, Action-Integrität, Bereitstellungsmatrix und HAProxy-Anfragefenster-Regression bestanden |
| Ruff-Lint und -Format, Offline-zizmor und Offline-Bereitstellung | 0 | Action- und Testformatprüfungen bestanden. Alle fünf Zeilen akzeptieren gültige Pfade und lehnen CR/LF in Pfaden ab |

## Sicherheitsauswirkung

Der Harness ordnet ausschließlich eine Transaktion zu, die im validierten
Anfragefenster beobachtet wurde. Vorhandene Evidenz- und Fehlerprüfungen
bleiben wirksam. Der CI-Export ist auf die gepinnten libModSecurity-Build-Pfade
beschränkt.

## Dokumentation und Runtime-Evidenz

Die verlinkten englischen und deutschen Records beschreiben die Änderungen.
Die Envoy- und Traefik-Ergebnisse belegen das Parsen der Konfiguration.
Das Apache-Ergebnis belegt die C17-Kompilierung.

## Nicht ausgeführte Prüfungen

Die vollständige Connector-Suite, der gehostete Workflow und neue Ende-zu-Ende-
Laufzeitprüfungen für HAProxy und Envoy erfordern den jeweiligen autorisierten
Laufzeitkontext und dessen Eingaben.

## Einschränkungen und Restrisiko

Der Parent pinnt weiterhin eine zuvor veröffentlichte Framework-Revision.
CI-Ergebnisse für diese lokale Reparatur stehen bis zur Veröffentlichung und
Pin-Synchronisierung aus. Bibliotheksherkunft für APR und httpd ist von der
Bereitstellung von libModSecurity unabhängig.

## Finaler Diff- und Review-Status

Lokal in einem isolierten Framework-Checkout für den Draft-PR geprüft.
Die verknüpfte Framework-Revision im Parent erfordert eine separate Integration.
