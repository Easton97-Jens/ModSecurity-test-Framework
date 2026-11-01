# Protokollintegritätsintegration nach dem Testumzug

**Sprache:** [English](20261101-02-protocol-test-integration.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261101-02-protocol-test-integration |
| UTC-Datum | 2026-11-01 |
| Framework-Basisrevision | `d503ddbea1a3b6df7766edc247b0a9886ff10668` |
| Issue oder Pull Request | Framework-Integration für Parent-Draft #348; Veröffentlichung ausstehend |

## Motivation und Problemstellung

Der abgeschlossene Umzug verschob alle Connector-Tests ins Framework. Dreizehn
Parent-#348-Prüfer-/Testdeltas verblieben an gelöschten Pfaden. Verwerfen verliert
24 Definitionen und Common-Protokollassertionen; Wiederherstellen verletzt
Eigentumsgrenzen. Der Nutzer wählte auch verifizierte Artefakt-/QUIC-Fixes aus
Drafts #143/#144 aus.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-Common-/Apache-/NGINX-Prüfer, sieben Python-Testmodule, drei Go-Testquellen
und Fixture-Annahme. Ein Mutationsprüfer muss seine tatsächlich kopierte Fixture
prüfen, keinen geerbten echten Parent. Parent-Source ist eine explizite externe
Validierungsabhängigkeit; keine Produktquelle, MRTS- oder fremde Host-Kontext-
Arbeit wird hier verändert.

## Akzeptanzkriterien

Alle13 zugeordneten Deltas und24 Definitionen erhalten;100 Standardfälle/
80 Ausführungen und alle Selektoren bewahren. Bindungen/Archiv/Map nativ
regenerieren. Positive Kontrollen bestehen; Mutationen erreichen den echten
Prüfer und scheitern. Integration vor separat autorisiertem Framework-Master-
Merge und exaktem Parent-Pin verifizieren. Kein Parent-Master-Merge oder breite
Qualifikationskampagne.

## Untersuchte Alternativen

Keine Parent-Tests wiederherstellen, alten Schema-Hash kopieren, Prüferverhalten
mocken, Kontext/Gates/Warnungen abschwächen oder ungeprüften Pin wählen.
Nur cwd auszuwählen genügte nicht. Ein echter isolierter Fixture-Git-Snapshot
erhält den Kontextvertrag ohne Produktionsbypass.

## Implementierungsentscheidung

Verifizierte #143 `b7d643f` und #144 `9e49913` normal mergen, dann Parent-
`db431efa`-Deltas über aktuelle Source-Map portieren. Standardauswahl erhalten.
Jeder Prüferprozess wählt den Git-HEAD seiner isolierten Fixture nach Mutation,
mit bereinigten Git-Overrides, isolierter Konfiguration und deaktivierten Hooks/
Templates/Signierung. Framework-Code/-Kontext bleiben echt und unverändert.
Nach Open im neuen Unvollständige-Antwort-UDS-Test idempotentes Close-Cleanup
registrieren.

## Geänderte Dateien und Tests

Die13 zugeordneten Quellen erhalten19 Go- und fünf Python-Definitionen sowie
bestehende Testerweiterungen/Common-Assertions. Gemeinsamer reiner Testhelfer
korrigiert Apache-/NGINX-Mutationseingaben. Vier generierte Inventar-/Archiv-/
Migrationsmap-Sichten, gepaarte Eigentumsdokumentation und Record aktualisieren.
#143/#144 behalten ihre Records und16 neu autorisierten On-demand-Methoden.
Keine Standardfälle hinzufügen oder in Sammlern verbergen.

## Befehle und Ergebnisse

RTK, Framework-Python und explizite Quell-/Ausgabewurzeln; externe Produkteingabe
`b43faa78d403afd492c007e8f4a740ad21da1ac9` plus reine Dokumentationsänderungen.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Alte Apache-/NGINX-Adoptionstargets | Je2 | Veraltete exakte Erwartungen reproduziert | Externer Befehlsnachweis |
| Dieselben Targets mit Integrationsprüfern | 0 | Ausgehandeltes Protokoll/const/Authority bestehen | Externer Befehlsnachweis |
| Native Bindungs-/Archiv-/Map-Generierung und Prüfungen | 0 |100/80 Standard,2551/1133 optional und1993 Basis-IDs erhalten | Externer Befehlsnachweis |
| Öffentliche Inventarannahme `--check` | 0 | Vollständige100-Fall-Grenze akzeptiert; keine Ausführung | Externer Befehlsnachweis |
| Erste12 Python-Methoden | 1 | Neun Mutationsfehler deckten geerbten echten Parent-Kontext auf | Externer Befehlsnachweis |
| Fünf fokussierte Methoden nach Fixture-Korrektur | 0 | Positive Kontrollen und echte Mutationsablehnung bestehen | Externer Befehlsnachweis |
| Dieselben12 Python-Methoden nach Fixture-Korrektur | 0 | Alle12 samt zuvor übersehenen Mutationen bestehen | Externer Befehlsnachweis |
| Integrierte Protokollclient-Suite und vier QUIC-Helfermethoden | 0 |43 Methoden plus vier Helfermethoden bestehen | Externer Befehlsnachweis |
| Explizite Framework-Dokumentations-/Pinprüfungen | 0 | Links,344 EN/DE-Paarprüfungen, Pfadreferenzen, Records und Pins bestehen | Externer Befehlsnachweis |
| `make check-common-helpers-c17 ON_DEMAND_TESTS=1` | 0 | Common-Protokoll-/Spätinterventionsassertionen; Warnings-as-errors | `pr348-test-migration-20261101.GnuEMR/common-build` |
| Zugelassenes Envoy-Go-Overlay `-race -json` | 0 | Acht Pakete;392 erfolgreiche Abschlüsse,0 Fehler/Skips | `pr348-test-migration-20261101.GnuEMR/go/validation.md` |
| Zugelassenes Traefik-Native-Go-Overlay `-race -json` | 0 |173 erfolgreiche Abschlüsse; ein expliziter Echtdienst-abhängiger Skip | Derselbe Go-Validierungsrecord |
| `go mod verify`, Modul-Diff und `gofmt -l` | 0 | Gepinnte Module verifiziert; Deklarationen/Formatierung unverändert | Derselbe Go-Validierungsrecord |

Offline-Abhängigkeitslücken und überlange AF_UNIX-Pfade bleiben dokumentierte
Setup-Fehler. Bestehende gelockte Module wurden materialisiert/verifiziert;
kurze aufgabeneigene Temporärpfade erfüllten die Socket-Voraussetzung. Ein
Dokumentationsaufruf erbte CONNECTOR_ROOT des Haupt-Parents und traf einen
fremden lokalen Policy-Link; der korrigierte Befehl wählt explizit dieses
Framework und besteht. Neue Hosted-Checks stehen noch aus.

## Sicherheitsauswirkung

Stellt Mutationseingabeherkunft wieder her und erhält Fail-closed-Protokoll-/
Phasen-/EOS-Verträge. Authentifizierung, Isolation, Warnungen, Gates und
Produktionskontextprüfung bleiben unverändert. Integritäts-/Regressionspflege,
keine neue validierte Connector-Schwachstelle oder authentifizierte Attestierung.

## Dokumentation und Runtime-Evidenz

EN/DE-Eigentumsanleitung und Record aktualisiert. Unit-/Race-/Common-Ergebnisse
belegen keinen echten Host-/TLS-/H2-/H3-Verkehr oder Lifecycle/Stream-Isolation.
Der übersprungene `TestUDSEngineNativeBodyPolicy` benötigt einen privaten
Common-/libModSecurity-UDS-Dienst; sein Echtdienstverhalten bleibt ungeprüft.

## Nicht ausgeführte Prüfungen

Keine volle historische/Standard-Suite-Kampagne, Live-Host-/TLS-/H2-/H3-
Qualifikation, neue Modul-/Toolchain-Version oder MRTS-Ausführung. Lokales
Go 1.27.3 entspricht der ausgewählten Toolchain; Modul-Minimum-Direktiven bleiben
bei 1.26.9 und sind kein Toolchain-Pin. Unveröffentlichte
Hosted-PR-/Master-Checks und Sonar stehen noch aus.

## Einschränkungen und Restrisiko

Protokollbewusste Prüfererwartungen binden die explizite Parent-Paritätssource.
Framework-Master-Integration und exakter Parent-Lock-/Workflow-Pin bleiben
getrennte Auslieferungsschritte; breitere ursprüngliche Qualifikation bleibt offen.

## Finaler Diff- und Review-Status

Nur aufgabeneigene Framework-Vorbereitung. Unabhängiger begrenzter Fixture-
Security-Review ohne Blocker und ohne Umgebungs-/Secret-Dump. Begrenzte Diff-/
Whitespace-Prüfungen und unabhängiger EN-DE-Review bestanden. Aktuelle CI/Sonar
und Exact-Head-Merge bleiben nötig. Keine Secrets/rohen sensiblen Payloads/vollständigen Umgebungen
oder tatsächlicher PR-Merge in diesem Vorbereitungsrecord behauptet.

### Abgleich mit aktuellem Master vor dem Merge

Der erste veröffentlichte Head `0fdf1e6f` bestand16 Hosted-Checks bei drei
vorgesehenen Skips; seine exakte Sonar-Analyse hatte Gate OK, alle fünf gelieferten
Bedingungen OK und keine OPEN/CONFIRMED-PR-Issues. Vor dem Merge setzte die
unabhängige #146 Master auf `c3f3aa4747315bdbfc7f6443edb47cef54a4e804`.
Der Exact-Head-Preflight stoppte bei Konflikten; kein PR wurde gemergt.
Ein normaler Master-Merge erhält alle Quellen und regeneriert nur vier
konfliktbehaftete Katalogausgaben mit den neuen Master-Tools.100 Standardfälle/
80 Ausführungen bleiben erhalten;2586 optionale Fälle/1140 Ausführungen,
526 feste Framework-Bindungen und alle1993 historischen Basis-IDs werden
bewahrt. Vier neue Post-Migrationsquellen bleiben explizit.

Die Sprachumschaltung im geerbten deutschen Informational-Response-Leitfaden
steht gemäß bestehendem Parent-Zweisprachigkeitsvertrag in English/Deutsch-
Reihenfolge. Kein fremder Produktfix, Selektor, Assertion, Regel oder Gate wird
verändert. Native Generierung/Prüfungen und öffentliche Annahme bestehen;
dieselben12 Python-Methoden,43 Protokollmethoden und vier Helfermethoden
bestehen erneut. Explizite Dokumentationsprüfungen bestehen mit348 EN/DE-
Paarprüfungen. Erste Wiederholungsbefehle nutzten unvollständige Modulnamensräume
und scheiterten am Import; korrigierte vollqualifizierte Befehle bestehen.

Frische zugelassene Traefik-Overlay-/Race-Ausführung wählt exakt16 erhaltene
Paritätstests:18 erfolgreiche Test-/Subtest-Abschlüsse,0 Fehler/Skips, leeres
stderr. Die neuen31 Informational-Response-Leaves kompilieren, werden aber
NICHT AUSGEFÜHRT; sie benötigen den unabhängig zuständigen Produktfix, der im
ausgewählten Parent `b43faa78` fehlt. Kein vollständiger Traefik-Suite-Pass nach
#146. Frühere volle Go-Ergebnisse vor #146 bleiben historisch. Evidenz: externer
Lauf `pr348-test-migration-20261101.GnuEMR/go/post-master146/validation.md`.
Frische Hosted-CI/Sonar des abgeglichenen Nachfolgers, autorisierter Exact-Head-
Framework-Merge, Master-Prüfung und abhängiger Parent-Pin bleiben erforderlich.
