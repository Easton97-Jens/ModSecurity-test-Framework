# Regression für Traefik-Native-Informationsantworten

**Sprache:** Deutsch | [English](20261101-01-traefik-native-informational.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261101-01-traefik-native-informational |
| UTC-Datum | 2026-11-01 |
| Framework-Basisrevision | `d503ddbea1a3b6df7766edc247b0a9886ff10668` |
| Issue oder Pull Request | Externes Connector-Finding `SEC-TRAEFIK-NATIVE-001`; separate Framework-Lieferung |

## Motivation und Problemstellung

Eine Informationsantwort darf die finale Responseheader-Prüfung nicht
verbrauchen. Das Framework liefert Regression und realen Hostadapter für
diesen externen Connector-Fehler; der Produktfix gehört ins Connector-Repository.

## Betroffene Komponenten und Sicherheitsgrenzen

Native Traefik-Pakettests, dedizierter Hostadapter, geprüfte Inventarbindungen,
exakte Quellzuordnungen und generierte Registrierung. MRTS und die allgemeine
Protokollmatrix bleiben unverändert. Keine Tests kehren in den Produktbaum zurück.

## Akzeptanzkriterien

100/102/103 ausdrücklich auf HTTP-Transport beobachten; ausschließlich finale
Schutzheader und Status einmal prüfen; Deny/Redirect, Request-EOS, begrenztes
P4, Streaming, Keepalive und einmaliges Cleanup erhalten. Die Standardgrenze
bleibt bei 100 Fällen. Reale gepinnte Traefik-/Plugin-/UDS-/libmodsecurity-Evidence
bleibt eine eigene Abnahmebedingung.

## Untersuchte Alternativen

ResponseRecorder allein belegt keine Informationsantwort-Semantik.
Vollständiges Response-Buffering verletzt den Streaming-Vertrag. Alle Spezialisten
in die Standardauswahl aufzunehmen überschritte deren feste 100-Fälle-Grenze.

## Implementierungsentscheidung

Sechs ausdrückliche Go-Spezialselektoren expandieren zu 31 Blättern. Reale
HTTP-Tests verwenden `httptrace.Got1xxResponse`; synchronisierter Abschluss
erlaubt sichere Transaktionsbeobachtung unter dem Race-Detektor. Vier Hostfälle
verwenden eine Keepalive-Verbindung. Das Inventar erlaubt nur diese exakten
Spezialistenidentitäten/-selektoren/-gruppen; vorhandene Quell-, Expansions-,
Provenienz- und Pfadprüfungen bleiben bestehen. Die Migrationsregistrierung
führt vier neue Framework-Quellzuordnungen als Ergänzungen nach der Migration,
während historische Dateien weiterhin strikt aus unveränderlichen Quellen
gelesen werden.

## Geänderte Dateien und Tests

Die neue `informational_response_test.go` prüft finale Entscheidungen (13),
Request-EOS (3), implizite finale Pfade (10), Streaming (1), Upgrade/Hijack (1)
und Headergrenzen (3). Der Hostadapter prüft separat 103-Deny, Deny ohne 103,
103-Allow und legitimen Folgezugriff. Source-Map, Inventar, Archiv und Test-Map
registrieren die zusätzlichen Fälle. Die zweisprachige Testanleitung beschreibt
Aufruf und Geltungsbereich.

## Befehle und Ergebnisse

Alle Shellbefehle verwenden RTK; Python gehört dem Framework. Die koordinierende
Aufgabe bewahrt exakte Aufrufe, Quelldigests und Laufausgaben außerhalb beider
Checkouts auf.

| Befehl | Exitcode | Kurzergebnis | Lauf-ID oder erlaubter Evidencepfad |
| --- | --- | --- | --- |
| Framework-Spezialoverlay, dann `go test -run '^TestInformationalResponse' -v ./...` auf unveränderter Connector-Basis `a6001a09210bc9516256d28af5da45d73f0fe2f2` | 1 | 10 finale Informationsantwortfälle und 3 Request-EOS-Fälle scheiterten; 3 Kontrollen ohne Informationsantwort bestanden | `unit-red/observed-red.json` unter dem externen Aufgabenstamm |
| Öffentlicher Framework-Einstieg mit sechs exakten Go-Selektoren und `--on-demand --strict-skips` | 0 | Alle 31 expandierten Go-Fälle bestanden gegen das Produktdelta | `unit-green/active-tests-5pnrf4rn/summary.json` unter dem externen Aufgabenstamm |

## Sicherheitsauswirkung

Der Reproduzierer bestätigte P3 für 103 statt final 201 und einen übersehenen
finalen Marker; ein beabsichtigtes Deny lieferte 200 mit geschützten Upstream-
Testbytes. Der korrigierte Go-Paarlauf hielt diese Bytes zurück und unterschied
den eigenen Ablehnungsbody. Die negativen Headergrenztests erhalten
Validierungsfehler. Dieser Bericht behauptet keinen eigenen Framework-
Schwachstellenfix.

## Dokumentation und Runtime-Evidenz

Siehe die zweisprachige [Testanleitung](../../../docs/testing/traefik-native-informational.de.md).
Reale Hostergebnisse, exaktes Commitpaar, Race/Vet und finale Scanevidence gehören
der koordinierenden Aufgabe und ihrem externen Lieferbericht. Ein Go-Paket-PASS
allein belegt keine Hostlaufzeitunterstützung.

### Sonar-Korrektur und autorisierte Integration

Die Integrationsfortsetzung behebt fünf neue PR-Befunde: `go:S3776` in den Tests
für finale Entscheidungen und impliziten Abschluss, `python:S3776` in Hostprobe
und Runner sowie `python:S1186` im absichtlich stillen Request-Log-Override.
Kohärente Helfer erhalten Assertions, Operationsreihenfolge und alle 31 Go-Fallnamen.
Der stille Override erklärt seinen Schutz privater Requestdaten. Keine Regel,
Schwelle, Gate, Warnung, Prüfung oder Assertion wird abgeschwächt oder unterdrückt.
Native Tools aktualisieren Quelldigests und generierte Registrierung; das
Standardinventar bleibt bei 100 Fällen und 80 Ausführungen.

Die initiale Sonar-Master-Baseline enthält 83 offene Framework-Issues, getrennt
von den fünf auftragsbezogenen PR-Issues. Die unabhängige Connector-Master-Baseline
enthält fünf Issues, seine ursprüngliche PR-Analyse keines. Diese datierten
Inventare liegen getrennt im externen Evidenceverzeichnis `integration/`.
Unabhängiger Baseline-Code bleibt unverändert.

Der Nutzer hat die reguläre Integration von Framework #146 und danach
Connector #435 mit dem tatsächlich entstandenen Framework-Master-SHA autorisiert.
Finale Head-CI, Sonar-Issues/-Gates, Regeln und Reviews werden nach der Korrektur
erneut geprüft. Der Koordinator dokumentiert terminale Ergebnisse und die frische
Hostabnahme des neuen Paares getrennt; frühere Paarnachweise bleiben historisch.

## Nicht ausgeführte Prüfungen

Diese begrenzte Teilaufgabe führte weder allgemeine Protokollmatrix noch MRTS
oder eine vollständige Repository-Testkampagne aus. Finales integriertes
Race/Vet, Secret-Scanning und drei reale Hostwiederholungen übernimmt die
koordinierende Aufgabe.

## Einschränkungen und Restrisiko

Die erste rote Ausgabe wurde über das Ausführungstool beobachtet; die erhaltene
Kurznotiz ist ein Beobachtungsbericht und kein wörtliches Rohlog. Basis-SHAs und
Quelldelta identifizieren das lokale Paar, bis neue Commits vorliegen.
Hostvoraussetzungen und Identitätsprüfungen müssen ohne abgeschwächte Isolation
erfüllt sein.

## Finaler Diff- und Review-Status

Übergabe an die koordinierende Aufgabe für finales Diff-, Whitespace- und
Secret-Review sowie separate Framework-/Connector-Draft-PRs. Framework-
Integration muss einer abhängigen Connector-Pinänderung vorausgehen. Kein direkter
Master-Push oder Bypass ist autorisiert. Reguläre Merges erfordern alle finalen
Head-Integrationsbedingungen.
