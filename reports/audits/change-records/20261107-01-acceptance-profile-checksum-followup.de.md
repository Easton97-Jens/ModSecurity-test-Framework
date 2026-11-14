# Folgearbeit zu Abnahmeprofilen und Prüfsumme

**Sprache:** [English](20261107-01-acceptance-profile-checksum-followup.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261107-01-acceptance-profile-checksum-followup |
| UTC-Datum | 2026-11-07 |
| Framework-Basisrevision | `d0c7e1036e57bdb980603f68e4e3e64e51de9049` |
| Issue oder Pull Request | [Framework Draft PR #169](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/169) |

## Motivation und Problemstellung

Der Prüfsummenabruf der archivierten HTTPD-Version leitet auf einen Archivhost
weiter, dessen TCP-Verbindung abläuft. Bestehende Companion-Executorpfade decken
H1 ab; getrennte H2-Pfade und die Strict-Qualifikation für Traefik native fehlen.
Die bisherigen NGINX-, Apache-, HTX-, SPOP- und ext_proc-Regressionen bleiben.

## Betroffene Komponenten und Sicherheitsgrenzen

Das Framework besitzt Apache-Metadatenzulassung und Downloadpfad, Opt-in-H2-
Executorpfade, Nachweisleser, Fixtures, Tests, natives Compilerinventar und den
Konfigurationsreferenzgenerator. Parent-Produktkorrekturen sind eine externe
Abhängigkeit. MRTS bleibt nur lesbar. Die Standardauswahl bleibt bei 100 Fällen.

## Akzeptanzkriterien

Offizielle Metadatenherkunft, unabhängige Archiv- und Metadatenhashes, direktes
verifiziertes HTTPS sowie Zurückweisung von Downloadfehlern und falschen Objekten
verlangen. Die bisherigen 32 Nicht-NGINX-IDs bleiben; 24 getrennte Profil-IDs
kommen hinzu. Tatsächliches TLS/H2, Regel-/Transaktions-/Antwortzuordnung, aktive
parallele Streamisolation, tatsächlicher Strict-Reset, gesunder Folgezugriff und
natives Cleanup sind erforderlich. Finale Commitpaarläufe und verpflichtende
gehostete Prüfungen bleiben getrennte Nachweise.

## Untersuchte Alternativen

Eine längere Zeitgrenze repariert keinen unerreichbaren Archiv-TCP-Endpunkt.
Ein aus dem heruntergeladenen Archiv abgeleiteter erwarteter Hash, ungeprüfte
Metadatensnapshots, Scannerunterdrückung oder ein übernommenes PASS eines anderen
Integrationsmodells würden den Vertrauens- oder Nachweisvertrag verletzen.

## Implementierungsentscheidung

Das exakte offizielle unveränderliche HTTPD-Distributionsobjekt aus Revision
`89000`, Version `2.4.69`, mit unabhängig geprüftem Metadaten-SHA-256
`7351aea97f61589f9803d432dc59e1002ba06e3b344fdba9ca281c2e82cf0b08`
verwenden. Aktueller literaler Archivpin und exakter Dateiname bleiben
verpflichtend. Cachewiederverwendung verlangt ebenfalls diese exakten
Objektbytes; sie behauptet keinen historischen Abruf. Globale TLS-, Redirect-
und Zeitgrenzenregeln bleiben unverändert.

Für dieses exakte Releasetupel wählt ein direktes 404 des kanonischen Archivs
das unabhängig geprüfte Quellarchiv derselben unveränderlichen Revision.
Beide nativen Producer verlangen direktes HTTP 200, null Redirects und den
unabhängigen Archivpin. Nur native Beschaffung erzeugt Cache-Herkunftsmarker.

Jedes neue Profil besitzt seine eigene tatsächliche Hostausführung. Companion-
Records erhalten die Lebenszykluszuordnung über opake Handles, ohne diese
auszugeben. Logische Host-/Handoff-Identität und gemeinsames Common-Engine-
Backend bleiben getrennt. Traefik native verwendet eine explizite Middleware-
Policy Safe(Vorgabe)/Strict aus dem externen Produkt. Ein reiner Test-Linkwrapper
aktiviert native Cleanupmetadaten; unabhängige Host-/Wirerecords belegen die
physische Verbindung. Der neue C-Observer gehört zum geschlossenen nativen
Compilerinventar.

Gehostete Befunde veranlassten begrenzte Reader-/Provenienz-Helferextraktionen
und gemeinsame Literale; jede Validierungsbedingung bleibt erhalten. Die
Zulassung absoluter regulärer ausführbarer Dateien verhindert, dass Hashprüfung
und PATH- beziehungsweise Cwd-basierte Host-/Service-Ausführung verschiedene
Dateien wählen. Finale Companion-Berichte ersetzen nur ihr geprüftes eigenes
Vorabbild nach nativem Cleanup und Quellen-/Artefaktzulassung; zwischenzeitliche
VALIDATED-Records qualifizieren keinen PASS. Publikations-, Objektwechsel- und
Programmpfad-Regressionen bleiben explizite Fehler. Kanonische Release-/Versions-
werte stammen aus ihrem einzigen Eigentümer.
Die abschließende Request-Join-Extraktion verschiebt zusätzlich die unveränderten
Wire-Identitäts- und Methoden-/Entity-Prüfungen aus der Rollenschleife in einen
Helfer. Ihre Reihenfolge vor nativer Hostauswahl und alle folgenden
Lebenszyklusprüfungen bleiben erhalten.

## Geänderte Dateien und Tests

- Apache-Provisionierung, Prüfsummenleser und gezielte Source-Recovery-Tests.
- Getrennte Companion- und Traefik-native-H2-Adapter, Regeln, Observer und
  Korruptionskontrollen der Leser; Git-erfasste Go-Regressionen in nativen Overlays.
- Opt-in-Registry: 56 IDs über sieben Profile; 25 NGINX-IDs und acht bestehende
  H2-/H3-Nachbarn ergeben 89 verlangte Hostausführungen / 85 unterschiedliche bloße
  Fall-IDs plus drei Apache-H1-Fälle. Vier gemeinsame NGINX-Namen verlangen eine
  explizite Executor- und Trafficvariantenidentität; Wiederholung erhöht keine
  eindeutige Fallzahl.
- Quellgestützte Konfigurationsreferenzeinträge und gepaarte Dokumentation.

## Befehle und Ergebnisse

Alle Shellbefehle verwenden RTK und explizite ausgewählte Wurzeln/Revisionen.
Vorläufige tatsächliche Hostdiagnosen führten alle 24 neuen H2-IDs aus. Die acht
Units des Metadatenhelfers, sieben Negativkontrollen durch den tatsächlichen
Shellpfad und das native HTTPD-Recovery-Target mit 18 Fällen bestanden.
Finale Ergebnisse am sauberen Paar, eindeutige Test-IDs, Quell-/Buildzulassung,
native Compilererfassung, gehostete CI und vollständige SHAs stehen im externen
Auftragsbericht; diese vorläufigen Diagnosen qualifizieren kein anderes Paar.

## Sicherheitsauswirkung

TLS-/Hostprüfung, private UDS-Eigentümerschaft, begrenzte reine Metadatennachweise,
Quell-/Artefaktzulassung und fehlschließendes Writerverhalten bleiben erhalten.
Strict-Aktionsanforderung und beobachteter Wire-Reset bleiben getrennt.
Typisierte beobachtete Transportbeendigung erfindet weder Response-EOS noch
Endpunktzuordnung. Keine Scannerausnahme, NOSONAR-Ergänzung, Gate-Abschwächung
oder Suche nach Zugangsdaten erfolgt.

## Dokumentation und Runtime-Evidenz

Gepaarter Protokollvorbereitungs-, Entwicklungs- und Traefik-native-H2-Guide
beschreiben Auswahl und Grenzen. Laufzeitrecords erhalten fehlgeschlagene
Diagnosen und unabhängig beobachtete Protokoll-, Phasen-/Regel-, Peer-/Folgezugriff-
und Cleanupfakten. Nachweise bleiben außerhalb von Git.

## Nicht ausgeführte Prüfungen

Die umfassende Gesamtabnahme bleibt **NOT_RUN**. Keine MRTS-Ausführung oder
Änderung, kein lokaler Sonar-Scanner, Merge oder administrativer Eingriff erfolgt.

## Einschränkungen und Restrisiko

Der vorhandene Sonar-Anschluss erlaubt GET, weist Issue-POST-Transitionen jedoch
zurück. Die 23 früheren und nachfolgenden gehosteten Vorkommen werden im externen
Bericht einzeln abgeglichen, einschließlich echter Quellkorrekturen und noch
offener technischer Vorschläge. Lokale Vorschläge schließen keine Serverbefunde
und bestehen kein gehostetes Gate.
Readbacks von Sonar und Apache-CRS/Aggregate am tatsächlich gelieferten Head
bleiben verpflichtend. Bestehende Advisory- und Legacyinventarbefunde werden
getrennt ausgewiesen.

## Finaler Diff- und Review-Status

Folgecommits erhalten die Historie des bestehenden Draft-PR-Branches. Finaler
begrenzter Diff, erzeugtes Inventar/Archiv, Dokumentation, Pins und aktuelle
Head-Prüfungen werden im externen Bericht abgeglichen. Bereitschaft verlangt
sämtliche Pflichtkriterien; dieser Quellrecord erklärt keine Bereitschaft.
