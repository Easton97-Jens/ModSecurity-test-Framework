# Change Record: HTTPD-2.4.71-H2-Quellaktualisierung

**Sprache:** [English](20261114-03-httpd-71-h2-source-update.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20261114-03-httpd-71-h2-source-update` |
| UTC-Datum | 2026-11-14 |
| Framework-Basisrevision | `b7caf33d6a151819527b5e713f9adb1991a1ac39` |
| Issue oder Pull Request | Framework #169; Parent #445 ist ein externer Verbraucher |

## Motivation und Problemstellung

Der ausgewählte externe Hostlauf enthält acht Apache-H2-Fälle. Der Framework-
`connector_suite/adapters/apache/harness/apache_h2_acceptance.py` lädt
`mod_http2.so`, wählt `Protocols h2` und TLS 1.3 und ruft den H2-Client auf.
Die bisherige Quelle 2.4.70 erreicht damit die Modul-/Protokollbedingungen von
[CVE-2026-119618](https://httpd.apache.org/security/json/CVE-2026-119618.json).
Apache nennt 2.4.55–2.4.70 als betroffen und 2.4.71 als korrigiert. Loopback
und `H2Direct Off` beseitigen den ausgewählten TLS-H2-Quellpfad nicht.

## Betroffene Komponenten und Sicherheitsgrenzen

Diese Framework-Änderung aktualisiert das geprüfte HTTPD-Quelltupel,
unveränderliche Prüfsummenmetadaten und aktuelle produktive Regressionserwartungen.
Exakte Provider-, Digest-, private Cache- und Extraktionskontrollen bleiben
durchgesetzt. Parent-Runtime-Artefakte und Integration bleiben separat zugeordnet.

## Akzeptanzkriterien

Zwei offizielle HTTPS-Metadatenquellen stimmen überein; das echte Archiv erfüllt
ihren Digest; der bestehende Cleanup-Patch passt strikt zur Release-Quelle;
der aktuelle Helfer lässt den echten privaten Cache zu; alle 20 Recovery-Tests
bestehen.

## Untersuchte Alternativen

2.4.70 beizubehalten lässt die ausgewählte H2-Quelle betroffen. Der bestehende
Cleanup-Patch ändert `h2_mplx.c`, die vorgelagerte CVE-Korrektur dagegen
`h2_request.c::assign_headers`; er ersetzt das Release-Update nicht.
H2 abzuschalten oder Prüfungen zu lockern würde den ausgewählten Vertrag ändern.

## Implementierungsentscheidung

Gewählt wird 2.4.71, laut
[offizieller Downloadseite](https://httpd.apache.org/download.cgi) am 2026-11-11
veröffentlicht. Das unabhängig geprüfte
[unveränderliche SVN-Objekt](https://dist.apache.org/repos/dist/!svn/bc/89368/release/httpd/httpd-2.4.71.tar.bz2.sha256)
und die [Archivmetadaten](https://archive.apache.org/dist/httpd/httpd-2.4.71.tar.bz2.sha256)
lieferten jeweils HTTP 200 über verifiziertes TLS ohne Redirects. Beide enthalten
dieselben 87 Bytes mit SHA256
`70a701f5fb69bc96355859a4519bc00d17050135142ab57f5f7bf74a20eb7c8c`.
Das echte Archiv umfasst 8618142 Bytes und hat den Hash
`2bc5da5a33c247341de082717d4ebcb5cb49e8b73a05b7fddf7d5d6dc2f8de62`.

## Geänderte Dateien und Tests

- `ci/lib/common.sh`: Literale für HTTPD-Version und Archiv-SHA256.
- `ci/provisioning/httpd-checksum-cache.py`: unveränderliche Metadaten-URL und SHA256.
- `tests/security_regression/test_httpd_source_recovery.py`: unabhängig geprüfte
  aktuelle Produktionsliterale; die vorhergehenden 18 Tests der synthetischen
  Fixture bleiben byteidentisch. Keine Testmethode wird ergänzt oder entfernt.
- Dieses Record-Paar; native generierte Inventare bleiben beim Koordinator.

## Befehle und Ergebnisse

Die folgenden Befehle benennen die ausgeführten Einstiegspunkte. Python wählte
das vorhandene Framework-eigene Python 3.15.2; temporäre und Cache-Pfade waren
extern. Exakte Argumente und qualifizierte Belege verbleiben in den
Offline-Belegen des koordinierenden Auftrags.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk bypass python -B -m unittest tests.security_regression.test_httpd_source_recovery -v` | 0 | 20 bestanden in 89.470 Sekunden; keine Fehlschläge, Fehler oder Skips | HTTPD71-Quellprüfung, 2026-11-14 |
| Aktuelle `ci/provisioning/httpd-checksum-cache.py`-CLI mit echtem Archiv, Prüfsumme und exaktem `--downloaded-from` | 0 | `downloaded_verified_metadata`; echter privater Cache zugelassen | Derselbe Offline-Lauf |
| `rtk bypass patch --dry-run --batch --forward --fuzz=0 -p1 -i` mit `ci/provisioning/patches/apache/h2-joined-stream-purge.patch` | 0 | Release-`h2_mplx.c` ohne Fuzz oder Offset akzeptiert; kein Quellschreibzugriff | Derselbe Offline-Lauf |
| `rtk bypass git diff --check` | 0 | Quell-Whitespace sauber | Derselbe Offline-Lauf |

## Sicherheitsauswirkung

Release-`h2_request.c::assign_headers` schreibt die synthetische Content-Length
nun passend zur vorgelagerten Korrektur nach `r->headers_in`. Quellprüfung des
ursprünglichen Pfads und strikte Cleanup-Patch-Kompatibilität sind von
Exploit-Tests getrennt. Beide CLI-Ausgabemodi und 16 Kontrollen zur Abweisung
veränderter Tupel bestehen innerhalb der vorhandenen Produktionsvertragstests.
Keine Pfad-, Ownership-, Single-Link-, Größen-, Metadaten-, Archiv-, TLS- oder
Redirect-Kontrolle wird gelockert.

## Dokumentation und Runtime-Evidenz

Dieses englisch/deutsche Paar dokumentiert die begrenzte Quelle und
Offline-Ergebnisse. Die Änderung führte keinen Apache-Build, keine Zulassung
von Runtime-Artefakten, keinen Dienststart, keine H2-Exploitation, keinen
Hostlauf mit 92 Fällen, kein CRS-Ergebnis und keinen Merge aus.

## Nicht ausgeführte Prüfungen

Frische Build-/Hostqualifikation und gehostetes CI/Sonar am resultierenden Commit
sind Koordinatorarbeit. Aktualität generierter Inventare und finale
Dokumentationsprüfungen stehen für diese Übergabe aus. Kein lokaler
Sonar-Qualitätsscanner wurde ausgeführt.

## Einschränkungen und Restrisiko

Archiv-/Cache-Zulassung und Quellprüfung belegen weder Kompilierung noch
Runtime-Sicherheit. Frische Artefaktprovenienz und Ausführung der ausgewählten
Hosts bleiben vor entsprechenden Runtime-Aussagen erforderlich.

## Finaler Diff- und Review-Status

Der Koordinator gab das exakte Delta der drei Quelldateien frei; begrenzte Tests
bestanden und die Quellhashes blieben danach unverändert. Dieses Record-Paar
geht für finale Bilingual-, Link-, Struktur-, Secrets- und Diff-Prüfungen zurück.
Keine Secrets oder sensiblen Rohdaten sind dokumentiert; Commit, Merge oder
Gesamtabschluss werden nicht behauptet.
