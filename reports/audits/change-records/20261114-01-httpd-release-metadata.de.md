# Change Record: HTTPD-Release-Metadaten

**Sprache:** [English](20261114-01-httpd-release-metadata.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20261114-01-httpd-release-metadata` |
| UTC-Datum | 2026-11-14 |
| Framework-Basisrevision | `6d491b22b00ade682e8090fba0b355e0a6414ccd` |
| Issue oder Pull Request | Framework #169; Parent #445 nutzt den Provisionierungshelfer |

## Motivation und Problemstellung

Der kanonische Common-Vertrag wählt bereits HTTPD 2.4.70. Die Konstanten für
unveränderliche Prüfsummenmetadaten wählten noch 2.4.69; deshalb wies der echte
Produktionshelfer das aktuelle Release-Tupel vor dem Metadatenabruf zurück.

## Betroffene Komponenten und Sicherheitsgrenzen

Diese Framework-Änderung betrifft den HTTPD-Prüfsummenhelfer, seine
Quellwiederherstellungstests, das generierte Spezialistenarchiv und dieses
Record-Paar. Release-, Quell-URL-, Provider-, private Cache- und
Extraktionsgrenzen bleiben erhalten.

## Akzeptanzkriterien

Der echte aktuelle Produktionshelfer wählt das unabhängig geprüfte
Metadatenobjekt in beiden CLI-Ausgabemodi. Veränderte SHA-, Quell-, Prüfsummen-,
Release- und Query-Tupel bleiben vor Cache-I/O abgewiesen. Alle 18 bisherigen
und zwei neuen Methoden bestehen; native Metadaten erhalten 100 Standardfälle
und 80 Selektoren.

## Untersuchte Alternativen

Die veralteten Konstanten beizubehalten lässt den tatsächlichen
Provisionierungsblocker bestehen. Metadatenprüfung oder Tupel- und
Privatdatei-Guards zu umgehen oder zu lockern wird verworfen.
Ein Versionsupgrade gehört nicht zu dieser Korrektur.

## Implementierungsentscheidung

Nur die beiden produktiven Metadatenkonstanten ändern sich. Gewählt wird
[die unveränderliche offizielle 2.4.70-Prüfsumme](https://dist.apache.org/repos/dist/!svn/bc/89127/release/httpd/httpd-2.4.70.tar.bz2.sha256)
mit dem Metadaten-SHA256
`f412d65db7585db8e5e20e0d10dd0e6deaa6a08f52ed07bd29437777b347d29e`.
Der Koordinator prüfte dieses Distributionsobjekt und die offizielle
Apache-Archivprüfsumme unabhängig über verifiziertes TLS ohne Redirects:
Beide enthalten dieselben 87 ASCII-Bytes. Dies ist ein Metadatenbeleg,
kein frischer Hash des vollständigen Archivs.

## Geänderte Dateien und Tests

- `ci/provisioning/httpd-checksum-cache.py`: nur zwei Konstanten.
- `tests/security_regression/test_httpd_source_recovery.py`: zwei zusätzliche
  Methoden für den aktuellen Vertrag ohne Konstantenprojektion der synthetischen Fixture.
- `connector_suite/reports/testing/test-selection-archive.generated.json`:
  Native Neugenerierung erhält alle 8325 bisherigen Definitionen in Reihenfolge
  und ergänzt zwei auf 8327. Das aktive Inventar bleibt byteidentisch.
- Dieses englisch/deutsche Record-Paar folgt dem Framework-Template mit 13 Überschriften.

## Befehle und Ergebnisse

Die Tabelle nennt native Einstiegspunkte; der koordinierende Auftrag erhält
die exakten Argumente, ausgewählten Umgebungswerte und qualifizierten Offline-Belege.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `make test-httpd-source-recovery` | 0 | 20 Methoden bestanden, keine Fehlschläge, Fehler oder Skips; 93,596 Sekunden | HTTPD70-Offline-Quellprüfung, 2026-11-14 |
| Produktionshelfer-CLI, beide Ausgabemodi | 0 / 1 | Aktuelles Tupel akzeptiert; 16 veränderte Tupel ohne stdout oder Cache-Schreibzugriff abgewiesen | Derselbe Offline-Lauf; Kontrollen liegen innerhalb der zwei neuen Methoden |
| `ci/tools/sync-maintenance-test-views.py --write`, dann `--check` | 0 / 0 | Exakt zwei generierte Postimages bestanden Secrets vor der Aktualitätsprüfung; 8327 Definitionen, 100 Fälle, 80 Selektoren | Derselbe Offline-Lauf |

## Sicherheitsauswirkung

Keine Guard-Bedingung ändert sich. Exakte Release-/Provider-Identität,
Metadaten- und Archivdigests, private Ownership, Dateien mit genau einem Link,
Größenlimits und Symlink-Abweisung bleiben durchgesetzt. Die Regression des
Produktions-Tupels schließt die Lücke der bisherigen synthetischen Release-Tests.
Eine allgemeine Aussage zur Schwachstellenfreiheit wird nicht getroffen.

## Dokumentation und Runtime-Evidenz

Dieses Record-Paar dokumentiert Quellkorrektur und Offline-Belege. Die Änderung
erhob keinen frischen Apache-Build-, Host-Extraktions-, Dienststart-,
H1-/CRS-Runtime- oder Lifecycle-Beleg. Advisory-Anwendbarkeit bleibt an die
separat geprüfte Quelle und ausgewählte Host-/Profilbedingungen gebunden.

## Nicht ausgeführte Prüfungen

Der vollständige Spezialistenkatalog wurde für diese Korrektur zweier Konstanten
nicht wiederholt. Frische Host-/Build-/Runtime-Prüfung und gehostete Analyse des
endgültigen kombinierten Commits sind getrennte Arbeiten des Koordinators.
Kein lokaler Sonar-Scanner wurde ausgeführt.

## Einschränkungen und Restrisiko

Metadatenzulassung allein belegt weder Archivdownload noch Kompilierung oder
erfolgreiche Host-Runtime. Künftige Release-Wechsel benötigen ein separat
geprüftes Metadatenobjekt, dessen Digest und passende Erwartungen für den
aktuellen Vertrag. Endgültige Commitpaar-Prüfung und Hosted-Ergebnisse stehen aus.

## Finaler Diff- und Review-Status

Der Koordinator gab den produktiven Diff zweier Konstanten und die gezielte
Testabdeckung unabhängig frei. Quelle und generierte Ausgaben gehen zur
begrenzten Prüfung und regulären Auslieferung zurück; finale Dokumentations-
und Whitespace-Ergebnisse erhält der Koordinator getrennt. Dieser Record
behauptet weder einen Merge noch den Abschluss des Gesamtauftrags.
