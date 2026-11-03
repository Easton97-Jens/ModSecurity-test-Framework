# Change Record

**Sprache:** [English](20261103-04-mrts-merged-pin-integration.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261103-04-mrts-merged-pin-integration |
| UTC-Datum | 2026-11-03 |
| Framework-Basisrevision | d7bc6006cfabbe545ff63685aaccd6ca722e12ab |
| Issue oder Pull Request | Framework #167; separat freigegebene MRTS-Abhängigkeit #6 |

## Motivation und Problemstellung

Die Readiness-Lieferung wählte weiterhin den MRTS-Stand vor Integration. Der aktuelle Benutzer hat die geordnete reguläre Squash-Integration ausdrücklich freigegeben. MRTS #6 erzeugte tatsächlich den Main-Commit `ee2174431c4edf97e66afe32558ce8454deb2397`; sein vollständiger Dateibaum entspricht dem geprüften PR-Head. Dieses tatsächliche Objekt statt eines PR-Heads oder hypothetischen Merge-SHAs auswählen.

## Betroffene Komponenten und Sicherheitsgrenzen

Nur der Framework-eigene Gitlink `tools/MRTS` und dieses Dokumentationspaar ändern sich. MRTS-Quellen, Parent-Pins und geschützte Broker-/Composite-Identitäten bleiben getrennte Eigentumsgrenzen. Der neue MRTS-Commit ändert drei geprüfte Policy-Digests und deren semantisches Reviewdokument; keine Generatorimplementierung ändert sich.

## Akzeptanzkriterien

Das tatsächliche MRTS-Mergeobjekt auswählen und sauber materialisieren. Tatsächliche Parent-Policybytes gegen Framework-/MRTS-Vererbungen sowie Paket-/Definitions-/Importintegrität und native Metadaten prüfen. Alle 100 Standardfälle, 80 Ausführungszeilen und Offline-Ausnahmen erhalten. Vor Framework-Merge frische CI, vollständiges Quality Gate A/A und echte Generatorkompatibilität am sauberen eingecheckten Head verlangen.

## Untersuchte Alternativen

Der Maintenance-Publisher würde einen weiteren begrenzten Draft statt dieses freigegebenen bestehenden PRs erzeugen. Pauschaler SHA-Ersatz würde unabhängige unveränderliche Identitäten ändern. Nur die exakt geprüfte Detached-Checkout-/Gitlink-Primitive des Updaters verwenden; historische Quellprüfungen nicht abschwächen.

## Implementierungsentscheidung

Den tatsächlichen MRTS-Main-Merge abrufen, sauberen Checkout der offiziellen Quelle prüfen, dieses Objekt detached auswählen und nur den Gitlink aktualisieren. Nativen Metadatenwriter und danach Checker ausführen. Inventar- und Archivbytes bleiben gleich, da deren Eingabebereiche MRTS ausschließen. Quellklassifikationen oder historische Basen nicht zur Verdeckung eines unabhängigen alten Migrationmapfehlers ändern.

## Geänderte Dateien und Tests

`tools/MRTS` und dieses EN/DE-Paar. Bestehende Tests bleiben unverändert: Updater-Bypassablehnung, Definitionsguards, Importatomarität und vier Paketintegritäts-/echte Generatortests. Keine Standardfälle oder Erwartungen werden ersetzt.

## Befehle und Ergebnisse

RTK und die bestehende Framework-eigene reguläre CPython-3.15.2-Umgebung mit expliziten Quellen und privaten Ausgaben. Exakte argv und Logs im Integrationslauf `20261103T175654Z-integration`, Artefakt `framework-precommit/commands.json`; der PR nennt die zulässige Evidenzwurzel.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `ci/tools/sync-maintenance-test-views.py --root <Framework> --write`, danach `--check` | 0 / 0 | Native Synchronisation/Prüfung; Inventar und Archiv bytegleich zur Basis | framework-precommit/metadata-*.log |
| `-m modsecurity_connector_ci.lib.active_test_inventory --check` | 0 | 100 Standardfälle, 80 Zeilen; Offline-Ausnahmen unverändert | framework-precommit/inventory.log |
| `checks/common/check-origin-governance.py` | 0 | Nur bestehender Scaffoldumfang | framework-precommit/origin-governance.log |
| Explizite Updater-/Definitions-/Import-/Paket-Unittestauswahl | 0 | 26 Tests ohne Skips | framework-precommit/regressions.log |
| Tatsächlicher Vererbungsquell-/Katalogvergleich | 0 | 27 kanonische Quellen, 21 Framework- und 12 MRTS-Einträge stimmen | framework-precommit/actual-inheritance-readback.json |

## Sicherheitsauswirkung

Keine Regel, Scanner, Gates, Quell-/Pfadgrenzen, Paketsiegel, Provenienzguards oder geschützte Identitäten werden abgeschwächt. Ablehnung ungültiger Globals, Traversal, Artefakt-/Revisionsabweichungen und geänderter Runtimepfadguards erhalten. Kein Publisher, geschützter Brokerdispatch oder administrativer Schritt.

## Dokumentation und Runtime-Evidenz

Dieses Paar dokumentiert nur die Framework-Abhängigkeitsintegration. MRTS-Mergefakten sind als externe Abhängigkeitsfakten gekennzeichnet. Die Prüfungen behaupten keinen Connector-Hostverkehr. Die separat beauftragten 13 echten Endpaar-Invokationen folgen nach Connectorintegration und behalten tatsächliche Build-/Quellidentitäten.

## Nicht ausgeführte Prüfungen

Der Exact-Head-Definitionsintegrationseinstieg benötigt einen sauberen eingecheckten Frameworkbaum und läuft daher nach diesem Pincommit; tatsächliches Ergebnis in aktuellen PR-/Evidenzreceipts. Hosted-Analyse folgt nach Veröffentlichung. Lokale Sonar-Vorprüfung, Installation und Authentifizierungsreparatur bleiben ausgesetzt. Keine umfassende Kampagne, Reset-/Multiplexprüfung oder geschützter Dispatch ausgewählt.

## Einschränkungen und Restrisiko

Eine explorative Migrationmapprüfung scheitert an `caller-f5523da.yml.fixture`, die in ihrer historischen Basis fehlt. Exakter unveränderter bb6-Generator sowie Fixture-/SourceMapbytes reproduzieren denselben Fehler. Der Generator schließt MRTS aus und wird weder von diesem Pinupdater noch dem erforderlichen Metadatenkoordinator aufgerufen. Fehler separat erhalten; weder PASS noch Grund zur Änderung historischer Blobzulassung. Endgültige integrierte Vererbung und Master-CI benötigen ihre eigenen tatsächlichen Revisionen.

## Finaler Diff- und Review-Status

Der Quelldiff enthält nur ausgewählten Gitlink und Dokumentationspaar. Metadateninvarianten und Whitespace vor Veröffentlichung prüfen; aktuelle CI, eingecheckte Kompatibilität und Mergeentscheidung bleiben im PR. Keine Zugangsdaten, Digestwerte oder Laufartefakte hier gespeichert.
