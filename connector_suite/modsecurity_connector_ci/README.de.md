# Connector-Testorchestrierung

**Sprache:** [English](README.md) | Deutsch

## Umfang und Schnittstelle

Dieses Paket besitzt die migrierte Connector-Testorchestrierung, Inventarzulassung,
Provisionierung, Cachevorbereitung, Runtime-Harnesses, Sammlung, Normalisierung,
Validierung und Reportgeneratoren. Sein eindeutiger Importnamespace ist
`modsecurity_connector_ci`. Dies ist Framework-Testcode, einschließlich Prüfungen
von Connector-Makefiles/-Workflows und Repository-Verträgen.

[Die öffentliche Schnittstelle](../../docs/connector-test-suite.de.md) verlangt
explizite `TEST_ROOT`, `CONNECTOR_ROOT`, exakte `CONNECTOR_REVISION`, Profil und
einen vorhandenen externen Ausgabeparent. Framework-eigene Unit-Fixtures dürfen
ohne Produktcheckout laufen. Produkt-Build/-Konfiguration/-Deployment bleiben
Connector-Code. Der Produktcheckout wird nie aus der Paketabstammung abgeleitet.

## Struktur

| Pfad | Verantwortung |
| --- | --- |
| `checks/` | Quell-, Konfigurations-, Dokumentations- und Evidence-Verträge |
| `lib/` | Gemeinsame Testauswahl, Quellbindung und Orchestrierungshelfer |
| `runtime/` | Host-Testlebenszyklus und geschützte Testintegrationen |
| `evidence/` | Laufbezogene Sammlung, Normalisierung und Validierung |
| `provisioning/` | Vorbereitung von Testkomponenten |
| `testtools/` | Explizite Testtool-Einstiege |

Auswahlautorität ist [active-cases.json](../config/testing/active-cases.json).
Schema 4 trennt feste Framework-Testquellhashes von erfassten Produktinputs.
Die ursprüngliche Basis umfasst 100 Standardfälle / 80 Ausführungen und 1893
On-demand-Fälle / 839 Ausführungen; neue Migrationsregressionen bleiben auf Abruf.
Die Standardgrenze bleibt 100; fehlende Quellen oder Drift verhindern Zulassung.

## Evidence und Sicherheit

Live-Beobachtungen werden an Lauf, Fall, Request, tatsächliche Transaktion und
Quellrevision gebunden. Niemals fremde Requestlogs übernehmen oder beobachteten
HTTP-Status durch Interventionsstatus ersetzen. Ausgeführten Verkehr vor
Assertions sichern. Fehlende Pflichtzeilen, Schreibfehler oder leere erforderliche
Ergebnismengen lassen den Lauf scheitern. Retries bewahren Versuche ohne höhere
Anzahl unterschiedlicher Fälle; gemischte Läufe oder Revisionen dürfen nicht
in eine erfolgreiche Zusammenfassung umgestempelt werden.

Geschützte Broker authentifizieren geschützte Parent-Basis und gepinnte
Framework-Quelle. Kandidatendateien dürfen kein privilegierter Code werden.
Fehlendes installiertes Gate oder fehlende Hostvoraussetzungen bleiben `BLOCKED`.
Ausgaben, Logs, Build-/Cachedaten und Downloads bleiben außerhalb der Checkouts;
Bodies, Zugangsdaten und private Umgebungswerte werden nie eingecheckt.

Ein erfolgreicher Validator belegt seinen Evidence-Vertrag, keinen neuen
Hostlauf. Build-, statische, native und gehostete Runtime-Ergebnisse behalten ihre
getrennte Bedeutung. Der Quellcheckout-Adapter behauptet nicht, dass sämtliche
migrierten Module im installierbaren Framework-Paket enthalten sind.
