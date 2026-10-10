# Change Record

**Sprache:** [English](20261009-42-nginx-early-mapper-event-evidence.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261009-42-nginx-early-mapper-event-evidence |
| UTC-Datum | 2026-10-09 |
| Framework-Basisrevision | b283851c1fd70a031832d2e95e10dfcc4bc4f068 |
| Issue oder Pull Request | Draft-Framework-PR #137 Follow-up |

## Motivation und Problemstellung

Echte NGINX-Common-Mapper-Fehler treten vor der Aufnahme kanonischer
Request-Metadaten auf. Ihr Source-`protocol_error` enthält deshalb leere
`method` und `uri`, während getrennt versiegelte Access-, Fault-, Config- und
Cleanup-Artefakte den tatsächlichen Request und die Transaction binden. Der
Bundle-Reader verlangte fälschlich die spätere Access-URI im frühen Event und
konnte echte R7-Evidence nicht aufbewahren.

## Betroffene Komponenten und Sicherheitsgrenzen

Der pure Common-Input-Fault-Vertrag und der strikte NGINX-Native-Bundle-Reader.
Source-Authority, Bytes, Receipts, Containment, Revisionen, Status,
Worker-Identität und Cleanup-Grenzen bleiben unverändert.

## Akzeptanzkriterien

Nur einen exakten frühen `protocol_error` mit leeren String-Werten für
Methode/URI und derselben Transaction akzeptieren. Fehlende, nichtleere,
fremde, falsch typisierte, doppelte oder falsch klassifizierte Events ablehnen.
Vor jeder Canonical-Projektion weiterhin exakte Access-/Fault-/Config-/Cleanup-
Korrelation und `driver_exit_code == 0` verlangen.

## Untersuchte Alternativen

Das Befüllen des Events aus rohen NGINX-Request-Daten wurde verworfen, weil das
Parent-Produkt diesen Fehlerpfad ausdrücklich auf bereits aufgenommene
kanonische Metadaten begrenzt. Das Weglassen der Methode-/URI-Prüfung wurde
verworfen, weil es die akzeptierte Form verbreitern würde.

## Implementierungsentscheidung

Die Pre-Mapping-Felder der beiden Common-Input-Fault-Records werden im puren
Helper und strikten Reader als exakt leer deklariert. Request-/Case-Identität
bleibt in authentifizierter Transaction, Access-Record, fester Konfiguration,
Own-Worker-Fault-Ledger und Cleanup-Event. Das aufbewahrte Source-Event wird nie
umgeschrieben.

## Geänderte Dateien und Tests

`tests/runners/nginx_common_input_faults.py`,
`tests/runners/nginx_native_operation_bundle.py`,
`tests/no_crs/test_nginx_common_input_faults.py`,
`tests/no_crs/test_nginx_native_operation_bundle.py` und dieses Record-Paar.
Positive Kontrollen decken beide Required-Cases ab; Negativkontrollen decken
nichtleere Methode oder URI sowie vorhandene Identitäts-, Rollen-, Phasen-,
Rule-, Reihenfolge-, Seal- und Pfadmutationen ab.

## Befehle und Ergebnisse

Fokussiertes RED: vier Pure-Helper-Fehler, weil nichtleere Felder akzeptiert
wurden (Log-SHA-256
`984446026f4a7c1afda32d1072cf9683f750de234cd1f2bb70e0311c6a0abf70`),
und ein versiegelter Bundle-Fehler an der alten URI-Gleichheitsprüfung
(Log-SHA-256
`2e09cc8e7a1c714aa0ae52ca7c7c29b490561404959a7d71be9b25c4af8c71b5`).
Fokussiertes GREEN: 30 Tests bestanden (Log-SHA-256
`df74f19ecb390bc8010ead80d08e78c175943f899efc6123d49d8d9dfab873ed`).
Die vollständige No-CRS-Contract-Suite bestand 405 Tests in 163,603 Sekunden
(Log-SHA-256
`a52e74f27d55a938adc4cd89e73964ee4a2021ac1bbf16e07b31b143cd417e8d`).
`make check-documentation` bestand. Der erste breite `make lint`-Versuch endete
mit Exit 2 am Repository-Root-Guard, weil ein geerbtes `FRAMEWORK_ROOT` auf
einen anderen Checkout zeigte (Log-SHA-256
`18b7c63ef0d732ecb34719ad419f732b655a35fee2f83908d54e6e3d060ed33c`);
er wird nicht als PASS gewertet. Ein frischer Lauf mit allen Repository-Roots
explizit an diesen Worktree gebunden bestand mit Exit 0, einschließlich NGINX-
Archiv/Digest-, Provenance-, Pin-, Workflow-, Katalog-, Dokumentations- und
finaler Whitespace-Prüfung (Log-SHA-256
`04cc905cee257a016a4c500f30297d15d94afe4e3aba4f0c06d13cad010793d6`).

## Sicherheitsauswirkung

Kein Validator wird deaktiviert. Die akzeptierte Form wird auf exakte leere
Strings verengt und bleibt an unveränderliche unabhängige Evidence gebunden.
Die Security-Prüfung fand einen Evidence-Vertragsdefekt, keine validierte
Schwachstelle.

## Dokumentation und Runtime-Evidenz

Dieses englisch/deutsche Change-Record-Paar dokumentiert den Framework-Vertrag.
R7 bleibt aufbewahrte Parent-Runtime-FAIL-Evidence, kein Framework-PASS und
wird nicht umetikettiert. Nach dem Fix lief noch keine gehostete Runtime.

## Nicht ausgeführte Prüfungen

Remote-CI/Sonar für den künftigen Commit, Parent-Gitlink-Integration, frischer
Build und der 97-Record-Lifecycle wurden noch nicht ausgeführt. Ruff bleibt
getrennt nicht verfügbar und wurde nicht ausgeführt.

## Einschränkungen und Restrisiko

Unit- und versiegelter Fixture-Erfolg belegen keine NGINX-Runtime. Der Parent-
Selector muss gemeinsam mit diesem Reader integriert werden; danach müssen
frische Exact-Source-Artefakte und echte Root/nobody-Requests finale Canonical-
Evidence erzeugen.

## Finaler Diff- und Review-Status

Fokussierter Diff und unabhängige Code-/Security-Prüfung fanden kein
handlungsrelevantes Problem; Dokumentation, 405 No-CRS-Tests und der korrekt
Root-gebundene breite Lint sind grün. Finaler Commit/Push/Readback und aktueller
Remote-Quality-Status stehen aus. Kein Merge, History-Rewrite oder MRTS-
Änderung.
