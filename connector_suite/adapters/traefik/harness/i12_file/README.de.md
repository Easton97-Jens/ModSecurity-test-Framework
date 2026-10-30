# Physisch dateibasierter HTTP-Zusatznachweis für Traefik I12

**Sprache:** [English](README.md) | Deutsch

Für die folgenden aktuellen Quellcheckout-Befehle beide Checkouts, einen
kompatiblen Interpreter und vorhandenen freigegebenen externen Speicher explizit
wählen. Diese Beispielpfade durch tatsächliche physische Pfade ersetzen;
Quellvorbereitung verlangt weiterhin die beschriebene unabhängige Zulassung und
autorisiert keinen Hostlauf.

```sh
export CONNECTOR_ROOT="/absolute/product/checkout"
export CONNECTOR_REVISION="$(git -C "$CONNECTOR_ROOT" rev-parse HEAD)"
export TEST_ROOT="/absolute/framework/checkout"
export FRAMEWORK_ROOT="$TEST_ROOT"
export FRAMEWORK_PYTHON="/absolute/framework-venv/bin/python"
export CODEX_TEMP_ROOT="/absolute/approved/external/storage"
export I12_TEST_ROOT="$CODEX_TEMP_ROOT"
export CONNECTOR_TEST_OUTPUT_ROOT="$CODEX_TEMP_ROOT"
export PYTHONSAFEPATH=1
export PYTHONPATH="$TEST_ROOT:$TEST_ROOT/connector_suite"
```

Dieser Producer misst eine reguläre Datei, die der tatsächliche HTTP-Client oder
Ziel-Backendprozess liest, und überträgt ihre Bytes über die vorhandenen
Traefik-Byte-APIs. Er ruft keine native SDK-File-Body-API auf und weist sie nicht
nach. Alle vier Original-IDs in
[supplement-plan.json](supplement-plan.json) bleiben unqualifiziert. Der physische
HTTP-Zusatznachweis lässt die native File-API-Pflicht offen. Eine unabhängige
Prüfung muss Regeln, Phasen und Erwartungen vor einem Hostlauf freigeben.

`acceptance.py` deklariert neun getrennte Ausführungen für die vier Original-IDs:
jeweils benign und Marker, zusätzlich die ForwardAuth-Requestkapazitätskontrolle.
Jede besitzt getrennte File- und Transaktionsschlüssel, exakte Dateigröße/-hash,
vollständige erzeugte Regeln und Regel-/Erwartungshashes. Der Requestmarker
erwartet P2-Regel 1100101 und 403. ForwardAuth verlangt Backendausschluss; Native
misst tatsächliches accept, Header und Bodypräfix, weil Dispatch vor Abschluss
von P2 beginnt. Der Responsemarker erwartet P4-Regel 1100301 und Safe-Clientstatus
200 mit exakt der Datei-Entity.
Die 4199-Byte-Kapazitätskontrolle der Default-MRC1-ForwardAuth-Kette erwartet
Hoststatus 401 ohne Sample/nativen Vorgang/Backend. Dies sind Erwartungen vor
dem Lauf, keine Beobachtungen oder automatischen Qualifizierungen. Tatsächlich
erzeugte Regeln und diesen Vertrag im unveränderlichen Admission-Ledger binden.
Beide Traefikprofile haben `strict_post_commit_action=0`; Strict ist ausschließlich
ein Konfigurations-/Startupnegativ ohne Zieltransaktion.

`source.py` öffnet ein lesereigenes privates Verzeichnis mit Modus 0700 und eine
einzelne relative reguläre Datei mit Modus 0600 über `O_NOFOLLOW`. Hardlinks,
Symlinks, nichtreguläre Dateien, falsche Eigentümer/Modi, falsche Größe/Hash,
verkürzte Reads, Pfadaustausch und erkennbare Änderungen an Größe/mtime/ctime/Inode
führen zum Fehler. Ein vollständiger Beleg enthält PID, monotone Zeitstempel,
Gerät/Inode/Eigentümer/Modus, Stat vor/nach dem Lesen, jeden Offset und
Read-Aufruf/-Rückgabewert/Chunk-Hash, Gesamtbytes/-hash, physisches EOF und die
tatsächlichen Close-Ergebnisse. Reads und Callbacks erfolgen synchron; der
Quelldateileser hält höchstens einen 24-Byte-Fixture-Chunk. Fehler behalten ihren
unvollständigen Beleg und schließen beide Deskriptoren. Der tatsächliche
Quellpfad lädt keinen vollständigen Body vor und dekodiert keine Hex-Payload.

Manifeste begrenzen Quelldateien auf 512 KiB, einzelne Reads auf 64 KiB und
Belege auf 4096 physische Reads. HTTP-Request- und Response-Wirebeobachtungen sind
auf 1 MiB begrenzt, einschließlich des Request-Chunkframings.

Jeder physische Read wird ein separat gerahmter HTTP-Chunk. TCP/HTTP dürfen
Schreibvorgänge zusammenfassen; native Chunkgrenzen benötigen weiterhin echte
Capture-Belege. Der abschließende HTTP-Chunk wird erst nach Quellenprüfung und
Close gesendet. Die sendall-Rückkehr belegt ausschließlich lokale Annahme.
Quelldatei-EOF, HTTP-Endmarker und TCP-EOF beweisen kein natives EOS. Die Adapter
lassen `native_eos=null` und leiten weder Commit, Finish/Free, Inspection noch
entfernte Zustellung ab. Tatsächliche Client-Responsebytes einschließlich eines
Präfixes vor Reset/Timeout bleiben unverändert erhalten.

Die Request- und Response-Marker liegen über zwei physische 24-Byte-Reads verteilt.
Die 4199-Byte-Requestkontrolle setzt ihren Marker an Offset 4160. Der aktuell
festgelegte ForwardAuth-Vertrag hat `forwardBody=true,maxBodySize=4096`; deshalb
ist dies eine Hostkapazitäts-Ablehnungskontrolle. Tatsächlichen Status sowie das
Fehlen jedes Autorisierungssamples, nativen Vorgangs und Backendzugriffs prüfen.
Kein weitergeleitetes, inspiziertes 4096-Byte-Präfix annehmen.
`maxResponseBodySize=32768` bleibt die getrennte Kapazitätsgrenze für die
Autorisierungsresponse.

Für Response-Belege akzeptiert `response_backend` genau einen korrelierten
Zielrequest und protokolliert accept vor Requestlesen und Quelldateiöffnung.
Vorhandenes unabhängiges Nachbarbackend und dessen Router erhalten. Gegen dieses
Backend für einen Zielrequest niemals einen TCP-Readinessprobe senden. Sein
Listening-Beleg beweist nur bind/listen; echte Hostbereitschaft muss über die
getrennte Nachbarroute geprüft werden.

## Integrationsübergabe

Es wurde kein Hostlauf durchgeführt. Der JSON-Plan enthält die vier exakten
Original-IDs, Capture-Varianten, Quellenkontrollen und noch erforderlichen Belege.
Neue versiegelte Admissions auf Grundlage der bereits geprüften Native-/Auth-
Infrastruktur erstellen und sämtliche Adapter-/Fixture-/Manifesthashes in deren
unveränderlichen Ledgers binden. Die Python-Dateien gemeinsam stagen, damit
`run.py` seine benachbarten Module importiert. Getrennte frische lesereigene
Quell- und Belegverzeichnisse mit Modus 0700 erstellen.

Der Controller verwendet folgende Argumentverträge mit vorab zugelassenen
literalen Pfaden, Ports und Transaktionsschlüsseln:

```text
run.py stage --manifest MANIFEST --fixture-root FIXTURES --private-root PRIVATE --evidence-root EVIDENCE
run.py client --manifest MANIFEST --fixture request-marker.txt --private-root PRIVATE --evidence-root EVIDENCE --port HOST_PORT --key EXACT_KEY --uri /no-crs/request-body
run.py backend --manifest MANIFEST --fixture response-marker.txt --private-root PRIVATE --evidence-root EVIDENCE --port BACKEND_PORT --key EXACT_KEY
```

`--transaction-id EXACT_NATIVE_ID` übergeben, wenn `X-Request-Id` vom Fileschlüssel
abweicht. `X-I12-Acceptance-Key` enthält stets den File-Zielschlüssel; das Backend
prüft beide exakten Header vor Dateiöffnung. Prozessidentität, Quellenbelege,
HTTP-Rawbytes und Entityhashes bleiben getrennt; der Parent erhält den echten
Waitstatus. Vollständiges HTTP-Framing wird unabhängig von TCP-EOF und nativem
EOS dekodiert.

Aufruf über die geprüfte Python-/RTK-Grenze des Controllers. Einmal stagen, dann
den tatsächlichen Leser als getrennten Client-/Backendprozess starten und dessen
Waitstatus erfassen. Ein Requestfile nutzt das vorhandene unabhängige Zielbackend;
ein Responsefile den vorhandenen benignen Zielclient mit `/no-crs/allow`. Nur die
exakte Transaktionsallowlist im wegwerfbaren Capture-Staging erweitern. Zentrale
Varianten `traefik-native` und `traefik-forwardauth`, Autorisierungsrelay,
native/Observer-Ereignisse, Client-Rawbytes, UDS-Belege und Cleanup erhalten.

Fehlende Datei, Symlink, nichtreguläre Datei, Mutation und Short-Read werden lokal
negativ geprüft. Für Hostnegative den zugelassenen Fehler in einer frischen
Quelle herstellen, Fehlerbeleg und Prozess-Waitstatus erhalten und tatsächlichen
Engineabbruch, einmaliges Finish/Free, gesunde Nachbarn und Cleanup prüfen. Ein
Quellenfehler lässt den HTTP-Endmarker aus und darf keinen Erfolg qualifizieren.
Vollständiges natives EOS, Commitreihenfolge, erste native Ursache, Inspection,
Backendeinschluss/-ausschluss und Observer-Korrelation bleiben eigene
Hostbelegpflichten.

## SDK-Grenze und Validierung

`sdk_capability.c` kompiliert/verlinkt die Requestfile-Funktion und beide
Byte-Append-Funktionen strikt, ohne sie aufzurufen. `sdk_capability.py` bindet
exakte Header-/Bibliothekshashes und inventarisiert C-Deklarationen/-Exporte.
Das installierte SDK 3.0.14 besitzt `msc_request_body_from_file`, aber keine
Responsefile-C-Deklaration und keinen solchen Export. Dieser Fähigkeitsbeleg
beweist weder produktive Routenaufrufe noch Ausführung der Requestfile-API.
Byte-Append nicht durch einen Test-File-API-Hook ersetzen und keine Responsefile-
API erfinden.

Fokussierter On-demand-Aufruf mit der obigen expliziten Umgebung:

```text
ON_DEMAND_TESTS=1 rtk proxy "$FRAMEWORK_PYTHON" -P -B -m unittest -v modsecurity_connector_tests.test_traefik_i12_file_source
```

Die Tests prüfen echte Child-Dateileserprozesse, physische Negative,
Read-/Hashzuordnung, vollständiges/unvollständiges HTTP-Framing über Socketpairs,
begrenzte Manifeste, Closefehler, dauerhaftes accept und Clientpräfixerhalt.
Das belegt ausschließlich die Producer-Schicht. Original-Oracles, Runtime-IDs,
zentrale Matrix, gemeinsame Generatoren, Framework/MRTS und produktiver Source
bleiben unverändert.

Das Child-Negativ für fehlende Dateien nutzt den unmittelbaren `ENOENT`-Pfad mit
`O_NOFOLLOW|O_NONBLOCK` und anschließendem Close des Rootdeskriptors. Ein früherer
paralleler Vier-Suiten-Lauf überschritt das unveränderte Prozessbudget von zehn
Sekunden; fokussierte Wiederholungen bestanden. Es wurden keine blockierenden
Quellpfadoperationen oder gelockerten Timeouts eingeführt.
