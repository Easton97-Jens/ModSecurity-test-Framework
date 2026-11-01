# Traefik-native I12-Hostmessungen

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

`prepare.py` verwendet die vorhandenen zentralen `traefik-native`-Capture-Objekte
und kopiert historische Build-Grundlagen in eine ausdrücklich gewählte externe
Wurzel. Alle Common-/Traefik-C-/Header- und nativen Go-Build-Eingaben werden vor
den exakt hashgeprüften Beobachtungs-Overlays aus dem aktuellen Checkout erneuert.
Produkt-/Capture-Bindung, versiegelte Dateiledger und Controller-Zulassung bleiben
von der Laufzeitqualifikation getrennt.

Die sieben Hostproben umfassen einen Chunked-Request, verzögerte Response-Writes,
P1-/P2-/P3-Ablehnung, späte P4-Safe-Ablehnung, MIME-Ausschluss und unabhängigen
Nachbarverkehr. Der separate Client bewahrt Socketbytes auf; das Backend hält
empfangene Entitybytes fest. Ein in P1/P2 abgelehnter Request darf das Backend
nicht erreichen. MIME-/Charset-Entscheidungen, natives EOS, Finish und Free
benötigen native Observer-Datensätze. TCP-EOF belegt nur die Transportbeobachtung.
Ein erfolgreicher Clientprozess bedeutet eine abgeschlossene Messung; das
tatsächlich erwartete Ergebnis steht in `oracle_pass`.

Die Vorbereitung startet keinen Host:

Die Vorbereitung benötigt `CODEX_TEMP_ROOT` mit der vorhandenen konfigurierten
externen Speicherwurzel. Die Variable vor diesen Befehlen aus der aktiven
Projektkonfiguration exportieren. Das Ausgabeziel muss ein neuer physischer
Unterpfad sein; vorhandene Vorfahren innerhalb dieser Wurzel müssen der
aufrufenden UID gehören und Schreibzugriff für Gruppe und andere verbieten.

```sh
rtk proxy "$FRAMEWORK_PYTHON" -P -B "$TEST_ROOT/connector_suite/adapters/traefik/harness/i12/native/prepare.py" \
  --repo "$CONNECTOR_ROOT" \
  --historical /absolute/approved/historical/source-run \
  --output "$CODEX_TEMP_ROOT/runs/task/native"
```

Nur den separat geprüften privaten Controller mit unveränderten Nonroot-
Zulassungsprüfungen und aufgabeneigenem Ressourcen-/Speicherbudget verwenden.
Vor dem Start `admission.json` und alle versiegelten Bindungen prüfen. Archivierte
Treiber weder gegen alte Evidence noch gegen einen Produktcheckout starten.
Die Ausgabewurzel muss für die Vorbereitung neu sein. Alle drei Prepare-Befehle
weisen Symlink-Pfade, Git-Checkout-Ziele und Pfade außerhalb des konfigurierten
externen Speichers vor Schreibzugriffen ab; Followups verlangen frische Ausgabeziele.

`review.py VERSUCHSVERZEICHNIS` fasst frische physische Client-/Backend-/Native-
und Hostdaten, Programm-/Bibliotheks-Mappings und Controller-Cleanup zusammen.
Bis zur unabhängigen Original-Oracle- und vollständigen Lifecycle-Paketprüfung
bleibt die Qualifikation ausdrücklich false. Das zentrale I12-Ledger bleibt
unverändert.

`prepare_followup.py ROOT faults-v3` erstellt eine separate UDS-Relay-Fixture
mit echter Engine für beschädigte MSE1-Antworten, interne Fehlerantworten,
`AcknowledgeApplied` mit tatsächlichem Opcode10, eine verzögerte16KiB-Response
mit Fehler im zweiten Chunk und aktiven Client-RST. Das physische Relay-Log
erfasst den exakt injizierten Opcode. `strict` prüft die Profilzulassung separat;
eine abgelehnte Strict-Konfiguration belegt keinen unterstützten Strict-Lifecycle.
`mime` prüft separat vorhandenen/fehlenden Request-/Response-Content-Type und
Charset sowie den MIME-Ausschluss.

Der zentrale Hostobserver lässt nur seine zwei historischen synthetischen IDs zu.
`prepare_host_scope.py ROOT` erstellt eine separate versiegelte Quellkopie, in der
ausschließlich diese Observer-Liste auf die 18 deklarierten synthetischen IDs
erweitert wird. Die Wiederholung nutzt deren `admission-*-host-v2.json`-Specs.
Frühere Läufe mit nicht zugelassenen IDs bleiben Teilmessungen.
`packet.py VERSUCH LABEL ORIGINAL_CASE_ID` liefert alle35 vorgeschriebenen
Beobachtungsfelder zur unabhängigen Prüfung; fehlende Callbacks bleiben unbekannt.
Oracle-Auswertung und Qualifikation erfolgen dabei nie. Echte Fehler können trotz
logischem Host-Write null Clientbytes ergeben; dieses physische Ergebnis getrennt
von HTTP-Recorder-Ergebnissen oder nativen Deny-Entscheidungen berichten.

Die aktuelle Vorbereitung exportiert jede versionierte reguläre Parent-Datei aus
dem exakten `HEAD`-Git-Baum, einschließlich Dateimodi, SHA256-Inventar und
Gitlink-Revisionsmetadaten. Git-Metadaten, Symlinks, Gitlink-Inhalte sowie nicht
committete/nicht versionierte Producer werden ausgeschlossen. `CODEX_TEMP_ROOT`
muss den konfigurierten privaten externen Speicherstamm bezeichnen; das Ziel
muss frisch und physisch darunter liegen. Der Exporter schreibt die vollständige
v2-Quellidentität vor Anwendung der vorhandenen zentralen Capture-Variante.
Anwendungsbeleg und eingefrorenes Inventar vor Capture erhalten tatsächliche
Quellrevision und Instrumentierungs-Hashes. Reine Fixture-Änderungen,
einschließlich nicht committeter Abnahme-Producer, benötigen separate explizite
Hashes; sie erben niemals eine Identität committeter Quellen. Die Vorbereitung
startet keinen Host und belegt keine Runtime-Qualifikation.
