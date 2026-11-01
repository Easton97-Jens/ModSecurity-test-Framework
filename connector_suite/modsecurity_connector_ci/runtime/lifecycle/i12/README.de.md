# Private I12-Capture-Quellen

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

Dieser reine Test-Quellvertrag erhält die exakten NGX-, HAProxy-, Envoy-, Apache-,
Traefik- und lighttpd-Capture-Implementierungen der I12-Prüfung. Er ändert keine
Connector-Produktdateien und startet keinen Host. Quellanwendung, Konfigurationsladen,
Build oder Treiber-Exit belegen keine Runtime-Abnahme. Root prüft physische
Originalbeobachtungen und das unabhängig belegte Oracle gesondert.

`manifest.json` ordnet logische Quelldateinamen SHA256-Objekten zu. Identische
Collector-, Client- und Backenddateien liegen einmal vor. Nahe Varianten sind
exakte Unified-Deltas gegen gemeinsame Objekte. Header und SDK-Accessor bleiben
Repository-Verweise; die historische C-Basis `0d903fc5…` ist als verlustfreie
Zeilendaten eingefroren. Historische C52/H5-, C270/H5- und Ca4/H581-Varianten
bleiben hashgebundene Deltas ohne kopierte Beobachterbäume. Die aktuelle gemeinsame
Observeridentität ist C `5038d006…`, H `5b7d8fa7…`, SDK-Accessor `89ff282b…`;
vollständige Hashes stehen im Manifest.
Historische Profileingabehashes binden an
`8cc32dceb06121f589150a9794f28878c5e4ba2a`; die unten beschriebene
Revisionsbindung aktueller Kopien bleibt davon getrennt. Historische,
im jeweiligen Umfang bytegleiche Revisionen und unterschiedliche Beobachter-ABIs
bleiben ausdrücklich erhalten.
Gespeicherte Deltas nutzen null Kontextzeilen; vollständige Basis- und
Ergebnishashes binden weiterhin jedes Byte, echte Patchanwendung wird ohne Fuzz
geprüft. Ein archivierter Helper mit ursprünglichen nachgestellten Leerzeichen
verwendet transparente JSON-Zeilenspeicherung. Beim Export entstehen seine exakten
Originalbytes; Quellen werden für die Leerzeichenprüfung weder beschnitten noch
normalisiert.

| Quellvariante | Getrennter Capture-Umfang |
| --- | --- |
| `nginx` | Exaktes Host-Overlay für drei Übersetzungseinheiten, typisierter Hosthelper, Treiber/Backend und gewarteter Client; unterstützte Safe-Fixture09 |
| `haproxy-direct` | Native HTX-Binding/Filter und SSL-Write-Erfassung |
| `haproxy-companion-host` | Separate Response-Companion-Hostvariante |
| `haproxy-spop-agent` | Separater diagnostischer Request-Agent/Backend |
| `envoy` | Gemeinsame ext_proc-/authz-Capture-Quelle; tatsächliches authz-Backend und eigenes ext_proc-Backend getrennt erhalten |
| `apache` | Historische exakte Overlays für drei Produktdateien sowie APR-/Native-/Hosthelper |
| `apache-current` | Gleiche Apache-Capture-Ergebnisbytes; aktuelle native C-/H-Basishashes und verpflichtender vollständiger v2-Export |
| `lighttpd` | Getrennte Stock-Sidecar-/patched-native-Fixtures einschließlich ursprünglicher und leerer Fälle |
| `traefik-native` | Tatsächliche native-UDS-Middleware-/Engine-/Runtime-Beobachtungsvariante |
| `traefik-forwardauth` | Separate Autorisierungs-/Response-Observer-Quellvariante |

Die zehn **Quellanwendungsprofile** umfassen neun historische Varianten plus
`apache-current`. Die Zahl der Runtime-Routen bleibt davon unabhängig.
Gemeinsame Quellen übertragen niemals Ausführung, EOS, Identität oder Ergebnis
auf Geschwisterrouten. Framework-/MRTS-Repositories und Gitlinks bleiben außerhalb
dieses Vertrags. Private Fixturedefinitionen sind laufbezogene Capture-Eingaben,
keine Ergänzung des wiederverwendbaren Katalogs.

## Unveränderliche Quellaufzeichnungen und gepflegter Analysecode

Die 61 historischen quellcodeartigen `text`-Objekte und der historische
Repository-Anker des gemeinsamen C-Observers sind jetzt als verlustfreie
`text_lines`-JSON-Daten gespeichert. Diese 62 Objekte rekonstruieren 346.634 exakte
ursprüngliche Bytes. Zusammen mit den 10 vorhandenen Zeilenobjekten enthält die
Registry 72 Zeilenobjekte, 16 andere Textobjekte, 48 Deltas und 19
Repository-Objekte. Jeder JSON-String erhält ursprüngliche Zeilenenden und
Leerzeichen. Der 53.532 Byte große C-Observer-Anker ist gegen Commit
`30d50a181278904a552e295d9a2c1ae1265e8b87` authentifiziert und behält die Identität
`0d903fc5e6432769a136931b7ebea16a6f87db941d28d23583ccccf4c75e6537`.
Die Rekonstruktion muss die ursprünglichen Bytes
und SHA256-Identitäten exakt ergeben. Historische Profilbindungen,
Vorher-/Ergebnishashes und Deltaidentitäten bleiben unverändert. Die expliziten
C-Pins aktueller Kopien in `apache-current`, `traefik-native` und
`traefik-forwardauth` binden den aktuellen Observer `5038d006…`; die historischen
Capture-Ergebnisbytes bleiben dadurch unverändert. Die Registry verweigert
Quellcode-Endungen in einfachem `text`-Speicher und verlangt für `text_lines`
`.json`-Speicher. Das Materialisieren geprüfter historischer Bytes in einer
ausdrücklich wegwerfbaren Kopie bleibt ein eigener Vorgang und begründet weder
Ausführung noch Qualifikation der aktuellen Revision.

Die aktuelle Envoy-Auswertung nutzt die gepflegten Module
`envoy/host_log_observations.py` und `envoy/grpc_stream_observations.py`.
Aktuelle Verbraucher führen keine Module aus dem Objektspeicher oder einem per
CLI ausgewählten Helper-Verzeichnis aus. Erhaltene Helper-Dateien werden nur
zur Authentifizierung historischer Herkunft gelesen. Neue Reviews und
Originalfallpakete erfassen die gepflegten Parserhashes getrennt von den
historischen Helperhashes. Historische Berichte und Freigaben behalten ihre
ursprünglichen Identitäten; sie werden nicht als Ergebnisse der neuen Parser
umgedeutet.

Die CI-Sonar-Analyse aus master klassifiziert Python-Testdateien über
`sonar-project.properties` und verwendet Python `3.15`. Gepflegte Quellen,
Validatoren, Parser und Tests bleiben analysierbar. Für diesen Speicherwechsel
wird kein Issue-, Quellen- oder Duplikationsausschluss verwendet.

## Prüfen und anwenden

Mit der obigen expliziten Quellcheckout-Umgebung:

```sh
rtk proxy "$FRAMEWORK_PYTHON" -P -B "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/i12/capture_sources.py" verify
ON_DEMAND_TESTS=1 rtk proxy "$FRAMEWORK_PYTHON" -P -B -m unittest discover -s "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/i12" -p test_capture_sources.py -v
```

Tests verlangen mit `I12_TEST_ROOT` oder `RUNNER_TEMP` vorhandenen genehmigten
externen Speicher und schreiben dort ausschließlich temporäre Daten. Die
Quellanwendung nutzt die im Manifest festgelegte externe Speicherwurzel.

Eine **wegwerfbare Quellkopie** ohne Git-Metadaten, Symlinks oder Hardlinks
vorbereiten. Die benötigten Basisdateien aus `source_targets` der gewählten
Variante kopieren; jeder nichtleere `before_sha256` muss exakt übereinstimmen.
SDK-/Upstream-Quellen, erzeugte Header und Toolchains sind separate Build-Eingaben,
keine beigepackten Artefakte. In der externen Kopie
`.i12-disposable-source-copy.json` mit genau folgendem Inhalt anlegen:

```json
{
  "format": "i12-disposable-source-copy-v1",
  "path": "/absolute/external/disposable-i12-copy",
  "disposable": true,
  "parent_sha": "8cc32dceb06121f589150a9794f28878c5e4ba2a"
}
```

Der Pfad muss die tatsächliche physische Kopie bezeichnen. Danach beispielsweise:

```sh
rtk proxy "$FRAMEWORK_PYTHON" -P -B "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/i12/capture_sources.py" apply --profile nginx --source-copy "$CODEX_TEMP_ROOT/disposable-i12-copy"
```

Das Werkzeug prüft vor jedem Schreiben sämtliche Basen und Objekte, wendet
exakte Kontextdeltas ohne Fuzz an und protokolliert die Ergebnishashes in
`i12-source-application-receipt.json`. Capture-Programme entstehen unter
`.i12-capture/<variant>/` und werden weder importiert noch ausgeführt. Fehlende
Marker, geänderte Basen oder Deltas, Git-Checkouts/-Metadaten, Symlinks, Hardlinks,
Pfadausbrüche und vorhandene Capture-Ziele werden abgelehnt. Git-Metadaten der
ausdrücklich festgelegten externen **Speichersteuerung** liegen außerhalb des
wegwerfbaren Teilbaums; sie erlauben keinen darin verschachtelten Checkout.

## Aktuelle Revision und vollständiges Exportinventar

Der v1-Marker und seine feste historische Eingabebasis bleiben unverändert
unterstützt. Aktuelle Quellkopien verwenden **v2**. Eine aktuelle Revision darf
niemals als diese historische Basis bezeichnet werden. Der vertrauenswürdige
Quellproduzent exportiert den vollständigen committeten Parent-Baum mit
`git archive` und erfasst mit `git ls-tree` Dateimodi, Baumidentität und
Gitlink-Revisionen. Gitlink-Inhalte sind ausgeschlossen. Der Produzent bindet
Git-Befehle und exakte Revision unabhängig; allein 40 Hexzeichen im Marker
belegen dem Capture-Werkzeug keine authentische Commitzuordnung.

Der v2-Marker enthält genau folgende Felder:

```json
{
  "format": "i12-disposable-source-copy-v2",
  "path": "/absolute/external/disposable-current-copy",
  "disposable": true,
  "source_revision": "850879e82ea729f274cb383507b05938df06027a",
  "snapshot_manifest": ".i12-source-export-manifest.json",
  "snapshot_manifest_sha256": "<complete lowercase SHA256 of the frozen inventory>"
}
```

Beispielpfad/-revision und SHA256-Platzhalter durch die tatsächlich gebundenen
Produzentenwerte ersetzen. `.i12-source-export-manifest.json` enthält genau
`format` (`i12-source-export-manifest-v1`), `source_revision` (gleich dem Marker),
`git_tree` (vollständige Git-Baumidentität aus 40 kleinen Hexzeichen), `files`
und `gitlinks`. `files` ordnet **jeder** exportierten regulären Parent-Datei genau
`{"mode": 420, "sha256": "<complete lowercase SHA256>"}` zu; ausführbare
Git-Dateien nutzen Modus 493 statt 420. Der Dateihash bindet alle Bytes, auch
binäre Fixtures. `gitlinks` ordnet jedem exportierten Gitlink-Pfad seine
vollständige Revision aus 40 Hexzeichen zu; fehlende oder leere
Gitlink-Verzeichnisse sind erlaubt, ihre Inhalte nicht. Beide Zuordnungen nutzen
begrenzte relative Pfade ohne Git-Metadaten oder Pfadausbrüche.

Nur Marker und Inventar selbst sind vom vollständigen Dateiinventar ausgenommen.
Doppelte Felder, unbekannte Schemafelder, abweichende Revisionen/Hashes, fehlende
oder zusätzliche Dateien/Verzeichnisse, falsche Dateimodi, Links, spezielle
Dateisystemobjekte und Gitlink-Inhalte werden vor Capture-Schreibzugriffen
abgelehnt. Jeder gewählte Profilwert `before_sha256` wird weiterhin unabhängig
geprüft; ein gültiger neuer Snapshot erlaubt keine geänderte Capture-Basis.
Die Prüfung liest sämtliche Inventardateien und lehnt Änderungen während der
Hashberechnung ab. Das vollständige eingefrorene Inventar bleibt nach der
Quellanwendung erhalten und beschreibt die Quelle **vor Capture**, keine
Buildausgaben. Nach Capture in einem getrennten Verzeichnis bauen; eine benutzte
Kopie kann nicht erneut als unberührter Export eingereicht werden.

Für den vollständigen v2-Export des aktuellen committeten Checkouts
`--profile apache-current` verwenden. Dieses zusätzliche Profil ändert nur die
nativen C-/H-Werte `before_sha256` von `ad8e5e36…`/`f9f63b62…` auf
`5038d006…`/`5b7d8fa7…`; sämtliche Capture-Ergebnisbytes, Produkt-Overlays,
SDK3.0.14-ABI und das historische Profil `apache` bleiben unverändert. Sein
`required_source_identity_format` lehnt v1-Marker vor jedem Schreiben ab, auch
wenn die Quellbytes ansonsten passen. Die Registry-Prüfung lehnt unbekannte
Pflichtformate ab. Der Quellanwendungsname erzeugt keinen neuen Lauf, keine
Transaktion und keine Runtime-Route: Das native Profil bleibt `apache-native`.
Historische Paket-/Buildherkunft bleibt als historisch gekennzeichnet; ein neuer
Vollbuild und tatsächlich geladene Images benötigen eigene Nachweise.

Die integrierte gemeinsame Korrektur erhält fünf historische HAProxy-/lighttpd-
Objekte als verlustfreie Textzeilenobjekte. Inhalts-Hashes und historische Ergebnis-
Hashes bleiben unverändert. Die Registry prüft 155 Objekte; diese Zahl zählt weder
Hostausführungen noch qualifizierte Anforderungen.

Der Anwendungsbeleg erfasst `source_revision`, `source_git_tree`, Inventar-SHA256,
Dateizahl und Gitlink-Metadaten getrennt von `delivery_product_baseline`. Ein
aktueller Build erhält dadurch keine historische Basisidentität. Beleg, Inventar,
Produzentenbefehle und Quellhashes zusammen mit Instrumentierungsdelta und
Build-/Ladenachweisen aufbewahren. Inventar und Beleg beweisen ausschließlich die
Quellanwendung, keinen vollständigen Build, keine geladene Modulidentität und
keine abgenommene Hosttransaktion.

Der aktuelle gemeinsame Beobachter übernimmt die `char *`- oder
`const char *`-Qualifikation des gewählten öffentlichen SDK-Konstruktors, ohne
Compilerwarnungen zu entfernen. Historische `ad8e5e36…`-/`f9f63b62…`-Objekte bleiben
exakte Rückwärtsdeltas ihrer festgelegten Basisobjekte; die C-Basis ist unabhängig
vom aktuellen Observer eingefroren. Alle bisherigen Profil-
und Objektergebnishashes bleiben unverändert; native ABI-Varianten benötigen
weiterhin ihre eigene vollständige Buildbindung.

## Build-, ABI- und Evidenzgrenzen

Erhaltene Vorbereitungs-, Build- und Treiberskripte sind exakte Quellnachweise.
Einige enthalten historische Laufpfade; andere nutzen die versiegelte Controller-ABI
`/mnt/src`, `/mnt/fixtures`, `/mnt/artifacts` und `/task`. Vor einem neuen Lauf
Quellen prüfen und Pfadverlagerungen reviewen. Verlagerte oder geänderte Bytes
benötigen eine neue Quell-/Hashbindung. Das Werkzeug ersetzt, lockert oder umgeht
keine UID-, Peer-, Ressourcen-, Ownership-, Dateisystem- oder Capability-Prüfung
des genehmigten Controllers. Archivierte Launcher nicht direkt gegen einen
Produktcheckout oder ein altes Evidenzverzeichnis ausführen.

- NGX bindet nginx1.31.6, SDK3.0.14 und die ursprünglichen 33 Parent-Dateien plus
  eine erzeugte Registrierungsdatei. Fixture09 verzichtet auf natives MIME Clear:
  SDK3.0.14 verwirft beim Merge mit Clear auch MIME-Ergänzungen desselben Ladevorgangs.
  Fixture08 bleibt der getrennte gemessene MIME-out-Fall. Native Limits und
  MIME-Entscheidungen gehören dem SDK. Der Treiber enthält einen echten HTTP-Backendserver
  in einem eigenen Thread; Clients sind getrennte gewartete Prozesse.
  Connection-/URI-/Header-Add-APIs bleiben nicht interceptiert.
- HAProxy bindet3.2.25, SDK3.0.14, die festgelegten37 GNU-Wraps und den eigenen
  SSL_write-Helper. Direct-, Companion-Host- und Agentquellen sind unterschiedlich.
  Öffentliche `openssl.cnf`-Dateien sind nur Konfiguration; Schlüssel oder
  Zertifikate sind nicht enthalten.
- Envoy bindet den erfassten Go1.27.2-/nativen SDK3.0.14-Vertrag. Die acht exakten
  C-/Go-/Build-Quelländerungen und zwei Go-Regressionsdateien für Quellkopien bleiben
  von physischer Hostevidenz getrennt. Vorhandene strenge CL-/Chunked- und
  gRPC-Endparser-Kontrollen bleiben erhalten und sind nach Materialisierung ausführbar.
- Apache bindet2.4.66/APR1.7.6/SDK3.0.14. Das historische C17/F-PIC/no-LTO-Overlay
  verlinkt Basismodulobjekte mit echten APR-Flags/System-Apache-Headern neu;
  damit wird kein sauberer vollständiger Modulneubau behauptet.
- lighttpd bindet1.4.85/SDK3.0.14. Patched native benötigt den vorhandenen Repository-Patch
  `connectors/lighttpd/patches/0001-lighttpd-msconnector-stream-hooks.patch`, seinen
  exakten Manifesthash und `LIGHTTPD_MSCONNECTOR_STREAM_HOOK_ABI_VERSION=2`.
  Stock-Module sind inkompatibel. Passende erzeugte Core-Header und vorhandene
  native Buildskripte verwenden. Geliehene synchrone HTTP/1.x-Entity-Callbacks
  erfolgen vor Transfer-Framing; HTTP/2 ist ausgeschlossen.
- Traefik native und forwardAuth erhalten getrennte exakte Quell- und
  Beobachterrevisionen. Native C-/Go-/SDK-Build-Eingaben benötigen die zuständige
  native Rezeptur; dieser Export belegt keinen frischen Build und keine Hostversion.

Compilerwarnungen, native Pins, SDK-eigene Bodylimits, ursprüngliche unbekannte
Oracles und historische Beobachtungen bleiben unverändert. Das Manifest schließt
Schlüssel, Zertifikate, Binärdateien, Archive, Caches, Git-Metadaten und schwere
Rohdaten aus. Jeder neue Lauf benötigt weiterhin unabhängig gebundene geladene
Images, effektive Konfiguration, echte Clients/Backend, native Phasen/EOS/Finish/Free,
physische Logs, Cleanup, Nachbargesundheit und Root-Review.

## Beabsichtigte null-Werte ursprünglicher Oracles

Der Oracle-Reconciler akzeptiert `intentional_null_fields.visible_status` nur
bei einem ursprünglich ausdrücklich vorhandenen `visible_status: null` ohne
Unresolved-Grund der Erwartung. Root muss dieses Feld separat interpretieren
und physische, versionierte Primärbelege liefern, die an die unabhängigen Quellen
des Records gebunden sind. Das vollständige effektive Oracle muss semantisch
bytegleich zum Original bleiben; die Erklärung darf keine Korrektur oder
Ersatzerwartung begleiten. Fehlende Felder `native_result`, `phase` oder
`visible_status` werden weiterhin abgelehnt. Beispielsweise bleibt der Clientstatus
im ursprünglichen Vertrag `phase2_over_limit` konfigurationsabhängig; dessen null
ist von einer unbekannten Fixture oder einer fehlenden Messung zu unterscheiden.

Diese reine Quelldisposition erhält den ursprünglichen null-Wert und vergibt keine
Lifecycle-Qualifikation. Client-/Hostbeobachtungen, sämtliche anwendbaren
Lifecycle-Felder, frische Ausführung und getrennte Root-Paketprüfung bleiben
verpflichtend. Andere null-Felder und ursprünglich unaufgelöste Oracles dürfen
diese Ausnahme nicht verwenden.

## Geprüfte aktuelle Traefik-Eingabebasen

Die vorhandenen Varianten `traefik-native` und `traefik-forwardauth` akzeptieren
für ihre beiden gemeinsamen Observer-Eingabedateien auch
`current_before_sha256`, ausschließlich nach erfolgreicher vollständiger
v2-Inventarprüfung. Dies sind explizite, geprüfte Manifest-Hashes, niemals aus
der gelieferten Kopie abgeleitete Werte. Der ursprüngliche `before_sha256` und
sämtliche instrumentierten Ergebnis-Hashes bleiben unverändert. Ein v1-Marker
kann die aktuelle Alternative nicht wählen. Der Anwendungsbeleg erfasst
`actual_before_sha256` für jedes Quellziel, einschließlich `null` für neue Dateien.
Unbekannte Quellbytes und Änderungen außerhalb der ausgewählten Ziele werden
weiterhin zurückgewiesen.

Drei historische HAProxy-Repository-Objekte sind als verlustfreie `text_lines`
gegen Commit `8cc32dceb06121f589150a9794f28878c5e4ba2a` authentifiziert eingefroren.
Ihre Identitäten und sämtliche abhängigen Delta-/Ergebnisidentitäten bleiben
unverändert. Dadurch bleibt historische Quellprüfung bei fortgeschriebenen
unabhängigen Produktdateien möglich; daraus entsteht weder ein neuer
HAProxy-Runtime-Nachweis noch eine Profilerweiterung.

Drei historische Traefik-Anker (`common/runtime/msconnector_runtime.c`,
`common/runtime/http_authorization_service.c` und
`connectors/traefik/response_observer/observer.go`) sind ebenfalls als verlustfreie
`text_lines` eingefroren und gegen Commit
`3a1bafecd0c38ccf20427d580c767ed42addf4aa` authentifiziert. Ihre ursprünglichen
SHA256-Identitäten, abhängigen Deltas, Profileingabe-/Ergebnishashes und Herkunft
bleiben unverändert. Dies repariert die historische Registry-Prüfung bei
fortgeschriebenen Produktdateien; daraus entstehen weder eine Freigabe geänderter
aktueller Eingabebytes noch Runtime-Nachweise.

Der historische NGINX-Anker
`connectors/nginx/src/ngx_http_modsecurity_access.c` ist ebenfalls als
verlustfreie `text_lines` eingefroren und gegen Commit
`c03352ba160675a94bf63125cceaa25367f52c27` authentifiziert. Seine ursprüngliche
SHA256-Identität, das abhängige Beobachtungsdelta und die Profilhashes bleiben
unverändert. Dadurch bleibt die vollständige Registry-Prüfung nach Fortschreibung
der aktuellen NGINX-Produktquelle gültig; daraus entsteht weder eine Freigabe
aktueller Quellen noch ein Runtime-Nachweis.

Die gepflegten Traefik-Prozesskontrollen verwenden
`ci/lib/i12_process_observation.py`, statt einen historischen Driver zu
importieren. Kontrollen zur Inspektion oder Instrumentierung archivierten
Drivertexts beziehen diesen einschließlich exakter Hashprüfung über
`Registry.content`. Apache-Kontrollen rekonstruieren ihre festgelegten
C-/H-Aufzeichnungen ebenfalls vor Kompilierung in ein privates wegwerfbares
Testverzeichnis. Keiner dieser Vorgänge ergänzt Szenarien oder wertet
historische Nachweise auf.
