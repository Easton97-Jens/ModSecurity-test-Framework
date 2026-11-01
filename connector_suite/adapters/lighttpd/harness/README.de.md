# lighttpd-Harness

**Sprache:** [English](README.md) | Deutsch

Status: native Konfigurationslade-, Start- und minimale Runtime-Smoke-Pfade

Der Connector verfügt über vier native Harness-Skripte:

- `prepare_native_smoke.sh` schreibt unten temporäre Common- und Lighttpd-Konfigurationen
  `BUILD_ROOT` mit deaktivierten beiden Körpermodi;
- `check_lighttpd_config.sh` lädt das reale Modul über reales `lighttpd -tt`;
- `start_lighttpd_smoke.sh` startet, prüft und stoppt lighttpd ohne Anfragen;
- `runtime_lighttpd_smoke.sh` sendet separat eine erlaubte und eine blockierte Anfrage.

Die entsprechenden Ziele sind:

```sh
make -C connectors/lighttpd check-lighttpd-config
make -C connectors/lighttpd start-smoke-lighttpd
make -C connectors/lighttpd runtime-smoke-lighttpd
```

Der Laufzeitrauch verwendet `OPTIONS *`, sodass der Lighttpd-Kern die zulässigen 200 zurückgeben kann
ohne nicht verwandte Bestandsmodule aus dem temporären Connector-Modul zu laden
Verzeichnis. Das Hinzufügen von `X-Modsec-Smoke: block` muss 403 aus der Regel `1000001` zurückgeben.
Das Skript überprüft auch die engen Common JSONL-Entscheidungsmetadaten.

`start-smoke-lighttpd` sendet bewusst null Anfragen und Berichte, die zählen.
Der Bridge-Selbsttest ist separat und wird niemals als Host-Beweis verwendet.

`run_lighttpd_smoke.sh` bleibt der Einstiegspunkt für das ältere Framework im Besitz
`sidecar_proxy`-Pfad. Es ist ein alternativer Weg und seine Beweise dürfen nicht sein
gemischt mit den Beweisen des nativen Moduls.

Der Dispatcher für den gesamten Lebenszyklus verwendet den generischen No-CRS-Bestandsläufer nicht wieder.
Es ruft `runtime-smoke-lighttpd-patched` auf
`full-lifecycle-lighttpd-patched`, das nur einen passenden Patch erstellt und lädt
Framework-synchronisiertes lighttpd-Kern/Modul-Paar. Das isolierte Ziel sendet das gleiche schmale Signal
Phase-1-200/403-Anfragen mit deaktivierten beiden Körpermodi; es ist kein Anfragetext,
Response-Body-, Phase-4- oder Capability-Promotion-Evidenz.

Nachweise zu Request-/Response-Bodies, CRS, Produktionshärtung,
Sicherheitsverifizierung und vollständiger Matrixabdeckung werden von diesem
Harness nicht bereitgestellt.

## HTTP/1.1-Pre-Upstream-Phase-2-Gate-Runner

`run_phase2_pre_upstream_gate.py` ist ein separater Repository-eigener Runner
für das ausgewählte gepatchte HTTP/1.1-`mod_proxy`-Request-Body-Profil. Er
nimmt einen frischen Task-eigenen Root, ein gestagetes passendes Lighttpd-
Binary/Modul, eine Rules-Datei und das libmodsecurity-Verzeichnis entgegen;
drei verschiedene private IPv4-Loopback-Ports wählt er selbst. Er startet
nur Task-eigene Foreground-Prozesse und zeichnet begrenzte Framing-/Zähler-
Metadaten auf, niemals Request-Nutzdaten.

Der Runner beweist, dass verzögerte Chunked-Phase-2-Deny-Bytes vor terminalem
EOS den Upstream weder verbinden noch erreichen, dass ein verzögerter
benigner Chunked-Allow erst nach EOS/Allow weitergeleitet wird und dass der
Host diesen erlaubten Request als genau eine nicht gechunkte `Content-Length`-
Lieferung in der Größe des zurückgehaltenen Bodys neu rahmt. Er verlangt
außerdem `501` ohne neue Upstream-Verbindung für `Incremental`, konfigurierte
`server.stream-request-body` und ausdrücklich aktivierte body-tragende
`Upgrade`- plus `gw.upgrade-with-request-body`. Er ist nur Request-Body-P2-
Evidence. Ein terminales
host-seitiges `501` nutzt ausschließlich einen Logging-Abschluss: Er zeichnet
die Audit-Phase genau einmal auf, ohne Request-Body-EOS oder eine Phase-2-
Entscheidung zu synthetisieren. Er fördert keine Claims zu Response-Body-P4,
CRS, HTTP/2/HTTP/3, unbeschränktem Streaming oder Production-Readiness.

Das Modul übergibt begrenzte Memory-/File-Bereiche an die native P2 ohne eigenes
kumuliertes Limit. Dieser Runner konfiguriert oder belegt die unabhängige
Host-Einstellung `server.max-request-size` nicht.

## Response-Body-Backend-Close-Profil

`run_lighttpd_backend_close.sh` ist ausschließlich für gepatchtes lighttpd.
Es erzeugt absichtlich `response_body_mode=streaming`, damit der aktuelle
Upstream-EOF-/Abort-Pfad für den Response-Body nachgewiesen werden kann. Ein
Stock-Host besitzt keinen versionsvertraglichen Streaming-Hook und bricht daher
fail-closed ab, bevor Runtime-Root, Host oder Listener angelegt werden; sein
Body-Modus darf nicht stillschweigend geändert werden. Für das Stock-
Transport-/Lifecycle-Profil ist stattdessen
`run_lighttpd_stock_lifecycle.sh` zu verwenden. Dessen V7/V11-Ergebnis ist
Host-/Transport-Evidence, kein typisiertes Stock-Response-Body-Connector-Event.

## Stock-Lifecycle-Profil

`run_lighttpd_stock_lifecycle.sh` führt das begrenzte Stock-Host-Profil aus und
speichert die Evidence außerhalb des Checkouts. Der aktuelle Lauf-Root ist
`lighttpd-stock-lifecycle-v6-v10-20260825T100000Z`.

Das Profil zeichnet V6 als begrenzten 2-Sekunden-Gateway-/Proxy-Backend-
Read-Timeout-Fallback auf: Direkte Client-Cancel-Propagation und ein
typisiertes Stock-Connector-Event werden nicht behauptet; der Host-Marker
`read timeout on socket` und ein Same-Host-Follow-up mit `200` sind erforderlich.
Rohe abgeschnittene Upstream-Response-Fixtures für V7/V11, acht begrenzte
parallele HTTP/1.1-`200`-Responses und Client-EOF nach Host-Terminierung werden
als Host-/Transport-Evidence aufgezeichnet. Restart-Controls müssen
`200 -> 403 -> 200` liefern. PIDFD-/Session-/Port-/UDS-Cleanup-Receipts sind
für den ersten und den Ersatz-Host erforderlich.

V12--V15 und die vollständige 17-Vektor-Abnahme bleiben `NOT_EXECUTED`; diese
begrenzten Receipts heben sie nicht hoch und belegen keinen vollständigen
Leak-Audit.

## No-CRS-Fixture-Isolation und Cleanup

Die No-CRS-Baseline verwendet den vertrauenswürdigen Namespace-Runner
`run_no_crs_fixture_trusted_namespace.py`. Der Runner lehnt einen Aufrufer als
Host-root oder mit gesetztem Set-ID-Bit ab und startet die vertrauenswürdige
Setup-Kette über die root-eigenen Binaries `/usr/bin/unshare`, das feste
`/usr/bin/dash` und `/usr/bin/mount` und danach `/usr/bin/bwrap`. Das
Shell-Setup macht die Mount-Propagation privat und mountet vor dem Eintritt in
bwrap ein privates `nosuid,nodev,noexec`-tmpfs auf `/tmp`. Bwrap stellt nur die
minimalen schreibgeschützten System- und Runtime-Binds bereit, die der Harness
benötigt, sowie den exakten Task-eigenen Smoke-Root als einzigen
beschreibbaren Bind. Der Fixture-Root selbst hat den Modus 0700.

Die Setup-Komponente ist die einzige Komponente, die Namespace- und
Mount-Capabilities benötigen darf. Sie bestätigt den Capability-Zustand nach
dem Setup; der Harness läuft nur weiter, wenn effektive, erlaubte,
vererbbare, ambient und Bounding-Capabilities vollständig null sind und
`no_new_privs` aktiviert ist. Der Testprozess behält keine Setup-Capabilities.
Fehlende Namespace-Unterstützung, ein unerwarteter Capability-Zustand oder ein
nicht verfügbares Execution-Isolation-Control führen zu einem fail-closed
Abbruch; es gibt keinen Fallback zum früheren Cleanup aus Pfadprüfung und
anschließendem `rmdir`.

Die Fixture-Lebensdauer ist an den privaten Namespace gebunden. Reguläre
Fertigstellung, Fehler bei der Fixture-Erstellung, Testfehler, Timeout,
Signalbeendigung, Helper-Fehler und teilweise Initialisierung beenden die
Kindprozessgruppe und den privaten Namespace. Der finale Namespace-State-
Verifier prüft ausschließlich die Capability-Sets, `no_new_privs`, den
Mount-Zustand und die Device/Inode-Identität (`dev:ino`) des festen
Fixture-Roots. Der Descriptor-I/O-Cleanup-Befehl prüft separat das
Allowlist-Inventar der Fixture-Blätter, behält jedes Blatt und löscht nichts
beziehungsweise löst den Fixture-Pfad nicht erneut auf. Alle Blätter und das
Verzeichnis verschwinden beim Abbau des privaten tmpfs-Namespace. Die
Mount-Propagation ist explizit privat, daher werden Fixture-Mounts nicht in
den Host-Mount-Namespace propagiert.

Bedrohungsmodell: Ein Prozess mit derselben UID kann den früheren Fixture-Pfad
während eines Laufs umbenennen, ersetzen oder neu anlegen. Die Sicherheitsgrenze
stützt sich deshalb nicht auf eine Inode-Prüfung mit anschließender Löschung
über einen Pfad. Die Fixture wird in einem privaten Mount-Namespace erstellt und
verwendet, der beschreibbare Root wird vom Runner kontrolliert und die
Namespace-Freigabe entfernt die privaten Mounts. Dadurch kann ein ersetzter
Host-Pfad nicht zum Cleanup-Ziel werden.

Der lokale verschachtelte Container besitzt nur eine einzeilige UID-/GID-Map
und kann daher den vollständigen Produktionspfad für Nicht-root lokal nicht
ausführen. Diese Einschränkung verhindert einen lokalen Produktions-
Integrationsclaim; sie erlaubt keinen unsicheren Fallback.

Der Pull-Request-Workflow `test-lighttpd` setzt beim Ausführen der
Namespace-Suite `LIGHTTPD_REQUIRE_NAMESPACE_INTEGRATION=1`. Ein nicht
verfügbarer unprivilegierter User-/Mount-/PID-Namespace ist daher ein
fehlgeschlagener Hosted-Sicherheitscheck und niemals ein übersprungener Erfolg
als Ersatz für Lifecycle-, Race-, Signal-, Absturz- und Teardown-Evidence.
