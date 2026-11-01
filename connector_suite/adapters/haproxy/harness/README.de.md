# HAProxy-Harness

**Sprache:** [English](README.md) | Deutsch

Status: Framework-Live-YAML-Laufzeit-Einstiegspunkt
Laufzeitstatus: Live-Anfrage-seitige YAML-Ausführung über HAProxy, SPOA/SPOP,
und libmodsecurity. Aktuelle Beweise:
Kein CRS `46 PASS / 0 FAIL / 8 BLOCKED`; Mit-CRS
`48 PASS / 0 FAIL / 7 BLOCKED`.

`run_haproxy_smoke.sh` ist als konnektorseitiger Einstiegspunkt für das Framework vorhanden
Laufzeitrauchläufer. Es listet freigegebene YAML-Fälle mit `case_cli.py` auf.
materialisiert jeden ausgewählten Fall, startet den lokalen HAProxy und die SPOP-Laufzeit live,
und ein lokales Backend sendet die Case-Curl-Anfrage über HAProxy und bestätigt die
beobachteter Status, schreibt pro Fall `result.json`, hängt an
`haproxy-results.jsonl` und gibt den Standard aus
`{ "haproxy": { "summary": ..., "cases": ... } }` Zusammenfassung JSON.

Der Full-Lifecycle-Dispatcher verwendet diesen SPOA/SPOP bewusst nicht wieder
Kompatibilitäts-Einstiegspunkt. Es ruft `runtime-smoke-haproxy-htx` auf
`full-lifecycle-haproxy-htx`, das einen Einweg-gepatchten Framework-synchronisierten HAProxy erstellt
Arbeitsbaum und wählt nur `filter modsecurity-htx` aus. Es lädt die Frameworks
kanonische No-CRS-Regeln und verwendet echte Host-Socket-Anfragen: P1-Regel `1100001`
gibt 403 zurück, die P1-Regel `1100002` gibt 429 zurück und die P3-Regel `1100201` gibt 403 zurück
nachdem eine Upstream-Reaktion beobachtet wurde. P2/P4 bleiben nutzlastfreier Host
Nur Beobachtungen. Der Harness schreibt rohe, begrenzte Host-Beweise separat
von Metadatenereignissen und behält `capability_promotion=not_permitted`; das ist es nicht
sichere/strikte Late-Action, First-Byte, Common-Runtime-Bridge oder Capability-
Beförderungsnachweise.

Das Framework kann eine lokale HAProxy-Binärdatei ohne globale Installation vorbereiten
bis `modules/ModSecurity-test-Framework/ci/provisioning/prepare-haproxy-runtime.sh`.
Der generische SPOA/SPOP-Kompatibilitätsharness verwendet die
Framework-synchronisierte HAProxy-Release, die nur im Framework
`ci/lib/common.sh` angeheftet ist; Ihre offizielle
Prüfsummendatei und Quell-Makefile wurden vor dem Hinzufügen der PIN überprüft. Die
Der vorbereitete Binärpfad lautet:

```text
/src/ModSecurity-conector-build/haproxy-runtime/haproxy/sbin/haproxy
```

Es gibt einen lokalen SPOA-Agent-Starter, der einen lokalen Selbsttest durchführen kann durch:

```sh
make -C connectors/haproxy self-test-spoa
```

Dieser Selbsttest startet HAProxy nicht, analysiert keine SPOP-Frames und lädt nicht
libmodsecurity und darf nicht als HAProxy-Laufzeitrauch gemeldet werden.

Eine separate SPOP-Laufzeitbinärdatei kann wie folgt erstellt werden:

```sh
make -C connectors/haproxy build-spoa-runtime
make -C connectors/haproxy self-test-spoa-runtime
```

Diese Binärdatei überprüft die lokale Analyse von HELLO/AGENT-HELLO, NOTIFY-Anforderungsargumenten,
Verifizierte `set-var txn.modsecdiag.blocked true` ACK-Kodierung und DISCONNECT
Handhabung. Während `make smoke-haproxy` sendet HAProxy `method`, `uri`,
`req.hdrs_bin` mit einem sicheren `req.hdrs`-Fallback und `req.body` zu dieser Laufzeit.
Die Laufzeit leitet diese Bytes an libmodsecurity weiter. Dies ist eine Live-Anfrage auf der Anforderungsseite
Beweise, keine vollständige SPOA-Implementierung in der Produktion.

Framework-Runtime-Smoke-Einstiegspunkt:

```sh
make smoke-haproxy
```

Framework HAProxy-Matrix-Einstiegspunkte:

```sh
make runtime-matrix-haproxy
make test-haproxy-no-crs
make test-haproxy-with-crs
```

`make runtime-matrix-haproxy` führt die Live-No-CRS- und With-CRS-HAProxy-Smokes aus
und aktualisiert dann den Laufzeit-Snapshot aus diesen zusammenfassenden JSON-Dateien. Geteilt
Ziele schreiben ihre eigenen Verzeichnisse:

- `/src/ModSecurity-conector-build/results/no-crs/haproxy-summary.json`
- `/src/ModSecurity-conector-build/results/with-crs/haproxy-summary.json`

Die kombinierte Stammzusammenfassung wird derzeit von der ausgewählten Live-Variante kopiert
Mit-CRS.Der aktuelle Einstiegspunkt `run_haproxy_smoke.sh` schreibt den PASS-Beweis unter
`/src/ModSecurity-conector-build/results/` nur, wenn Live-HAProxy NOTIFY sendet
Zur Laufzeit wertet libmodsecurity die materialisierte Regeldatei HAProxy aus
erzwingt störende 403-Entscheidungen über den Set-Var/Deny-Pfad und die
Der beobachtete Status entspricht der YAML-Erwartung.

Der Einstiegspunkt prüft die HAProxy-Laufzeitvoraussetzungen, bevor Beweise geschrieben werden. Wenn
Wenn die lokale HAProxy-Binärdatei fehlt, wird versucht, den Framework-Vorbereitungshelfer zu verwenden.
Wenn dieser Helfer erfolgreich ist, sind die HAProxy-Binär-/Quellenerfassungsblocker erfolgreich
aus `blocked_reasons` entfernt. Wenn alle Live-Durchsetzungsprüfungen erfolgreich sind:

- `make smoke-haproxy` startet HAProxy und die SPOP-Laufzeit live und sendet lokal
  HTTP-Anfragen über HAProxy und Aufzeichnung neuer Beweise pro Fall;
- `spoe_runtime_status` ist `live-request-side-verified`;
- `modsecurity_binding_status` ist `live-enforcement-verified`;
- `runtime_verified` ist `true` für live ausgeführte PASS/FAIL-Fallzeilen;
- `crs_verified` wird durch den With-CRS `crs_sqli_anomaly_block` PASS nachgewiesen.

Der ModSecurity-Bindungsselbsttest kann direkt ausgeführt werden:

```sh
make -C connectors/haproxy build-modsecurity-binding
make -C connectors/haproxy self-test-modsecurity-binding
make -C connectors/haproxy self-test-modsecurity-binding-crs
```

Dieser Selbsttest überprüft die prozessinterne Phase-1-Headerblockierung und den Anforderungstext
Verarbeitung und CRS-SQLi-Entscheidungen, wenn das CRS-Ziel verwendet wird. Nur
`make smoke-haproxy` kann den Status der Live-Durchsetzung fördern.

Aktuelle Live-Beweise auf Anfrage umfassen:

- `REQUEST_URI`
- `REQUEST_HEADERS` und `REQUEST_HEADERS_NAMES`
- `ARGS` und `ARGS_NAMES`
- `REQUEST_COOKIES` und `REQUEST_COOKIES_NAMES`
– `REQUEST_BODY` für URL-codierte, JSON-, XML- und mehrteilige Anfragen
- `FILES`
- Blockierung von CRS-SQLi-Anomalien mit der vorbereiteten CRS-Präambel

Der Anforderungshauptpfad verwendet die HAProxy-Anforderungspufferung `tune.bufsize 65536`.
SPOE `max-frame-size 65532` und ein `req.body`-Argument. Größer, gestreamt, oder
Mehrrahmenkarosserien bleiben außerhalb der bewährten Fläche.

Zukünftige HAProxy-Förderungen über den aktuellen Teilstatus hinaus erfordern weiterhin:

- Vollständiger Nachweis der SPOA/SPOP-Implementierung in der Produktion oder eine ausgewählte Alternative
  Integrationspfad
- Antwort-Header/Body-Phase-Nachweis
- Audit-/Protokollbehauptungsnachweise
- Umleitung und nicht-403-störende Statuszuordnung
- umfassendere Leistungs- und Fehlermodusnachweise

Ausführbare Fälle und Läufer sind Eigentum des Frameworks, zum Beispiel:

- `modules/ModSecurity-test-Framework/tests/cases/`
- `modules/ModSecurity-test-Framework/tests/runners/case_cli.py`

Ein angekündigtes `body_len`, das vom empfangenen `req.body`-Sample abweicht, wird als unvollständiges, nicht unterstütztes Transport-Sample abgewiesen (Admission-Status 503), ohne BODY_LIMIT-Klassifizierung. Das vollständige Sample eines Frames wird libModSecurity übergeben; diese Route implementiert keinen inkrementellen Transport des gesamten Bodys.
