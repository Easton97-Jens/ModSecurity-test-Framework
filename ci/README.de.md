# CI

**Sprache:** [English](README.md) | Deutsch

Status: eingerüstet

CI Hilfsskripte gehören hierher, nachdem sie nachweislich konnektorneutral sind oder
eindeutig steckerbezogen.

`ci/common.sh` ist der gemeinsame Shell-config/helper-Einstiegspunkt. Es zentralisiert
Build-Roots, Source-Roots, ModSecurity-Kern refs/URLs, Repo-Local-Connector
Quellvorgaben, Serverquelle versions/URLs, Python-Auswahl, optional
Hinweise zur installierten Laufzeit und Protokollierungshilfen. Es ist passiv: es beschaffen
definiert nur Variablen und Funktionen.

Wichtige lokale Einstiegspunkte:

- `ci/cloud-quick-check.sh`: framework/generator/lint Prüfung auf Lightweight-CI.
- `ci/quick-all.sh`: lokal bevorzugte schnelle Orchestrierung; kann BLOCKIERT zurückgeben.
- `ci/fetch-smoke-sources.sh`: expliziter Helfer zum Abrufen der Quelle.
- `ci/fetch-crs.sh`: explizit OWASP CRS Holt den Helfer mithilfe des zentralen Pins von
  `ci/common.sh`.
- `ci/prepare-crs.sh`: generierte CRS setup/preamble Helfer für den `with-crs`
  Testvariante.
- `ci/prepare-haproxy-runtime.sh`: lokale HAProxy-Quelle fetch/build Helfer. Es
  verwendet nur die HAProxy URL/version/checksum-Werte aus `ci/common.sh`,
  überprüft die offizielle Prüfsumme, prüft `TARGET=linux-glibc` Unterstützung im
  hat das Quell-Makefile heruntergeladen und stellt die Binärdatei unter `BUILD_ROOT` bereit.
- `ci/doctor.sh`: lokale prerequisite/readiness Diagnose.
- `ci/run-connector-smokes.sh`: lokale Apache+NGINX Smoke-Orchestrierung.
- `ci/run-envoy-smoke.sh`, `ci/run-haproxy-smoke.sh`,
  `ci/run-lighttpd-smoke.sh` und `ci/run-traefik-smoke.sh`: im Besitz des Frameworks
Runtime-Smoke-Einstiegspunkte für die neuen Connector-Starter. Sie derzeit
  Schreiben Sie einen BLOCKED-Nachweis, wenn das Connector-Repository nur über einen Harness verfügt
  Vertrag und kein ausführbares Laufzeitkabel.
- `ci/run-connector-starter-checks.sh`: build/self-test Starterbeweis für
  Envoy, HAProxy, lighttpd und Traefik. Diese Ergebnisse sind kein Laufzeitfehler
  Nachweise.

Der vollständige Laufzeitnachweis bleibt über die Makefile-Smoke-Ziele lokal.
Apache- und NGINX-Connector-Code stammt aus `connectors/apache` und
`connectors/nginx` standardmäßig; Externe Connector-Repository-Abrufe erfordern
explizites Opt-in.

Envoy-, HAProxy-, lighttpd- und Traefik-Runtime-Smoke-Runner verwenden lokale Roots
nur: `SOURCE_ROOT=/src`, `BUILD_ROOT=/src/ModSecurity-conector-build`,
`TMP_ROOT=$BUILD_ROOT/tmp`, `LOG_ROOT=$BUILD_ROOT/logs` und
`RESULTS_DIR=$BUILD_ROOT/results` sofern nicht ausdrücklich durch einen anderen überschrieben
erlaubter Pfad unter `/src`. Sie führen keine globalen Installationen durch.

Der HAProxy-Vorbereitungshelfer löst möglicherweise die lokale HAProxy-Binärvoraussetzung.
aber es führt keinen SPOE/SPOA-Verkehr aus und erzeugt keinen Laufzeitrauch
PASS Nachweise.

CRS Laufzeitvalidierung ist variantenbasiert:

- `MODSECURITY_TEST_VARIANT=no-crs` behält das bestehende lokale Fallregelverhalten bei.
- `MODSECURITY_TEST_VARIANT=with-crs` injiziert `MODSECURITY_RULE_PREAMBLE_FILE`
  vor generierten lokalen Fallregeln.

Es werden nur das CRS-Repository URL, die Git-Referenz, der Quellpfad und der Laufzeitpfad definiert
in `ci/common.sh`.
