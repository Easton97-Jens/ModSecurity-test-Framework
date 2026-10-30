# NGINX Smoke-Harness

**Sprache:** [English](README.md) | Deutsch

Status: eingerüstet

Dieser Harness ist ein connector-spezifischer Proof-of-Concept-Läufer für die Dynamik
NGINX-Modul, das aus der schreibgeschützten Quellkopie `ModSecurity-nginx` erstellt wurde. Das ist es nicht
eine vollständige Regressionssuite.

Lokal beobachtet am 15.05.2026: Von der Quelle erstelltes NGINX `1.31.0` vom GitHub-Tag
`release-1.31.0` hat den von YAML erwarteten HTTP-Status für alle aktuellen Freigaben zurückgegeben
minimale Fälle.

## Grenzen

- Hält private Case-Artefakte unter `BUILD_ROOT`; aktivierte Worker-Docroots
  verwenden den unten beschriebenen, separat autorisierten externen Projection Parent.
- Erstellt oder ändert kein `<external-source-root>/*`-Repository.
- Importiert keine NGINX- oder ModSecurity-nginx-Quelle in dieses Monorepo.
- Meldet `pass` nur, wenn NGINX den von YAML erwarteten HTTP-Status für a zurückgibt
  echte lokale Anfrage.
- Liest Regel, Anfrage, Header, Text, mehrteiligen Text, Antwortvorrichtung usw
  erwarteter Status von YAML bis `modules/ModSecurity-test-Framework/tests/runners/case_cli.py`.

## Nutzung

```sh
REFRESH=1 \
BUILD_NGINX_FROM_SOURCE=1 \
BUILD_ROOT=/src/ModSecurity-conector-build \
make smoke-nginx

BUILD_ROOT=/src/ModSecurity-conector-build \
make smoke-nginx
```

Die Full-Smoke-Konfiguration verwendet ein festes direktes offizielles
GitHub-Release-Asset:

```sh
BUILD_NGINX_FROM_SOURCE=1
# Framework-synchronized NGINX release tuple; do not duplicate it here.
NGINX_REQUIRE_PINNED_PROVENANCE=1
```

Dies wählt das Framework-synchronisierte direkte GitHub-Release-Asset.
Der Full-Smoke-Release-Resolver weist `latest` und `/releases/latest` vor
Cache-Lookup oder -Schreiben, Netzwerkzugriff, Download oder Extraktion ab.
Die Cache-Identität bindet das gesamte Tupel: Source-Modus, Repository-URL,
Release-Tag, Source-Git-Ref, Release-Asset-Name und SHA-256. Spätere
NGINX-Updates müssen dieses Tupel atomar ändern; nur Tag oder Archivname zu
ändern ist keine gültige Full-Smoke-Provenance.

`NGINX_REQUIRE_PINNED_PROVENANCE=1` weist zusätzlich geerbte native
Binary-/Modul-Overrides ab. Der Full-Smoke-Pfad baut das ausgewählte
Release-Asset und verwendet kein System- oder MRTS-NGINX-Binary als
Full-Smoke-Evidence.

Wenn NGINX, das dynamische Modul oder `libmodsecurity.so` fehlt, das Skript
beendet `77` und markiert das Ergebnis als `blocked`.

## Nachweis der nativen P3/P4- und HTTP/2-Anwendbarkeit

Der Real-Host-Kabelstrang leitet Fälle, die `RESPONSE_HEADERS` verwenden, über ihn weiter
lokal deterministisch vorgelagert. Dies ist der native Phase-3-Pfad; es ist kein
Synthetischer Antwortheader. Die kanonische Auswahl für den gesamten Lebenszyklus fügt außerdem hinzu
connector-spezifische Phase-4-sichere und strenge Fälle. Ihre Ergebnisse müssen bleiben
separat: „safe“ erwartet ein Post-Commit-Ereignis `log_only`, während „strict“ ein Ereignis erwartet
Post-Commit-Ereignis `connection_aborted`. Beide Veranstaltungen tragen
`integration_mode: native-nginx-http-module`.

Jeder Hostaufruf zeichnet die `nginx -V`-Ausgabe der ausgewählten Binärdatei auf
`$LOG_DIR/nginx-version.log` und schreibt
`$LOG_DIR/nginx-http2-applicability.json`. Die Datei ist absichtlich
konservativ:

- nein `--with-http_v2_module` bedeutet `NOT_APPLICABLE`, also macht der Gurt nein
  HTTP/2-Anfrage;
- Ein Host mit diesem Flag ist immer noch `NOT_EXECUTED`, bis ein HTTP/2-Connector im Besitz ist
  Fall und passende Listener-Konfiguration werden ausgewählt.

Folglich weder ein erfolgreicher Build noch das Vorhandensein des Konfigurationsflags
ist ein HTTP/2-Laufzeitanspruch.

## Geteilte Fälle

Canonical-Lifecycle-Aufrufer aktivieren `NGINX_DOCROOT_PROJECTION=1` und übergeben
einen bestehenden, externen, root-owned `NGINX_DOCROOT_PROJECTION_PARENT` sowie
einen sicheren, frischen direkten Child-Pfad `NGINX_DOCROOT_PROJECTION_ROOT`.
Bei einem Multi-Case-Batch bleibt dieser Root ein nicht angelegter Namens-Seed:
Der Parent-Dispatch weist jedem Case einen eigenen Geschwisterpfad
`nginx-case-<UUID>` zu. Der native First-Byte-Wrapper weist unabhängig einen
Geschwisterpfad `nginx-first-byte-<UUID>` unter demselben Parent zu. Nur der
Projection-Helper legt das ausgewählte Child an; bestehende Children und
Symlinks bleiben verboten und werden nie zur Wiederverwendung gelöscht.
Direkte Harness-Aufrufe mit `RUN_ONE_CASE=1` verwenden weiterhin exakt den
übergebenen frischen Root. Private Regeln, Logs, Cache und Canonical Evidence
werden nicht in den Projection Parent verschoben.

Standardmäßig iteriert der Harness jede `*.yaml`-Datei in:

```text
modules/ModSecurity-test-Framework/tests/cases/
modules/ModSecurity-test-Framework/tests/cases/
modules/ModSecurity-test-Framework/tests/cases/connector-specific/nginx/
```

So führen Sie eine Teilmenge aus:

```sh
BUILD_ROOT=/src/ModSecurity-conector-build \
SMOKE_CASES="phase1_header_block phase2_args_block" \
make smoke-nginx
```

Der Harness materialisiert die NGINX-Regeldatei, Anforderungsvariablen und Anforderungen
Header, Anforderungstext, mehrteiliger Text und Antwort-Fixture aus jeder YAML-Datei
zur Laufzeit. Es verwendet nur `/__modsec_smoke_ready` mit deaktivierter ModSecurity
Bereitschaftsprüfungen. Duplizieren Sie nicht die Regel, den Anforderungspfad, die Anforderungsmethode usw.
Header, Text, Antwortvorrichtung oder erwarteter HTTP-Status im Harness.

Das Blockieren des Antwortkörpers bleibt nicht gefördert, bis der NGINX-Smoke-Test ein beobachtet
stabiles HTTP 403 für den gleichen häufigen YAML-Fall.
