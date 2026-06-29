# NGINX Laufzeitberechtigungsauflösung

**Sprache:** [English](nginx-runtime-failure-classification.md) | Deutsch

Datum: 21.05.2026

Dieser Hinweis aktualisiert die vorherige Laufzeitklassifizierung vom 20.05.2026 NGINX. Das tut es
Connector-Code gemäß `connectors/nginx/src/`, YAML Erwartungen nicht ändern,
XFAIL Status oder RESPONSE_BODY Verifizierung.

## Zusammenfassung

Der vorherige lokale NGINX Source-Build-Smoke gab 43 PASS, 11 FAIL und zurück
0 GESPERRT. Jeder Fehler wird HTTP 200 erwartet und beobachtet HTTP 403. Die Fallebene
NGINX Fehlerprotokolle zeigten:

```text
htdocs/index.html is forbidden (13: Permission denied)
```

Die generierten Dateien waren lesbar, aber der Laufzeitbaum befand sich unter einem übergeordneten Baum
Verzeichnis, das der NGINX-Worker nicht durchlaufen konnte. Das machte die 11-Fälle
**harness/filesystem blockiert**, nicht Connector-Gap, Laufzeitunterschied oder wahrscheinlich
Fehlerbeweise.

Der Harness stellt jetzt NGINX Worker-bezogene Laufzeitdateien unter einem lesbaren lokalen Standort bereit
Arbeitsstammverzeichnis für diese Umgebung nutzen (`/tmp/ModSecurity-conector-nginx-runtime-0`
während der Root-Run-Validierung). Es legt Berechtigungen nur innerhalb der generierten fest
Nutzt den Arbeitsstamm und erfordert keine systemweiten NGINX Konfigurationsänderungen,
globale Installationen oder umfassende chmod-Hacks.

Ein späterer `make smoke-nginx` Laufzeitdurchlauf über frisch erstellten Source-Build
Artefakte abgeschlossen mit **54 PASS, 0 FAIL, 0 BLOCKED**. Nein
In den Laufzeitprotokollen wurde eine `htdocs/index.html`-Berechtigungsverweigerung beobachtet.

## Fallklassifizierung

| Fall | Bereich | Vorherige aktuelle | Neueste aktuelle | Neueste Klassifizierung |
| --- | --- | ---: | ---: | --- |
| `phase2_args_pass` | Phase 2 `ARGS` Pass-Through | 403 | 200 | PASS im aktuellen lokalen NGINX Smoke |
| `action_allow_phase1_pass` | Phase 1 `allow` Pass-Through | 403 | 200 | PASS im aktuellen lokalen NGINX Smoke |
| `response_body_pass` | RESPONSE_BODY Durchleitung | 403 | 200 | Nur Pass-Through-Nachweise; RESPONSE_BODY bleibt nicht hochgestuft |
| `v2_transformation_url_decode_pass_no_match` | `t:urlDecode` No-Match-Pass-Through | 403 | 200 | PASS im aktuellen lokalen NGINX Smoke |
| `v3_args_names_get_pass_no_match` | `ARGS_NAMES` No-Match-Pass-Through | 403 | 200 | PASS im aktuellen lokalen NGINX Smoke |
| `v3_request_cookies_names_pass_no_match` | `REQUEST_COOKIES_NAMES` No-Match-Pass-Through | 403 | 200 | PASS im aktuellen lokalen NGINX Smoke |
| `v3_request_cookies_pass_no_match` | `REQUEST_COOKIES` No-Match-Pass-Through | 403 | 200 | PASS im aktuellen lokalen NGINX Smoke |
| `v3_request_headers_names_pass_no_match` | `REQUEST_HEADERS_NAMES` No-Match-Pass-Through | 403 | 200 | PASS im aktuellen lokalen NGINX Smoke |
| `nginx_phase4_content_type_out_of_scope` | NGINX Phase-4-Inhaltstyp-Nur-Protokoll-Probe | 403 | 200 | PASS im aktuellen lokalen NGINX Phase-4-Log-only-Smoke; nicht RESPONSE_BODY Hochstufung |
| `nginx_phase4_minimal_log_only` | NGINX Phase-4-Minimal-Log-Only-Probe | 403 | 200 | PASS im aktuellen lokalen NGINX Phase-4-Log-only-Smoke; nicht RESPONSE_BODY Hochstufung |
| `nginx_phase4_safe_log_only` | NGINX Phase-4-sichere Nur-Protokoll-Probe | 403 | 200 | PASS im aktuellen lokalen NGINX Phase-4-Log-only-Smoke; nicht RESPONSE_BODY Hochstufung |

## Interpretation

- Die 11 vorherigen 403 Ergebnisse werden nun als gelöste Harness-Berechtigung klassifiziert
  Blocker.
- Der aktuelle lokale NGINX-Lauf liefert dafür Laufzeit-Pass-Through-Nachweise
  Fälle in dieser Source-Build-Umgebung.
- `response_body_pass` und die NGINX Phase-4-Log-Only-Probes sind **nicht**
  RESPONSE_BODY Verifizierung oder Nachweis der Kompatibilität des stabilen Antwortkörpers.
- Es erfolgt keine XFAIL/PASS-Werbung für die Unterstützung der Blockierung von Antworttexten.
- `make smoke-all` wurde für diesen Snapshot nicht ausgeführt, daher gibt es keine vollständige PASS-Zählung
  behauptet.

## Hinweise zum Harness

Der NGINX-Harness benötigt generierte Laufzeit-, Protokoll- und `htdocs`-Bäume, die die
Der Arbeitsprozess kann durchlaufen und lesen. In Root-Run-Umgebungen die Standardeinstellung
Die Wurzel der Harnessarbeit befindet sich unter `${TMPDIR:-/tmp}`; Nicht-Root-Läufe verwenden
`${RUNNER_TEMP:-${TMPDIR:-/tmp}}`, sofern nicht `NGINX_HARNESS_WORK_ROOT` gesetzt ist.

Der Fix betrifft absichtlich lokal die generierten Harnesspfade:

- Keine global/system NGINX Konfigurationsänderungen
- keine globale Installationsvoraussetzung
- Kein CHMOD außerhalb des generierten Harness-Arbeitsstammverzeichnisses
- nein `chmod 777`
- Keine Änderungen gemäß `connectors/nginx/src/`
