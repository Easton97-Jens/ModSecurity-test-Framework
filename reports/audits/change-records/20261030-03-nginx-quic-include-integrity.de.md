# Integrität der konfigurierten NGINX-QUIC-Includes

**Sprache:** [English](20261030-03-nginx-quic-include-integrity.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261030-03-nginx-quic-include-integrity |
| UTC-Datum | 2026-10-30 |
| Framework-Basisrevision | `f5a0940c56edbb94d55d309636ce3d6f501e31a2` |
| Issue oder Pull Request | Bei lokaler Vorbereitung noch kein Framework-PR zugewiesen |

### Nachtrag nach dem Testumzug — 2026-11-01

Der Nutzer hat die Arbeit fortgesetzt und neue Tests freigegeben. Draft #144
übernimmt Framework-Master `d503ddbea1a3b6df7766edc247b0a9886ff10668` durch
einen normalen Branch-Merge, nicht durch einen PR-Merge. Er bleibt unabhängig
von Draft #143; Parent-Pin/-Source und MRTS bleiben unverändert. Ursprüngliche
Aussagen ohne neue Tests unten gelten nur für die Vorbereitung vom30.Oktober.

Vier neue einzeln ausgewählte On-demand-Methoden in
`tests/security_regression/test_common_shell_sonar_contracts.py` prüfen echte
Shellfunktionen mit reinen Header-Verzeichnis-Fixtures: exakte konfigurierte
QUIC-Include-Reihenfolge, Annahme konfigurierter Bäume ohne QUIC, Ablehnung
unkonfigurierter Bäume und Vorrang expliziter installierter Header. Keine
geprüfte Funktion wird gemockt. Standardselektoren, Inventarbindungen und
generierte Migrationszuordnung bleiben unverändert; das Standardinventar
bleibt bei100 expandierten Fällen.

Alle vier exakten `CommonShellSonarContractsTest.test_nginx_*`-Selektoren
bestanden mit Framework-Python über RTK und externen Temporär-/Cache-Wurzeln.
Die primäre Reihenfolgeregression scheiterte am unveränderten `d503ddbe`-Helfer
erwartungsgemäß (ein Assertion-Fehler, Exit1: `src/event/quic` fehlt);
dieselbe Regression besteht mit diesem Fix. Die Run-Wurzel lautet
`quic-helper-regressions-20261101.qfNWdw`. Diese Tests belegen Flagauswahl,
keine tatsächliche Kompilierung und keinen H3-Verkehr. Die echten Compiler-
Ergebnisse vom30.Oktober bleiben historische, getrennte Nachweise und wurden
in diesem Nachtrag nicht erneut ausgeführt.

`make check-documentation check-canonical-common-pins` bestand (Links,
340 Sprachpaare, Pfadreferenzen, Change Record und Pins); Shellsyntax und
Whitespace bestanden. Der erste Dokumentationslauf lehnte eine zusätzliche
Überschrift zweiter Ebene ab; als Unterabschnitt erfüllt sie den Vorlagenvertrag
wieder. Unabhängiger finaler Test-/EN-DE-Review ohne Blocker.

## Motivation und Problemstellung

Der Include-Producer für konfigurierte NGINX-Quellen ließ `src/event/quic` aus.
Bei echter `NGX_OPENSSL`-/`NGX_QUIC`-Konfiguration bindet `ngx_core.h` die Datei
`ngx_event_quic.h` ein; die vorhandene konsumierende C17-Prüfung scheiterte vor
der Connector-Kompilierung. Die generierte native NGINX-Include-Liste enthält
dieses Verzeichnis bereits. Dies betrifft gemeinsame Compile-Input-Integrität,
keinen Connector-Defekt.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-eigene `ci/lib/common.sh`, konkret `ci_nginx_source_dir_flags`.
Vertrauenswürdige konfigurierte Quellpfade werden Compiler-Include-Argumente.
Keine Änderung von Pfadauswahl, Provisionierung, kanonischen Pins, Compiler-
oder Berechtigungsregeln.

## Akzeptanzkriterien

- Die bereits fehlgeschlagene V3-C17-Prüfung besteht mit korrigiertem Helfer.
- Die vorhandene Konfiguration ohne V3 kompiliert weiterhin.
- Quellvoraussetzungen, Vorrang installierter Header, Rückgabestatus und
  erforderliche Compiler-Warnungen bleiben unverändert.
- Nach abgeschlossenem Umzug nur autorisierte fokussierte Selbsttests ergänzen;
  keine Standardselektoren oder Runtime-Kampagne hinzufügen.
- Gepaarte Dokumentation und unabhängige Framework-Auslieferung bleiben korrekt.

## Untersuchte Alternativen

QUIC nicht deaktivieren, generierte Makros nicht vortäuschen, `-Werror` nicht
abschwächen, Header nicht in andere Verzeichnisse kopieren und keinen
konsumentenspezifischen Include-Workaround einführen. Die zentrale Ergänzung
repariert alle Aufrufer ohne Änderung der Suche. Eine Pflicht für das
QUIC-Verzeichnis würde ältere Quellbäume unnötig ausschließen.

## Implementierungsentscheidung

Nur `-I$ci_nginx_dir/src/event/quic` hinter dem vorhandenen Event-Include ergänzen.
Bisherige Voraussetzungen und relative Reihenfolge aller vorhandenen
Verzeichnisse erhalten. Keine Existenzpflicht für QUIC-Header/-Verzeichnis.

## Geänderte Dateien und Tests

`ci/lib/common.sh`; `docs/development.md` / `.de.md`; dieses Record-Paar.
Am30.Oktober keine Testquelle, Fixture, keinen Fall und keine Assertion geändert.
Zwei vorhandene Shell-Status-/Helfervertragstests wurden wiederverwendet; sie
mocken den Include-Selektor und beweisen selbst keine QUIC-Include-Korrektheit.
Die tatsächliche konsumierende C17-Kompilierung lieferte diesen Nachweis.
Der Nachtrag vom1.November ergänzt die vier Methoden und ihre Fixture-Factory
in der oben genannten Selbsttestdatei.

## Befehle und Ergebnisse

Exakte Aufrufe des externen Konsumenten, ausgewählte Quellwurzeln,
Konfigurationsdigests und Befehlsresultate bleiben in `validation.md` im
zulässigen Run `framework-nginx-quic-includes-20261030.yubq4W` erhalten.
Konsumentenquelle war explizit Parent
`db431efaa62e5dd408846c0feec4fd9751421247`; dies ist eine externe
Validierungsabhängigkeit, keine Parent-Code-, Pin- oder Auslieferungsänderung.

| Befehl / aufbewahrter Ablauf | Exitcode | Kurzergebnis | Evidenz |
| --- | --- | --- | --- |
| `v3-on-before`: vorhandenes `rtk bypass make check-nginx-c17` | 2 | Fehlende `ngx_event_quic.h` mit unverändertem Basishelfer reproduziert | Externe `validation.md` |
| `v3-on-after`: dasselbe vorhandene C17-Target, korrigierter Helfer | 0 | Alle gelisteten Übersetzungseinheiten mit `-std=c17 -Wall -Wextra -Werror` kompiliert | Externe `validation.md` |
| `v3-off-after`: dasselbe Target, vorhandene Konfiguration ohne V3 | 0 | Kompatibilitätskontrolle ohne V3 bestanden | Externe `validation.md` |
| `rtk bypass sh -n ci/lib/common.sh` | 0 | POSIX-Shellsyntax bestanden | Externer Befehlsrecord |
| `rtk bypass bash -n ci/lib/common.sh` | 0 | Bash-Syntax bestanden | Externer Befehlsrecord |
| Vorhandener Framework-Unittest-Aufruf mit zwei Methoden | 0 | Status-/Helferverträge bestanden; keine neuen Tests | Externe `validation.md` |
| Vorhandenes konsumierendes `check-nginx-c-standard-wiring` | 0 | C17-, Quellabdeckungs-, Blocker- und Warnungsvertrag bestanden | Externe `validation.md` |
| Vorhandenes Framework-`check-canonical-common-pins` | 0 | Kanonischer Pinvertrag unverändert und bestanden | Externe `validation.md` |
| Vorhandenes Framework-`check-documentation` | 0 | Links, 334 Sprachpaare, Pfadreferenzen und Change-Record-Struktur bestanden | Externer Befehlsrecord |

## Sicherheitsauswirkung

Keine Sicherheitsremediation oder Vulnerability-Behauptung. Dieselbe
vertrauenswürdige Quellwurzelgrenze, Fehler bei fehlenden Voraussetzungen,
Warnungen und kanonische Pins bleiben erhalten. Fehlende Header oder
deaktiviertes QUIC werden nicht in Runtime-Erfolg umgedeutet.

## Dokumentation und Runtime-Evidenz

Das EN/DE-Entwicklungspaar beschreibt die vollständige Include-Liste
konfigurierter Quellen und die Compile-only-Evidenzgrenze. Kein Host gestartet,
kein Netzwerkverkehr erzeugt und keine TLS-/H2-/H3-Runtime-Qualifikation erhoben.
Keine Parent-Gitlink- oder MRTS-Änderung; separate vorhandene Framework-Arbeit
wird nicht integriert.

## Nicht ausgeführte Prüfungen

Keine archivierten Suites, Host-Smokes, vollständige Protokoll-/
TLS-Matrix oder neue Qualifikationskampagne. Sie liegen außerhalb des aktuellen
Integritätsumfangs. Hosted-Checks und Sonar benötigen den künftigen exakten
PR-Head; Ergebnisse früherer Heads werden nicht wiederverwendet. Vollständiges
lokales `lint` wurde wegen enthaltener fachfremder Suites nicht aufgerufen;
relevante Syntax-, Vertrags- und Dokumentationschecks wurden ausgeführt.

## Einschränkungen und Restrisiko

Die lokale Compiler-Prüfung nutzte aufbewahrte NGINX-1.31.6-Konfigurationen,
nicht alle unterstützten Versionen oder die ursprünglich angefragten gepinnten
TLS-/Runtime-Profile. Verhalten installierter Header und Voraussetzungen älterer
Bäume besitzen nun auch fokussierte Verzeichnis-/Flagregressionen, keinen
versionsübergreifenden Kompilierungsnachweis. Dieser Fix ist noch nicht im von Parent
gepinnten Framework-Stand integriert.

## Finaler Diff- und Review-Status

Quelländerung ist eine Ergänzung der Include-Liste. Root prüfte den begrenzten
Diff; unabhängiges finales Aufrufer-, Kompatibilitäts- und EN/DE-Review ohne
Blocker. Keine Secrets, rohen HTTP-Daten oder vollständigen Umgebungswerte
aufgezeichnet. Bereit für normale separate Framework-Draft-Auslieferung;
Hosted-Checks bleiben bis zur Veröffentlichung dieses exakten Heads
unverifiziert. Kein PR-Merge, Parent-Pointer-Update oder MRTS-Eingriff wird hier
behauptet.
