# Change Record

**Sprache:** [English](20261115-01-sonarcloud-framework-repairs.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261115-01-sonarcloud-framework-repairs |
| UTC-Datum | 2026-11-15 |
| Framework-Basisrevision | e4762167bed1ec6a28f7a207c8fb5b9ec258656a |
| Issue oder Pull Request | Aufgabenbranch `codex/framework-sonar-repair-20261115`; PR-Erstellung nach dem ersten Commit |

## Motivation und Problemstellung

Das gebundene Projekt `Easton97-Jens_ModSecurity-test-Framework` lieferte alle 115 offenen/bestätigten Befunde: 32 Vulnerability-Einstufungen und 83 Wartbarkeitshinweise. Analyse `f1f25af4-6af9-4df5-8b96-5a0645ac66cd` vom `2026-11-14T23:21:13Z` betrifft `452f7fc7ca1d9c44c9e768cef565f52882a40e2d`. Zur Basisrevision unterscheidet sich nur der MRTS-Gitlink; die betroffenen Framework-Quellen sind identisch. Das letzte Cloud-Gate ist `ERROR`, ausschließlich wegen Sicherheitsrating E für neuen Code. Die Hotspot-Abfrage lieferte insgesamt 0.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-Parser/Runner, private Testclient-Dateinamen, Eingabezulassung für Qualifikationsevidenz, Shell-Prüfungen, OSV-Ergebnispfade und Reportformatierung. Parent-Quellen, vorhandene Änderungen/Gitlink und MRTS bleiben durch diese Aufgabe unverändert. Die Korrekturen belegen keine Connector-Runtime-Qualifikation.

## Akzeptanzkriterien

Alle Befunde aktuellen Quellen zuordnen; nachgewiesene Fehler und zutreffende Wartbarkeitshinweise ohne schwächere Analyseabdeckung, Validierung oder Gates beheben; gültiges Verhalten und ASCII-Protokollsemantik erhalten; Pfadablehnung und gültige Receipts prüfen; gemeinsamen Diff und Dokumentationspaar prüfen. Eine neue Cloud-Freigabe und die Disposition möglicher Fehlalarme bleiben getrennte, nicht ausgeführte externe Schritte.

## Untersuchte Alternativen

Keine Regelabschaltung, breiten Ausschlüsse, `NOSONAR`, erzwungene HTTPS-Umschreibung oder Entfernung notwendiger Python-Klammern. Bereits vorhandene HTTPS-Server bleiben erhalten. Vom berechtigten Operator gewählte CLI-Verzeichnisse behalten ihren Vertrag. Ein isolierter Worktree schützt die ursprünglichen Checkouts.

## Implementierungsentscheidung

Zwei Traefik-Clients erlauben vor Datei-/Netzwerkzugriffen nur eine begrenzte Dateinamenskomponente. Eingabe-JSONs des gepatchten lighttpd-Proposals nutzen die vorhandene Zulassung über `read_json()` / `evidence_path()`. Reine Hilfsfunktionen reduzieren Parser-/Runner-Komplexität, Regex erhalten ASCII-Ziffern, wiederholte Werte werden Konstanten und Exception-/Collection-Behandlung wird vereinfacht. Neun Shell-Standardzweige erhalten den erfolgreichen Fortlauf ausdrücklich. OSV übergibt den Ergebnispfad an den Versuch-Helper und bindet ihn lokal; exakter Scannerbefehl und Retry-Vertrag bleiben erhalten. Reportzeilen behalten durch ein `extend()` ihre Reihenfolge.

## Geänderte Dateien und Tests

- `connector_suite/adapters/traefik/harness/i12/native/client.py`, `connector_suite/adapters/traefik/harness/i12_auth/client.py` und `connector_suite/modsecurity_connector_ci/runtime/lifecycle/i12/lighttpd/patched_qualification.py`.
- Runner-Module: `nginx_lifecycle_sequence.py`, `nginx_native_operation_bundle.py`, `nginx_native_operation_contract.py`, `runner_core.py`, `nginx_event_boundary_operations.py`, `nginx_http11_framing.py`, `nginx_mime_operations.py`, `nginx_native_operation_projection.py`, `nginx_phase4_operations.py`, `nginx_raw_h1.py` unter `tests/runners/`.
- `tests/normalizers/integrity_hash_chain_normalizer.py`, `tests/security_regression/git_provenance_test_support.py`, `ci/lib/common.sh`, `.github/workflows/ci-security-osv.yml`, `ci/reporting/generate-case-matrix.py`.
- Neuer gezielter `tests/security_regression/test_sonar_path_boundaries.py`; sieben Methoden decken 15 expandierte Szenarien ab. Die bestehende Auswahl des aktiven Inventars bleibt unverändert.
- Dieses englisch/deutsche Change-Record-Paar. Generierte Reports werden nicht bearbeitet.

## Befehle und Ergebnisse

| Befehl / Verfahren | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk bypass /usr/local/bin/sonar-with-env list issues -p Easton97-Jens_ModSecurity-test-Framework --format json --page-size 500 --page 1` | 0 | 115/115 Befunde geliefert | `framework-sonar-20261115/issues.json` |
| Derselbe Starter, `api get` für explizit gebundene Projektanalysen, Gate und Hotspots | 0 | Exakte analysierte Revision; Gate ERROR; 0 Hotspots | Analyseidentität oben |
| Explizites `analyze secrets --stdin` vor Lesezugriffen und nach Änderungen | 0 | Ausgewählte Bytes bestanden; Rohausgabe unterdrückt | Aufgabeneigene ausgewählte Inhalte |
| Protokollgruppe: fünf ausgewählte unittest-Methoden und `verify_protocol.py` | 0 | 16 vorhandene Szenarien plus 14 Alt/Neu-Vergleiche; Syntax für acht Module; Git-Fixture-Bytes identisch | `framework-sonar-20261115/protocol-quality/RESULTS.md` |
| Pfadgruppe: `test_sonar_path_boundaries` | 0 | 15 Szenarien bestanden; dieselbe Basisauswahl zeigt die ursprünglichen Fehler (5 fehlgeschlagene Prüfungen, 7 Ausnahmen) | `framework-sonar-20261115/path-findings/` |
| Root: vier ausgewählte Shell-/OSV-/Report-unittest-Methoden | 0 nach Korrektur | Shell-Kompatibilität und Reportreihenfolge bestanden; OSV-Befehlsvertrag und fünf Retry-Szenarien bestanden | `framework-sonar-20261115/coordinator/` |
| `rtk bypass "$PYTHON" -B "$CODEX_RUN_ROOT/framework-sonar-20261115/coordinator/verify_report.py"` | 0 | Eine Report-Fehlerausgabe entspricht der Basis und der geforderten Metadatenreihenfolge | `framework-sonar-20261115/coordinator/verify_report.py` |

Run-relative Evidenzpfade liegen unter dem konfigurierten `CODEX_RUN_ROOT`. Die abschließende integrierte Verifikation steht unten; das genaue Befehls-/Selektorenmanifest ist dauerhaft bei der Aufgabenevidenz abgelegt.

## Sicherheitsauswirkung

Die Dateinamen-/Evidenzkorrekturen betreffen neun Security-Befundstellen. Negativtests lehnen Traversal, absolute Pfade, Backslashes, Steuerzeichen und überlange Tokens vor I/O ab; gültige Namen behalten Request-/Response-/Fehler-Receipts. Evidenztests lehnen sowohl externe Fallverzeichnisse als auch externe Source-Binding-Eingaben ab und lassen zugelassene Eingaben die bestehende Qualifikationsgrenze erreichen. Das sind gezielte Zulassungsprüfungen, keine historische I12-Ausführung.

Die verbleibenden 23 Security-Befunde sind mögliche Fehlalarme oder bewusst gewählte Eingaben eines berechtigten CLI-Aufrufers: 13 in CFamily-/Native-Kontext-/Native-Receipt-/Runtime-Snapshot-Helfern, sieben in Protokoll-/lighttpd-/nginx-Helfern, zwei bereits aktive HTTPS-Server und eine fälschlich als Logging eingestufte C-Pfadformatierung. JSON-Inhalt kann einen festen Ausgabedateinamen nicht umleiten. Snapshot `--build-root` wählt absichtlich lokale Eingaben und besitzt keine private Eingabe-Allowlist; diese darf nicht aus der getrennt begrenzten Reportausgabe abgeleitet werden. Ein künftiger privilegierter Dienst mit nicht vertrauenswürdigen CLI-Eingaben bräuchte einen eigenen Vertrag. Drei `python:S1110`-Befunde betreffen aufgrund der Python-Präzedenz notwendige Klammern. Keine Cloud-Transition oder Hotspot-Freigabe wurde vorgenommen.

## Dokumentation und Runtime-Evidenz

Nur dieses Change-Record-Paar ändert lesergerichtete Dokumentation. Keine Host-Runtime, kein vollständiger Lifecycle, keine Matrix oder historische I12-Qualifikation wurde ausgeführt. Gezielte Tests prüfen nur Parserverhalten und Pfadzulassung. Daraus folgt keine Parent-Integration oder MRTS-Änderung.

## Nicht ausgeführte Prüfungen

Eine neue vollständige Sonar-Analyse gehört in die bestehende CI. Der Benutzer autorisierte am 2026-11-15 Commit, Push und Draft-PR dieses geprüften Aufgabenbranches; Cloud-Disposition und Merge gehören nicht zu dieser Freigabe. Aktuelle Liefer- und Analysebelege werden nach Veröffentlichung im Aufgabenplan und PR geführt. Lokaler Aggregate-/Agentic-Scanner und Sonar MCP wurden nicht verwendet. Ruff fehlt in der Framework-Umgebung; kein Paket wurde installiert. Vollständiges `make lint` erweitert auf unbeteiligte Suiten und wurde durch gezielte Validierung ersetzt. Die konfigurierte Framework-venv meldet Python 3.14.4, während `.python-version` 3.15.2 pinnt; CI mit exakt gepinntem Interpreter bleibt ungeprüft. Keine Toolchain-/Dependency-Datei wurde geändert.

## Einschränkungen und Restrisiko

Lokale Korrekturen zielen auf 80 Wartbarkeitsbefunde und neun Security-Stellen; nur eine neue Cloud-Analyse kann die Regelerledigung bestätigen. Für 26 Befunde (23 Security, drei notwendige Klammerausdrücke) bestehen quellengestützte Review-Empfehlungen; sie wurden nicht stillschweigend akzeptiert oder als Fehlalarm markiert. Die Cloud bleibt beim bisherigen fehlgeschlagenen Analysestand. Die begrenzte Szenarienzahl belegt keine projektweite technische Erzwingung der aktiven Inventargrenze. Das Gesamtergebnis auf Dienstebene bleibt bis Lieferung, aktueller Analyse und geprüfter Disposition teilweise offen.

## Finaler Diff- und Review-Status

Lokaler Aufgabenbranch `codex/framework-sonar-repair-20261115` im isolierten Framework-Worktree. Bei Abschluss der lokalen Verifikation waren Staging, Commit, Push und PR noch nicht ausgeführt. Die spätere Benutzerfreigabe erlaubt deren Ausführung; Merge und Wechsel des ursprünglichen Checkouts sind nicht Teil dieser Lieferung. Vorhandene Parent-Handoffs und Framework-Checkout-Identität bleiben erhalten. Die automatischen Edit-Hooks konnten auf dem externen Worktree zunächst nicht abschließen; erfolgreiche explizite Scans lösten diese Voraussetzung vor weiteren Lesezugriffen. OSV scheiterte zunächst am exakten Befehlsvertrag und bestand nach Beibehaltung des Helper-lokalen `result_file`; ein anfänglicher Importfehler des externen Report-Verifiers wurde vor dessen Szenario korrigiert. Keine Secret-Werte oder Rohbefunde sind dokumentiert.


Die unabhängige vollständige Diff-Prüfung fand eine eingeführte Regression: Ein extrahierter Body-Limit-Mapper verwendete `field` ohne Bindung. Der `NameError` wurde reproduziert und durch den festen Schlüssel `"body_limit_outcome"` korrigiert. Eine echte vorhandene Reject-Fixture prüft nun Wert und Originalereignis-Herkunft. Die erneute Symbolprüfung fand keine weiteren undefinierten Globals; das vollständige Review meldet keine weiteren materiellen Befunde.

Abschließender integrierter Aufruf, mit den dokumentierten Framework-Werten für `PYTHON` und `CODEX_RUN_ROOT` normalisiert, vom Aufgaben-Worktree aus:

```sh
rtk bypass "$PYTHON" -B "$CODEX_RUN_ROOT/framework-sonar-20261115/coordinator/run_integrated.py"
```

Beobachtet: Exit 0. Das Manifest `framework-sonar-20261115/coordinator/verification.json` enthält die tatsächlich expandierten argv, cwd, vollständigen Testselektoren, begrenzten nicht geheimen Umgebungswerte und jedes Exit-Ergebnis. Die sechs Auswahlen decken genau 100 aufgabenspezifische Szenarien ab: Runner 36, Protokolltests 16, Protokollvergleich 14, Pfadtests 15, Shell-/OSV-/Reporttests 18 und Reportvergleich 1. Alle bestanden. Syntax aller geänderten Python-Dateien, statische Symbolprüfung, `sh -n ci/lib/common.sh` und `git diff --check` bestanden ebenfalls. Diese Wiederholung prüft den integrierten Quellstand; sie zählt dieselben Szenarien nicht erneut als neue Fälle.

Die nativen Dokumentationsprüfungen sind `rtk make check-doc-links check-change-records check-bilingual-docs check-repository-path-references` mit dem konfigurierten Framework-`PYTHON` und externem `BUILD_ROOT`. Die lokale Pfadprüfung lehnte anfangs maschinenspezifische Evidenzreferenzen ab; die Dokumentation verwendet jetzt portable konfigurierte Wurzeln. Die EN/DE-Gegenprüfung fand gleichwertige Fakten und forderte das nun ergänzte exakte Befehlsmanifest. Keine Scannerregel oder Prüfung wurde dafür abgeschwächt.
