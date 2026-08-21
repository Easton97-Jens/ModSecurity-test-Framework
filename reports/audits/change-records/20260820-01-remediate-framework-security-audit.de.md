# Change Record

**Sprache:** [English](20260820-01-remediate-framework-security-audit.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260820-01-remediate-framework-security-audit` |
| UTC-Datum | 2026-08-20 |
| Framework-Basisrevision | `bd69ee96e0e7082317d4afe1232bee625665eb9a` |
| Issue oder Pull Request | Vom Nutzer autorisierte Framework-Draft-PR-Auslieferung; der beim Commit erstellte Record erfindet bewusst keine PR-Nummer, Commit-SHA oder Hosted-Check-Resultate |

## Motivation und Problemstellung

Ein defensives Framework-Audit bestätigte fünf unabhängige Kontrollen, die
unsichere Eingaben akzeptieren oder unsichere Evidenz erhalten konnten:
Symlinks im Source-Tree, Archive-Links, externe oder veraltete Runtime-
Snapshot-Daten und abgelehnte Request-Body-Payloads in JSONL-Normalizern. Die
Arbeit behebt ausschließlich diese Framework-Kontrollen und dokumentiert
`FND-FRAMEWORK-0093` bis `FND-FRAMEWORK-0097`.

## Betroffene Komponenten und Sicherheitsgrenzen

- `ci/provisioning/materialize-connector-source.py`: Nicht vertrauenswürdige
  Source-Tree-Einträge dürfen beim Materialisieren die Source-Root nicht
  verlassen.
- `ci/lib/runtime-component-common.sh`: Ein verifiziertes Archiv darf vor dem
  Extrahieren weiterhin nur reguläre Dateien und Verzeichnisse enthalten.
- `ci/reporting/update-runtime-snapshot.py`: Runtime-Report-Input darf keinen
  Case außerhalb der konfigurierten Roots lesen oder veraltete `PASS`-Evidenz
  in ein aktuelles Resultat umwandeln.
- `tests/normalizers/*.py`: Ein abgelehntes body-ähnliches Feld darf niemals in
  normalisierten Output geschrieben werden.

Kein Connector, kein Parent-Product-Source, kein Gitlink und keine MRTS-
Source-/Runtime-Fläche wird geändert.

## Akzeptanzkriterien

- Der Materializer lehnt File- und Directory-Symlinks vor dem Kopieren ab.
- gzip- und xz-Archive mit Link-Membern werden abgelehnt; reguläre Member
  lassen sich weiterhin extrahieren.
- Runtime-Snapshots verwenden nur einen vertrauenswürdigen in-root Case-Pfad
  und ausschließlich aktuelle Run-Evidenz; `not_run` kann nicht zu `PASS`
  aufgewertet werden.
- Event-, Decision- und Hash-Chain-Normalizer geben bei Standard-, verschachtelten
  Camel-Case- oder Bindestrich-Body-Keys keinen Output aus.
- Fokussierte Regressionstests und statische Prüfungen bestehen ohne Netzwerk,
  Host-Smoke, Matrix- oder MRTS-Ausführung.

## Untersuchte Alternativen

Unsichere Einträge nur zu überspringen oder Output erst nach seiner Erzeugung
zu bereinigen wurde verworfen: Das ließe mehrdeutige Teil-Artefakte oder ein
Leak-Fenster. Die gewählten Kontrollen scheitern an der gemeinsamen Grenze
fail-closed: Links vor Extraktion/Kopie abweisen, Report-Pfade vor dem
Metadata-Laden begrenzen und bei jedem Validierungsfehler leeren Normalizer-
Output erzeugen.

## Implementierungsentscheidung

Die Änderungen erhalten gültige reguläre Datei- und Archivpfade. Der Snapshot-
Report modelliert fehlende aktuelle Evidenz explizit, statt früheren Runtime-
Status wiederzuverwenden. Body-Feld-Aliase werden vor dem Policy-Match
kanonisiert, damit Schreibvarianten die Redaction-Kontrolle nicht umgehen. Kein
Security-Gate wird abgeschwächt und kein externes Artefakt oder Ziel wurde
angesprochen.

## Geänderte Dateien und Tests

- Source-Kontrollen: `ci/provisioning/materialize-connector-source.py` und
  `ci/lib/runtime-component-common.sh`.
- Evidenz-Kontrollen: `ci/reporting/update-runtime-snapshot.py` sowie
  `tests/normalizers/security_event_normalizer.py`,
  `tests/normalizers/decision_jsonl_normalizer.py` und
  `tests/normalizers/integrity_hash_chain_normalizer.py`.
- Regressionsabdeckung: `tests/security_regression/test_materialize_connector_source.py`,
  `test_runtime_component_download.py`, `test_runtime_snapshot_sonar.py` und
  `test_normalizer_payload_safety.py` sowie der Normalizer-Security-Checker.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Private deterministische Materializer-Prüfung | 0 | Pre-Fix-Symlink wurde dereferenziert; Post-Fix-Test lehnt File- und Directory-Links ab | `20260820T185914Z-framework-defensive-security-audit` |
| Private deterministische Archiv-Prüfung | 0 | Pre-Fix-Tar-Link-Member wurde akzeptiert; Regression lehnt Symlink- und Hardlink-Member ab | Gleiche Run-ID |
| `python3.14 -m unittest ...test_materialize_connector_source.py` | 0 | 2 Tests bestanden | Gleiche Run-ID |
| `python3.14 -m unittest ...test_runtime_component_download.py` | 0 | 19 Tests bestanden, inklusive regulärem xz-Control und Link-Ablehnung | Gleiche Run-ID |
| `python3.14 -m unittest ...test_runtime_snapshot_sonar.py` | 0 | 7 Tests bestanden | Gleiche Run-ID |
| `python3.14 -m unittest ...test_normalizer_payload_safety.py` | 0 | 3 Tests bestanden | Gleiche Run-ID |
| `python3.14 ci/checks/security/check-security-data-flow-normalizers.py` | 0 | Normalizer-Data-Flow-Kontrolle bestanden | Gleiche Run-ID |
| `sh -n ci/lib/runtime-component-common.sh` | 0 | Shell-Syntax bestanden | Gleiche Run-ID |
| `make check-documentation` | 0 | Links, Sprachpaare, Pfadprüfungen und Change-Record-Contract bestanden | Gleiche Run-ID |
| `make check-no-crs-catalog` | 0 | PASS (166 Cases) | Gleiche Run-ID |
| Finales `make lint` | 0 | Vollständige lokale Lint-, Contract-, Workflow-, Provenance-, Dokumentations- und Whitespace-Suite bestanden | Gleiche Run-ID |
| Finales `make quick-check` | 0 | Vollständige Lint-Voraussetzung plus statischer MRTS-Importer-Check bestanden; keine MRTS-Quelle wurde initialisiert oder ausgeführt | Gleiche Run-ID |

## Sicherheitsauswirkung

Die ursprünglichen Pfade und alternative Umgehungsvarianten wurden ausschließlich
mit harmlosen privaten Fixtures erneut geprüft. Links scheitern jetzt fail-
closed, veraltete und out-of-root Snapshot-Inputs erzeugen keinen aktuellen
Pass, und abgelehnte Body-Payloads erscheinen nicht auf stdout. Die unabhängige
Endprüfung fand einen verwandten Pfad für stale Counts/Text-Evidence in der
Snapshot-Korrektur; er wurde vor der finalen Suite behoben und regressionsgetestet.
Das sind lokale Source-Level-Ergebnisse; weder Hosted-CI noch Production-Runtime
werden behauptet.

## Dokumentation und Runtime-Evidenz

Dieses englische Record und sein deutsches Gegenstück dokumentieren die
Remediation. Ein sanitisiertes lokales Evidenz-Receipt liegt im Parent Finding
Store. Es wurde keine Connector-Runtime-, Host-Smoke-, Full-Matrix- oder MRTS-
Evidenz gesammelt.

## Nicht ausgeführte Prüfungen

- `make check-test-matrix` wurde nicht ausgeführt, weil es Framework-Reports
  über den with-MRTS-Pfad aktualisiert; das liegt außerhalb der Nutzerfreigabe.
- Kein netzwerkgebundener Provisioner, Download, Connector-Smoke, Full-Runtime-
  Matrix oder externes Ziel wurde ausgeführt.
- Der gehostete Codex-Security-Deep-Scan-Koordinator war in dieser Sitzung nicht
  verfügbar; stattdessen wurden ein manuelles Multi-Surface-Review und ein
  erfolgreicher Diff-Scan-Preflight festgehalten.
- Ein Delivery-Lauf von `make lint` im sauberen Worktree traf auf einen nicht
  zusammenhängenden, timing-sensitiven Writerless-FIFO-Observation-Test. Sein
  genau einmal erlaubter fokussierter Wiederholungslauf bestand; dieser Record
  bezeichnet den vollständigen Delivery-Lint-Lauf nicht als grün, und die
  Hosted-CI des aktuellen Heads bleibt die maßgebliche Nachprüfung.

## Einschränkungen und Restrisiko

Das Audit hat die Production-Reachability jedes zurückgestellten Kandidaten
nicht nachgewiesen, unter anderem bei veränderlichen Upstream-Opt-in-Sources und
nativen MRTS-Report-Producern. Die Archivmember-Prüfung ist bewusst für alle
Link- und Spezial-Member fail-closed; ein künftiger Formatbedarf muss eine
separat geprüfte sichere Repräsentation ergänzen.

## Finaler Diff- und Review-Status

Der ursprüngliche Framework-Audit-Working-Tree enthielt nur lokale, unstaged
Remediation und dieses Record-Paar. Der Nutzer hat später die Auslieferung
dieser exakt Framework-eigenen Änderung über einen Task-Branch, Commit, Push
und Draft PR autorisiert. Dieser versionierte Record erfindet bewusst weder die
spätere Commit-SHA noch PR-Nummer, Hosted-Checks oder Merge-Status; die
Delivery-Evidenz hält diese beobachteten Fakten separat fest. Parent-Gitlink und
MRTS bleiben unverändert. Finales git diff --check, fokussierte Tests,
Dokumentation, No-CRS-Katalog, make lint und make quick-check bestanden in der
zugehörigen ursprünglichen lokalen Finding-Evidenz. Der formale Deep-Scan-
Koordinator bleibt blocked_environment; das manuelle Multi-Surface-Review
behauptet nicht, ihn zu ersetzen.
