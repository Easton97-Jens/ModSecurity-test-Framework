# Change Record

**Sprache:** [English](20260718-01-fix-framework-common-structure.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260718-01-fix-framework-common-structure` |
| UTC-Datum | `2026-07-18` |
| Framework-Basisrevision | `cdc91a398d6c156eaff927d742b23018a3817fb6` |
| Issue oder Pull Request | Zum Zeitpunkt dieses Records keiner; ein Draft PR folgt dem Commit dieses Records. |

## Motivation und Problemstellung

`test-common / common-structure` verlangte exakt 141 YAML-Dateien, während der aktuelle Framework-Katalog 179 enthält. Das Entfernen dieses veralteten Guards legte einen zweiten Defekt offen: Die Runtime-Discovery validierte einen `former_xfail`-/`connector-gap`-Security-Data-Flow-Katalogfall vor der Eignungsfilterung, obwohl diese reine Katalogbeschreibung absichtlich keine Runtime-`rules` besitzt.

## Betroffene Komponenten und Sicherheitsgrenzen

- `.github/workflows/test-common.yml`: CI-Bestand- und Materialisierungsvertrag.
- `tests/runners/runner_core.py`: Grenze für Repository-YAML-Discovery und Runtime-Schemavalidierung.
- `tests/workflow_contract/test_common_structure_workflow.py`: fokussierte Regressionsabdeckung.
- `Makefile` und `docs/testing-and-evidence{,.de}.md`: lokales Test-Target und dokumentierter Vertrag.

Die Änderung erhält YAML-Parsing, Fallvalidierung, Shell-Quoting und task-eigene temporäre Output-Grenzen. Sie ist keine Security-Remediation und ändert weder Sonar-Regeln, Exclusions oder Scanner-Konfiguration noch Parent-Inhalte oder MRTS.

## Akzeptanzkriterien

- Keine feste YAML-Bestandzahl blockiert eine gültige Katalogerweiterung.
- Ein leerer Bestand und eine leere Apache-Common-Auswahl schlagen explizit fehl.
- Nicht-Runtime-Katalogfälle werden vor der Runtime-spezifischen Schemavalidierung ausgeschlossen.
- Jeder ausgewählte Runtime-Fall wird weiterhin validiert, materialisiert und geprüft.
- Der fokussierte Regressionstest und die wörtliche common-structure-Kontrolle bestehen.
- Englische/deutsche Dokumentation und dieses gepaarte Change Record stimmen überein.

## Untersuchte Alternativen

- Das Aktualisieren von `141` auf `179` würde einen weiteren veralteten Inventarvertrag erzeugen.
- Ein globales Manifest würde die dokumentierte YAML-/Runner-Quelle der Wahrheit duplizieren.
- Synthetische Runtime-`rules` würden connector-neutrale reine Katalog-Evidence-Beschreibungen falsch darstellen.

## Implementierungsentscheidung

Der Workflow prüft nur noch einen nichtleeren YAML-Bestand und eine nichtleere dynamische Apache-Common-Auswahl. Der Runner liest Fallmetadaten, wendet die bestehende Eignungslogik an und führt die vollständige Runtime-Schemavalidierung nur für ausgewählte Runtime-Fälle aus. Dedizierte statische Checks bleiben für reine Katalogfälle zuständig; die vorhandene Materialisierungs- und Status-Assertion-Schleife bleibt für Runtime-Fälle erhalten.

## Geänderte Dateien und Tests

- `.github/workflows/test-common.yml`
- `Makefile`
- `tests/runners/runner_core.py`
- `tests/workflow_contract/test_common_structure_workflow.py`
- `docs/testing-and-evidence.md`
- `docs/testing-and-evidence.de.md`
- dieses englische/deutsche Change-Record-Paar

Der fokussierte Test führt dynamisch `case_cli.py list-cases` aus und beweist, dass eine nicht ausführbare Security-Data-Flow-Katalogbeschreibung nicht materialisiert wird. Die wörtliche Workflow-Kontrolle liefert den positiven Materialisierungs-/Statuspfad.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `make test-workflow-contract` mit externem `BUILD_ROOT` | `0` | Zwei fokussierte Workflow-Vertragstests bestanden. | `20260718T081746Z-framework-common-structure-d6ee7cec` / `evidence/common-structure-current.md` |
| Wörtlicher `common-structure`-Materialisierungs-/Assertion-Block mit externem `RUNNER_TEMP` | `0` | Aktuelle Apache-Common-Fälle wurden erfolgreich materialisiert und geprüft. | `20260718T081746Z-framework-common-structure-d6ee7cec` / `evidence/common-structure-current.md` |
| `python -m compileall -q tests/runners tests/workflow_contract` mit externem Pycache | `0` | Geändertes Python und fokussierter Test kompilierten. | Task-eigener temporärer Pfad |
| `make lint` mit externem Pycache/Build-Root | `0` | Projektchecks abgeschlossen; siehe Einschränkungen für die Warnung des festen `/tmp`-Subchecks. | Task-eigener temporärer Pfad |
| `git diff --check` | `0` | Kein Whitespace-Fehler. | Framework-Worktree |

## Sicherheitsauswirkung

Keine Security-Remediation wurde durchgeführt. Die fokussierte Prüfung fand keine neue RCE-, Path-Traversal-, YAML-, `case.env`-, Subprocess- oder Temporary-Output-Schwachstelle im geänderten Discovery-Pfad. Ein separater Protocol-URL-Evidence-Redaktionskandidat wurde für spätere fokussierte Validierung erfasst und ist nicht Teil dieser Änderung.

## Dokumentation und Runtime-Evidence

`docs/testing-and-evidence.md` und das deutsche Gegenstück dokumentieren den dynamischen common-structure-Vertrag und sein fokussiertes lokales Test-Target. Die wörtliche Workflow-Kontrolle erzeugte nur lokale Struktur-/Materialisierungs-Evidence; sie behauptet keine Connector-Runtime-Unterstützung oder Sonar-Quality-Gate-Erfolg.

## Nicht ausgeführte Prüfungen

- Ruff und Pyright waren in der ausgewählten Repository-Umgebung nicht verfügbar; keine Tool-Installation war autorisiert.
- ShellCheck ist nicht direkt auf den geänderten Inline-GitHub-Actions-YAML-Shell-Block anwendbar; die Framework-Shell-Syntaxchecks liefen über `make lint`.
- Vollständige Connector-, CRS- und MRTS-Matrizen liegen außerhalb dieser fokussierten CI-Reparatur.
- Das unabhängige Sonar-Quality-Gate benötigt separate Remediation.

## Einschränkungen und Restrisiko

Der native CRS-Version-Pinning-Subcheck verwendet fest `/tmp`. Seine Sandbox-Redirections wurden verweigert, daher kann der Gesamt-Exit von `make lint` nicht beweisen, dass dieser eine Subcheck Inputs untersucht hat. Es wurde kein Source-Workaround und kein nicht registrierter temporärer Ort verwendet. Der Draft PR kann kein verifiziertes Quality Gate erreichen, solange der unabhängige Sonar-Backlog ungelöst bleibt.

## Finaler Diff- und Review-Status

Der Pre-Commit-Review bestätigt einen fokussierten Framework-only-Diff, sauberen Whitespace und keine Änderung an Parent-Produkt/Gitlink oder MRTS. Commit, Push, Draft PR und exakte Head-CI-/Review-Verifikation sind zum Erstellungszeitpunkt dieses Records noch ausstehend.
