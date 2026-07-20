# Change Record

**Sprache:** [English](20260720-02-fix-flow-sequence-action-pins.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260720-02-fix-flow-sequence-action-pins` |
| UTC-Datum | 2026-07-20 |
| Framework-Basisrevision | `784977615acfc55567e37b863309abc4a38ac877` |
| Issue oder Pull Request | `FND-FRAMEWORK-0031`; [Framework-Draft-PR #38](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/38) auf `agent/codex-cloud-action-pin-flow-sequence` |

## Motivation und Problemstellung

Der Action-Pin-Validator untersuchte einen `uses`-Eintrag am Beginn einer
YAML-Flow-Sequenz nicht. Eine veränderliche externe Action konnte die
Full-SHA-Kontrolle umgehen.

## Betroffene Komponenten und Sicherheitsgrenzen

Der Framework-Validator verarbeitet PR-gesteuertes YAML vor GitHub Actions.
Weder Connector-Runtime noch Parent-Source oder MRTS-Inhalt sind beteiligt.

## Akzeptanzkriterien

- Veränderliche Actions an erster und Komma-Position einer Flow-Sequenz ablehnen.
- Eine äquivalente Full-SHA-Action akzeptieren und Block-/Flow-Map-Checks erhalten.

## Untersuchte Alternativen

Das Ersetzen des Standardbibliotheks-Parsers durch eine YAML-Abhängigkeit würde
den Pin-Check vor Entwicklungsabhängigkeiten verändern.

## Implementierungsentscheidung

`[` wird in Collection-Position erkannt, `]` getrackt und der vorhandene
Depth-bewusste Scanner/Syntax-Guard für Flow-Sequenz-Einträge verwendet.

## Geänderte Dateien und Tests

- `ci/checks/security/check-workflow-action-pins.py`
- `tests/security_regression/test_workflow_action_pins.py`
- `docs/github-actions-workflow-security.md` und `.de.md`

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | ---: | --- | --- |
| `PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 python3 -m unittest …flow_sequence…` vor dem Fix | 1 | Negative Regression reproduzierte die Umgehung; positiver Control bestand. | Isolierter Framework-Worktree |
| `PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.security_regression.test_workflow_action_pins` | 0 | 25 fokussierte Standardbibliotheks-Tests bestanden. | Isolierter Framework-Worktree |
| `PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 python3 -m py_compile …` | 0 | Geänderte Python-Dateien kompilierten. | Isolierter Framework-Worktree |
| `git diff --check` | 0 | Keine Whitespace-Fehler. | Isolierter Framework-Worktree |

## Sicherheitsauswirkung

Der ursprüngliche Pfad und die Komma-Positionsumgehung wurden durch den echten
Validator erneut geprüft; eine Full-SHA ist der legitime gleichgrenzige Control.

## Dokumentation und Runtime-Evidenz

Die englische/deutsche Guidance nennt Flow-Sequenz-Maps. Keine Host-Runtime-
Evidence, weil es eine statische Validator-Remediation ist.

## Nicht ausgeführte Prüfungen

Der vollständige abhängigkeitsgestützte Framework-Lint-/Permission-Check ist
wegen fehlender Framework-virtueller Umgebung blockiert; keine Parent-Umgebung
wurde ersetzt. GitHub, Sonar, Review und Cloud-Rescan folgen in der PR-Phase.

## Einschränkungen und Restrisiko

Komplexe nicht unterstützte YAML-Syntax muss fail-closed bleiben. Die
Cloud-Schließung benötigt einen frischen authentifizierten Final-master-Scan.

## Finaler Diff- und Review-Status

Fokussierter Diff- und Whitespace-Review sind abgeschlossen. Keine Secrets,
Parent-Änderungen oder MRTS-Änderungen sind enthalten. Draft-PR #38 existiert;
jeder weitere Push benötigt einen frischen Zyklus aus lokaler, Remote- und
PR-Head-SHA sowie CI-/Review-Verifikation.
