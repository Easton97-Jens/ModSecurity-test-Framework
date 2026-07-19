# Change Record — 20260719-01-migrate-framework-python-313-ci

**Sprache:** [English](20260719-01-migrate-framework-python-313-ci.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260719-01-migrate-framework-python-313-ci` |
| UTC-Datum | `2026-07-19` |
| Framework-Basisrevision | `047c11140ba7f2bd170b6f313d0223d0cd37f1be` |
| Issue oder Pull Request | Ausstehend — Task-Branch `agent/framework-python-313-master-migration`; normaler Framework-PR ist noch nicht erstellt |

## Motivation und Problemstellung

Der aktuelle Framework-master wählte Python 3.13 breit aus, ließ aber den
strikten CI-Dependency-Lock an das CPython-3.12.13-CP312-PyYAML-Wheel gebunden.
Hosted Jobs scheiterten korrekt fail closed, weil ein CP313-Wheel einen anderen
SHA-256 besitzt. Der source-eigene Security-Checker verlangte weiter 3.12.13,
und jedem `setup-python`-Use fehlte `check-latest: false`.

Der gleiche statische Vertrag legte einen getrennten Provenance-Drift offen:
Workflows pinnen `actions/upload-artifact` bereits an den unveränderlichen
v7.0.1-Commit, während der Custom-Action-Lock noch v5.0.0 verzeichnete. Dieser
Record deckt die minimale kombinierte Reparatur ab, die für einen kohärenten,
fail-closed Python-3.13-CI-Vertrag erforderlich ist.

## Betroffene Komponenten und Sicherheitsgrenzen

- Zwölf `actions/setup-python`-Uses in acht Workflows verwenden exaktes
  CPython `3.13.14` mit `check-latest: false`.
- `requirements-ci.lock` benennt das geprüfte CP313-PyYAML-6.0.3-Linux-x86_64-
  Wheel und seinen verifizierten SHA-256.
- `ci/checks/security/check-ci-security-contract.py` erzwingt dieselbe exakte
  Version und verlangt weiterhin hash-gesperrte Installation.
- `ci/tooling/security-tools.lock.yml` entspricht dem aktiven
  unveränderlichen `actions/upload-artifact`-v7.0.1-Pin.
- Der gepaarte CI-Security-Tooling-Leitfaden dokumentiert den exakten
  CP313-Vertrag.

Die Grenze ist CI-Dependency- und Action-Provenance. Keine Permission,
Artifact-Retention, kein mutabler Tag, `--require-hashes`, Parent,
Parent-Gitlink oder MRTS-Verhalten wird geändert.

## Akzeptanzkriterien

1. Jeder aktive Python-CI-Use im Scope ist exakt `3.13.14` mit
   `check-latest: false`.
2. CP313-Dateiname und SHA-256 in `requirements-ci.lock` stimmen mit dem
   offiziellen Artifact überein und bestehen Target-ABI
   `pip download --require-hashes`.
3. CI-Security-Checker und Action-Lock akzeptieren aktuellen Source, während
   ihre Negativ-Controls Mismatches weiterhin ablehnen.
4. Englische und deutsche Security-Dokumentation bleiben äquivalent.
5. Exakte PR-Head- und resultierende-Master-Hosted-Validierung bleiben nötig.

## Untersuchte Alternativen

- Das Wiederherstellen von CPython 3.12.13 ließe den alten Lock arbeiten,
  erfüllte aber nicht die gewünschte Python-3.13-Migration.
- `--require-hashes` zu löschen oder zu lockern würde den Defekt verbergen und
  ein Supply-Chain-Control schwächen; es wurde verworfen.
- Aktive v7.0.1-Action-Pins zurückzurollen wäre nicht zugehörige Rollback-
  Arbeit. Nur den veralteten Provenance-Record zu aktualisieren ist die
  kleinste konsistente Reparatur.
- Direkter `master`-Push ist verboten; Delivery verwendet einen normalen
  Task-Branch-PR.

## Implementierungsentscheidung

Der gewählte Vertrag ist exaktes CPython `3.13.14` mit `check-latest: false`.
Der geprüfte CP313-Wheel-SHA-256 ist
`0f29edc409a6392443abf94b9cf89ce99889a1dd5376d94316ae5145dfedd5d6`.
Der aktive Action-Lock verzeichnet nun den v7.0.1-unveränderlichen Commit
`043fb46d1a93c77aae656e7c1c64a875d1fc6a0a`.

Es wird keine Dependency im Checkout installiert. Die Target-ABI-Validierung
lädt nur das gepinnte Wheel in das task-eigene externe Run-Verzeichnis. Parent
und MRTS bleiben unverändert.

## Geänderte Dateien und Tests

- Acht Workflow-Dateien: `lint.yml`, `check-action-versions.yml`,
  `check-common-versions.yml`, `ci-security-osv.yml`,
  `ci-security-quality.yml`, `ci-security-scorecard.yml`,
  `ci-security-secrets.yml` und `ci-security-workflow-lint.yml`.
- `requirements-ci.lock`, `ci/checks/security/check-ci-security-contract.py`
  und `ci/tooling/security-tools.lock.yml`.
- `docs/security/ci-security-tooling.md` und sein deutsches Gegenstück.
- Dieses englisch/deutsche Change-Record-Paar.

Es waren keine Testsource-Änderungen nötig. Das vorhandene
`test_current_workflows_and_lock_pass` scheitert mit altem inkonsistentem
Source und besteht mit repariertem Source. Die Suite behält Negativ-Tests für
fehlende exakte Version, fehlendes `check-latest`, fehlende Hash-Sperre sowie
fehlerhafte oder mutable Action-Referenzen.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `ci/checks/security/check-ci-security-contract.py --root .` über die vorhandene Framework-virtuelle Umgebung | 0 | Aktueller CI-Security-Vertrag bestand. | `20260719T211529Z-framework-python-313-master-migration-939e61b5` |
| `make ... test-ci-security-contract check-github-actions-workflows test-workflow-action-pins` mit externem `BUILD_ROOT` und `TMP_ROOT` | 0 | 69 CI-Security-Tests, Action-Pins und Permissions bestanden. | Task-eigenes `downloads/build` |
| `pip download --require-hashes` für CP313, `manylinux2014_x86_64` und ABI `cp313` | 0 | Nur das geprüfte Wheel wurde geladen; lokaler SHA-256 entsprach dem Lock. | Task-eigenes `downloads/pyyaml-cp313` |
| `gh api repos/actions/upload-artifact/git/ref/tags/v7.0.1 --jq .object.sha` | 0 | Offizieller Tag löst auf `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` auf. | Externe GitHub-API-Evidence |
| `git diff --check` | 0 | Kein abgegrenzter Whitespace-Fehler. | Task-Worktree |

## Sicherheitsauswirkung

Der ursprüngliche CP313/CP312-Mismatch bleibt fail closed: `--require-hashes`
und die negative Contract-Coverage bleiben erhalten. Der legitime CP313-Pfad
hat einen exakten geprüften Wheel-Digest. Der veraltete Action-Lock wird mit
dem bereits aktiven unveränderlichen Commit synchronisiert, nicht mit einem
mutablen Tag. Kein Bypass, keine Suppression, Permission-Erweiterung,
Scanner-Waiver oder Quality-Gate-Änderung wurde durchgeführt.

Originaler Hosted-Fehler und alternative Bypass-Evidence bleiben für exakten
PR-Head und resultierenden Master erforderlich, bevor eines der Findings
verifiziert werden kann.

## Dokumentation und Runtime-Evidenz

Der gepaarte CI-Security-Tooling-Leitfaden verzeichnet nun CPython `3.13.14`
und das CP313-Wheel. Dieser Record dokumentiert nur statische CI- und Target-
Artifact-Evidence; er behauptet keine Connector-Runtime, keinen Lifecycle und
keine gehostete CPython-Runtime.

## Nicht ausgeführte Prüfungen

- Aggregiertes `make lint`: wurde zweimal mit task-eigenem externem Output
  gestartet, aber dieser Execution-Wrapper lieferte nach seiner Verbose-Ausgabe
  keinen terminalen Exit-Code. Jeder verbleibende Makefile-Baustein wurde
  danach einzeln mit Exit-Code 0 ausgeführt: Workflow-Contracts, CI-Security-
  Tests, Change Record, CRS-Provenance, Action-Pins, Dokumentation, Datenfluss,
  Katalog und Shell-Contracts. Es ist deshalb als `not_run_to_terminal`, nicht
  als vollständiger aggregierter Pass erfasst.
- Exakte PR-Head-GitHub-Actions, Review, SonarQube Cloud und resultierende-
  Master-Verifikation: ausstehend bis zur normalen PR-Erstellung und dem
  Protected Merge.
- Lokale CPython-3.13.14-Runtime: auf diesem Host nicht verfügbar. CP313-
  Target-Wheel-Auflösung ist Artifact-Auswahl-Evidence, kein Hosted-Runtime-
  Beweis.

## Einschränkungen und Restrisiko

Die vorhandene Framework-virtuelle Umgebung nutzt CPython 3.14.4. Sie
validiert den statischen Vertrag, ersetzt aber nicht gehostetes CPython-3.13.14-
Verhalten. Master enthält den fehlerhaften Vertrag weiter, bis der Task-PR
gemergt ist. Bestehender master-only-SonarCloud-Backlog und unabhängige GitHub-
Konfigurationsfindings werden weder geändert noch waived.

## Finaler Diff- und Review-Status

Der Pre-Commit-Scoped-Diff wurde geprüft und `git diff --check` bestand. Es
sind keine Credentials, Tokens, Raw-Logs oder sensitiven Payloads dokumentiert.
Commit, Push, PR-Review und Exact-Head-Hosted-Validierung stehen aus; dieser
Record wird mit ihren tatsächlichen Identifikatoren und Ergebnissen aktualisiert,
sobald sie existieren.
