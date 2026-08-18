# Automatisches HAProxy-HTX-Maintenance-Update verhindern

**Sprache:** [English](20260818-01-prevent-htx-automatic-maintenance-update.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260818-01-prevent-htx-automatic-maintenance-update` |
| UTC-Datum | 2026-08-18 |
| Framework-Basisrevision | `59b17f26b09ade5a6a354cec86e78b03da2717a4` |
| Issue oder Pull Request | Framework-PR [#96](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/96) |

## Motivation und Problemstellung

Das kanonische Maintenance-Update von PR #96 klassifizierte das unabhängig
gepinnte HAProxy-HTX-Tupel als automatisch. Es ersetzte das geprüfte HTX-3.2.21-
Tupel durch das generische HAProxy-3.2.22-Tupel. Dadurch schlug die
Runtime-Inventar-Distinktionskontrolle in Actions-Lauf `32065088898`, Job
`95543983427`, fehl.

## Betroffene Komponenten und Sicherheitsgrenzen

- `ci/tools/check-common-versions.py` kontrolliert die Grenze zwischen
  Upstream-Listing und Maintenance-Plan.
- `ci/lib/common.sh` ist die kanonische geprüfte Pin-Autorität.
- `ci/provisioning/runtime-component-lock.json` ist die generierte
  Runtime-Lock-Projektion für die Provisionierung.

Das HTX-Profil bleibt ein unabhängig geprüfter Release-, URL- und Digest-
Tupel; automatische Maintenance darf das generische HAProxy-Artefakt nicht
stillschweigend einsetzen.

## Akzeptanzkriterien

- Ein neueres HTX-Release oder ein HTX-Checksum-Drift erzeugt Manual Review
  und kein automatisches Update.
- Der generische HAProxy-Update-Pfad bleibt automatisch.
- Das eingecheckte HTX-Tupel und der generierte Lock enthalten wieder 3.2.21
  und dessen geprüfte SHA-256.
- Der ursprüngliche Runtime-Inventar-Fehler und ein alternativer
  Checksum-Drift-Pfad sind durch deterministische Tests abgedeckt.

## Untersuchte Alternativen

- Die HTX-gegen-generisch-Distinktionsassertions zu aktualisieren oder zu
  entfernen wurde verworfen, weil dies die unabhängige Provenance-Kontrolle
  entfernen würde.
- Nur die Descriptor-Policy zu ändern wurde verworfen, weil der Planer jedes
  `outdated`-Ergebnis unabhängig von diesen Metadaten aufnimmt.

## Implementierungsentscheidung

Der HTX-Descriptor ist als `manual_review` klassifiziert; sein vollständiges
unabhängiges atomares Tupel ist als byte-exakte Manual-Provenance registriert.
Beide Resolver-Pfade, die zuvor automatische Updates lieferten, liefern jetzt
Review-required-Ergebnisse ohne Updates. Der generierte Lock wurde aus dem
wiederhergestellten kanonischen 3.2.21-Tupel regeneriert. Generisches HAProxy
behält seine automatische Policy.

## Geänderte Dateien und Tests

- `ci/tools/check-common-versions.py`
- `ci/lib/common.sh`
- `ci/provisioning/runtime-component-lock.json` (generiert)
- `tests/security_regression/test_common_versions_sonar_provenance.py`
- Dieses englische/deutsche Change-Record-Paar.

Die Tests decken den ursprünglichen neueren Release-Pfad, reinen Checksum-
Drift, den Ausschluss aus dem Manual-Plan und den legitimen automatischen
generischen-HAProxy-Update-Pfad ab.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Fokussiertes Pre-Fix-Runtime-Sync-Testmodul | 1 | Die zwei exakten HTX-Assertions des ausgewählten Actions-Jobs wurden reproduziert. | Actions-Lauf `32065088898`, Job `95543983427` |
| `python ci/tools/sync-runtime-components.py --write` | 0 | Runtime-Lock aus kanonischen Pins regeneriert. | Lokaler isolierter Worktree |
| Fokussierte 37-Test-Security-/Runtime-Suite | 0 | HTX-Manual-Review-, Checksum-Drift-, Lock-, Sync- und Descriptor-Kontrollen bestanden. | Lokaler isolierter Worktree |
| `python ci/tools/sync-runtime-components.py --check` | 0 | Generierte Projektionen sind aktuell. | Lokaler isolierter Worktree |
| `./ci/tools/safe-make.sh -s lint` | 0 | Vollständige Framework-Lint-, Security-, Runtime-Lock-, Dokumentations- und Workflow-Contract-Suite bestanden. | Lokaler isolierter Worktree mit projektzulässigem Report-Root |
| `python -m ruff check ...` | 1 | Ruff ist nicht im ausgewählten Framework-Environment installiert; es wurde keine Dependency installiert. | Lokale Environment-Evidenz |

## Sicherheitsauswirkung

Der ursprüngliche Pfad (`official listing → HTX resolver → automatic plan →
common pins → generated lock`) erzeugt kein automatisches HTX-Update mehr. Der
neue Version-Transition-Test beweist dies, und der Checksum-Drift-Test deckt
den alternativen Resolver-Zweig ab. Keine Host-Allowlist, Digest-Validierung,
Action-Pin oder Qualitätskontrolle wurde abgeschwächt.

## Dokumentation und Runtime-Evidenz

Dieses gepaarte Change Record ist die leserorientierte Dokumentationsänderung.
Es wurde keine Live-Connector-Runtime ausgeführt, weil die Korrektur die
Maintenance-Klassifizierung und generierte Metadaten, nicht das Connector-
Verhalten, ändert.

## Nicht ausgeführte Prüfungen

- Die Hosted-Checks für den aktuellen Head stehen aus, bis diese Korrektur
  committed und nach PR #96 gepusht wurde.
- Ruff ist im bestehenden Framework-Environment nicht verfügbar; die
  Installation liegt außerhalb des Dependency-Umfangs dieser Korrektur.

## Einschränkungen und Restrisiko

Der HTX-3.2.22-Kandidat ist absichtlich für eine separate geprüfte Provenance-
und Kompatibilitätsentscheidung zurückgestellt. Diese Aufgabe mergt PR #96
nicht und ändert keinen Parent- oder MRTS-Zustand.

## Finaler Diff- und Review-Status

Der fokussierte Review von Source- und generiertem-Lock-Diff ist abgeschlossen;
`git diff --check` besteht. Dieser Record enthält keinen Commit, Push,
PR-Merge, Credentials oder rohe sensible Logs.
