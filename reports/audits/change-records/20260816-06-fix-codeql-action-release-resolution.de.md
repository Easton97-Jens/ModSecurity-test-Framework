# Change Record: 20260816-06-fix-codeql-action-release-resolution

**Sprache:** [English](20260816-06-fix-codeql-action-release-resolution.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260816-06-fix-codeql-action-release-resolution` |
| UTC-Datum | `2026-08-16` |
| Framework-Basisrevision | `f583bbfd74f8e0e76f0a65378702cbbaad77e7d8` |
| Issue oder Pull Request | Resulting-Master-Workflow-Lauf `31975000540`; ein Pull-Request- oder Commit-Ergebnis ist durch diesen Record nicht festgestellt. |

## Motivation und Problemstellung

Der `Check common.sh versions`-Lauf auf dem resultierenden Master scheiterte
im kanonischen Maintenance-Resolver mit Exit-Code 2. Die beobachtete CodeQL-
Quelle war `github/codeql-action/releases/latest`; deren Antwort bezeichnete
ein CodeQL-Bundle (`codeql-bundle-v2.26.3`) statt eines numerischen Action-
Release-Tags. Der generische Parser für stabile Actions konnte dadurch keinen
unterstützten `latest_upstream`-Action-Release erzeugen, und der geschlossen
scheiternde Resolver beendete den Maintenance-Plan.

## Betroffene Komponenten und Sicherheitsgrenzen

Betroffen sind der kanonische Maintenance-Resolver und der lock-bewusste
Workflow-Tool-Updater des Frameworks. Die relevante Grenze ist die vertrauens-
würdige CI-Wartung, die offizielle GitHub-Release-Metadaten konsumiert und
einen automatisch ausgewählten Action-Tag desselben Majors auf einen
unveränderlichen Commit auflöst. Parent,
Connector-Runtime und das schreibgeschützte `tools/MRTS`-Checkout liegen
außerhalb des Scopes.

## Akzeptanzkriterien

1. CodeQLs `latest_upstream` wird von einer begrenzten offiziellen Release-Seite
   bezogen, nicht vom Bundle-anfälligen Endpunkt `releases/latest`.
2. Es sind nur veröffentlichte, nicht vorveröffentlichte, numerische Action-
   Tags auswählbar.
3. CodeQL-Updates innerhalb desselben Majors bleiben automatisch; ein neuer
   Major wird nur zur manuellen Prüfung gemeldet.
4. Ein automatisch ausgewählter Tag desselben Majors wird über die Git-API
   aufgelöst und seine unveränderliche Commit-Identität bleibt validiert; ein
   Ergebnis über Major-Grenzen hinweg ist ausschließlich Prüfmetadaten.
5. Die Auflösung anderer Actions und das geschlossen scheiternde Verhalten
   bleiben unverändert.

## Untersuchte Alternativen

- Das weitere Parsen von `releases/latest` wurde abgelehnt, weil die
  beobachtete Antwort ein CodeQL-Bundle und kein Action-Release ist.
- Ein Bundle-Tag als Action-Version wurde abgelehnt, weil dies den
  Provenienz- und Immutable-Pin-Contract der Action schwächen würde.
- Die automatische Anwendung eines neuen Majors wurde abgelehnt; die
  bestehende Richtlinie verlangt dafür manuelle Prüfung.
- CodeQL aus dem kanonischen Maintenance-Lauf zu entfernen wurde abgelehnt,
  weil jeder kanonische CI-Pin im gemeinsamen Maintenance-Plan verbleiben muss.

## Implementierungsentscheidung

Der Updater erhält eine begrenzte Auswahl des neuesten stabilen numerischen
Action-Tags über alle Majors aus der Release-Seite. Der kanonische Maintenance-
Resolver verwendet diese Auswahl ausschließlich für CodeQLs Upstream-Vergleich
und behält die bestehende Auswahl desselben Majors für automatische kompatible
Updates bei. Nur ein automatisch ausgewählter Tag desselben Majors durchläuft
die bestehende Git-API-Auflösung und die Validierung des unveränderlichen
Commits; das Ergebnis über Major-Grenzen hinweg wird zur manuellen Prüfung
vermerkt und nicht angewendet. Bundle-Tags, fehlerhafte oder Prerelease-Tags
sowie ein neuer Major werden von der automatischen Anwendung ausgeschlossen.
Die Laufzeitprüfung bindet `github/codeql-action` zusätzlich fest an
`same-major-release` und weist einen fehlerhaften `latest-release`-Lock zurück.

## Geänderte Dateien und Tests

Dieser Task ändert den kanonischen Resolver, den Updater, fokussierte
Regressionstests, den gepaarten Security-Guide und den gepaarten Change Record:

- `ci/tools/canonical_maintenance.py`;
- `ci/tools/update-workflow-tools.py`;
- `tests/ci_security/test_canonical_maintenance.py`; und
- `tests/ci_security/test_update_workflow_tools.py`;
- `docs/security/ci-security-tooling.md`;
- `docs/security/ci-security-tooling.de.md`;
- `reports/audits/change-records/20260816-06-fix-codeql-action-release-resolution.md`; und
- `reports/audits/change-records/20260816-06-fix-codeql-action-release-resolution.de.md`.

Die fokussierten Tests decken die Zurückweisung von Bundle- und fehlerhaften/
nichtnumerischen Release-Tags, die Auswahl eines neueren Majors zur Prüfung,
weiterhin automatische Updates desselben Majors, die Bestätigung des
unveränderlichen Commits und die Zurückweisung eines fehlerhaften CodeQL-
`latest-release`-Locks ab.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Lauf-ID oder freigegebener Evidenzpfad |
| --- | --- | --- | --- |
| `gh run view 31975000540 --repo Easton97-Jens/ModSecurity-test-Framework --json headSha,jobs,conclusion` | `0` | Der Resulting-Master-Lauf auf `f583bbfd74f8e0e76f0a65378702cbbaad77e7d8` scheiterte im `canonical-maintenance` bei der Auflösung verpflichtender Scopes mit Exit-Code 2. | [Lauf 31975000540](https://github.com/Easton97-Jens/ModSecurity-test-Framework/actions/runs/31975000540) |
| `env PYTHONDONTWRITEBYTECODE=1 python -m unittest -v tests.ci_security.test_update_workflow_tools tests.ci_security.test_canonical_maintenance` | `0` | 43 fokussierte Updater- und Canonical-Maintenance-Tests in der hash-gesperrten Task-Umgebung bestanden. | Framework-Task-Worktree |
| `env PYTHONDONTWRITEBYTECODE=1 ./ci/tools/safe-make.sh check-documentation` | `0` | Dokumentationslinks, bilinguale Variablen-/Pfadreferenzen und Change-Record-Contracts bestanden. | Framework-Task-Worktree |
| `env PYTHONDONTWRITEBYTECODE=1 ./ci/tools/safe-make.sh lint` | `0` | Vollständiger Lint mit kanonischer, Workflow-, Dokumentations-, Provenance- sowie CI-Sicherheits-/Contract-Abdeckung bestand. | Task-eigener externer Validierungsbereich |
| `git diff --check -- docs/security/ci-security-tooling.md docs/security/ci-security-tooling.de.md reports/audits/change-records/20260816-06-fix-codeql-action-release-resolution.md reports/audits/change-records/20260816-06-fix-codeql-action-release-resolution.de.md` | `0` | Keine Whitespace-Fehler in den geänderten Dokumentations- und Record-Dateien. | Framework-Task-Worktree |

## Sicherheitsauswirkung

Die Änderung erhält die Supply-Chain-Grenze: Nur offizielle numerische Action-
Tags sind Kandidaten, und ein automatisch ausgewählter Tag desselben Majors
wird an seinen unveränderlichen Commit gebunden. Ein Tag über Major-Grenzen
hinweg ist ausschließlich Prüfmetadaten. Es wird keine neue GitHub-
Berechtigung oder Credential eingeführt. Ein fehlerhafter, gebündelter oder
nicht verifizierbarer Release bleibt ein fataler oder manuell zu prüfender
Zustand. Kein Sicherheits-Contract wird geschwächt.

## Dokumentation und Runtime-Evidenz

Die englischen und deutschen Security-Guides dokumentieren die beobachtete
Bundle-Antwort des Endpunkts, die begrenzte Release-Seite, den automatischen
Pfad desselben Majors, die unveränderliche Commit-Validierung und die manuelle
Prüfung eines neuen Majors sowie die Laufzeitbindung an `same-major-release`.
Lauf `31975000540` ist ausschließlich beobachtete Fehler-Evidenz aus
Runtime/Lifecycle; er beweist weder einen erfolgreichen Hosted-Korrekturlauf,
ein Pull-Request-Ergebnis, einen Merge noch ein SonarQube-Cloud-Ergebnis.

## Nicht ausgeführte Prüfungen

- Gehostete Pull-Request-Prüfungen und die SonarQube-Cloud-Analyse bleiben
  für die Delivery-Phase ausstehend; vollständiger Framework-Lint und das
  fokussierte Security-Review bestanden lokal.
- Nach der korrigierenden Arbeitsbaumänderung wurde kein neuer Master-Dispatch
  ausgeführt.

## Einschränkungen und Restrisiko

Die Korrektur bleibt unverifiziert, bis die zuständige Implementierungs-
validierung und ein frischer Hosted-Lauf zeigen, dass der kanonische
Maintenance-Workflow erfolgreich abschließt. Vor jedem Merge muss SonarQube
Cloud unabhängig Quality Gate bestanden sowie 0 neue Issues und 0,0 %
Duplication on New Code melden.

## Finaler Diff- und Review-Status

Der finale Diff umfasst ausschließlich die oben gelisteten acht Framework-
Pfade. Es wurden keine Secrets, Tokens, rohen Response-Bodies oder vollständigen
Logs aufgenommen. Die Arbeitsbaumänderungen sind bei diesem Record-Update
nicht gestaged und nicht committed; es gab keinen Push, Pull Request, Merge,
Parent-Gitlink-Update oder MRTS-Vorgang.
