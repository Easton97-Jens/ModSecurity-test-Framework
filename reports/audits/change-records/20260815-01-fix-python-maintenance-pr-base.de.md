# Change Record — 20260815-01-fix-python-maintenance-pr-base

**Sprache:** [English](20260815-01-fix-python-maintenance-pr-base.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260815-01-fix-python-maintenance-pr-base` |
| UTC-Datum | `2026-08-15` |
| Framework-Basisrevision | `01952978772995c054ba6a4cba86adc5d0cd1e7d` |
| Issue oder Pull Request | Gemeldeter GitHub-Actions-Run `31899169302`; der aktuelle User autorisierte nach der geprüften lokalen Änderung eine task-eigene Draft-PR-Delivery-Fortsetzung. Konkrete PR- und Head-SHA-Evidenz wird außerhalb dieses versionierten Records aufbewahrt. |

## Motivation und Problemstellung

Der geplante CPython-Maintenance-Publisher konnte einen Kandidaten validieren
und anschließend in `peter-evans/create-pull-request` scheitern, weil ein
ausgecheckter Maintenance-Branch zur impliziten Pull-Request-Basis der Action
wurde. Der Publisher muss seinen Kandidaten immer von einem lokalen `master`
aufbauen, der exakt `origin/master` entspricht, und einen bestehenden
Maintenance-Branch dennoch vor dessen Wiederverwendung validieren.

## Betroffene Komponenten und Sicherheitsgrenzen

Die Framework-eigene Änderung betrifft die GitHub-Actions-Publisher-
Trust-Grenze in `.github/workflows/check-python-version.yml`, den statischen
CI-Security-Contract-Checker und seine Regressionstests. Der Workflow behält
das begrenzte GitHub-App-Token, den unveränderlichen Action-Pin,
Least-Privilege-Permissions, den festen Maintenance-Branch und die
`.python-version`-only-Publish-Allowlist. Parent, Connector-Runtime und MRTS
sind nicht betroffen.

## Akzeptanzkriterien

1. Der Workflow holt `origin/master`, validiert einen vorhandenen passenden
   Maintenance-Branch aus einem detached Checkout und erzeugt anschließend
   lokalen `master` bei `origin/master` neu und setzt ihn hart darauf zurück,
   bevor der Kandidat angewendet wird.
2. Der Kandidatpfad beweist, dass er sauber auf `master` startet und nur
   `.python-version` von `origin/master` abweicht.
3. Die Pull-Request-Action benennt `base: master` und den festen
   Maintenance-Branch getrennt; der Pfad ohne bestehenden Branch erzeugt
   keinen lokalen Maintenance-Branch.
4. Der CI-Security-Contract weist Regressionen des Trusted-Base-Lebenszyklus,
   der Base/Branch-Trennung und der Changed-Path-Constraints zurück.
5. Die erforderlichen fokussierten und nativen Workflow-Contract-Checks
   bestehen lokal.

## Untersuchte Alternativen

- Nur `base: master` hinzuzufügen würde die nicht vertrauenswürdige
  ausgecheckte Working-Base nicht reparieren und reicht nicht aus.
- Den bestehenden Maintenance-Branch als lokalen Branch auszuchecken würde
  den Publisher-State mehrdeutig lassen; daher bleibt die detached Validierung.
- Den Maintenance-Branch vor der Kandidatenvalidierung zu erzeugen würde die
  No-Update-Path-Anforderung verletzen, deshalb bleibt der false-Pfad ein No-op.

## Implementierungsentscheidung

Der bestehende Maintenance-Branch wird geholt und auf einen Nachfahren von
`origin/master` mit einem ausschließlich aus `.python-version` bestehenden,
whitespace-sauberen Diff beschränkt. Er wird ausschließlich für die
Existing-Branch-Contract-Checks detached ausgecheckt. Danach erzeugt der
Workflow lokalen `master` bei `origin/master` neu, setzt ihn hart auf diesen
Remote-Ref zurück und beweist ausgewählten Branch sowie sauberen Tree vor dem
Anwenden des Kandidaten. Das Post-Update-Diff ist direkt an `origin/master`
gebunden; die Publisher-Action verwendet explizit `base: master` mit
`automation/update-framework-python-314` als ihrem Branch.

## Geänderte Dateien und Tests

- `.github/workflows/check-python-version.yml` ergänzt die Trusted-Base-
  Wiederherstellung, die explizite Pull-Request-Base, detached Existing-Branch-
  Validierung und master-gebundene Kandidatenassertions.
- `ci/checks/security/check-ci-security-contract.py` bindet den neuen Step,
  die Action-Inputs und die überprüften Step-Digests in den CI-Security-
  Contract ein.
- `tests/ci_security/test_ci_security_contract.py` ergänzt negative
  Regressionen für implizite/gleiche Base, nicht-detached Wiederverwendung,
  vorzeitige Branch-Erzeugung, fehlenden Trusted-Reset und fehlende
  Master-/Diff-Assertions.
- Dieses englisch/deutsche Change-Record-Paar dokumentiert die
  Framework-eigene Änderung.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Ausgewähltes Virtual Environment: `python -m unittest tests.ci_security.test_ci_security_contract tests.ci_security.test_python_version_contract tests.ci_security.test_update_python_version -v` | `0` | 57 fokussierte CI-Security-, Python-Version- und Updater-Tests bestanden. | Task-eigener externer Validation-Root |
| `ci/checks/security/check-ci-security-contract.py --root .` | `0` | CI-Security-Contract bestanden. | Task-eigener externer Validation-Root |
| `make test-ci-security-contract` | `0` | 174 CI-Security-Contract-Tests bestanden. | Task-eigener externer Validation-Root |
| `make check-github-actions-workflows` | `0` | Workflow-Syntax-, Pin-, Permission- und Versionscontract-Checks bestanden. | Task-eigener externer Validation-Root |
| `make test-workflow-security-contract` | `0` | 9 Workflow-Security-Regressionstests bestanden. | Task-eigener externer Validation-Root |
| `python -m py_compile` für den geänderten CI-Checker und Test | `0` | Beide geänderten Python-Module kompilierten erfolgreich. | Task-eigener externer Validation-Root |
| `make check-documentation` | `0` | Link-, bilinguale Variable-, Repository-Pfad- und Change-Record-Checks bestanden. | Task-eigener externer Validation-Root |
| `make test-change-record-contract` | `0` | 4 Change-Record-Contract-Tests bestanden. | Task-eigener externer Validation-Root |

## Sicherheitsauswirkung

Dies ist eine Remediation der CI-Trust-Grenze. Sie beseitigt die
Working-Base-Mehrdeutigkeit des Publishers, ohne Token-Scope, Permissions,
erlaubte Schreibpfade, Action-Mutabilität oder Auto-Merge-Verhalten zu
erweitern. Der fokussierte Security-Diff-Review ergab kein separates
reportierbares Security-Finding; der ursprüngliche Availability-Defekt wird
durch den eingecheckten Workflow und fail-closed Contract-Tests behandelt.

## Dokumentation und Runtime-Evidenz

Dieses gepaarte Change Record ist die englisch/deutsche
Dokumentationsänderung. Lokale Contract-Evidenz wurde erhoben; es wurde kein
gehosteter Workflow gestartet, daher sind der tatsächliche GitHub-Actions-
Runner, die GitHub-App-Installation und die Service-Interaktion von
`create-pull-request` nicht erneut ausgeführt.

## Nicht ausgeführte Prüfungen

- Kein Live-GitHub-Actions-Dispatch und kein gehosteter Exact-Head-Run wurden
  ausgeführt, weil der autorisierte Scope normale Draft-PR-Delivery, nicht
  Workflow-Ausführung umfasst.
- Weder Merge, Parent-Änderung, MRTS-Änderung, Gitlink-Update, Force-Push noch
  ein direkter `master`-Write sind autorisiert oder durchgeführt.

## Einschränkungen und Restrisiko

Der lokale Contract beweist das beabsichtigte YAML und negative Regressionen,
kann jedoch weder GitHub-gehostete Runner-Semantik noch GitHub-App-Permissions
beweisen. Ein manueller oder geplanter trusted-`master`-Run ist weiterhin
erforderlich, um den ursprünglichen `create-pull-request`-Fehlerpfad Ende zu
Ende zu beobachten.

## Finaler Diff- und Review-Status

Der abgegrenzte Diff, der Whitespace-Check und der CI-Security-Contract-Review
sind lokal abgeschlossen. Es werden keine Credentials, Tokens, Raw-Logs oder
sensitiven Payloads festgehalten. Der aktuelle User hat den fokussierten
Commit, normalen Push und die Draft-PR-Fortsetzung autorisiert; konkrete
Remote-/PR-Evidenz wird außerhalb dieses versionierten Records aufbewahrt.
