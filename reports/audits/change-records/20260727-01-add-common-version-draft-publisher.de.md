# Change Record: Common-Version-Draft-PR-Publisher

**Sprache:** [English](20260727-01-add-common-version-draft-publisher.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260727-01-add-common-version-draft-publisher` |
| UTC-Datum | 2026-07-27 |
| Framework-Basisrevision | `47e50e7bc43ba7a3b5bad1a9448111794f664cc0` |
| Issue oder Pull Request | Framework-Draft-PR [#53](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/53), Task-Branch `agent/common-version-native-publisher`; der aktuelle Benutzer hat einen geschützten Merge nach frischer finaler Evidenz autorisiert, aber noch kein Merge oder Auto-Merge ist erfolgt. |

## Motivation und Problemstellung

Der geplante Common-Version-Workflow konnte sicher einen ephemeren Kandidaten
erzeugen, aber weder einen reviewbaren Draft-PR veröffentlichen noch seinen
eigenen Common-Version-ShellCheck bestehen. Er benötigt einen engen Update-Pfad,
der ohne separat konfiguriertes Secret oder GitHub-App-Credential nutzbar bleibt.

## Betroffene Komponenten und Sicherheitsgrenzen

Betroffen sind der Framework-Workflow, sein CI-Sicherheitsvertrag, `common.sh`
und die APXS-Listen-Consumer. Dies berührt die CI-Schreibberechtigungsgrenze:
Kandidatenauflösung muss read-only bleiben, während ein vertrauenswürdiger
Publisher nur einen Draft-PR für `ci/lib/common.sh` erzeugen darf. Parent,
MRTS-Quellen und beide Gitlinks liegen außerhalb dieser Änderung.

## Akzeptanzkriterien

- Resolver und Kandidatenvalidator sind im Source tokenfrei und verwenden nur
  `contents: read`.
- Der Publisher ist auf Zeitplan/manuell/Default-Branch begrenzt, hat nur
  `contents`-/`pull-requests`-Write-Rechte und erzeugt oder aktualisiert einen
  Draft-PR auf festem Branch.
- Der Publisher löst einen 64-stelligen SHA-256-Kandidaten unabhängig erneut
  auf und akzeptiert nur einen `ci/lib/common.sh`-Working-Tree-Diff.
- ShellCheck-Blocker werden ohne Suppressions korrigiert; Parent und MRTS
  bleiben unverändert.

## Untersuchte Alternativen

Ein read-only Workflow kann Versionen nicht über einen PR pflegen. Der
GitHub-App-Publisher des Workflow-Tool-Updaters ist nicht gleichwertig, weil
seine App-Konfiguration extern fehlt und er Workflow-Dateien ändert. PAT,
direkter Push, breites Staging oder Auto-Merge würden die Berechtigungsgrenze
aufweiten und wurden verworfen.

## Implementierungsentscheidung

Der Workflow hat jetzt die Jobs `resolve`, `candidate-validate` und `publish`.
Reader arbeiten nur auf temporären Kopien. Der Publisher löst erneut auf und
bindet den Kandidaten per SHA-256, validiert ihn erneut, begrenzt den Pfad und
übergibt den kurzlebigen nativen `github.token` nur der vorhandenen, per
vollständigem SHA gepinnten Action `peter-evans/create-pull-request`. Der Pfad
bleibt ausschließlich Draft.

## Geänderte Dateien und Tests

- `.github/workflows/check-common-versions.yml` enthält die Drei-Job-Topologie.
- `ci/checks/security/check-ci-security-contract.py` und
  `tests/ci_security/test_ci_security_contract.py` definieren und mutieren
  den Least-Privilege-Workflow-Vertrag.
- `ci/lib/common.sh`, `ci/tools/doctor.sh` und
  `ci/runtime/smoke-installed.sh` verwenden einen POSIX-APXS-Listen-Helper;
  `tests/no_crs/test_apxs_cache_selection.py` deckt literale Glob-Zeichen und
  Fallback-Auswahl ab.
- Zweck des Action-Locks und die zweisprachige Workflow-Sicherheitsdokumentation
  beschreiben die neue geprüfte Verwendung der vorhandenen gepinnten PR-Action.
- Die SonarQube-Cloud-Remediation vom 2026-07-28 ersetzt wiederholte
  Contract-Prädikate und die Kandidaten-Hash-Längenprüfung durch benannte
  Konstanten und entfernt einen ungenutzten Parameter. Sie erhält die exakten
  erforderlichen Workflow-Strings und führt keine Suppression, Berechtigung
  oder Verhaltensänderung ein.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `sh -n` für geänderte Shell-Dateien | 0 | Shell-Syntax bestanden. | Task-eigener externer Evidenzpfad; PR #53 |
| APXS-Literal-Glob-/Fallback-Kontrolle | 0 | Ein literales `*` wurde nicht expandiert und der spätere `sh`-Kandidat gewählt. | Derselbe Task-eigene Evidenzpfad |
| `shellcheck -x ci/lib/common.sh ci/checks/catalog/check-common-helpers.sh` | 0 | Exakter ShellCheck-Scope des Common-Version-Workflows lokal bestanden. | Derselbe Task-eigene Evidenzpfad |
| Gelockter Ruff-Check und Format-Check | 0 | Alle CI-Security-Python-Ziele bestehen Lint- und Formatvalidierung. | Derselbe Task-eigene Evidenzpfad |
| Gelocktes actionlint mit ShellCheck | 0 | Der geänderte Common-Version-Workflow besteht GitHub-Actions-Linting. | Derselbe Task-eigene Evidenzpfad |
| `python3 ci/checks/documentation/check-change-records.py` | 0 | Gepaarte Change-Record-Überschriften und wechselseitige Links bestehen den Vertrag. | Derselbe Task-eigene Evidenzpfad |
| `git diff --check` und gestagtes Äquivalent | 0 | Keine Whitespace-Fehler. | Commit `7d369ed2a7be5a72d1ebccafb626db76f4c70f57` |
| Erste Hosted-Checks von PR #53 | ungleich null | CI-Remediation für Workflow-Body-ShellCheck, Ruff-Formatierung und Change-Record-Überschriften erforderlich. | GitHub-Actions-Runs `30299159464`, `30299159306`, `30299140782`, `30299159376` |
| `make test-ci-security-contract` mit der ausgewählten Framework-Virtualenv | 0 | 137 CI-Security-Contract-, Mutations-, Evidenz-, Provenienz- und Updater-Tests nach der Sonar-Remediation bestanden. | Task-eigener Lauf `20260728-pr53-sonar-master` |
| `make lint` mit der ausgewählten Framework-Virtualenv | 0 | Native Lint-, Workflow-Contract-, Dokumentations-, Pinning- und fokussierte CI-Security-Prüfungen bestanden. | Task-eigener Lauf `20260728-pr53-sonar-master` |

## Sicherheitsauswirkung

Dies ist CI-Berechtigungshärtung, keine Produkt-Sicherheitsremediation. Die
ursprünglichen unsicheren Pfade werden strukturell erneut geprüft:
Reader-Token-Exposition, Write-Rechte, veralteter Checkout, kurzer
Kandidaten-Hash, direkter Push, Token-Substitution und Pfadaufweitung weist der
Contract-Test zurück. Die alternative Umgehung über Workflow-Dateiänderungen
bleibt aus diesem nativen-Token-Design ausgeschlossen.
Der Refaktor vom 2026-07-28 erhält die exakten geschützten Strings als benannte
Konstanten; die vollständige Contract- und Mutationssuite beweist weiterhin,
dass Berechtigungs-, Token-, Checkout-, Hash-Längen-, Direkt-Push- und
Pfad-Scope-Regressionen verworfen werden.

## Dokumentation und Runtime-Evidenz

Die englische und deutsche Workflow-Sicherheitsdokumentation sowie dieser
gepaarte Record wurden aktualisiert. Es lief kein Connector- oder MRTS-
Runtime-Lifecycle, weil dies eine Framework-CI-Wartungsänderung ist. PR #53
liefert die Delivery-Evidenz; ein späterer geplanter oder manueller
Default-Branch-Lauf muss die automatische Draft-PR-Veröffentlichung beobachten.

## Nicht ausgeführte Prüfungen

Der isolierte Framework-Task-Worktree besitzt keine freigegebene
Framework-Virtualenv; die Policy verbietet deren beiläufiges Erstellen oder
Ersetzen. Python-Unit-Tests, der vollständige CI-Sicherheits-Contract-Test und
`make lint` liefen nicht lokal. Der enge Change-Record-Check verwendete
die verfügbare System-Python nur, weil er keine Drittanbieterabhängigkeit hat;
die gelockten eigenständigen Ruff- und actionlint-Binärdateien wurden in den
Task-eigenen externen Evidenzpfad geladen. Exakte Hosted-Checks für den PR-Head
sind weiterhin die erforderliche Delivery-Evidenz.

## Einschränkungen und Restrisiko

Der native Token kann die GitHub-App für `update-workflow-tools.yml` nicht
sicher ersetzen; dieser Workflow bleibt unverändert. Es werden kein
Credential-Wert, Secret, direkter Push, Parent-Änderung, MRTS-Änderung oder
Gitlink-Änderung eingeführt. Hosted-Remediation-Evidenz für den geänderten
PR-Head steht auf dieser Record-Revision noch aus.

## Finaler Diff- und Review-Status

Der gestagte Scope-Diff und der Whitespace-Diff wurden vor Commit
`7d369ed2a7be5a72d1ebccafb626db76f4c70f57` geprüft; Task-Worktree war sauber
und lokale/Remote-/PR-Heads stimmten auf diesem Commit überein. Draft-PR #53
ist offen. Das Folge-Amendment dieses Records korrigiert die beobachteten
CI-Format- und Template-Defekte; zu diesem Zeitpunkt autorisierte es weder
Merge noch Auto-Merge.

Das Folge-Commit vom 2026-07-28 behebt vier aktuelle SonarQube-Cloud-
Maintainability-Befunde ohne Suppressions. Der Benutzer hat einen Merge erst
nach der neuen exakten CI-, SonarQube-Cloud-, Review- und Ruleset-Runde
autorisiert; der PR bleibt bis zum Abschluss dieser Runde ein Draft.
