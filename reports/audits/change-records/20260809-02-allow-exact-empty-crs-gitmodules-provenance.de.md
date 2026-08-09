# Change Record: Nur kanonische leere CRS-`.gitmodules`-Provenance-Metadaten zulassen

**Sprache:** [English](20260809-02-allow-exact-empty-crs-gitmodules-provenance.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260809-02-allow-exact-empty-crs-gitmodules-provenance |
| UTC-Datum | 2026-08-09 |
| Framework-Basisrevision | a7a8dcdd62da8d0e4d7ea36549f7c54c5d614e68 |
| Issue oder Pull Request | Nutzerautorisierte Framework-Reparatur Phase A auf dem task-eigenen Branch `fix/crs-empty-gitmodules-provenance`; Draft-Pull-Request und Delivery-Evidenz stehen aus. |

## Motivation und Problemstellung

Der geschützte CRS-Lifecycle-Lauf 31328046595 stoppte vor der Candidate-
Admission, weil der freigegebene CRS-Commit
`55b09f5acfd16413e7b31041100711ceb7adc89c` eine reguläre null Byte große
Root-Datei `.gitmodules` besitzt. Der alte Fetcher wies jeden solchen Pfad ab,
obwohl der freigegebene Tree keinen Gitlink hat und die Datei Git's kanonische
Empty-Blob `e69de29bb2d1d6434b8b29ae775ad8c2e48c5391` ist.

## Betroffene Komponenten und Sicherheitsgrenzen

Die Änderung ist auf Framework-CRS-Quellprovisionierung in
`ci/provisioning/fetch-crs.sh`, `ci/provisioning/crs-provenance.sh` und
`ci/provisioning/prepare-crs.sh`, ihre Provenance-Regression-Suite und gepaarte
Framework-Dokumentation beschränkt. Die Grenze lässt nur den zentral gepinnten
HTTPS-Origin und unveränderlichen Commit zu, bevor Source später durch die
Connector-Vorbereitung verbraucht wird. Parent, MRTS, Gitlinks,
Caller-Workflow-Autorität und Connector-Runtime-Verhalten ändern sich nicht.

## Akzeptanzkriterien

- Ein freigegebener Checkout ohne `.gitmodules` und ohne Gitlinks bleibt
  akzeptiert.
- Eine vorhandene Root-`.gitmodules` wird nur als kanonische Empty-Blob
  `e69de29bb2d1d6434b8b29ae775ad8c2e48c5391` mit `100644` in Tree, Index und
  Worktree akzeptiert.
- Rekursiver Tree und Checkout-Index weisen jeden `160000`-Gitlink ab.
- Nichtleere, falsche Mode-, verlinkte, spezielle, nicht getrackte,
  abweichende, doppelte, verschachtelte, konfigurierte oder registrierte
  Submodule-Zustände schlagen vor der Nutzung fehl.
- Eine Ersetzung nach erfolgreichem Fetch schlägt fehl, bevor `prepare-crs.sh`
  ein Source-Template, eine Rule oder ein Plugin liest oder eine Runtime-Datei
  schreibt.
- Git-Inspektionsfehler schlagen fail-closed fehl und kein Pfad ruft
  `git submodule` auf.

## Untersuchte Alternativen

Das Beibehalten der pauschalen Präsenz-Abweisung erhält das False Positive. Das
Zulassen beliebiger `.gitmodules`-Dateien, Gitlinks oder rekursiver
Initialisierung würde die Provenance-Grenze über die geprüfte Regel hinaus
erweitern. Das Ableiten des Verhaltens aus Release-Tag oder Caller-Input würde
wieder mutable Auswahl einführen. Die gewählte Regel ist auf eine
unveränderliche Blob und einen No-Submodule-Zustand begrenzt.

## Implementierungsentscheidung

Nach der Prüfung von Origin, gefetchtem Objekt, aufgelöstem Objekt und
ausgechecktem Commit ruft der Fetcher einen gemeinsamen Verifier auf, der den
freigegebenen Tree rekursiv und den Checkout-Index untersucht. Er erlaubt
entweder keinen Root-`.gitmodules`-Eintrag oder exakt
`100644 blob e69de29bb2d1d6434b8b29ae775ad8c2e48c5391` an diesem Root-Pfad.
Letzteres verlangt zusätzlich Objektgröße null, eine nicht verlinkte reguläre
null Byte große Checkout-Datei, denselben Raw-Worktree-Hash, einen sauberen
mode-sensitiven Diff, keine lokale `submodule.*`-Konfiguration, keine
`.git/modules`-Registry, keine nicht getrackte Source und keinen Tree- oder
Index-Gitlink. `prepare-crs.sh` ruft denselben Verifier erneut auf, bevor es
Source-Dateien verbraucht oder Runtime-Output schreibt. Jeder
Inspektionsfehler blockiert; keines der Skripte ruft `git submodule` auf.

## Geänderte Dateien und Tests

- `ci/provisioning/fetch-crs.sh` und die neue sourcebare
  `ci/provisioning/crs-provenance.sh` ersetzen die pauschale Manifest-Präsenz-
  Abweisung durch den begrenzten Empty-Blob-/No-Submodule-State-Verifier.
- `ci/provisioning/prepare-crs.sh` prüft denselben Verifier erneut, bevor es
  CRS-Source-Dateien verbraucht oder Runtime-Output schreibt.
- `tests/security_regression/test_crs_git_ref_provenance.py` ergänzt exakte
  Empty-Positiv-, adversariale State-, Failure-Injection- und
  Successful-Fetch-zu-Replacement-zu-Prepare-Abdeckung.
- `docs/reference/variables.{md,de.md}` und
  `docs/testing-and-evidence.{md,de.md}` beschreiben die begrenzte Regel und
  ihre Grenze.
- Dieser gepaarte Change Record und Index-Eintrag dokumentieren nur Framework
  Phase A.

## Befehle und Ergebnisse

Die folgenden replay-sicheren Befehlsvorlagen sind in den englischen und
deutschen Records identisch. Setze die Kleinbuchstaben-Shellvariable
`task_run_root` auf ein konfiguriertes task-eigenes externes Run-Verzeichnis,
`framework_python=python3`,
`actionlint_bin="$task_run_root/evidence/runner-temp/actionlint/actionlint"`
und `zizmor_bin="$task_run_root/evidence/runner-temp/zizmor/zizmor"`. Die
Vorlagen bewahren die beobachteten Befehle, ohne einen lokalen Entwicklerpfad
oder ein Secret einzubetten.

<pre>
C01 rtk proxy sh -n ci/provisioning/fetch-crs.sh ci/provisioning/crs-provenance.sh ci/provisioning/prepare-crs.sh
C02 rtk proxy env BUILD_ROOT="$task_run_root/target/build" TMP_ROOT="$task_run_root/target/tmp" LOG_ROOT="$task_run_root/target/log" PYTHON="$framework_python" make test-crs-provenance-contract
C03 rtk proxy env BUILD_ROOT="$task_run_root/docs-final-verified/build" TMP_ROOT="$task_run_root/docs-final-verified/tmp" LOG_ROOT="$task_run_root/docs-final-verified/log" PYTHON="$framework_python" make check-bilingual-docs check-doc-links check-change-records
C04 rtk proxy env STATE_HOME="$task_run_root/lint/state" BUILD_ROOT="$task_run_root/lint/build" TMP_ROOT="$task_run_root/lint/tmp" LOG_ROOT="$task_run_root/lint/log" PYTHONPYCACHEPREFIX="$task_run_root/lint/pycache" PYTHONNOUSERSITE=1 make PYTHON="$framework_python" lint
C05 rtk proxy env STATE_HOME="$task_run_root/lint-final/state" BUILD_ROOT="$task_run_root/lint-final/build" TMP_ROOT="$task_run_root/lint-final/tmp" LOG_ROOT="$task_run_root/lint-final/log" PYTHONPYCACHEPREFIX="$task_run_root/lint-final/pycache" PYTHONNOUSERSITE=1 make PYTHON="$framework_python" lint
C06 rtk proxy git diff --check
C07 rtk proxy "$actionlint_bin" -shellcheck=/usr/bin/shellcheck .github/workflows/*.yml
C08 rtk proxy "$zizmor_bin" --offline .github/workflows
</pre>

| Befehls-ID | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| C01 | 0 | POSIX-Shell-Syntax akzeptierte den gemeinsamen Verifier und beide Entry-Points. | Task-eigenes externes Framework-Worktree |
| C02 | 0 | 18 fokussierte Provenance-Tests bestanden, einschließlich Inspektionsfehlern, adversarialen und Replacement-before-Prepare-Fällen. | Task-eigene externe Phase-A-Evidenz |
| C03 | 0 | Dokumentation, EN/DE-Links und Change-Record-Vertrag bestanden. | Task-eigene externe Phase-A-Evidenz |
| C04 | 2 | Der initiale native Lint stoppte nur, weil die erste Record-Revision einen verbotenen lokalen Entwicklerpfad enthielt; es wurde kein Implementierungsfehler gemeldet. | Task-eigene externe Phase-A-Evidenz |
| C05 | 0 | Der vollständige native Lint bestand nach der Korrektur des Dokumentationspfads. | Task-eigene externe Phase-A-Evidenz |
| C06 | 0 | Der finale Whitespace-Check des getrackten Diffs bestand. | Task-eigene externe Phase-A-Evidenz |
| C07 | 0 | Lockfile-verifizierte actionlint und ShellCheck akzeptierten alle Workflows. | Task-eigene externe Phase-A-Evidenz |
| C08 | 0 | Lockfile-verifiziertes zizmor meldete keine Befunde; 37 Repository-Suppressions wurden angewandt. | Task-eigene externe Phase-A-Evidenz |

## Sicherheitsauswirkung

Diese Remediation entfernt ein False Positive und erhält Kontrollen für
unveränderlichen Origin, unveränderlichen Commit, No-Gitlink, No-Recursion und
Source-Consumption. Der ursprüngliche Leere-Datei-Fehler reproduziert vor der
Reparatur; die legitime exakte Empty-Blob besteht nun. Alternative Inhalte,
Dateitypen, Tree-/Index-Werte, Konfiguration, Registry, Git-Command-Error-
Pfade und eine Ersetzung nach Fetch bleiben fail-closed. Eine unabhängige
Source-to-Sink-Prüfung wird nicht als Delivery-Evidenz verwendet; die finalen
gehosteten PR-Security-Gates bleiben erforderlich.

## Dokumentation und Runtime-Evidenz

Die englische/deutsche Variablen- und Test-Dokumentation beschreibt nun die
exakte Ausnahme und ihre Grenzen. Der isolierte echte Fetch ist nur Evidence
für die Provisionierungsgrenze; er ist keine Connector-Runtime-, Parent-
Lifecycle-, Hosted-CI- oder MRTS-Evidence. Ein neuer resulting-master
Lifecycle-Lauf bleibt nach den geordneten Parent-Phasen erforderlich.

## Nicht ausgeführte Prüfungen

Das konfigurierte CPython 3.14.6 ist lokal nicht verfügbar; die fokussierten
Tests verwenden das verfügbare lokale CPython 3.14.4 und sind keine
CI-äquivalente Evidenz. Gehostete PR-Checks, CodeQL, SonarQube Cloud,
Review-Status und Merge-Checks stehen bis zum vollständigen finalen Diff und
Draft-PR aus.

## Einschränkungen und Restrisiko

Der Verifier beweist den Zustand bei jedem Fetch- und Source-Consumption-Check.
Er behauptet keinen Connector-Runtime-Support und ersetzt nicht spätere
geschützte Parent-Lifecycle-Evidence. Ein gleichzeitiger Host-Writer könnte
nach dem finalen Consumption-Check noch racen und würde eine unabhängig
nachgewiesene Schreibberechtigung im verifizierten Source-Root erfordern;
diese Framework-Regel etabliert keine solche Berechtigung.

## Finaler Diff- und Review-Status

Source, fokussierte Tests, EN/DE-Dokumentation und dieser gepaarte Record sind
lokal auf dem task-eigenen Framework-Branch. Native Lint, Dokumentation,
Whitespace, actionlint und zizmor bestanden; Security-Diff- und Delivery-Review
bleiben vor normaler Framework-Delivery erforderlich. Es werden kein Commit,
Push, Pull-Request, Hosted-Ergebnis, Gitlink-Update, Parent-Änderung oder
MRTS-Aktion behauptet.
