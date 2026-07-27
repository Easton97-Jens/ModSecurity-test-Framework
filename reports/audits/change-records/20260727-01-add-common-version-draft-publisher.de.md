# Änderungsnachweis: Common-Version-Draft-PR-Publisher ergänzen

**Sprache:** [English](20260727-01-add-common-version-draft-publisher.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260727-01-add-common-version-draft-publisher` |
| UTC-Datum | 2026-07-27 |
| Framework-Basisrevision | `47e50e7bc43ba7a3b5bad1a9448111794f664cc0` |
| Issue oder Pull Request | Task-Branch `agent/common-version-native-publisher`; Draft-PR beim Schreiben dieses Records ausstehend. Kein Merge oder Auto-Merge ist autorisiert. |

## Motivation und Entscheidung

Der geplante Common-Version-Workflow erzeugte sicher einen ephemeren
Kandidaten, konnte aber weder einen Draft-PR veröffentlichen noch seinen
eigenen ShellCheck-Schritt bestehen. Die neue Drei-Job-Topologie verwendet
dieselbe kurzlebige native GitHub-Job-Token-Methode wie der Framework-
Python-Version-Publisher, weil ihr Wartungs-Scope nur `ci/lib/common.sh` und
keine Workflow-Datei umfasst.

`resolve` und `candidate-validate` bleiben `contents: read`, im Source
tokenfrei und arbeiten nur auf einer temporären Kopie. `publish` läuft nur für
ein geplantes/manuelles Default-Branch-Event im autoritativen Repository. Er
hat nur `contents`-/`pull-requests`-Write-Rechte, löst den Kandidaten erneut
auf, vergleicht dessen SHA-256 mit dem read-only validierten Ergebnis und weist
jeden Working-Tree-Diff außerhalb von `ci/lib/common.sh` zurück. Der einzige
explizite Token-Consumer ist die per vollständigem SHA gepinnte Action
`peter-evans/create-pull-request`; sie erstellt oder aktualisiert genau einen
Draft-PR auf festem Branch und kann ihn nicht mergen.

## Scope und Sicherheitsgrenze

- Geändert: Common-Version-Workflow, CI-Sicherheitsvertrag und Tests,
  ShellCheck-Korrekturen in `common.sh`, APXS-Listen-Consumer, zweisprachige
  Workflow-Sicherheitsdokumentation, der Zweck des bestehenden Action-Locks und
  dieser gepaarte Record.
- Es kommen weder PAT, Repository-Secret, GitHub-App-Credential, direkter Push,
  breites Staging, Auto-Merge, Parent-Änderung, MRTS-Source-Änderung noch
  Gitlink-Änderung hinzu.
- `update-workflow-tools.yml` bleibt unverändert: Hosted-Evidenz beweist, dass
  dem nativen Token dort die benötigte Workflow-Datei-Autorität fehlt.
- Negative Contract-Mutationen weisen Reader-Write-Rechte oder Token-Exposition,
  einen veralteten Checkout, direkten Push, nicht überprüften Token-Input und
  Pfadaufweitung zurück.

## Verifikation

| Befehl | Exit-Code | Ergebnis |
| --- | --- | --- |
| `sh -n` für `ci/lib/common.sh`, `check-common-helpers.sh`, `doctor.sh` und `smoke-installed.sh` | 0 | Geänderte Shell-Dateien bestanden die Syntaxprüfung. |
| `sh -eu -c '. ci/lib/common.sh; … ci_find_bin_list …'` | 0 | Der APXS-Listen-Helper wählte einen späteren gültigen Kandidaten und wies eine ungültige Liste zurück. |
| `shellcheck -x ci/lib/common.sh ci/checks/catalog/check-common-helpers.sh` | 0 | Der exakte ShellCheck-Scope des Common-Version-Workflows bestand. |
| `git diff --check` | 0 | Keine Whitespace-Fehler im aktuellen Task-Diff. |

Der isolierte Framework-Task-Worktree besitzt keine Framework-Virtualenv. Die
lokale Policy verbietet das beiläufige Erstellen oder Ersetzen einer solchen
Umgebung; daher sind Python-Tests, CI-Sicherheits-/Workflow-Contract-Ausführung,
Dokumentationschecks, `make lint`, actionlint, zizmor und Ruff lokal
`not_run`. Hosted-PR-Checks und SonarQube Cloud bleiben exakte Head-Evidenz und
stehen bis zur Auslieferung aus.

Ein breiterer lokaler ShellCheck-Aufruf meldet vorbestehende Befunde in den
nicht zusammenhängenden Skripten `doctor.sh` und `smoke-installed.sh`. Deren
bestehende Diagnose- und Source-Following-Befunde liegen außerhalb des exakten
ShellCheck-Scopes des Workflows; diese Änderung ersetzt dort nur die unsichere
APXS-Kandidatenlisten-Wortaufteilung und unterdrückt keine Lint-Kontrolle.

## Restrisiko und Review

Es werden keine Credential-Werte, Secrets, rohen Hosted-Logs, Parent-Änderungen
oder MRTS-Änderungen festgehalten. Der fokussierte Review deckt die
Autoritätsgrenze ab: Upstream-Daten bleiben read-only, bis der Publisher sie
unabhängig validiert sowie an Hash und Pfad bindet. Ein geplanter/manueller
Publisher-Run nach einem Merge muss die Draft-PR-Erstellung noch beweisen.
Dieser Record autorisiert keinen Merge.
