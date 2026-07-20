# Change Record

**Sprache:** [English](20260720-03-add-framework-python-313-updater.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260720-03-add-framework-python-313-updater` |
| UTC-Datum | 2026-07-20 |
| Framework-Basisrevision | `9dab40c2b8799dc1e4597cb2a2c223ec3f6cd72b` |
| Issue oder Pull Request | [Draft PR #39](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/39) auf Task-Branch `agent/add-framework-python-updater`; der erste veröffentlichte Head war `4a31df044ea2c2c7526828e54978238639b57dd4`. |

## Motivation und Problemstellung

Das Framework wiederholte einen exakten CPython-Patch in Workflow-YAML und in
einem unabhängigen CI-Lock-Kommentar, während `test-common.yml` Python vor dem
Setup eines überprüften Interpreters verwendete. Es gab keinen nativen,
begrenzten Updater und keine getestete Publisher-Grenze für einen zukünftigen
stabilen CPython-3.13-Patch.

## Betroffene Komponenten und Sicherheitsgrenzen

Diese reine Framework-Änderung kontrolliert Workflow-YAML, Python-
Metadatenparsing, runner-eigene temporäre Outputs, eine einzelne Source-Tree-
Versionsdatei, automatische Job-Credentials und einen expliziten Token-Input
einer Draft-PR-Action. Parent-Gitlink, Parent-Quellcode, Connector-Runtime und
der read-only Inhalt von `tools/MRTS` sind nicht betroffen.

## Akzeptanzkriterien

- `.python-version` ist die einzige Autorität für den exakten CPython-Patch und
  jede normale Setup-Action liest sie mit `check-latest: false`.
- Ein Resolver akzeptiert nur einen strikt höheren veröffentlichten stabilen
  3.13-Patch von einem begrenzten festen Python.org-JSON-Endpunkt und schreibt
  bei Unsicherheit nie.
- Read-only Kandidatenvalidierung nutzt hash-gelockte Abhängigkeiten, bevor der
  Publisher denselben Kandidaten unabhängig erneut auflöst.
- Der einzige vom Publisher commitete Repository-Inhalt ist
  `.python-version`; sein Draft-PR-Body ist runner-temporär, sein Branch ist
  fest und es existiert kein Auto-Merge-Pfad.
- Contracts, englische/deutsche Dokumentation und ein gepaarter Change Record
  decken Quell-, Workflow- und Betriebsgrenzen ab.

## Untersuchte Alternativen

Floating-Referenzen `3.13` oder `3.13.x` verringern manuelle Wartung, erlauben
aber unsichtbaren Patch-Drift. Ein manuell gepflegter exakter Patch behält
Reproduzierbarkeit, liefert aber keine geplante Kandidatenevidenz. Das gewählte
Design aus exaktem Pin sowie geplantem Resolver/Kandidaten/Publisher hält den
Patch überprüfbar und begrenzt automatische Wartung auf einen Draft-PR.

## Implementierungsentscheidung

Der native Updater verwendet nur den öffentlichen Python.org-Release-JSON-
Endpunkt, kein Token, keine Redirects, ein 1-MiB-Antwortlimit und strikte
Schema-/Versionsprüfungen. Er meldet explizite Statuswerte und ändert nach
einem Stale-Value-Check atomar nur eine reguläre `.python-version`-Datei. Der
Wartungsworkflow besitzt genau die Jobs `resolve`, `candidate-validate` und
`publish`. Reader-Jobs deklarieren keine explizite Token- oder Secret-
Referenz; ihr Checkout-Credential ist nicht persistent und read-scoped. Der
Publisher ist auf vertrauenswürdigen Default-Branch gegated, validiert den
Kandidaten erneut, fordert einen Ein-Datei-Diff, übergibt sein write-scoped
Token explizit nur an die gepinnte Pull-Request-Action und verwendet
`draft: true` mit festen `add-paths`.

Der erste Draft-PR-Head machte drei task-eigene Kompatibilitäts- und
Härtungsprobleme sichtbar, bevor die Delivery verifiziert werden konnte. Das
Kandidatenartefakt ist jetzt die feste direkte Datei
`RUNNER_TEMP/framework-python-3.13-candidate`, die innerhalb des Updaters
abgeleitet wird, statt ein vom Aufrufer gewählter CLI-Pfad zu sein; der
semantische Workflow-Contract weist ein Argument nach diesem Flag zurück.
Kandidaten-Runner-Pfade werden zur Step-Laufzeit über `$GITHUB_ENV`
initialisiert, wo der Runner-Kontext gültig ist, und der literale
Markdown-Body besitzt eine enge ShellCheck-Annotation. Schließlich erkennt
der abhängigkeitsfreie YAML-Fallback ein List-Mapping nur, wenn auf den
Doppelpunkt Whitespace oder Wertende folgt; dadurch bleiben Klartextskalare
wie `ARGS:foo.` und vorhandene `name: Content-Type`-Mappings erhalten.

## Geänderte Dateien und Tests

- `.python-version`, alle betroffenen Workflows, `Makefile` und der Kommentar
  in `requirements-ci.lock`.
- `ci/tools/update-python-version.py` und
  `ci/checks/security/check-python-version.py`, der CI-Security-
  Wartungscontract und der gemeinsame Fallback-YAML-Parser.
- CI-Security-, Workflow-Contract- und Updater-Regressionstests.
- Englische/deutsche CI-Security- und GitHub-Actions-Sicherheitsdokumentation.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder freigegebener Evidenzpfad |
| --- | ---: | --- | --- |
| Framework-eigenes Python 3.14 `-m py_compile` über geänderte Python-Dateien | 0 | Geänderte Implementierung und Tests kompilierten. | Task-Storage `20260720T180337Z-framework-python-313-updater-f3349a7e` |
| Framework-eigenes Python 3.14, fokussierte Updater-/Contract-/Common-Workflow-Unittest-Auswahl | 0 | 27 versionsneutrale Tests bestanden. | Isolierter Framework-Worktree |
| `check-ci-security-contract.py --root <task-worktree>` | 0 | Aktuelle Workflows und der Drei-Job-Writer-Contract bestanden. | Isolierter Framework-Worktree |
| `check-python-version.py --root <task-worktree>` | 0 | Kanonische Quelle und rekursiver Python-Workflow-Contract bestanden. | Isolierter Framework-Worktree |
| Fokussierte Updater-, CI-Security-Contract-, Python-Version-Contract- und Parser-Hardening-Tests | 0 | 35 versionsneutrale Regressionen bestanden nach der Exact-Head-Remediation. | Isolierter Framework-Worktree |
| `make test-ci-security-contract` | 0 | 84 CI-Security-Tests bestanden nach der Exact-Head-Remediation. | Isolierter Framework-Worktree |
| `make test-workflow-contract`, `make check-github-actions-workflows`, `make check-documentation` und `make lint` | 0 | Workflow-, Dokumentations- und finale lokale Lint-Gates bestanden. | Task-Storage `20260720T180337Z-framework-python-313-updater-f3349a7e` |

## Sicherheitsauswirkung

Die Änderung entfernt doppelte Patch-Autorität, weist bare/floating/Matrix-
Selektionspfade zurück und stellt sicher, dass ein Cross-Job-Kandidat keinen
Schreibvorgang direkt autorisieren kann. Resolver-Transport, feste
Kandidatenmaterialisierung, Repository-Schreibscope und Draft-PR-Publikation
haben jeweils explizite Fail-Closed-Kontrollen und Negativtests. Der finale
Diff remediiert außerdem das low-severity-Framework-Härtungsfinding
`FND-FRAMEWORK-0033`, das bewies, dass der Wartungscontract zuvor künftige
explizite Secret-/Token-Referenzen außerhalb des überprüften Publisher-Inputs
akzeptierte. Die Fertigstellung deckt auch serialisierte
`${{ toJSON(secrets) }}`- und `${{ toJSON(github) }}`-Kontexte ab, die jetzt
fail-closed scheitern, ohne legitime `github.sha`- oder
`github.repository`-Kontrollen zurückzuweisen; finale lokale und gehostete
Verifikation bleiben erforderlich.
Die Exact-Head-Remediation verfolgt außerdem `FND-FRAMEWORK-0037`
(Workflow-Kontext- und Literal-Body-Lint), `FND-FRAMEWORK-0038`
(Fallback-YAML-Skalarparsing) und das release-blockierende
`FND-FRAMEWORK-0039` (Kandidatenausgabepfad). Um diese Checks zu bestehen,
wurde keine Kontrolle abgeschwächt.

## Dokumentation und Runtime-Evidenz

Die gepaarten englischen/deutschen Leitfäden dokumentieren die kanonische
Quelle, die feste Metadatenautorität, Kandidaten-/Publisher-Trennung, die
No-Auto-Merge-Eigenschaft und gehostete Exact-Head-Kontrollen. Lokale Runtime-
Evidenz ist bewusst versionsneutral; den exakten CPython-3.13-Kandidaten
validiert der GitHub-Actions-Kandidatenvalidierungsjob, bevor sein Publisher
laufen darf.

## Nicht ausgeführte Prüfungen

Lokal war kein CPython-3.13-Executable verfügbar; exakte Kandidatenruntime-
Validierung wird daher nicht lokal behauptet. Die gepinnten gehosteten
actionlint-, ShellCheck-, zizmor-, Ruff-, Pyright-, GitHub-Actions-,
SonarQube-Cloud-, Review-Status- und Lifecycle-Validierungen des generierten
PR bleiben Exact-Head-PR-Kontrollen; es wurde kein globales oder User-Site-Tool
als Ersatz installiert.

## Einschränkungen und Restrisiko

Das Repository kann die Workflow-Quelle begrenzen, aber lokal nicht beweisen,
wer sie dispatchen darf, welche GitHub-Token-Policy gilt, ob der Default-Branch
geschützt ist oder ob alle gehosteten Checks und Reviews für einen token-
erstellten Draft-PR-Head neu laufen. Der Publisher bleibt daher Draft-only und
ein Mensch muss die gehosteten Kontrollen vor einem Merge verifizieren.

## Finaler Diff- und Review-Status

Draft PR #39 ist offen. Sein erster veröffentlichter Head
`4a31df044ea2c2c7526828e54978238639b57dd4` machte die verfolgten Lint-,
Parser- und Kandidatenausgabefindings sichtbar; die hier beschriebene
Remediation benötigt einen neuen Exact-Head-Check von GitHub Actions,
SonarQube Cloud und Review-/Thread-Status, bevor die Aufgabe bei `verified_pr`
stoppen darf. Kein Merge, Parent-Gitlink-Wechsel oder MRTS-Wechsel ist im Scope.
