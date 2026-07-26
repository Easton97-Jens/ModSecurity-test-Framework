# Änderungsprotokoll: Framework-MRTS-Submodule-Updater hinzufügen

**Sprache:** [English](20260726-02-add-framework-mrts-submodule-updater.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260726-02-add-framework-mrts-submodule-updater |
| UTC-Datum | 2026-07-26 |
| Framework-Basisrevision | c27c644e088904b71b8380d16ee34f1b36f2c001 |
| Issue oder Pull Request | Framework-PR #47, `Easton97-Jens-patch-1` nach `master`. Dieses Protokoll autorisiert weder einen Merge noch einen direkten Default-Branch-Push. |

## Motivation und Problemstellung

PR #47 fügte bisher drei unbenutzte Submodule-Umgebungsvariablen zum
Workflow-Tool-Updater hinzu. Das Framework benötigt stattdessen einen
tatsächlich getrennten, eingeschränkten Wartungsablauf für den MRTS-Gitlink:
einen unveränderlichen Remote-Commit auflösen, ihn ohne Write-Credential
validieren und ausschließlich einen passenden Draft-Pull-Request erstellen
oder aktualisieren. Das Parent-`update-submodules.yml` liefert die gewünschte
Resolver-/Validator-/Publisher-Struktur, aber dessen Parent-Pfad,
Upstream-Referenz und Publisher-Mechanik dürfen nicht wortgleich über die
Repository-Grenze kopiert werden.

## Betroffene Komponenten und Sicherheitsgrenzen

- `.github/workflows/update-submodules.yml` ist ein Framework-only geplanter
  oder manuell gestarteter Updater für den Framework-eigenen
  `tools/MRTS`-Gitlink.
- Resolver und Validator besitzen `contents: read`, kein Secret, keine
  explizite Token-Referenz und persistieren keine Credentials. Der Validator
  checkt zuerst die vertrauenswürdige Framework-Default-Revision aus und
  initialisiert dann ausdrücklich nur das deklarierte direkte Submodule, bevor
  er die aufgelöste unveränderliche SHA auscheckt.
- Der Default-Branch-gegate Publisher besitzt nur `contents: write` und
  `pull-requests: write`. Er löst die SHA erneut auf, beschränkt sowohl
  bestehende als auch gestagte Änderungen auf `tools/MRTS`, führt keinen
  Force-Push aus und erstellt nur einen Draft-PR. Er hat keinen PR-Trigger,
  keine Merge-Operation, kein Default-Branch-Ziel, keinen App-Private-Key und
  keinen MRTS-Source-Write-Schritt.
- `ci/tools/update-workflow-tools.py` erlaubt den neuen Workflow ausdrücklich
  für die Wartung unveränderlicher Action-Pins. Der CI-Sicherheitsvertrag
  bindet die erforderliche Job-Topologie, Berechtigungen, Referenz, Pfad- und
  Non-Force-Kontrollen.
- Parent-Source und Gitlink, MRTS-Source/Branch/Commit sowie jede
  Framework-Gitlink-Aktualisierung außerhalb des künftigen Wartungs-Draft-PRs
  sind nicht Teil des Umfangs.

## Akzeptanzkriterien

- `update-submodules.yml` löst nur die volle SHA bei
  `Easton97-Jens/MRTS` `refs/heads/main` auf, vergleicht sie mit `tools/MRTS`
  und tut nichts, wenn der Gitlink bereits übereinstimmt.
- Die Validierung ist read-only, verwendet einen credentials-freien Checkout
  mit `submodules: false`, initialisiert ausdrücklich nur `tools/MRTS`, checkt
  den Kandidaten detached aus und führt `make quick-check` aus.
- Ein erfolgreicher Publisher darf nur den `tools/MRTS`-Gitlink auf dem festen
  Wartungsbranch verändern, nutzt einen normalen Non-Force-Push und erstellt
  oder aktualisiert genau einen passenden Draft-PR; er merged nicht und
  aktualisiert `master` nicht direkt.
- Der vorhandene Updater für unveränderliche Action-Pins umfasst den neuen
  Workflow, und fokussierte positive/negative CI-Sicherheitstests weisen eine
  MRTS-`master`-Ref, Reader-Credential-Injection und Force-Push zurück.
- Englische und deutsche Dokumentation und dieses Änderungsprotokoll
  beschreiben denselben eingeschränkten Entwurf.

## Untersuchte Alternativen

- Die unbenutzten Variablen in `update-workflow-tools.yml` beizubehalten wurde
  verworfen: Sie liefern keine Kandidatenauflösung, Validierung oder
  Gitlink-Aktualisierung.
- Den Parent-Workflow wortgleich zu kopieren wurde verworfen, weil er auf den
  falschen Pfad/das falsche Repository zielen und ein für das Framework
  unzulässiges Parent-`force-with-lease` übernehmen würde.
- Den bestehenden Workflow-Tool-Publisher MRTS aktualisieren zu lassen wurde
  verworfen, weil Action-/Tool-Lock-Wartung und eine Gitlink-Aktualisierung
  verschiedene erlaubte Pfade und Credential-Grenzen haben.
- Ein rekursiver automatischer Checkout wurde vom Framework-Workflow-Vertrag
  verworfen; der Validator initialisiert nur das deklarierte direkte Submodule
  nach dem credentials-freien Default-Branch-Checkout.

## Implementierungsentscheidung

Der neue Workflow folgt dem Parent-Lebenszyklus strukturell und bewahrt die
strengeren Framework-Kontrollen. Er verwendet `tools/MRTS`,
`https://github.com/Easton97-Jens/MRTS.git` und die beobachtete
Repository-Default-Referenz `refs/heads/main` statt der veralteten PR-#47-
Referenz `master`. Er löst und revalidiert eine volle SHA vor der
Gitlink-Aktualisierung. Der stabile Wartungsbranch ist
`automation/update-framework-mrts-submodule`; er wird nur akzeptiert, wenn ein
bestehender passender Draft-PR den exakten Titel/Basisbranch besitzt und keinen
Pfad außer `tools/MRTS` ändert.

Der Digest des überprüften Publisher-Bodys des bestehenden Tool-Updater-
Workflows wurde bewusst aktualisiert, nachdem seine explizite Pfad-Allowlist
den neuen Workflow erhielt. Der Publisher wird dadurch nicht semantisch
erweitert: Normaler Push, Draft-only-Verhalten und gestagte Scope-Prüfung
bleiben unverändert.

## Geänderte Dateien und Tests

- `.github/workflows/update-submodules.yml` fügt den eingeschränkten
  MRTS-Resolver, Validator und Draft-PR-Publisher hinzu.
- `.github/workflows/update-workflow-tools.yml` und
  `ci/tools/update-workflow-tools.py` fügen diesen Workflow zur exakten
  Action-Pin-Wartungs-Allowlist hinzu; die überholte reine Umgebungsänderung
  aus PR #47 wird entfernt.
- `ci/checks/security/check-ci-security-contract.py` und
  `tests/ci_security/test_ci_security_contract.py` binden und testen das neue
  Workflow-Profil einschließlich negativer Ref-/Token-/Force-Push-Mutationen.
- Die gepaarten Workflow-Sicherheits- und CI-Tooling-Guides dokumentieren
  dieselben Grenzen auf Englisch und Deutsch.
- Dieses gepaarte Änderungsprotokoll schafft Delivery-Traceability.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `make PYTHON=.venv/bin/python test-ci-security-contract` | 127 | Der saubere externe Worktree enthält keine lokale `.venv`; daraus wurde kein Source-Fehler abgeleitet. | Framework-Task-Worktree. |
| `make PYTHON=<reviewed Framework test interpreter> test-ci-security-contract` | 0 | 136 CI-Sicherheits-, Workflow-, Updater- und Python-Vertragstests bestanden nach den überprüften Workflow-/Profilkorrekturen. | Framework-Task-Worktree; zugelassenes externes Pycache-Root. |
| `make PYTHON=<reviewed Framework test interpreter> check-github-actions-workflows` | 0 | Immutable-Action-Pin- und Permission-Checks akzeptierten alle 16 Workflows einschließlich des neuen Updaters. | Framework-Task-Worktree. |
| `make PYTHON=<reviewed Framework test interpreter> test-workflow-action-pins` | 0 | 25 Immutable-Action-Pin-Regressionstests bestanden. | Framework-Task-Worktree. |
| `make PYTHON=<reviewed Framework test interpreter> check-documentation` | 0 | Link-, zweisprachige, Repository-Pfad- und Change-Record-Verträge bestanden. | Framework-Task-Worktree. |
| `make PYTHON=<reviewed Framework test interpreter> lint` | 0 | Das projektnative vollständige Lint-Ziel bestand einschließlich Shell-/Python-Syntax, Verträgen, Security-Checks, Dokumentation und Whitespace-Validierung. | Framework-Task-Worktree. |
| `git diff --check` | 0 | Der laufende Source-Diff hatte vor der finalen Prüfung keine Whitespace-Fehler. | Framework-Task-Worktree. |
| `gh pr view 47 --repo Easton97-Jens/ModSecurity-test-Framework --json headRefOid,baseRefOid,statusCheckRollup` | 0 | Bestätigte Basis `c27c644…`, beobachteten Head `36a81c…` und den externen OSV-Check-Fehler. | Run `20260726T094125Z-rebuild-pr-47-submodule-aligned`, OSV-Service-Quittung. |
| `gh run view 30196691788 --repo Easton97-Jens/ModSecurity-test-Framework --log-failed` | 0 | Der fehlgeschlagene OSV-Job meldete externe RPC-Service-Unerreichbarkeit und Scanner-Exit-Code 127. | Dieselbe zurückbehaltene Quittung. |
| `gh run view 30197914476 --repo Easton97-Jens/ModSecurity-test-Framework --log-failed` | 0 | Der erste aktualisierte PR-Head scheiterte nur an Ruff-Formatierung von `check-ci-security-contract.py`; Ruff-Lint selbst bestand. | Hosted-PR-#47-CI-Evidenz. |
| `ci/tools/fetch-security-tool.py --tool ruff` und gesperrte Ruff-Check-/Format-Prüfung | 0 | Das lock-verifizierte Ruff-Binary formatierte die eine Python-Datei; fokussierte Lint- und Format-Prüfungen bestanden. | Framework-Task-Worktree, Runner-eigenes externes Tool-Verzeichnis. |
| `make PYTHON=<reviewed Framework test interpreter> test-ci-security-contract` | 0 | Die 136-Test-CI-Sicherheits-Suite bestand erneut nach der reinen Formatkorrektur. | Framework-Task-Worktree. |
| `gh run view 30197914475 --repo Easton97-Jens/ModSecurity-test-Framework --log-failed` | 0 | Der OSV-Vergleich scheiterte erneut nur wegen externer OSV-RPC-Service-Unerreichbarkeit, gefolgt von Scanner-Exit-Code 127. | Run `20260726T094125Z-rebuild-pr-47-submodule-aligned`, OSV-Service-Quittung. |

## Sicherheitsauswirkung

Dies ist CI-Wartung und Trust-Boundary-Härtung, keine Product-Security-
Remediation. Die positive Kontrolle ist der echte Workflow, der den nativen
CI-Sicherheitsvertrag erfüllt. Negative Mutationen beweisen die Zurückweisung
einer veralteten MRTS-`master`-Ref, einer Reader-`github.token`-Injection und
eines Force-with-Lease-Pushes. Der Workflow führt keinen nicht vertrauens-
würdigen PR-Code aus und hält das einzige Write-Token aus Resolver und
Validator heraus. Die Parent-Operation `--force-with-lease` wurde bewusst nicht
übernommen.

## Dokumentation und Runtime-Evidenz

Beide Workflow-Sicherheits- und CI-Tooling-Guides erhalten entsprechende
englische/deutsche Einträge. Es wurde kein gehosteter Wartungsrun manuell
gestartet, weil ein erfolgreicher Run einen Remote-Wartungsbranch und Draft-PR
erstellen oder aktualisieren könnte; diese Delivery-Aktion bleibt vom
PR-Update und normalen Hosted-Checks abhängig. Der vorbestehende PR-OSV-
Service-Fehler wird als secret-freie externe Quittung zurückbehalten. Seine
kanonische Parent-Finding-Allocation ist derzeit blockiert, weil der Mount
`.codex/findings` das Anlegen des erforderlichen neuen Verzeichnisses
`FND-GITHUB-0009` mit `Read-only file system` zurückweist.

## Nicht ausgeführte Prüfungen

- Ein gehosteter `Update MRTS submodule`-Run wurde nicht manuell ausgelöst, um
  vor dem erfolgreichen Source-PR keine Remote-Branch-/PR-Nebenwirkung zu
  erzeugen.
- Hosted Actions, SonarQube Cloud, Review-Threads und Branch Protection sind
  exakte PR-Head-Kontrollen und werden erst nach dem Push des aktualisierten
  Branches beobachtet.

## Einschränkungen und Restrisiko

Lokale Source- und Contract-Checks können GitHub-gehostetes Verhalten,
Remote-MRTS-Verfügbarkeit oder Draft-PR-Erstellung nicht beweisen, bevor ein
geplanter/manueller Run zulässig ist. Der bekannte OSV-Service-Fehler liegt
außerhalb dieses Diffs und bleibt ein release-blockierender Hosted-Check, bis
er erfolgreich erneut ausgeführt wird; kein Scanner, Quality Gate, Test oder
Berechtigung wurde geschwächt. Der nicht verfügbare Parent-Finding-Store-
Write-Zugriff verhindert die kanonische Allocation seines neuen Findings, aber
Evidenzquittung und Einschränkung werden zurückbehalten. Kein Merge oder
direkter Default-Branch-Schritt ist autorisiert.

## Finaler Diff- und Review-Status

Der begrenzte Source-Diff erhielt einen fokussierten Workflow-/Security-Review:
Der einzige Write-Pfad ist Default-Branch-gegate, auf den MRTS-Gitlink
beschränkt und verwendet weder Force-Push noch MRTS-Source-Write. Der finale
lokale vollständige Lint-, Dokumentations-, Immutable-Pin-, CI-Sicherheits- und
Whitespace-Check bestand. Der erste aktualisierte PR-Head hatte einen rein
mechanischen Ruff-Formatfehler; der Folge-Commit enthält exakt diese
lock-verifizierte Formatkorrektur und führt die fokussierte Suite erneut aus.
Die verbleibenden exakten Kontrollen sind seine Hosted-Checks und nach
zulässigem Dispatch der gehostete Wartungslebenszyklus. Dieses Protokoll
repräsentiert weder einen Merge, eine Gitlink-Änderung noch die Verifikation
dieses künftigen Wartungslebenszyklus.
