# Change Record

**Sprache:** [English](20260718-01-fix-framework-crs-ref-provenance.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260718-01-fix-framework-crs-ref-provenance` |
| UTC-Datum | `2026-07-18` |
| Ursprüngliche Framework-Basisrevision | `cdc91a398d6c156eaff927d742b23018a3817fb6` |
| Abgeglichene Framework-Basisrevision | `9954b99a31fab0006cdf903ab477c8158c50fea8` |
| Reconciliation-Merge-Commit | `cae1f9deae756766ef7eb54fa3e6a808411f242f` |
| Issue oder Pull Request | Framework-Draft-PR #26 (`codex/fix-framework-crs-ref-provenance`) mit erforderlichem neuem exakten Non-Force-Push-Head-Verifikationszyklus. |
| Frühere Reconciliation-Evidenz | `e3b9903ddd2607d131e419ff780acbcee14ace3c`; die aktuelle normale Master-Reconciliation ersetzt den nicht veröffentlichten lokalen Synchronisationszustand. |

## Motivation und Problemstellung

`FND-FRAMEWORK-0004` / `RC-FW-002-crs-git-ref-provenance` stellte fest, dass
das Framework ein veränderliches CRS-Tag oder einen anderen Caller-gesteuerten
Ref an Git übergeben und `FETCH_HEAD` konsumieren konnte. Diese
Framework-eigene Änderung bindet die Provisionierung an einen zentral geprüften
vollständigen Commit und weist abweichende Quellauswahl-Eingaben vor jeder
Git-Operation ab.

## Betroffene Komponenten und Sicherheitsgrenzen

- `ci/lib/common.sh`: zentraler CRS-Origin, Release-Metadaten und
  unveränderliche Commit-Provenance.
- `ci/provisioning/fetch-crs.sh`: Grenze für externen Source-Root, Git,
  Remote-Origin, Commit-Objekt, Checkout und Submodule.
- `tests/security_regression/test_crs_git_ref_provenance.py`: Fake-Git-Tests
  an der Prozessgrenze für Regression, Kontrolle und Bypass-Evidenz.

Die Sicherheitsgrenze betrifft ausschließlich die Framework-CRS-Quellprovenance.
Parent-Code und Parent-Gitlink werden nicht geändert; MRTS bleibt in diesem
Task-Worktree unberührt und nicht initialisiert.

Der veröffentlichte #26-Head lag vor Framework-master
`9954b99a31fab0006cdf903ab477c8158c50fea8`. Ein normaler, nicht
umschreibender Merge wurde im Versionsprüfer additiv aufgelöst: Der
CRS-Guard für ein geprüftes Release und einen unveränderlichen Commit bleibt
erhalten, während die
aktuelle Master-NGINX-Provenance aus Release-Tag/exaktem Release-Asset/
verpflichtlicher SHA-256, deren Updater-Check und Regressionen, die
PCRE2-Digest-Durchsetzung, Workflow-Full-SHA-Controls und
Common-Structure-Controls unverändert geerbt bleiben. Der abgeglichene direkte
Diff enthält nur die zwölf beabsichtigten CRS-Provenance-Pfade.

## Akzeptanzkriterien

- Nur der literale freigegebene HTTPS-CRS-Origin und der vollständige Commit
  `55b09f5acfd16413e7b31041100711ceb7adc89c` erreichen einen Git-Sink.
- Tags, Branches, Namespaces, abgekürzte und nicht zugehörige IDs,
  URL-/Ref-Overrides und unsichere Git-Umgebungswerte schlagen vor der
  Consumption fail-closed fehl.
- Origin, `FETCH_HEAD^{commit}`, das aufgelöste Commit-Objekt und das finale
  `HEAD^{commit}` entsprechen demselben freigegebenen Commit.
- Vorhandene Quellpfade und jedes `.gitmodules`-Manifest schlagen fail-closed
  fehl.
- Ein neueres CRS-Release wird ohne automatische Änderung gemeldet; für jede
  Provenance-Änderung ist ein geprüftes Paar aus Release-Tag und unveränderlichem
  Commit erforderlich.
- Die fokussierten Negativ-, Kontroll- und Bypass-Tests bestehen ohne echten
  CRS-Download oder MRTS-Mutation.

## Untersuchte Alternativen

- Das Ersetzen von `CRS_GIT_REF` durch eine SHA wurde verworfen, weil die
  aktuelle Versionsberichterstattung es als Release-Metadaten behandelt. Es
  bleibt ausschließlich Metadatum und wird niemals an Git übergeben.
- Wiederverwenden, Zurücksetzen oder Bereinigen eines bestehenden Checkouts
  wurde verworfen, weil schmutzige Dateien, lokale Konfiguration, Hooks,
  verlinkte Worktrees und befüllte Submodule die Vertrauensgrenze erweitern.
- Die rekursive Submodule-Initialisierung wurde verworfen, bis eine separate
  freigegebene Submodule-Provenance-Regel existiert.

## Implementierungsentscheidung

`CRS_APPROVED_REPO_URL` und `CRS_APPROVED_COMMIT` sind literale zentrale
Werte; Umgebungsversuche, sie zu setzen, werden beim Sourcen von `common.sh`
überschrieben. `CRS_REPO_URL` und `CRS_GIT_REF` behalten
Kompatibilitäts-Metadatenrollen, aber ein abweichender Wert wird vor Git
abgewiesen.

Der Fetch-Pfad erzeugt atomar ein frisches Quellverzeichnis, initialisiert ein
isoliertes Git-Repository, setzt und liest den literalen HTTPS-Origin zurück
und lädt nur den vollständigen Commit mit deaktivierten Tags und
Submodule-Rekursionen. Er bereinigt Git-Konfigurations-, Hook-, TLS-, Askpass-
und SSH-Umgebungssteuerungen, erzwingt TLS-Verifikation, vergleicht
fetched/aufgelöste/ausgecheckte Commit-IDs und weist `.gitmodules` ab, nachdem
der Parent-Nachweis erbracht ist. Er verwendet niemals `--branch`, `clone`
oder `checkout --detach FETCH_HEAD`.

## Geänderte Dateien und Tests

- `ci/lib/common.sh`
- `ci/provisioning/fetch-crs.sh`
- `Makefile` und `ci/checks/catalog/check-crs-version-pinning.sh`
- `ci/tools/check-common-versions.py`
- `tests/security_regression/test_crs_git_ref_provenance.py`
- `docs/reference/variables.md` und `docs/reference/variables.de.md`
- dieses gepaarte Change Record
- EN/DE/JSON-Finding-Records von `FND-FRAMEWORK-0004`, die vor Delivery mit
  der tatsächlichen Evidenz dieser Aufgabe aktualisiert werden

Der fokussierte Test enthält eine legitime Frisch-Checkout-Kontrolle und
Negativabdeckung für Tag/Branch/Namespace/kurze-oder-nicht-zugehörige-ID,
Runtime-Override, bestehenden Checkout, unerwarteten Origin,
Fetched-/Objekt-/HEAD-Mismatch, Submodule-Manifest und unsichere
Git-Umgebungseingaben sowie ein neueres Release, das keine ungeprüfte
Tag-zu-Commit-Aktualisierung erzeugen darf.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk env … python -m unittest discover -s tests/security_regression -p test_crs_git_ref_provenance.py -v` (Baseline) | `1` | 8 Tests / 13 erwartete Fehler belegten den verwundbaren Pfad vor dem Source-Fix. | Task-Run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| Derselbe fokussierte Befehl (initiale #26-Implementierung) | `0` | 9 Mock-Git-Provenance-Tests bestanden. | Task-Run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| `rtk make BUILD_ROOT=… TMP_ROOT=… test-crs-provenance-contract` (Reconciliation 2026-07-19) | `0` | 10 Mock-Git-Provenance-Tests bestanden, einschließlich der Updater-Regression für das geprüfte Release-Paar. | Aktueller Task-Run `20260719T081017Z-framework-pr-resolution-20260719-840082e0` |
| `rtk proxy env TMP_ROOT=… BUILD_ROOT=… sh ci/checks/catalog/check-crs-version-pinning.sh` | `0` | Der Guard für freigegebenen literalen Origin, Commit und Release-Metadaten bestand. | Aktueller Task-Run `20260719T081017Z-framework-pr-resolution-20260719-840082e0` |
| Derselbe Katalog-Guard mit `CRS_GIT_REF=main` | `77` (erwartete Negativkontrolle) | Der Runtime-Override der Release-Metadaten wurde vor dem Catalog-Scan abgewiesen. | Aktueller Task-Run `20260719T081017Z-framework-pr-resolution-20260719-840082e0` |
| `rtk sh -n ci/lib/common.sh` | `0` | POSIX-Shell-Syntax bestanden. | Task-Run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| `rtk sh -n ci/provisioning/fetch-crs.sh` | `0` | POSIX-Shell-Syntax bestanden. | Task-Run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| `rtk env … python -m unittest discover -s tests/security_regression -v` | `0` | Vollständige Security-Regression-Discovery: 22 Tests bestanden. | Task-Run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| `rtk shellcheck -S error -x ci/lib/common.sh ci/provisioning/fetch-crs.sh` | `0` | ShellCheck-Error-Level bestanden. | Task-Run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| `rtk make check-variable-documentation`, `check-bilingual-docs`, `check-doc-links` und `check-documentation` | `0` | Alle ausgewählten Dokumentationsprüfungen bestanden. | Task-Run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| `rtk make lint` mit Repository-Root-`OUTPUT_ROOT` und task-eigenen Cache-/Temp-Pfaden | `0` | Framework-Lint bestanden. Ein früherer externer `OUTPUT_ROOT`-Versuch wurde vor der Source-Analyse durch die Lint-Harness-Voraussetzung abgewiesen. | Task-Run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| `rtk sh ci/checks/catalog/check-crs-version-pinning.sh` | `0` | Direkter Pinning-Check bestanden, nachdem sandboxed Lint sein festes `/tmp`-Temporärdatei-Limit gezeigt hatte. | Task-Run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| `rtk git diff --check` | `0` | Aktueller Framework-Diff enthält keine Whitespace-Fehler. | Task-Worktree |
| `rtk env … make test-crs-provenance-contract test-workflow-action-pins test-workflow-contract` | `0` | 10 CRS-, 21 Workflow-Action-Pin- und 2 Common-Structure-Vertragstests bestanden im abgeglichenen Worktree. | `20260719T081017Z-framework-pr-resolution-20260719-840082e0/build/pr26-reconciliation.7k83wI` |
| `rtk env … python3 -m unittest -v tests.security_regression.test_nginx_archive_digest tests.security_regression.test_nginx_release_provenance tests.security_regression.test_pcre2_archive_digest` | `0` | 15 NGINX-/PCRE2-Archivintegritäts- und Provenance-Regressionen bestanden im abgeglichenen Worktree. | `20260719T081017Z-framework-pr-resolution-20260719-840082e0/build/pr26-reconciliation.7k83wI` |
| `rtk env … sh -n …; sh ci/checks/catalog/check-crs-version-pinning.sh` | `0` | Geänderte Shell-Pfade parsen und der genehmigte CRS-Kontrollfall besteht; `CRS_GIT_REF=main` blockiert unabhängig mit Exit `77`. | task-eigener temporärer Pfad |
| `rtk env FRAMEWORK_ROOT=<PR-#26-Worktree> … make lint` | `0` | Finales repository-natives Lint bestand mit abgeglichener Framework-Wurzel sowie externen Bytecode-/Temp-Pfaden. | task-eigener Build-Pfad |
| Framework-Draft-PR-CI und SonarQube Cloud | Ausstehend | Erst nach beobachtetem Exact-Head-Abschluss eintragen. | Ausstehend |

## Sicherheitsauswirkung

Der ursprüngliche Mutable-Ref-Pfad wird durch die Baseline-Mock-Fixture
reproduziert und durch die aktuelle Implementierung abgewiesen. Die legitime
Kontrolle erhält nur den zentralen Origin und Commit. Der alternative
Bypass-Review deckt Tags, Branches, Ref-Namespaces, Umgebungs-Overrides,
bestehende Checkouts, Submodule, Git-Konfigurations-/TLS-/Askpass-Steuerungen,
Origin und die Gleichheitskette `FETCH_HEAD`/Objekt/`HEAD` ab. Die unabhängige
Codex-Security-Revalidierung fand nach den finalen Testerweiterungen keine
blockierende Source-Control-Lücke.

## Dokumentation und Runtime-Evidenz

Die englische/deutsche Variablenreferenz unterscheidet nun Release-Metadaten
vom nicht überschreibbaren Provisioning-Commit und dokumentiert
fail-closed-Verhalten für bestehenden Source und Submodule. Es wurden kein
realer CRS-Netzwerk-Fetch, kein Runtime-Smoke und keine dynamische
Upstream-Tag-Mutation durchgeführt: Die Aufgabe verlangt fokussierte
gemockte Git-Provenance-Tests und keinen CRS-Content-Download.

## Nicht ausgeführte Prüfungen

- Framework-Draft-PR-CI, SonarQube Cloud, Review und Review-Thread-Prüfungen
  benötigen den neuen exakten Non-Force-Push-Head-Zyklus. Ältere Head-Ergebnisse
  zählen nicht als Evidenz für den abgeglichenen Head.
- Ein realer Netzwerk-CRS-Fetch und eine dynamische Upstream-Tag-Mutation
  werden nicht ausgeführt: Beides überschreitet den Scope der gemockten
  Proof-/Nicht-Download-Vorgabe.

## Einschränkungen und Restrisiko

`CI_ROOT`, das aus `PATH` gewählte `git`-Programm, der Framework-Quellbaum,
der Host-TLS-Trust-Store und exklusiver Jobbesitz von `SOURCE_ROOT` bleiben
lokale Vertrauensgrenzen. Ein gleichzeitiger lokaler Schreiber mit Zugriff auf
das Parent-Verzeichnis des externen Source-Roots kann nach der
Verzeichniserzeugung weiterhin Dateisystemrennen versuchen. Ein nicht
erreichbarer freigegebener Commit schlägt fail-closed fehl. Der zentrale Commit
ist eine geprüfte Identität, keine Kette signierter Release-Attestierungen.

## Finaler Diff- und Review-Status

Der abgeglichene lokale Source-/Test-/Dokumentations-Review, finale Lint und
Whitespace-Check bestanden. Die unabhängige Codex-Security-Revalidierung
meldete unter den dokumentierten Trust-Grenzen keinen blockierenden
Source-Control-Bypass. Der direkte Diff gegen Framework-master ist auf die
zwölf beabsichtigten CRS-Pfade beschränkt; Master-only-NGINX-, PCRE2-,
Workflow-, Runner-, Fixture- und Change-Record-Controls bleiben unverändert
geerbt. Merge-Commit `cae1f9deae756766ef7eb54fa3e6a808411f242f` stellt den
abgeglichenen lokalen Head her; der Non-Force-Push stellt den PR-Head für neue
PR-CI-, SonarQube-, Review- und Thread-Evidenz her. Kein Framework-master-Merge,
Parent-Gitlink-Update oder MRTS-Änderung ist autorisiert.
