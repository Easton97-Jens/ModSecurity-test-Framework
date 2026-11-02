# Change Record

**Sprache:** [English](20261102-01-framework-python315-source-bootstrap.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261102-01-framework-python315-source-bootstrap |
| UTC-Datum | 2026-11-02 |
| Framework-Basisrevision | `91145b7ba721bdec4e89af754cf40bf496fd2a08` |
| Issue oder Pull Request | Lokale Implementierungsübergabe; bei Vorbereitung noch kein Migrations-PR erstellt |

## Motivation und Problemstellung

Framework-Interpreter und geplanter Patch-Updater wechseln von CPython 3.14 auf
3.15; der vertrauenswürdige OSV-Basis-Bootstrap bleibt erhalten. Für offizielles
PyYAML 6.0.3 fehlt ein geprüftes CP315-Wheel; die binäre Installation scheiterte.
Der Nutzer autorisierte den Build des verifizierten offiziellen Quellcodes
anstelle eines inoffiziellen Wheels.

## Betroffene Komponenten und Sicherheitsgrenzen

Betroffen sind kanonische Python-/PyYAML-Pins, generierte Selektor-/Lock-Ansichten,
Installer, Build-Tool-Lock, Updater-Workflows, exakte Sicherheitsverträge,
Validierungs-Snapshots, Analyse-Baselines und gepaarte Dokumentation. Build-
Backend-Ausführung bleibt von Runtime-Installation und geerbten Credentials
getrennt. OSV führt ausschließlich Bootstrap-Code der vertrauenswürdigen Basis
aus. Parent-Gitlink und Connector-Runtime liegen außerhalb dieses Records;
MRTS bleibt schreibgeschützt behandelt.

## Akzeptanzkriterien

Kanonischer Selektor und Updater akzeptieren nur stabile ASCII-Patchversionen
von CPython 3.15. Kandidat, Runtime und feste Publisher-Identität stimmen überein.
Der Quellbuild verifiziert offizielle Quellen und vier exakte Build-Wheels,
baut offline ohne LibYAML, installiert nur PyYAML und besteht die
Abhängigkeitsprüfungen. OSV erlaubt historische binäre Bootstraps nur für die
exakten gepinnten SHA-/Versionspaare; aktuelle Basen verwenden ihren
vertrauenswürdigen Helper. Snapshot-Validierung enthält alle neuen
Hash-gebundenen Installer-Eingaben. Die Dokumentation trennt lokale Prüfungen,
tatsächliche 3.15-Quellbuilds, Advisory-Momentaufnahmen und nicht ausgeführte
gehostete Validierung.

## Untersuchte Alternativen

3.14 beizubehalten erfüllt den Migrationsauftrag nicht. Floating-Versionen,
inoffizielle CP315-Wheels, ungepinnte Build-Tools, indexbasierte Build-Isolation
oder Bootstrap-Code vom PR-Head würden die Provenienz schwächen. Der verifizierte
Quellbuild mit expliziten isolierten Build-Abhängigkeiten erfüllt den Umfang.

## Implementierungsentscheidung

Der argumentlose Shell-Installer delegiert an einen Standardbibliothek-Python-
Helper. Offizielles Quellarchiv und vier geprüfte reine Python-Build-Wheels
werden vor der Verwendung SHA-256-verifiziert. Eine temporäre venv baut ein
reines PyYAML-Wheel ohne LibYAML; Build und Installation laufen mit bereinigter
Umgebung, ohne Index und ohne Abhängigkeitsauflösung. Das lokal gebaute Wheel
erhält vor der Runtime-Installation einen Hash-Lock. Build-Tools bleiben
außerhalb der Runtime. Ziele müssen eine venv oder das verifizierte
setup-python-Präfix von GitHub Actions sein. Temporäre Ausgaben und Wheel-/Hash-
Locks bleiben im externen Runner-/Build-Temporärspeicher und werden beim
Verlassen entfernt. Historische Wheel-Installationen bleiben unterstützt.

OSV erhält ausschließlich `f73f8842f45318e2df8aff1d31855eeb7c20a22f` / `3.13.14`
und `91145b7ba721bdec4e89af754cf40bf496fd2a08` / `3.14.10` und `68ca7b411db12ed96ee6208aa792b43e8043470c` / `3.14.10`. Nur das erste Tupel
darf eine fehlende Datei ersetzen. Andere Basen benötigen strikt 3.15 und ihren
ausgecheckten zentralen Helper; fehlende Helper lösen keinen Ersatzpfad aus.
Beide historischen Env-Zuordnungen und das bedingte Programm sind reviewgebunden.

## Geänderte Dateien und Tests

Die Implementierung umfasst `ci/lib/common.sh`, `.python-version`,
`requirements-ci.lock`, `ci/pyyaml-build-tools.lock.json`, zentrale Shell-/Python-
Installer, kanonische Python-/Workflow-Synchronisierer, Python-Updater,
Workflow-Tool-Snapshot-Eingaben, CI-Workflows/-Sicherheitsprüfer und Analyse-
Konfiguration. Tests prüfen strikte Versionsgrammatik, Metadaten/Readiness,
Quell-/Hash-/Build-Isolation, zugelassene Ziele, einzeln manipulierte Bootstrap-
Eingaben, historische Pfade, bösartige Workflow-Änderungen und vorgeschlagene
Bäume. Beide gepflegten englisch/deutschen Sicherheitsleitfäden wurden angepasst.

## Befehle und Ergebnisse

`PYTHON314`, `PYTHON315`, `PYTHON315_BIN`, `SYSTEM_PATH`, `RUFF` und `BUILD_EVIDENCE`
bezeichnen die Framework-eigenen Interpreter und externe Evidenzwurzel der
Aufgabe. Hostspezifische Zuordnungen stehen ausschließlich im lokalen
Ausführungsplan. Befehle liefen im Framework-Worktree.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk bypass env TMPDIR=$BUILD_EVIDENCE/contracts/tmp PYTHONPYCACHEPREFIX=$BUILD_EVIDENCE/contracts/pycache $PYTHON314 -m unittest tests.ci_security.test_ci_security_contract tests.ci_security.test_framework_ci_security_contract tests.ci_security.test_python_version_contract -q` | 0 | 60 Tests in der bestehenden 3.14-Umgebung bestanden | `framework-python315-20261102`, begrenzte Contract-Evidenz |
| `rtk bypass env TMPDIR=$BUILD_EVIDENCE/contracts/tmp PYTHONPYCACHEPREFIX=$BUILD_EVIDENCE/contracts/pycache $PYTHON314 -m unittest tests.ci_security.test_update_workflow_tools.WorkflowToolUpdaterTests.test_canonical_validation_snapshot_is_private_and_rejects_redirects tests.ci_security.test_update_workflow_tools.WorkflowToolUpdaterTests.test_proposed_tree_validation_accepts_a_tool_only_candidate tests.ci_security.test_update_workflow_tools.WorkflowToolUpdaterTests.test_proposed_tree_validation_does_not_modify_the_source_checkout -q` | 0 | Drei Snapshot-/Proposed-Tree-Tests bestanden | Dieselbe Aufgabe, begrenzte Contract-Evidenz |
| `rtk bypass $PYTHON314 ci/checks/security/check-ci-security-contract.py` | 0 | CI-Sicherheitsvertrag bestanden | Dieselbe Aufgabe, Tool-Transkript |
| `rtk bypass env TMPDIR=$BUILD_EVIDENCE/updater PYTHONDONTWRITEBYTECODE=1 $PYTHON315 -m unittest tests.ci_security.test_update_python_version tests.ci_security.test_updater_readiness tests.ci_security.test_sync_canonical_python_pins tests.ci_security.test_ci_dependency_source_build` | 0 | Source-Installer-Worker meldete 50 bestandene Tests unter tatsächlichem CPython 3.15.2 | Dieselbe Aufgabe, Source-Installer-Worker-Transkript |
| `rtk bypass env PATH=$PYTHON315_BIN:$SYSTEM_PATH TMPDIR=$BUILD_EVIDENCE/updater PYTHONDONTWRITEBYTECODE=1 bash ci/tools/install-hash-locked-ci-dependencies.sh` | 0 | Source-Installer-Worker beobachtete tatsächlichen Pure-Wheel-Build, Installation und pip-Prüfungen | Dieselbe Aufgabe, Source-Installer-Worker-Transkript |
| Official OSV `POST /v1/querybatch` for PyYAML 6.0.3, setuptools 84.2.1, wheel 0.48.0, Cython 3.3.1, packaging 26.3 | 0 | Koordinator beobachtete keine Schwachstellen-IDs in dieser Advisory-Momentaufnahme exakter Versionen | Dieselbe Aufgabe, Koordinator-Transkript |
| `rtk bypass env TMPDIR=$BUILD_EVIDENCE/contracts/tmp PYTHONPYCACHEPREFIX=$BUILD_EVIDENCE/contracts/pycache PYTHON=$PYTHON314 BUILD_ROOT=$BUILD_EVIDENCE/contracts/build make check-documentation` | 0 | Links, zweisprachige Variablendokumentation, Repository-Pfade und Change-Record-Struktur bestanden | Dieselbe Aufgabe, Dokumentations-Worker-Transkript |
| `rtk bypass $RUFF format ci/checks/security/check-ci-security-contract.py ci/checks/security/check-python-version.py ci/tools/update-workflow-tools.py tests/ci_security/test_python_version_contract.py tests/ci_security/test_ci_security_contract.py tests/ci_security/test_framework_ci_security_contract.py` | 0 | Drei Dateien formatiert, drei unverändert | Dieselbe Aufgabe, Contract-Worker-Transkript |
| `rtk bypass $RUFF check ci/checks/security/check-ci-security-contract.py ci/checks/security/check-python-version.py ci/tools/update-workflow-tools.py tests/ci_security/test_python_version_contract.py tests/ci_security/test_ci_security_contract.py tests/ci_security/test_framework_ci_security_contract.py` | 0 | Alle Prüfungen bestanden; Upstream-Warnung zur 3.15-Unterstützung bleibt | Dieselbe Aufgabe, Contract-Worker-Transkript |
| `rtk bypass git diff --check` | 0 | Whitespace-Prüfung vor Dokumentationsübergabe bestanden | Dieselbe Aufgabe, begrenzte Contract-Evidenz |


Zusätzliche Koordinator-Prüfungen bestanden auf echtem Python 3.15.2: 72 Vertrags-/Generatortests, 16 Canonical-Maintenance-Tests, native Python-/Workflow-Pin-/Berechtigungsprüfungen, Actionlint für fünf geänderte Workflows und Ruff-Lint/-Format über 19 geänderte Python-Dateien. Unabhängiges Source-Build-Review fand keinen Blocker bei Helper-SHA `cf25436ad89407c416b64635924f8eecd1cb9d66d40faa7776ab7a433aa591ea`. Build-Werkzeuglizenzen geprüft: PyYAML/setuptools/wheel MIT, Cython Apache-2.0, packaging Apache-2.0 OR BSD-2-Clause.

Gehostetes CPython-3.15.2-Setup, geprüfter Source-Build, Pure-Wheel-Installation und Pip-Prüfungen bestanden; der gehostete Wheel-SHA entsprach beiden lokalen Builds. Erste CI zeigte alte Inline-Installationsannahmen und fünf Typisierungs-/Importfehler in Tests. Folgekorrekturen prüfen echte argumentlose Delegation und ausführbare Helper-Kontrollen und erhalten Installation-vor-Snapshot/Anwendung/Validierung. Die 27 betroffenen Workflow-/CRS-Tests und 24 typisierten Builder-/Maintenance-Tests bestanden auf 3.15; Runtime-Helper und Security-Gates wurden nicht abgeschwächt.

Sonar-Nachbesserungen erhalten alle Gates und begrenzen temporäre Build-Pfade
durch explizite `RUNNER_TEMP`-Zulassung: physischer externer Pfad, aktuelle UID,
keine gemeinsamen Schreibrechte und vertrauenswürdige Vorfahren. Generische
Public-Temp-Umgebungs-Fallbacks entfallen. ASCII-only-Regex-Semantik bleibt
explizit, während Komplexität, Literale und Test-Assertion-Grenzen vereinfacht
wurden. Source-Build und Pip-Prüfungen bestanden erneut; kein Finding wurde
unterdrückt oder als False Positive markiert. Der gemeinsame Framework-PR
ersetzt den anfänglichen Migrations-PR.

## Sicherheitsauswirkung

Es wird keine Schwachstellenbehebung behauptet. Die Migration erhält
unveränderliche Pins, Prüfsummen, begrenzte Veröffentlichungspfade/-Rechte und
Trusted-Base-Ausführung. Quellbuilds ergänzen Backend-Ausführung; verifizierte
Artefakte, isolierte Build-Tools, bereinigte Umgebung und Offline-Build/-Install
begrenzen diese Oberfläche. Tests weisen manipulierte Hashes, historische
Identitäten, Helper-Befehle und Bootstrap-Reihenfolgen zurück.

## Dokumentation und Runtime-Evidenz

Beide Sprachpaare von `docs/security/ci-security-tooling` und
`docs/github-actions-workflow-security` dokumentieren 3.15, Build-Grenzen,
historische Ausnahmen und Scanabdeckung. Tatsächliche Quellbuild-Evidenz unter
3.15.2 bleibt von Contract-Test-Evidenz unter 3.14 getrennt. Connector-Host-
Runtime- oder Produktionsreife-Evidenz wurde nicht erhoben.

## Nicht ausgeführte Prüfungen

Gehostete CI, veröffentlichte Migrations-PR-Prüfungen und Quality Gates waren
bei dieser lokalen Übergabe nicht ausgeführt. Vollständige Repository-Integration bleibt bis zu frischer Evidenz Sache
des Koordinators; die vier lokalen Dokumentationsprüfungen bestanden. Connector-Runtime-Suiten und MRTS-Ausführung waren für diese
Framework-Änderung nicht erforderlich.

Lokales Pyright war mangels installiertem Node-Executable nicht ausführbar; der unverändert gepinnte gehostete Node-/Pyright-Pfad bleibt erforderlich. Ein optionales vollständiges Provenienz-Regressionsmodul zeigte einen bestehenden ModSecurity-Release-Listen-Fixture-Widerspruch außerhalb dieser Python-Migration; seine neuen Source-/OSV-Grenzfälle bestanden separat.

Lokale vollständige CI-Security-Discovery führte 348 Tests aus: Zwei Fehler entstanden am unveränderten FIFO-Child-Startup-Readiness-Limit, direkt und über die verschachtelte CRS-Suite; der Child wies die FIFO trotzdem ab. Ein gezielter Wiederholungslauf dieses unveränderten FIFO-Falls bestand. Die 27 betroffenen Workflow-/CRS-Tests hatten bereits separat bestanden. Diese Timing-Grenze bleibt ausdrücklich dokumentiert; Timeout- und Ablehnungsanforderungen wurden nicht gelockert. Frische gehostete Prüfungen bleiben erforderlich.

## Einschränkungen und Restrisiko

Der OSV-Workflow scannt derzeit zwei benannte Manifeste und erkennt den
benutzerdefinierten JSON-Build-Tool-Lock nicht automatisch. Die manuelle Abfrage
exakter Versionen ist eine Advisory-Momentaufnahme und keine laufende Workflow-
Scanabdeckung. Ein Build geprüfter Quellen führt zusätzlichen Code aus und
belegt weder zukünftige Artefaktverfügbarkeit noch Schwachstellenfreiheit.
Tatsächliche gehostete Actions-setup-python-Ausführung und Publisher-Verhalten
benötigen nachfolgende CI-Evidenz.

## Finaler Diff- und Review-Status

Der unstaged Implementierungsdiff und Whitespace wurden lokal geprüft. Der
Dokumentations-/Contract-Worker führte weder breites Staging noch Git-Delivery
aus. Credentials oder sensible Rohlogs sind nicht enthalten. Dieser Record ist
eine lokale Übergabe und keine Behauptung abgeschlossener PR-/CI-/Merge-Arbeit.
Der Koordinator verantwortet integriertes Review, Dokumentationsprüfungen und
Delivery-Status.
