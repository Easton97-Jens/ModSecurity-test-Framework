# Change Record — 20260722-02-migrate-framework-python-314-ci

**Sprache:** [English](20260722-02-migrate-framework-python-314-ci.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260722-02-migrate-framework-python-314-ci` |
| UTC-Datum | `2026-07-22` |
| Framework-Basisrevision | `1fd3b362e0fed9766c6920e3c7bd1939535850f2` |
| Issue oder Pull Request | Framework-PR #42; dieses CPython-3.14.6-Follow-up ist lokal validiert, während Commit, übermittelter Exact Head, gehostete Checks und resultierende-Master-Evidenz noch ausstehen. |

## Motivation und Problemstellung

Die CI-Python-Baseline des Frameworks muss vom bisherigen CPython-3.13-Vertrag zu überprüftem CPython `3.14.6` wechseln, ohne seine Provenance-, Versionsauswahl- oder untrusted-Pull-Request-Controls zu schwächen. Kanonischer Selektor, Kandidat-Maintainer, CI-Workflow, strikt hash-gesperrtes Dependency-Artifact und Static-Tool-Baselines müssen gemeinsam geändert werden, damit kein widersprüchlicher CI-Vertrag entsteht.

Das OSV-Pull-Request-Design führt die vertrauenswürdige Basisrevision aus und liest die PR-Head-`.python-version` nur als begrenzte Daten. Diese Migration aktualisiert seine Major-spezifische Grammatik auf stabiles CPython 3.14 und bewahrt zugleich die Grenze ohne PR-Head-Checkout und ohne PR-Head-Ausführung.

## Betroffene Komponenten und Sicherheitsgrenzen

Die Framework-eigene Grenze ist CI-Interpreter-/Dependency-Provenance und Workflow-Trust. Der beabsichtigte Migrationsvertrag umfasst:

- `.python-version` als regulären, nicht symlinkten kanonischen Selektor mit strikter, mit Zeilenumbruch abgeschlossener stabiler `3.14.<numeric patch>`-Grammatik;
- `.github/workflows/check-python-version.yml`, seinen festen Pfad `${{ runner.temp }}/framework-python-3.14-candidate` und den Review-Branch `automation/update-framework-python-314`;
- `ci/checks/security/check-python-version.py`, `ci/checks/security/check-ci-security-contract.py` und `ci/tools/update-python-version.py` als erzwingende/prüfende/aktualisierende Grenze;
- `requirements-ci.lock` mit überprüftem CP314-PyYAML-Artifact und Hash;
- Ruff `py314` in `pyproject.toml`, Python `3.14` in `pyrightconfig.json` sowie die gepaarte CI-Security-Dokumentation und diesen gepaarten Change Record.

Der Updater vertraut nur seiner dokumentierten öffentlichen Python.org-JSON-Autorität und verwendet keinen GitHub-Token, folgt keinen Redirects, scrapt kein HTML und schreibt keinen Repository-Pfad außer `.python-version`. Der OSV-PR-Job behält seinen vertrauenswürdigen Basis-Checkout, den begrenzten Head-Blob-Read und die Invariante ohne PR-Head-Ausführung. Parent-Source, Parent-Gitlink, Connector-Runtime und Inhalt von `tools/MRTS` sind nicht im Scope.

## Akzeptanzkriterien

1. `.python-version` ist eine reguläre nicht symlinkte UTF-8-Datei, die exakt den mit Zeilenumbruch abgeschlossenen stabilen Wert `3.14.6` enthält; der Vertrag weist floating selectors, wildcards, prereleases und fehlerhafte Varianten zurück.
2. Aktive `actions/setup-python`-Uses wählen die kanonische Datei mit `python-version-file: .python-version` und `check-latest: false`, ausgenommen nur die unabhängig verifizierten Kandidat- und OSV-PR-Head-Datendateien.
3. `check-python-version.yml` ist nur geplant/manuell, trennt read-only Auflösung von Kandidatvalidierung, materialisiert nur `${{ runner.temp }}/framework-python-3.14-candidate` und erlaubt seinen Publisher nur für einen erneut validierten Kandidaten mit Gate `github.ref == 'refs/heads/master'`.
4. Der Publisher kann nur einen Draft-PR auf `automation/update-framework-python-314` erstellen oder aktualisieren, dessen erlaubter Änderungspfad `.python-version` ist; er merged weder automatisch noch akzeptiert er eine floating version.
5. Der native Updater akzeptiert nur veröffentlichte stabile CPython-3.14-Patch-Metadaten von Python.org und bewahrt sein fail-closed-, no-redirect- und single-file-write-Verhalten.
6. `requirements-ci.lock` benennt `PyYAML-6.0.3-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl` und den offiziellen SHA-256 `c458b6d084f9b935061bc36216e8a69a7e293a2f1e68bf956dcd9e6cbcd143f5` bei Beibehaltung von `--require-hashes` und `--only-binary=:all:`.
7. Ruff und Pyright verwenden die expliziten Baselines `py314` und `3.14`.
8. Der OSV-PR-Pfad validiert strikte stabile CPython-3.14-Daten, führt aber nur die vertrauenswürdige Basisrevision aus; er darf PR-Head-Source oder Workflow-Content weder auschecken noch ausführen.
9. Englischer/deutscher Leitfaden, README-Index und Change-Record-Paar bleiben äquivalent und enthalten keine erfundenen lokalen, gehosteten, Runtime-, Delivery- oder Security-Finding-Ergebnisse.

## Untersuchte Alternativen

- CPython 3.13 beizubehalten würde die verlangte 3.14.6-Migration unvollständig lassen.
- Ein mutabler, wildcard- oder `check-latest`-Selektor würde den reproduzierbaren überprüften Versionsvertrag schwächen.
- `--require-hashes` zu entfernen, einen Source-Build zu erlauben oder ein CP313-Wheel beizubehalten würde die CP314-Dependency-Grenze schwächen oder brechen.
- PR-Head-Content im OSV-Job auszuchecken oder auszuführen würde die untrusted Workflow-/Source-Ausführungsgrenze ausweiten und wird verworfen.
- Ein generischer Publisher-Branch oder eine breitere File-Allowlist würde Wartung weniger reviewbar machen; der feste Branch und die `.python-version`-Allowlist bleiben erhalten.

## Implementierungsentscheidung

Die gewählte Baseline ist exaktes CPython `3.14.6`. `.python-version` bleibt die einzige Quelle der Interpreterauswahl mit strikter stabiler `3.14.<numeric patch>`-Grammatik und einem abschließenden Zeilenumbruch. Der Kandidatjob ist die einzige Wartungsausnahme und darf einen unabhängig validierten Kandidaten über `${{ runner.temp }}/framework-python-3.14-candidate` weitergeben; OSV `pull-request-head` bleibt die einzige Head-Daten-Ausnahme. Keine Ausnahme autorisiert einen breiten Dateipfad, eine floating version oder PR-Head-Source-Ausführung.

`ci/tools/update-python-version.py` bleibt der native Python.org-JSON-Updater. `check-python-version.yml` löst auf, validiert und veröffentlicht anschließend bedingt einen Draft-Wartungs-PR. Sein Publisher löst den Kandidaten unabhängig erneut auf und validiert ihn, ist durch `github.ref == 'refs/heads/master'` gegatet, verwendet `automation/update-framework-python-314` und erlaubt `.python-version` als einzigen Änderungspfad. `pyproject.toml` und `pyrightconfig.json` wechseln gemeinsam zu `py314` und `3.14`, damit die statische Analyse die überprüfte Baseline nutzt.

Das CP314-Dependency-Tupel ist `PyYAML-6.0.3-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl` mit offiziellem SHA-256 `c458b6d084f9b935061bc36216e8a69a7e293a2f1e68bf956dcd9e6cbcd143f5`. Der Lock verlangt weiter ein Binary-Artifact, exakten Hash und `pip check`; er fügt keine automatische Dependency-Remediation hinzu.

## Geänderte Dateien und Tests

Die CPython-3.14.6-Migration ändert den kanonischen Selektor, die
Static-Analysis-Baseline, das CP314-Lock-Tupel, die Python-Maintenance- und
OSV-Workflows, ihre drei erzwingenden/prüfenden/aktualisierenden Python-Pfade
und ihre fokussierte Regression-Coverage:

- `.python-version`, `pyproject.toml`, `pyrightconfig.json` und `requirements-ci.lock`;
- `.github/workflows/check-python-version.yml` und `.github/workflows/ci-security-osv.yml`;
- `ci/tools/update-python-version.py`,
  `ci/checks/security/check-python-version.py` und
  `ci/checks/security/check-ci-security-contract.py`;
- `tests/ci_security/test_update_python_version.py`,
  `tests/ci_security/test_python_version_contract.py`,
  `tests/ci_security/test_ci_security_contract.py` und
  `tests/ci_security/test_framework_ci_security_contract.py`; sowie
- den gepaarten CI-Security-Leitfaden, den gepaarten README-Index und dieses
  englisch/deutsche Change-Record-Paar.

Der gleiche PR-Branch enthält außerdem separat getrackte Sonar-Remediation-
Änderungen an CI-Security- und Parser-Hardening-Regressionstests. Dieser
Python-Change-Record benennt diese eigenständigen Findings weder um noch schließt er sie.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Fokussierte Python-Migrations-Contracts | `0` | 61 Updater-, Versionscontract-, CI-Contract- und Framework-CI-Contract-Tests liefen im ausgewählten lokalen CPython-3.14.4-Virtual-Environment erfolgreich. | Task-eigene externe Validierungsroots |
| Separat geänderte CI-Security-/Parser-Regressionen | `0` | 49 Downloader-, Workflow-Tool-Updater- und Parser-Hardening-Tests liefen erfolgreich. | Task-eigene externe Validierungsroots |
| Native-Framework-Lint-Vertrag | `0` | `make lint` lief im ausgewählten lokalen CPython-3.14.4-Virtual-Environment erfolgreich, einschließlich Syntax-, CI-Security-, Workflow-, Provenance-, Dokumentations-, Katalog- und Diff-Hygiene-Checks. | Task-eigene externe Validierungsroots |
| Hash-gesperrter CP314-Dependency-Dry-Run | `0` | `pip install --dry-run --ignore-installed --no-index --only-binary=:all: --require-hashes` wählte das zurückgehaltene überprüfte CP314-PyYAML-Wheel und würde `PyYAML-6.0.3` installieren. | Task-eigene CP314-Artifact-Evidenz |
| Negativkontrolle des Vor-Migrations-CP313-Hashes | `1` (erwartet) | Der absichtlich bewahrte CP313-Digest lehnte das CP314-Artifact mit Hash-Mismatch ab und beweist, dass der alte Lock nicht unbemerkt wiederverwendet werden kann. | Task-eigenes Negativ-Fixture |
| Dependency-Konsistenz | `0` | `python -m pip check` meldete keine defekten Requirements. | Ausgewähltes lokales Virtual Environment |
| Python.org-Updater-/Netzwerkvalidierung sowie gehostete GitHub-Actions-, SonarQube-Cloud-, PR- und resultierende-Master-Checks | `not_run` | Gehostete Exact-Head-Evidenz bleibt nach dem normalen PR-Update erforderlich. | Keine |

## Sicherheitsauswirkung

Dieser Record beschreibt eine CI-Sicherheitsgrenzen-Migration; er beansprucht keine Security-Remediation und schließt kein Finding. Die erforderlichen Controls bleiben erhalten: exakte `.python-version`-Auswahl, `check-latest: false`, immutable Action-Pins, hash-gesperrte Binary-Installation, Python.org-only/no-redirect-Metadatenbehandlung, feste Kandidat-/Publisher-Pfade und das OSV-PR-Ausführungsmodell auf vertrauenswürdiger Basis. Keine Permission-Erweiterung, kein mutabler Tag, kein Source-Build-Fallback, kein automatischer Merge, kein Scanner-Waiver, keine Quality-Gate-Änderung, keine Parent-Änderung und keine MRTS-Änderung werden dokumentiert.

## Dokumentation und Runtime-Evidenz

Der gepaarte CI-Security-Leitfaden dokumentiert die 3.14.6-Baseline, strikte stabile CPython-3.14-Grammatik, kontrollierten Kandidatpfad, Python.org-Updater, Publisher-Branch, Static-Tool-Baselines, exaktes CP314-PyYAML-Tupel und die erhaltene OSV-Trust-Grenze. Das README indexiert dieses Paar. Lokale Contract- und Lock-Dry-Run-Evidenz wurde mit CPython 3.14.4 erfasst; sie validiert den CP314-ABI-Vertrag, ersetzt aber keinen gehosteten exakten-3.14.6-Runner. Keine Connector-Runtime, kein GitHub-gehosteter Lifecycle, keine Python.org-Live-Updater-Anfrage und keine echte Package-Installation wurden beansprucht.

## Nicht ausgeführte Prüfungen

- Keine Python.org-Live-Anfrage oder Updater-Netzwerkprüfung lief.
- Keine echte Package-Installation lief; die CP314-Evidenz verwendet nur ein zurückgehaltenes Artifact und einen Pip-Dry-Run.
- Kein lokales Ruff- oder Pyright-Executable wurde installiert oder ersetzt. Ihre checksum-verifizierten gehosteten CI-Checks bleiben erforderlich, weil das ausgewählte Virtual Environment diese Tools nicht enthält.
- Kein Migrations-Commit, Push, übermittelter Exact-Head-PR, GitHub Actions, SonarQube Cloud, Merge oder resultierender-Master-Check wurde für dieses Follow-up ausgeführt oder beobachtet.

## Einschränkungen und Restrisiko

Inhalt und lokale Checks können CPython-3.14.6-Runner-Verfügbarkeit, einen Live-PyPI-Installationspfad, Python.org-Metadatenverhalten, GitHub-Event-Kontext, `runner.temp`-Semantik, Branch Protection oder das SonarQube-Cloud-Exact-Head-Ergebnis nicht beweisen. Der ausgewählte lokale Runner ist CPython 3.14.4, nicht das konfigurierte 3.14.6. Die Migration ist daher lokal validiert, aber nicht gehostet verifiziert. Dieser Record trifft keine Connector-Runtime-Behauptung und ändert die schreibgeschützte Grenze `tools/MRTS` nicht.

## Finaler Diff- und Review-Status

Die gepaarte Dokumentation bestand lokale Link-, Variable-, Path-Reference-, Change-Record-, Whitespace- und Scoped-Diff-Checks als Teil des nativen Lint-Vertrags. Ein vollständiger Final-Diff-Security-Review, normaler Task-Branch-Commit/Push, gehostete Exact-Head-Checks und der separate resultierende-Master-Gate-Review bleiben Delivery-Voraussetzungen. Historische Change Records bleiben unverändert; Credentials, Tokens, Raw-Logs und sensitive Payloads werden hier nicht dokumentiert.
