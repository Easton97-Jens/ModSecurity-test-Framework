# Change Record — 20260722-02-migrate-framework-python-314-ci

**Sprache:** [English](20260722-02-migrate-framework-python-314-ci.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260722-02-migrate-framework-python-314-ci` |
| UTC-Datum | `2026-07-22` |
| Framework-Branch-Vorgängerrevision | `1fd3b362e0fed9766c6920e3c7bd1939535850f2` |
| Gehostete PR-Basisrevision | `f73f8842f45318e2df8aff1d31855eeb7c20a22f` |
| Issue oder Pull Request | Framework-PR #42; die initiale CPython-3.14.6-Migration wurde als `e0564d219980d62bc37162ac6c11641f289f1b71` übermittelt. Gehostete CPython-3.14.6-Verfügbarkeit und Sonar bestanden dort, während OSV einen Trusted-Base-CP313/PR-Head-CP314-Lock-Mismatch und Ruff Formatierungsdrift meldeten. Das sicherheitserhaltende Source-Follow-up bei `2930e04e1558b5b10bdeb87a76abb077a2085566` korrigierte diese Controls und das fokussierte Pyright-Test-Fixture-Typing-Problem. Sein gehosteter `python-ci-security-quality`-Run `29962792445` / Job `89067507532`, der reparierte OSV-Control, alle nicht übersprungenen PR-Checks und das PR-SonarQube-Cloud-Quality-Gate bestanden. Resultierende-Master-Evidenz ist unbeobachtet; jeder spätere PR-Head braucht frische Exact-Head-Evidenz. |

## Motivation und Problemstellung

Die CI-Python-Baseline des Frameworks muss vom bisherigen CPython-3.13-Vertrag zu überprüftem CPython `3.14.6` wechseln, ohne seine Provenance-, Versionsauswahl- oder untrusted-Pull-Request-Controls zu schwächen. Kanonischer Selektor, Kandidat-Maintainer, CI-Workflow, strikt hash-gesperrtes Dependency-Artifact und Static-Tool-Baselines müssen gemeinsam geändert werden, damit kein widersprüchlicher CI-Vertrag entsteht.

Das OSV-Pull-Request-Design führt die vertrauenswürdige Basisrevision aus. Es
wählt seinen Interpreter nur aus deren begrenztem Blob-Selektor. Die exakte
historische Basis `f73f8842f45318e2df8aff1d31855eeb7c20a22f` liegt vor
diesem Selektor und erhält allein festen Wert `3.13.14`, passend zu ihrem
CP313-only-Trusted-Lock. Diese Migration aktualisiert jeden anderen normalen
Pfad auf stabiles CPython 3.14 und bewahrt die Grenze ohne PR-Head-Selektor,
PR-Head-Checkout und PR-Head-Ausführung.

## Betroffene Komponenten und Sicherheitsgrenzen

Die Framework-eigene Grenze ist CI-Interpreter-/Dependency-Provenance und Workflow-Trust. Der beabsichtigte Migrationsvertrag umfasst:

- `.python-version` als regulären, nicht symlinkten kanonischen Selektor mit strikter, mit Zeilenumbruch abgeschlossener stabiler `3.14.<numeric patch>`-Grammatik;
- `.github/workflows/check-python-version.yml`, seinen festen Pfad `${{ runner.temp }}/framework-python-3.14-candidate` und den Review-Branch `automation/update-framework-python-314`;
- `ci/checks/security/check-python-version.py`, `ci/checks/security/check-ci-security-contract.py` und `ci/tools/update-python-version.py` als erzwingende/prüfende/aktualisierende Grenze;
- `requirements-ci.lock` mit überprüftem CP314-PyYAML-Artifact und Hash;
- Ruff `py314` in `pyproject.toml`, Python `3.14` in `pyrightconfig.json` sowie die gepaarte CI-Security-Dokumentation und diesen gepaarten Change Record.

Der Updater vertraut nur seiner dokumentierten öffentlichen Python.org-JSON-Autorität und verwendet keinen GitHub-Token, folgt keinen Redirects, scrapt kein HTML und schreibt keinen Repository-Pfad außer `.python-version`. Der OSV-PR-Job behält seinen vertrauenswürdigen Basis-Checkout, begrenzte Head-Manifest-Reads, die Basis-Interpreter-/Basis-Lock-ABI-Paarung und die Invariante ohne PR-Head-Ausführung. Parent-Source, Parent-Gitlink, Connector-Runtime und Inhalt von `tools/MRTS` sind nicht im Scope.

## Akzeptanzkriterien

1. `.python-version` ist eine reguläre nicht symlinkte UTF-8-Datei, die exakt den mit Zeilenumbruch abgeschlossenen stabilen Wert `3.14.6` enthält; der Vertrag weist floating selectors, wildcards, prereleases und fehlerhafte Varianten zurück.
2. Aktive `actions/setup-python`-Uses wählen die kanonische Datei mit `python-version-file: .python-version` und `check-latest: false`, ausgenommen nur die unabhängig verifizierte Kandidatdatei und die private OSV-Trusted-Base-Bootstrap-Datei.
3. `check-python-version.yml` ist nur geplant/manuell, trennt read-only Auflösung von Kandidatvalidierung, materialisiert nur `${{ runner.temp }}/framework-python-3.14-candidate` und erlaubt seinen Publisher nur für einen erneut validierten Kandidaten mit Gate `github.ref == 'refs/heads/master'`.
4. Der Publisher kann nur einen Draft-PR auf `automation/update-framework-python-314` erstellen oder aktualisieren, dessen erlaubter Änderungspfad `.python-version` ist; er merged weder automatisch noch akzeptiert er eine floating version.
5. Der native Updater akzeptiert nur veröffentlichte stabile CPython-3.14-Patch-Metadaten von Python.org und bewahrt sein fail-closed-, no-redirect- und single-file-write-Verhalten.
6. `requirements-ci.lock` benennt `PyYAML-6.0.3-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl` und den offiziellen SHA-256 `c458b6d084f9b935061bc36216e8a69a7e293a2f1e68bf956dcd9e6cbcd143f5` bei Beibehaltung von `--require-hashes` und `--only-binary=:all:`.
7. Ruff und Pyright verwenden die expliziten Baselines `py314` und `3.14`.
8. Der OSV-PR-Pfad führt nur die vertrauenswürdige Basisrevision aus und wählt einen strikten stabilen CPython-3.14-Wert aus deren begrenztem Basis-Blob. Nur die exakte Basis vor dem Selektor `f73f8842f45318e2df8aff1d31855eeb7c20a22f` darf `3.13.14` verwenden; jeder andere CP313-Selektor oder jede andere fehlende Basisdatei scheitert geschlossen. Er darf keinen PR-Head-Python-Selektor lesen sowie PR-Head-Source oder Workflow-Content weder auschecken noch ausführen.
9. Englischer/deutscher Leitfaden, README-Index und Change-Record-Paar bleiben äquivalent und enthalten keine erfundenen lokalen, gehosteten, Runtime-, Delivery- oder Security-Finding-Ergebnisse.

## Untersuchte Alternativen

- CPython 3.13 beizubehalten würde die verlangte 3.14.6-Migration unvollständig lassen.
- Ein mutabler, wildcard- oder `check-latest`-Selektor würde den reproduzierbaren überprüften Versionsvertrag schwächen.
- `--require-hashes` zu entfernen, einen Source-Build zu erlauben oder ein CP313-Wheel beizubehalten würde die CP314-Dependency-Grenze schwächen oder brechen.
- PR-Head-Content im OSV-Job auszuchecken oder auszuführen würde die untrusted Workflow-/Source-Ausführungsgrenze ausweiten und wird verworfen.
- Ein generischer Publisher-Branch oder eine breitere File-Allowlist würde Wartung weniger reviewbar machen; der feste Branch und die `.python-version`-Allowlist bleiben erhalten.

## Implementierungsentscheidung

Die gewählte Baseline ist exaktes CPython `3.14.6`. `.python-version` bleibt die einzige Quelle der Interpreterauswahl mit strikter stabiler `3.14.<numeric patch>`-Grammatik und einem abschließenden Zeilenumbruch. Der Kandidatjob ist die einzige Wartungsausnahme und darf einen unabhängig validierten Kandidaten über `${{ runner.temp }}/framework-python-3.14-candidate` weitergeben. OSV `pull-request-head` darf nur seine feste private Trusted-Base-Bootstrap-Datei verwenden: Es kopiert einen begrenzten Basis-Blob und akzeptiert striktes 3.14, ausgenommen allein die exakte Basis vor dem Selektor `f73f8842f45318e2df8aff1d31855eeb7c20a22f`; diese wählt `3.13.14`, damit es zu ihrem CP313-Hash-Lock passt. Die Ausnahme autorisiert weder einen breiten Dateipfad noch eine floating version, einen PR-Head-Python-Selektor oder PR-Head-Source-Ausführung.

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
| Gehosteter initial übermittelter Head | `1` | Run `29956021487` lehnte CP314-PyYAML korrekt gegen den CP313-only-Hash-Lock der vertrauenswürdigen Basis ab; Run `29956021568` bestand Lint und meldete vier deterministische Ruff-Formatänderungen. Derselbe Head bestätigte eine gehostete CPython-3.14.6-Runtime und bestand Sonar. | GitHub-Actions-Runs `29956021487` / `29956021568`, Framework-PR-#42-Head `e0564d219980d62bc37162ac6c11641f289f1b71` |
| Trusted-Base-OSV-Follow-up-Contracts | `0` | Vollständiges `make test-ci-security-contract` bestand 133 Tests einschließlich fehlender-Selektor-f73-CP313-, nicht-allowlisted-CP313-Zurückweisungs-, Base-3.14- und obsolete-PR-Head-Selektor-Regressionen. | Task-eigener Follow-up-Validation-Root |
| Deterministisches Ruff-Follow-up | `0` | Das überprüfte checksum-verifizierte Ruff-0.15.22-Binary bestand den exakten gehosteten Lint- und Format-Scope nach Formatierung der vier gemeldeten Dateien. | Task-eigene überprüfte CI-Tool-Extraktion |
| Gehostete Exact-Source-Follow-up-PR-Checks | `0` | Exact-Source-Head `2930e04e1558b5b10bdeb87a76abb077a2085566` bestand den gehosteten `python-ci-security-quality`-Run `29962792445` / Job `89067507532`; auch der reparierte OSV-Control, alle anderen nicht übersprungenen PR-Checks und das PR-SonarQube-Cloud-Quality-Gate bestanden. | GitHub Actions, GitHub-PR-#42-Checks und SonarQube-Cloud-PR-#42-Analyse |
| Python.org-Updater-/Netzwerkvalidierung und resultierende-Master-Checks | `not_run` | Keine Python.org-Live-Updater-Netzwerkprüfung lief. PR #42 ist nicht gemergt, daher existieren weder resultierende-Master-SHA noch resultierende-Master-Check. Jeder spätere PR-Head braucht frische Exact-Head-Evidenz. | Keine |

## Sicherheitsauswirkung

Dieser Record beschreibt eine CI-Sicherheitsgrenzen-Migration; er beansprucht keine Security-Remediation und schließt kein Finding. Die erforderlichen Controls bleiben erhalten: exakte `.python-version`-Auswahl, `check-latest: false`, immutable Action-Pins, hash-gesperrte Binary-Installation, Python.org-only/no-redirect-Metadatenbehandlung, feste Kandidat-/Publisher-Pfade und das OSV-PR-Ausführungsmodell auf vertrauenswürdiger Basis. Sein einziger SHA-gebundener CP313-Kompatibilitätsfall deckt nur die exakte Basis vor dem Selektor ab; er verhindert einen CP313/CP314-ABI-Mismatch ohne einen PR-Head-Python-Selektor zu lesen. Keine Permission-Erweiterung, kein mutabler Tag, kein Source-Build-Fallback, kein automatischer Merge, kein Scanner-Waiver, keine Quality-Gate-Änderung, keine Parent-Änderung und keine MRTS-Änderung werden dokumentiert.

## Dokumentation und Runtime-Evidenz

Der gepaarte CI-Security-Leitfaden dokumentiert die 3.14.6-Baseline, strikte stabile CPython-3.14-Grammatik, kontrollierten Kandidatpfad, Python.org-Updater, Publisher-Branch, Static-Tool-Baselines, exaktes CP314-PyYAML-Tupel und die erhaltene OSV-Trust-Grenze einschließlich ihres einen SHA-gebundenen CP313-Kompatibilitätsfalls. Das README indexiert dieses Paar. Lokale Contract- und Lock-Dry-Run-Evidenz wurde mit CPython 3.14.4 erfasst; das Exact-Source-Follow-up `2930e04e1558b5b10bdeb87a76abb077a2085566` bestand zusätzlich gehostete Python-Quality, repariertes OSV, andere nicht übersprungene PR-Checks und das PR-SonarQube-Cloud-Quality-Gate. Dieses Source-Head-Ergebnis ersetzt keine frische Evidenz für einen späteren PR-Head oder resultierenden Master. Keine Connector-Runtime, keine Python.org-Live-Updater-Anfrage und keine echte Package-Installation wurden beansprucht.

## Nicht ausgeführte Prüfungen

- Keine Python.org-Live-Anfrage oder Updater-Netzwerkprüfung lief.
- Keine echte Package-Installation lief; die CP314-Evidenz verwendet nur ein zurückgehaltenes Artifact und einen Pip-Dry-Run.
- Kein lokales Pyright-Executable wurde installiert oder ersetzt. Ein zurückgehaltenes checksum-verifiziertes Ruff-Binary wurde nur für den exakten CI-Lint-/Format-Scope verwendet; das gehostete Ruff- und Pyright-Ergebnis des Source-Follow-ups bestand, während jeder spätere PR-Head frische gehostete Evidenz braucht.
- Kein resultierender-Master-Check wurde beobachtet, weil PR #42 nicht gemergt ist. Dieser Record beansprucht kein Ergebnis für einen späteren Dokumentations-Evidenz-Abgleich-Commit.

## Einschränkungen und Restrisiko

Das Exact-Source-Follow-up `2930e04e1558b5b10bdeb87a76abb077a2085566` beweist seine gehosteten PR-Event-Ergebnisse einschließlich Python-Quality, repariertem OSV, anderer nicht übersprungener PR-Checks und des PR-SonarQube-Cloud-Quality-Gates, kann aber weder GitHub-Event-Kontext eines späteren PR-Heads, `runner.temp`-Semantik, Branch Protection noch ein resultierendes-Master-Ergebnis beweisen. Der ausgewählte lokale Runner ist CPython 3.14.4, nicht das konfigurierte 3.14.6. Keine resultierende-Master-Evidenz ist verfügbar. Dieser Record trifft keine Connector-Runtime-Behauptung und ändert die schreibgeschützte Grenze `tools/MRTS` nicht.

## Finaler Diff- und Review-Status

Die gepaarte Dokumentation bestand lokale Link-, Variable-, Path-Reference-, Change-Record-, Whitespace- und Scoped-Diff-Checks als Teil des nativen Lint-Vertrags. Das Exact-Source-Follow-up erhielt einen Final-Diff-Security-Review ohne reportierbares High/Critical-Issue, wurde normal committed und gepusht und bestand seine gehosteten Exact-Head-Checks bei `2930e04e1558b5b10bdeb87a76abb077a2085566`. Der separate resultierende-Master-Gate-Review bleibt Delivery-Voraussetzung, und jeder spätere PR-Head braucht neue Exact-Head-Verifikation. Historische Change Records bleiben unverändert; Credentials, Tokens, Raw-Logs und sensitive Payloads werden hier nicht dokumentiert.
