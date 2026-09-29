# AWS-LC release maintenance

**Sprache:** [English](20260929-02-enable-aws-lc-maintenance.md) | Deutsch

## Identität

| Field | Value |
| --- | --- |
| Change-ID | 20260929-02-enable-aws-lc-maintenance |
| UTC | 2026-09-29 |
| Base | e18f112f0089098cb9d8cb48ab9b8f93cd6d381a |
| PR | [PR #122](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/122) |

## Motivation und Problemstellung

Neue AWS-LC-Releases erforderten bislang manuelle Änderungen. Das neueste stabile Release wird künftig über den bestehenden kanonischen Draft-PR-Workflow gepflegt.

## Betroffene Komponenten und Sicherheitsgrenzen

Nur AWS-LC-Pins, Deskriptor-Policy, Tests und gepaarte Dokumentation ändern sich. Feste Repository-Identität, begrenzte Tag-Auflösung, Prüfung des aktuellen Pins, atomare Updates, Kandidaten-Revalidierung und Publisher-Berechtigungen bleiben erhalten.

## Akzeptanzkriterien

Stabile numerische Releases werden über Major-Grenzen hinweg gewählt; Drafts, Vorabversionen, unvollständige Release-Flags und FIPS-spezifische Tags bleiben ausgeschlossen. Fremde Repositorys, ungültige oder umgebogene aktuelle Pins, Downgrades, fehlende Kandidaten-Commits und unvollständige atomare Updates werden abgelehnt. Der gerenderte Kandidat muss unverändert bleiben und ohne manuellen Review im gemeinsamen Planer ankommen.

## Untersuchte Alternativen

Ein einmaliges Update pflegt zukünftige Releases nicht. Ein weiterer Updater dupliziert bestehende Mechanismen. Ungepinnte Branches und abgeschwächte Provenance-Prüfungen kommen nicht infrage.

## Implementierungsentscheidung

Der vorhandene Deskriptor verwendet automatische Latest-stable-Wartung; sein überholter Eintrag für manuelle Variablen entfällt. Der automatische Git-Provenance-Resolver und gemeinsame Planer werden wiederverwendet. v5.10.0 wird zusammen mit dem aufgelösten Commit 3fe7e081e62131b6776f0d923312b5e6756907ce gesetzt. Die Git-Referenz wird unabhängig von Release-Metadaten geprüft. Der wöchentliche Zeitplan und die Draft-PR-Review-Grenze bleiben erhalten.

## Geänderte Dateien und Tests

`ci/lib/common.sh`, `ci/tools/check-common-versions.py`, `tests/security_regression/test_common_version_atomic_provenance.py`, `tests/ci_security/test_aws_lc_maintenance.py`, beide Variablenreferenzen und dieses Record-Paar. Vierzehn gezielte Tests umfassen leichte/annotierte Tags, unveränderte Commit-Identitäten und den echten Planerpfad. Der vorherige CodeQL-Fix bleibt unverändert.

## Befehle und Ergebnisse

[Verifizierter Vorbereitungslauf](https://github.com/Easton97-Jens/ModSecurity-test-Framework/actions/runs/36554336208). Python 3.14.7.

Baseline-Regression: erwarteter Assertion-Fehler (Exit 1) gegen die ursprüngliche manuelle Policy. Danach 14 AWS-LC-Tests erfolgreich.

| Command | Exit |
| --- | --- |
| `python3 -m unittest tests.ci_security.test_aws_lc_maintenance -v` | 0 |
| `python3 -m unittest tests.security_regression.test_common_version_atomic_provenance -v` | 0 |
| `./ci/tools/safe-make.sh test-ci-security-contract` | 0 |
| `./ci/tools/safe-make.sh lint` | 0 |
| `./ci/tools/safe-make.sh check-documentation` | 0 |
| `ruff check tests/ci_security/test_aws_lc_maintenance.py` | 0 |
| `ruff format --check tests/ci_security/test_aws_lc_maintenance.py` | 0 |
| `pyright --project pyrightconfig.json` | 0 |
| `python3 ci/tools/check-common-versions.py --check --component AWS-LC --json` | 0 |
| `git diff --check` | 0 |


## Sicherheitsauswirkung

Es wird keine Security-Remediation oder TLS-Provider-Umstellung behauptet. Bestehende Fail-closed-Prüfungen bleiben erhalten. Neue Major-Releases sind prüfbare Pin-Kandidaten, kein Nachweis nachgelagerter Runtime-Kompatibilität.

## Dokumentation und Runtime-Evidenz

Englische und deutsche Variablenreferenzen beschreiben dieselbe Policy. Es wurden keine AWS-LC-Builds, TLS-Handshakes, Connector-Smokes oder Runtime-Nachweise erfasst. Kein generierter Runtime-Report wurde manuell geändert.

## Nicht ausgeführte Prüfungen

Das lokale Python 3.13.5 kann die vorhandene Python-3.14-Syntax nicht parsen. Akzeptanztests verwenden deshalb den repository-gepinnten CI-Interpreter. Live-AWS-LC-Connector-Builds und End-to-End-Runtime-Prüfungen liegen außerhalb dieser Provenance-Wartungsänderung.

## Einschränkungen und Restrisiko

Die geplante Automatik wird nach dem PR-Merge wirksam. Bestehende Publisher-Wiederverwendungsprüfungen können diesen manuell erweiterten Wartungsbranch bis zum Merge ablehnen; es gibt keine Umgehung. Auto-Merge bleibt aus und NGINX behält seinen OpenSSL-Buildpfad.

## Finaler Diff- und Review-Status

Der Kandidat enthält nur diese acht Dateien und keine temporären Vorbereitungsworkflows oder -skripte. Die Veröffentlichung erhält den PR-Parent per nicht erzwungenem Fast-Forward. CI nach dem Push wird getrennt geprüft.
