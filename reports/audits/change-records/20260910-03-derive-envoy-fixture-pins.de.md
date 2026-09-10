# Change Record

**Sprache:** [English](20260910-03-derive-envoy-fixture-pins.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260910-03-derive-envoy-fixture-pins` |
| UTC-Datum | 2026-09-10 |
| Framework-Basisrevision | `ea2a157984c7e3b754c1a2d6e9837039895fcafe` |
| Issue oder Pull Request | Framework-PR [#118](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/118) enthält diese Korrektur auf demselben Branch; die geschützte Integration wartet auf frische Evidenz für den exakten Head. |

## Motivation und Problemstellung

Das vertrauenswürdige kanonische Update in PR #118 hebt geprüfte
Komponenten-Tuples an. Mehrere Regression-Fixtures suchten weiterhin nach
alten wörtlichen Werten oder erwarteten sie. Dadurch lehnten sie ein legitimes
geprüftes Update ab oder konnten ihre vorgesehene Mutation unbemerkt
überspringen, bevor sie die Provenance- und generierten Runtime-Controls
abdeckten.

Diese Framework-only-Korrektur adressiert das validierte Finding
`FND-FRAMEWORK-0122`. Sie ändert Test-Fixtures und deren test-only Parser;
kanonischer Pin, Runtime-Downloader, Lock-Checker, Workflow, Berechtigung,
Token und Provisioning-Pfad bleiben unverändert.

## Betroffene Komponenten und Sicherheitsgrenzen

- `tests/security_regression/common_version_fixture_support.py`
- `tests/security_regression/test_modsecurity_v3_git_ref_provenance.py`
- `tests/security_regression/test_runtime_component_sync.py`
- `tests/security_regression/test_common_version_atomic_provenance.py`
- `tests/security_regression/test_pcre2_archive_digest.py`
- `tests/fixtures/pcre2-digest/`

Die relevante Grenze ist der vertrauenswürdige kanonische Update-
Validierungspfad. Aktive Envoy-Tuple-Werte müssen quellabgeleitet bleiben;
veränderte oder doppelte aktive Werte müssen vor einem Provenance-sensitiven
Git- oder Runtime-Sink weiterhin fail-closed abgelehnt werden.

## Akzeptanzkriterien

- Positive Snapshot-/Reentry-Controls lesen den aktuellen Envoy-Wert aus dem
  synthetischen Fixture-Quelltext, ohne Shell-Quelle auszuwerten.
- Der Duplicate-Active-Pin-Control liefert weiterhin vor Git-Aktivität `77`.
- Runtime-Component-Mutations-Controls leiten aktuelle Version, URL und Digest
  ab und verwenden anschließend einen unabhängig veränderten Wert, den der
  Checker ablehnt.
- HAProxy-Koinzidenz- und Series-Mismatch-Fixtures schreiben ihre verfügbare
  Quellkopie strukturell um, sodass ein geprüftes Release keine Testmutation
  unbemerkt verschwinden lassen kann.
- Das kopierte APR-util-Update-Fixture ersetzt aktuelle Zuweisungen
  strukturell, bevor es sein bewusst synthetisches Ausgangstuple setzt.
- Das PCRE2-Archivfixture leitet Archivname und Archivwurzel aus der aktuellen
  geprüften Version ab, während sein lokales Source-Payload versionsfrei bleibt.
- Bestehende Controls für aktuellen Lock und kanonische Quelle bestehen weiter.
- Kein produktiver Pin, Checker, Downloader, Workflow-Permission oder
  Publisher-Scope wird gelockert.

## Untersuchte Alternativen

Das Festschreiben des aktuell beobachteten Envoy-Releases würde den Fehler beim
nächsten geprüften Update erneut erzeugen. Das Sourcen von `common.sh` im
Python-Helper würde unnötig Fixture-Shell-Code ausführen. Das Lockern des
fail-closed Checkers würde ein gültiges Control entfernen. Diese Alternativen
werden verworfen.

## Implementierungsentscheidung

Der gemeinsame test-only Helper liest oder ersetzt nun strukturell genau eine
unterstützte Shell-Zuweisung mit seiner nicht-ausführenden Assignment-Grammatik.
Die Provenance-Tests leiten ihren erwarteten bzw. doppelten Envoy-Wert aus
Quelltext ab. Runtime-Synchronisations-Controls leiten aktuelle Envoy- und
HAProxy-Werte ab, bevor sie einen unabhängig veränderten Wert oder ein
verfügbares Fixture ändern. Das atomare APR-util-Fixture bereitet sein festes
synthetisches Ausgangstuple strukturell vor. Der PCRE2-Archivtest leitet seine
generierte Archividentität aus der aktuellen geprüften Version ab statt aus
einem alten Release-Verzeichnis. Absichtlich feindliche Foreign-Host- und
Shell-Expression-Testdaten bleiben unverändert.

Der bestehende PR-Branch erhielt zuerst einen normalen Merge des aktuellen
Framework-`master`; der einzelne `common.sh`-Konflikt behielt die von `master`
abgeleiteten OpenSSL-NGINX-TLS-Aliasse und damit die bereits integrierte
Invariante bei.

## Geänderte Dateien und Tests

- `tests/security_regression/common_version_fixture_support.py`
- `tests/security_regression/test_modsecurity_v3_git_ref_provenance.py`
- `tests/security_regression/test_runtime_component_sync.py`
- `tests/security_regression/test_common_version_atomic_provenance.py`
- `tests/security_regression/test_pcre2_archive_digest.py`
- `tests/fixtures/pcre2-digest/`
- dieses gepaarte Change Record

Die Korrektur umfasst positive Snapshot-Propagation, Duplicate-Active-Pin-
Ablehnung, Ablehnung veränderter Runtime-Profile, HAProxy-Release-Series-
Controls, atomare APR-util-Update-Vorbereitung, PCRE2-Archivverifikation und
den Fresh-Initialization-Control. Sie ergänzt keine Runtime-Artefakte und
ändert kein Connector-Verhalten.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Fokussierter Pre-Patch-Snapshot-/Reentry-Test | 1 | Die erwartete veraltete `1.39.0`-Assertion wurde gegen die aktuelle `1.39.1`-Fixture-Ausgabe reproduziert. | Task-eigener Korrektur-Worktree |
| Fokussierter Pre-Patch-Runtime-Sync-Mutations-Test | 1 | Die erwarteten alten Versions- und Digest-Source-Needles fehlten nach dem kanonischen Update. | Task-eigener Korrektur-Worktree |
| `bash -n ci/lib/common.sh` | 0 | Die Shell-Quelle nach dem Same-Branch-Merge ist syntaktisch gültig. | Task-eigener Korrektur-Worktree |
| `python -m py_compile` für geänderte Testquellen | 0 | Geänderte Python-Quellen kompilierten mit der ausgewählten Framework-Umgebung. | Task-eigener Korrektur-Worktree |
| Fokussierte Provenance-Positiv- und Negativ-Controls | 0 | Vier gewählte Snapshot-, Duplicate-, Fresh-Init- und Altered-Pin-Controls bestanden. | Task-eigener Korrektur-Worktree |
| Runtime-Sync-Mutations-Control und Runtime-Lock-Suite | 0 | Ein geänderter Mutations-Control und 13 Lock-Controls bestanden. | Task-eigener Korrektur-Worktree |
| Erstes `make lint` nach der ersten Korrektur | 2 | Der verbleibende veraltete HAProxy-HTX-Mutations-Needle wurde sichtbar; der beobachtete Fehler wurde vor der Auslieferung korrigiert. | Task-eigener Korrektur-Worktree |
| `python -m unittest tests.security_regression.test_runtime_component_sync -v` | 0 | Alle 19 Runtime-Synchronisations-Controls einschließlich der korrigierten HAProxy-Fälle bestanden. | Task-eigener Korrektur-Worktree |
| `python -m unittest tests.security_regression.test_common_version_atomic_provenance -v` | 0 | 30 Controls für kanonisches Update und Provenance bestanden. | Task-eigener Korrektur-Worktree |
| `python -m unittest tests.security_regression.test_pcre2_archive_digest -v` | 0 | Alle 3 PCRE2-Digest-Controls bestanden mit dem versionsabgeleiteten Archivfixture. | Task-eigener Korrektur-Worktree |
| Finaler korrekt gebundener `make lint` | 0 | Der vollständige lokale Lint bestand, einschließlich Dokumentation, Workflow-Sicherheit, kanonischer Pins, Runtime-Lock/-Sync, Provenance und Archiv-Controls. | Task-eigener Korrektur-Worktree |

## Sicherheitsauswirkung

Der ursprüngliche Envoy-Stale-Fixture-Pfad wurde vor dem Patch reproduziert
und besteht nach der quellabgeleiteten Reparatur. Die gleichartigen
HAProxy- und APR-util-Source-Coupling-Pfade werden strukturell vorbereitet,
bevor ihre vorgesehenen Controls laufen, und der positive PCRE2-Archivcontrol
erreicht jetzt die aktuelle geprüfte Archividentität. Die alternativen Controls
für doppelte Pins und unabhängig veränderte Runtime-Tuples bleiben fail-closed.
Kein angreiferkontrollierter Input erreicht die früheren Assertions; kein
Security-Control wird geschwächt.

## Dokumentation und Runtime-Evidenz

Dieses englisch/deutsche Paar dokumentiert die Framework-only-Korrektur des
Validierungsvertrags. Der normale Master-Merge ist Lifecycle-Kontext; es wurde
keine Evidenz für Runtime-Service, Download oder Connector-Ausführung erhoben.

## Nicht ausgeführte Prüfungen

Der komplette Exact-Head-Workflow-/CodeQL-/SonarQube-Zyklus bleibt nach
finalem PR-Branch-Commit und -Push noch ausstehend. Kein neuer kanonischer
Maintenance-Dispatch, keine Parent-Änderung, keine MRTS-Änderung und keine
Runtime-Matrix wurden ausgeführt.

## Einschränkungen und Restrisiko

Die Reparatur bleibt absichtlich auf Test-Source-Coupling begrenzt. Sie beweist
kein Runtime-Verhalten. Der geschützte Merge bleibt davon abhängig, dass der
aktuelle PR-Head non-Draft, konfliktfrei und unter dem aktiven Ruleset voll
grün ist.

## Finaler Diff- und Review-Status

Der normale Master-Merge-Konflikt wurde mit Shell-Syntax- und Whitespace-Checks
geprüft. Der Korrektur-Diff bestand den vollständigen lokalen Lint und ein
unabhängiges Security-Review; Exact-Head-CI- und Protected-Merge-Nachweis
stehen noch aus. Es werden weder Force-Push noch direkter Master-Write,
Check-Rerun/-Cancellation oder Branch-Protection-Bypass verwendet.
