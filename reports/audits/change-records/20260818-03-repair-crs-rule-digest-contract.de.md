# Den atomaren CRS-Regel-Digest-Wartungsvertrag reparieren

**Sprache:** [English](20260818-03-repair-crs-rule-digest-contract.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260818-03-repair-crs-rule-digest-contract |
| UTC-Datum | 2026-08-18 |
| Framework-Basisrevision | c6add258c3ffb50c89a3cb94bd56102dd636b2f1 |
| Issue oder Pull Request | Draft-[PR #99](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/99) |

## Motivation und Problemstellung

PR #99 aktualisierte das kanonische OWASP Core Rule Set von v4.28.0 auf
v4.29.0, ließ aber den Fingerprint der geprüften SQLi-Regeldatei und eine
Event-Schema-Ansicht auf dem vorherigen Release. Die fail-closed portablen und
vertraglichen Jobs lehnten deshalb die inkonsistente Source-Provenance ab.

## Betroffene Komponenten und Sicherheitsgrenzen

- `ci/lib/common.sh` ist die kanonische Autorität für CRS-Provenance-Pins.
- `ci/tools/check-common-versions.py` überquert die freigegebenen GitHub-
  Release- und Contents-APIs, um begrenzte Wartungskandidaten vorzubereiten.
- `ci/tools/crs_contract_pins.py`, `sync-crs-contract-views.py` und der
  Katalogvertrag konsumieren nur die kanonischen Werte.

Die Grenze führt von externen Release- und Dateimetadaten zu unveränderlichen
lokalen Pins. Die Reparatur erhält Repository-Allowlist, Stable-v4-Grenze,
unveränderlichen aufgelösten Commit, begrenztes Content-Decoding und
fail-closed generierte Ansichten.

## Akzeptanzkriterien

1. CRS-Tag v4.29.0, aufgelöster Commit und SHA-256 der geprüften Regeldatei
   stimmen überein.
2. Die automatische CRS-Wartung schlägt diese drei Werte atomar vor und
   übernimmt nie einen unvollständigen Kandidaten.
3. Generierte Schemas und die CRS-Test-Fixture werden aus den kanonischen Pins
   abgeleitet und weisen fehlerhafte oder fehlende Regel-Digests ab.
4. Bestehende Security- und Quality-Controls bleiben aktiv und relevante lokale
   Verträge bestehen.

## Untersuchte Alternativen

- Den v4.29.0-Digest in einzelnen Schemas fest zu codieren, wurde abgelehnt,
  weil dadurch eine zweite Provenance-Autorität entstünde.
- Den Fingerprint der geprüften Regel aus dem Vertrag zu entfernen, wurde
  abgelehnt, weil dies genau den fail-closed Control schwächen würde, der den
  Fehler aufdeckte.
- Den aktualisierten Tag und Commit als ausreichend zu behandeln, wurde
  abgelehnt, weil die ausgewählte Regeldatei eine zusätzliche konsumierte
  Source-Identität ist.

## Implementierungsentscheidung

`CRS_RULE_FILE_SHA256` ist ein strikt geparstes kanonisches Literal. Der
Maintenance-Resolver liest die geprüfte SQLi-Regeldatei über die GitHub-
Contents-API am bereits verifizierten unveränderlichen Commit, begrenzt und
verifiziert ihren Base64-Content und die Git-Blob-Identität und erzeugt eine
SHA-256-Aktualisierung in der bestehenden atomaren CRS-Gruppe. Contract-Views
projizieren den Digest und leiten ihren `crs_git_ref` aus dem kanonischen
Release-Tag ab, sodass keine unabhängig veralteten Werte verbleiben.

Der Git-Blob-SHA-1-Vergleich ist ausschließlich Protokollformat-Validierung,
niemals ein Security- oder Provenance-Pin; er ist explizit als
`usedforsecurity=False` markiert. Die sicherheitsrelevante Source-Identität
bleibt der separat abgeleitete SHA-256. Die beiden
`dataclasses.replace`-Rückgaben sind explizit als `ComponentResult` typisiert,
und die redundante Base64-Exception-Oberklasse entfällt.

## Geänderte Dateien und Tests

- Kanonischer CRS-Pin, Parser, Active-Pin-Vererbung, Maintenance-Resolver und
  Katalog-Ownership-Prüfung.
- CRS-Contract-View-Synchronisierer und alle generierten CRS-Ansichten.
- Regressionen für Digest-Parsing, atomare Update-Planung, Reparatur eines
  veralteten Digests, fehlerhaften GitHub-Content und generierte Event-
  Provenance.
- Regression, dass der Git-Blob-Format-SHA-1 nur mit
  `usedforsecurity=False` aufgerufen wird.
- Englische und deutsche Variablen-Dokumentation sowie dieses gepaarte
  Change-Record.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `sync-crs-contract-views.py --check --root <task-worktree>` | 0 | Generierte CRS-Contract-Views stimmen mit den kanonischen Pins überein. | Task-eigene externe Validierungsumgebung |
| `make -s test-canonical-crs-contract-pins` | 0 | Kanonische View-Prüfung und 9 Synchronisierer-Tests bestanden. | Task-eigene externe Validierungsumgebung |
| `make -s test-crs-provenance-contract` | 0 | 22 CRS-Provenance-Regressionstests bestanden. | Task-eigene externe Validierungsumgebung |
| `make -s test-ci-security-contract` | 0 | 282 CI-Security-Contract-Tests bestanden mit explizit gebundenem Task-Worktree. | Task-eigene externe Validierungsumgebung |
| CRS-Pin-Shell-Syntax, Katalogprüfung und kanonische Versionsvalidierung | 0 | Kanonische Pin- und Shell-Verträge bestanden. | Task-eigene externe Validierungsumgebung |
| `make -s lint` | 0 | Vollständiges natives Lint sowie Contract-, Provenance-, Runtime-, Workflow-, Dokumentations- und Change-Record-Suiten bestanden. | Task-eigene externe Validierungsumgebung |
| `git diff --check` | 0 | Keine Whitespace-Fehler im Framework-eigenen Remediation-Diff. | Task-eigene externe Validierungsumgebung |

## Sicherheitsauswirkung

Dies ist eine Supply-Chain-Härtungsreparatur. Der ursprüngliche Fehlerpfad –
ein aktualisiertes CRS-Release mit altem geprüften Regel-Digest – wird erneut
getestet. Alternative fehlerhafte, fehlende, doppelte oder nicht kanonische
Digests sowie fehlerhafter GitHub-Content werden abgewiesen; keine Allowlist,
Provenance-, Test-, Quality-Gate- oder Workflow-Kontrolle wird deaktiviert.

## Dokumentation und Runtime-Evidenz

Die englischen und deutschen Variablenreferenzen beschreiben jetzt die
vollständige atomare CRS-Provenance-Gruppe. Es wurden keine Connector-Runtime-,
Produktions-, Credential- oder GitHub-App-Evidenzen erfasst oder abgeleitet.

## Nicht ausgeführte Prüfungen

- Frische exakte GitHub-Actions und die SonarQube-Cloud-Analyse stehen bis zum
  Framework-eigenen Folgeremediation-Commit und PR-Update aus.
- Für diese CI-Maintenance-Vertragskorrektur war keine Connector-Integration
  oder Produktionsruntime erforderlich.

## Einschränkungen und Restrisiko

Der Remote-Contents-Lookup ist auf das geprüfte CRS-Repository, einen
unveränderlichen Commit und den einen festen SQLi-Regelpfad begrenzt. Sind
GitHub-Metadaten nicht verfügbar oder fehlerhaft, schlägt die Wartung
fail-closed fehl, statt einen Pin zu aktualisieren.

## Finaler Diff- und Review-Status

Der erste Framework-eigene Remediation-Commit bestand natives Lint,
Whitespace-Review und einen unabhängigen Security-Diff-Review. Ein kleiner
Folgediff adressiert jetzt SonarClouds vier exakte Quality-Gate-Anmerkungen;
seine fokussierte CRS-Provenance-Suite mit 23 Tests, der vollständige native
Lauf `make -s lint`, das Whitespace-Review und der erneute unabhängige
Security-Diff-Review bestanden. Ein zweiter absichtlich getrennter PR-Commit/-
Push sowie die exakte Hosted-Verifikation stehen noch aus. Parent und MRTS
bleiben außerhalb der Änderung.
