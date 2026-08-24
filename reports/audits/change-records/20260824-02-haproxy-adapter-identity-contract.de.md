# Change Record

**Sprache:** [English](20260824-02-haproxy-adapter-identity-contract.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260824-02-haproxy-adapter-identity-contract` |
| UTC-Datum | 2026-08-24 |
| Framework-Basisrevision | `7bf8b7cb771f856a70123451332089a9f24036de` |
| Issue oder Pull Request | [Framework-Draft-PR #111](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/111); unabhängig von Parent-PR #279; offen und Draft, nicht gemergt, nicht auf Ready for review gesetzt und kein Auto-Merge aktiviert. |
| Verifizierter PR-Head beim Follow-up-Evidence-Capture | `255858132c9c3759f92023ca3062a6a67cba90c6` |

## Motivation und Problemstellung

Der Katalog `five-connectors-with-crs-no-mrts` band den HAProxy-Framework-
Smoke-Entrypoint an `haproxy-native-htx-filter` / `native-htx-filter`.
Statisches Source-Tracking zeigt, dass dieser Entrypoint den connector-eigenen
SPOE/SPOP-Smoke-Harness aufruft, während der native HTX-Filter ein separater
Parent-Full-Lifecycle-Pfad bleibt. Das Profil benötigte deshalb eine
geschlossene Identitätskorrektur, ohne den echten nativen HTX-Adapter
umzubenennen oder hochzustufen.

## Betroffene Komponenten und Sicherheitsgrenzen

- `ci/checks/catalog/five_connectors_with_crs_no_mrts.py` besitzt das
  geschlossene Profil, die Validierung nicht vertrauenswürdiger Evidenz, die
  Schema-Prüfungen und die nicht hochstufende Resultat-Erzeugung.
- Das Normalized-Event- und das Manifest-Schema beschränken jetzt jedes
  Connector/Adapter/Modus-Tupel, statt beliebige Tokens zu akzeptieren.
- Der Framework-Smoke-Entrypoint wird als statische Dispatch-Bindung geprüft;
  die connector-eigene Prozesstopologie und Host-Runtime-Evidenz bleiben
  außerhalb dieses Repositorys.

Es werden weder Parent-Source noch Parent-Gitlink, MRTS-Inhalt,
Workflow-Berechtigungen, Runtime-Summary, Root-/sudo-Verhalten oder eine
Connector-Capability-Deklaration geändert.

## Akzeptanzkriterien

1. Die ausgewählte HAProxy-Profilidentität ist
   `haproxy-spoe-spop-agent` / `spoe-spop-agent`.
2. Die erhaltene native HTX-Identität ist
   `haproxy-native-htx-filter` / `native-htx-filter` und bleibt ein separater
   Full-Lifecycle-Katalogeintrag.
3. Unbekannte IDs, falsche Modi und pfadübergreifende Evidenz schlagen sowohl
   bei Schema- als auch bei Katalogvalidierung fehl.
4. Der statische Smoke-Dispatch des Profils, das Report-Tupel und der nicht
   hochstufende Status bleiben an die ausgewählte SPOP-Identität gebunden.
5. Die Identitäten von Apache, Envoy, Traefik und lighttpd bleiben unverändert.

## Untersuchte Alternativen

- Das Umbenennen des nativen HTX-Adapters wurde verworfen, weil es einen echten
  Full-Lifecycle-Identifier stillschweigend verändert hätte.
- Die Auswahl von HTX allein anhand des Smoke-Skript-Namens wurde verworfen;
  Source-Dispatch und Parent-Harness-Pfad zeigen SPOE/SPOP.
- Ein neues Profil oder eine neue Schema-Version war nicht erforderlich: Der
  native HTX-Identifier bleibt unverändert und ein expliziter
  `reject-and-regenerate`-Profil-Migrationsdatensatz ist die
  Migrationsgrenze. Alte mit HTX gekennzeichnete Fünf-Connector-Events werden
  nicht als SPOP-Evidenz akzeptiert und müssen aus dem tatsächlichen
  SPOP-Pfad neu erzeugt werden.

## Implementierungsentscheidung

Das Framework besitzt nun einen geschlossenen HAProxy-Adapterkatalog mit zwei
Einträgen. Die Fünf-Connector-Ansicht `ADAPTERS` wählt nur den SPOP-Eintrag.
Der native HTX-Eintrag besitzt keinen Framework-Smoke-Entrypoint und benennt
sein separates Parent-Full-Lifecycle-Target. Event- und Manifest-Schemas
verwenden geschlossene Connector/Adapter/Modus-Alternativen und der lokale
Schema-Auswerter validiert, dass genau ein Tupel passt. Aggregate-Reporting
übernimmt die bereits validierte Manifest-Identität; erfolgreiche Validierung
bleibt `CONTRACT_VALIDATED` mit `host_runtime_status: UNATTESTED`.

## Geänderte Dateien und Tests

- `ci/checks/catalog/five_connectors_with_crs_no_mrts.py`
- `tests/schemas/five-connectors-with-crs-no-mrts/normalized-event.schema.json`
- `tests/schemas/five-connectors-with-crs-no-mrts/manifest.schema.json`
- `tests/ci_security/test_five_connector_with_crs_no_mrts_contract.py`
- `docs/testing-and-evidence.md` und `.de.md`
- `docs/connector-integration.md` und `.de.md`
- dieses gepaarte englische/deutsche Change Record

Der vorhandene Framework-Contract-Test deckt nun beide erhaltenen
HAProxy-Einträge, die geschlossene direkte Schema-Ablehnung, die Bindung des
ausgewählten Entrypoints, die Aggregate-Report-Identität, Nicht-Promotion und
die unveränderten Nicht-HAProxy-Adapter ab.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| JSON-Parse der geänderten Schemas mit Framework-Python | 0 | Beide geänderten Schemas lassen sich parsen. | Isolierter Framework-Worktree |
| Initialer `py_compile`-Aufruf außerhalb des Task-Worktrees | 1 | Sofort korrigiert; weder Source noch Artefakt wurden geändert. | Task-Transcript |
| `python -m py_compile` für geänderten Katalog und Test | 0 | Kompilierung mit Cache außerhalb des Worktrees bestanden. | Registrierte Task-Cache-Wurzel |
| Fokussiertes `unittest`-Contract-Modul | 0 | Contract-, Identitäts-, Schema- und Security-Regressionstests bestanden. | Registrierte Task-Temp-Wurzel |
| `make test-five-connectors-with-crs-no-mrts-contract` | 0 | Nativer Framework-Target bestanden. | Registrierte Task-Build-Wurzel |
| `make test-ci-security-contract` | 0 | 291 Framework-CI-Security- und Contract-Tests einschließlich der HAProxy-Identitätsfälle bestanden. | Registrierte Task-Build-Wurzel |
| `make test-ci-security-contract` nach der Ruff-Formatkorrektur | 2 | Die unveränderte writerless-FIFO-Timing-Race schlug fehl; der exakte isolierte bestehende Regressionstest bestand. | Task-Transcript und registrierte Task-Temp-Wurzel |
| CRS-Provenance-, Makefile-, Runtime-Component-Lock- und Runtime-Component-Sync-Targets | 0 | Fokussierte Framework-Security- und Regressionstargets bestanden. | Registrierte Task-Build-Wurzel |
| `make check-documentation` | 0 | Dokumentationslinks, bilinguale Begleiter, Pfade und Change-Record-Contract bestanden vor den finalen Evidenzzeilen. | Isolierter Framework-Worktree |
| Finaler vollständiger `make lint`-Versuch | 2 | Ein timing-sensitiver, unveränderter FIFO-Regressionstest verfehlte eine eigene Readiness-Beobachtung; weder Product-Code noch Test wurden geändert. | Task-Transcript |
| Isolierter FIFO-Regressions-Neustart | 0 | Der exakte vorhandene FIFO-Regressionstest bestand sofort mit Task-eigenem Temp-Storage. | Registrierte Task-Temp-Wurzel |
| Codex-Security-Diff-Scan und Revalidierung versiegelter Artefakte | 0 | Vollständige Working-Tree-Abdeckung; null reportable Findings. | Versiegelter task-eigener Security-Scan-Nachweis (nicht committet) |
| Finale Dokumentations- und Diff-Checks | 0 | `make check-documentation` und `git diff --check` bestanden nach Finalisierung des Change Records. | Isolierter Framework-Worktree |
| Follow-up mit Framework-Python `-m py_compile` | 0 | Der geänderte Katalog und Contract-Test kompilierten mit Cache außerhalb des Worktrees. | Follow-up-Task-Run |
| Follow-up mit fokussiertem `unittest`-Contract-Modul | 0 | Alle 29 Contract-, Identitäts-, Schema- und Security-Regressionstests bestanden. | Follow-up-Task-Run |
| Follow-up mit `make test-five-connectors-with-crs-no-mrts-contract` | 2 | Der unveränderte writerless-FIFO-Timing-Test verfehlte eine Readiness-Beobachtung; weder Source noch Test wurden geändert. | Follow-up-Task-Run |
| Follow-up mit isolierter writerless-FIFO-Regression | 0 | Der exakte vorhandene Regressionstest bestand isoliert. | Follow-up-Task-Run |
| Follow-up mit vollständigem `make test-ci-security-contract` | 0 | Alle 291 Framework-CI-Security- und Contract-Tests bestanden. | Follow-up-Task-Run |

## Sicherheitsauswirkung

Dies ist eine Härtung der Validierungsgrenze. Ein reiner Schema-Consumer kann
keinen unbekannten Adapter oder nicht zusammenpassenden HAProxy-Modus mehr
akzeptieren, und das Profil kann native HTX-Evidenz nicht als SPOE/SPOP-
Evidenz oder umgekehrt behandeln. Die statische Entrypoint-Prüfung ist keine
Runtime-Behauptung. Keine Sicherheitskontrolle wurde geschwächt, keine
Suppression wurde hinzugefügt, und Metadaten allein können weiterhin weder
einen Runtime-`PASS` noch eine Capability-Promotion erzeugen.

Der abgeschlossene Framework-spezifische Codex-Security-Diff-Review ergab null
reportable Findings bei vollständiger Abdeckung der geänderten Dateien. Sein
generisches Source-Inventar schließt `ci/`, `docs/` und `tests/` absichtlich
aus; der versiegelte Scan enthält deshalb zusätzlich einen expliziten
Reviewed-Files-Beleg für alle zehn geänderten Dateien. Dies ist ein statischer
Contract-Review, keine Runtime-Evidenz.

## Dokumentation und Runtime-Evidenz

Die gepaarten englischen/deutschen Integrations- und Evidenzleitfäden
unterscheiden das ausgewählte SPOP-Profil von der erhaltenen HTX-
Full-Lifecycle-Identität. In diesem Framework-only-PR wurden weder eine
Parent-HAProxy-Runtime noch Connector-Host, SPOA-Prozess, native HTX-Runtime
oder MRTS-Prozess gestartet. Es wird weder ein realer SPOE/SPOP-Host-`PASS`
noch ein nativer-HTX-Runtime-`PASS` beansprucht. `CONTRACT_VALIDATED` bleibt
von Host-Runtime-`PASS` getrennt; die Pfadschlussfolgerung ist statische
Source-Evidenz, keine Host-Runtime-Evidenz.

## Nicht ausgeführte Prüfungen

Der vollständige Parent-HAProxy-SPOE/SPOP-Smoke und die native HTX-
Full-Lifecycle-Runtime wurden nicht ausgeführt: Sie benötigen Parent-eigene
Build-Artefakte, CRS-/Runtime-Abhängigkeiten und Connector-Host-Ausführung,
die außerhalb dieser Framework-only-Aufgabe liegen. Eine Runtime-Workflow-
Summary wurde absichtlich nicht neu erzeugt.

## Einschränkungen und Restrisiko

Das Framework validiert den Identitätsvertrag und seine statische
Dispatch-Bindung; es kann keinen Host-Producer authentifizieren oder beweisen,
dass ein echter HAProxy/SPOP- oder HTX-Prozess lief. Diese Fakten bleiben
Parent-eigen und benötigen ihre eigene Exact-Head-Runtime-Evidenz.

## Finaler Diff- und Review-Status

Beim Follow-up-Evidence-Capture war der exakte PR-Head
`255858132c9c3759f92023ca3062a6a67cba90c6`: lokaler `HEAD`,
`origin/codex/haproxy-adapter-identity-contract` und Framework-Draft-PR #111
waren identisch, und der Branch war gepusht. Die finalen Dokumentations- und
Diff-Checks waren abgeschlossen. Die Hosted-PR-Checks für diesen exakten Head
waren abgeschlossen: CodeQL (actions, c-cpp und python), SonarCloud Code
Analysis, `actionlint-and-contract`, `check-action-versions`,
`common-structure`, `portable-contract`, `pull-request-head`,
`pull-request-range`, `python-ci-security-quality`, `scaffold-lint` und
`zizmor` bestanden. Die drei Advisory-Checks waren übersprungen und werden
nicht als bestanden dargestellt.

PR #111 bleibt offen und Draft. Er wurde weder gemergt noch auf Ready for
review gesetzt, und Auto-Merge ist nicht aktiviert. Dieser reine
Dokumentations-Follow-up hält den finalen Post-Commit-Local/Remote/PR-Head und
die Hosted-Check-Evidenz im PR und in der Abschluss-Evidenz fest, statt einen
selbstreferenziellen Record-Commit zu erzeugen. Der abgeschlossene
Security-Diff-Review, die fokussierten Contract-Tests, der vollständige
CI-Security-Lauf und der isolierte FIFO-Neustart bleiben als Task-Evidenz
erhalten. Weder Parent-Gitlink noch MRTS-Inhalt oder Parent-Produktcode werden
gestagt oder geändert.
