# Re-Entry des geerbten Upstream-Snapshots beheben

**Sprache:** [English](20260821-02-fix-inherited-upstream-snapshot-reentry.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260821-02-fix-inherited-upstream-snapshot-reentry |
| UTC-Datum | 2026-08-21 |
| Framework-Initialrevision | 89881a1b33219fc18df3cf2f15dda53261d13443 |
| Framework-Delivery-Basis beim Rebase | 798bff0c921ab8c7f10b2ca949304d58e7f205a2 |
| Issue oder Pull Request | Parent-Finding FND-PARENT-0191; Framework-Draft-PR ausstehend |

## Motivation und Problemstellung

Die Parent-/Framework-Runtime-Bridge kann `ci/lib/common.sh` einmal sourcen,
um kanonische Pins zu exportieren, und ein zweites Mal mit `set -a`, um ihre
geschützte Umgebung zu erhalten. Die zweite Auswertung exportierte den
internen Framework-Snapshot `CI_INHERITED_UPSTREAM_ENV`. Ein späterer
Framework-ModSecurity-v3-Guard erfasste diesen Snapshot erneut, interpretierte
seine eingebetteten kanonischen Zeilen als neue geerbte Eingabe und blockierte
das resultierende doppelte `ENVOY_VERSION` korrekt vor dem Git-Zugriff.

## Betroffene Komponenten und Sicherheitsgrenzen

- `ci/lib/common.sh`
- `tests/security_regression/test_modsecurity_v3_git_ref_provenance.py`

Die Grenze ist der inerte Snapshot der geerbten Umgebung, der ungeprüfte
Active-Pin-Overrides vor Download-, Git-, Checkout-, Extraktions- oder
Build-Sinks abweist. Die internen Snapshot-Metadaten selbst sind kein
Upstream-Pin und dürfen nicht erneut in diese Eingangsgrenze eintreten.

## Akzeptanzkriterien

- Eine Framework-generierte `set -a`-Umgebung darf erneut in den
  ModSecurity-v3-Provenance-Guard eintreten, ohne einen falschen
  Duplicate-Pin-Block zu erzeugen.
- Direkte geerbte Active-Pin-Abweichungen, veränderliche Refs, fremde URLs und
  ein falscher genehmigter Commit bleiben vor Git fail-closed.
- Eine echte doppelte Active-Pin-Zeile bleibt fail-closed.
- Bestehende statische ModSecurity-v3-Topologie- sowie benachbarte APR-/CRS-
  Provenance-Contracts bleiben grün.
- Parent-Gitlink und verschachtelter MRTS-Status bleiben unverändert.

## Untersuchte Alternativen

- Das Entfernen des Duplicate-Pin-Guards wurde verworfen, weil es die
  Source-Integrity-Grenze schwächen würde.
- Das Akzeptieren von vom Caller bereitgestelltem `CI_INHERITED_UPSTREAM_ENV`
  als vertrauenswürdige Eingabe wurde verworfen, weil es Framework-generierte
  Bridge-Metadaten und keine Provenance ist.
- Ein Parent-only-Strip wurde für diese Aufgabe nicht gewählt, weil der Nutzer
  das Framework ausgewählt hat und die veralteten Metadaten im gemeinsamen
  Framework-Helper entstehen.

## Implementierungsentscheidung

`common.sh` entfernt jetzt ausschließlich veraltete
`CI_INHERITED_UPSTREAM_ENV`-Metadaten und ihren Status, bevor es den frischen
Snapshot über den festen Pfad `/usr/bin/env` oder `/bin/env` erzeugt. Direkte
geerbte Pins bleiben in diesem frischen Snapshot und werden durch den
vorhandenen Guard weiterhin byte-identisch geprüft. Kein Release-Pin, URL,
Digest, Gitlink, Checkout-Policy, Berechtigung oder Source-Acquisition-
Verhalten wurde geändert.

## Geänderte Dateien und Tests

- `ci/lib/common.sh`: schließt veraltete interne Snapshot-Metadaten vor der
  nächsten geschützten Umgebungserfassung aus.
- `tests/security_regression/test_modsecurity_v3_git_ref_provenance.py`:
  reproduziert die Parent-/Framework-Re-Entry-Sequenz und ergänzt Controls für
  direkte Abweichung, Duplicate-Line und falschen genehmigten Commit.
- Dieses englische/deutsche Change-Record-Paar und die gepaarten Record-Indizes.

Die neue Re-Entry-Regression schlug vor der Shell-Änderung mit
`ENVOY_VERSION is duplicated in the inherited environment` fehl und besteht
nach der Änderung.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Fokussierte Re-Entry-Regression vor der Shell-Änderung | 1 | Reproduzierte den fail-closed Duplicate-`ENVOY_VERSION`-Blocker. | Framework-Task-Worktree |
| Fokussierte Re-Entry-Regression nach der Shell-Änderung | 0 | Re-Entry erreicht den genehmigten ModSecurity-v3-Provenance-Guard. | Framework-Task-Worktree |
| `make test-modsecurity-v3-provenance-contract` | 0 | 21 V3-Provenance-, Topologie-, Origin-, Ref-, Commit-, Loader- und Git-Controls bestehen. | Framework-Task-Worktree |
| `make test-apr-util-provenance` | 0 | 13 APR-util-Provenance-Controls bestehen. | Framework-Task-Worktree |
| `make test-crs-provenance-contract` | 0 | 23 CRS-Provenance- und Gitlink-Controls bestehen. | Framework-Task-Worktree |
| `sh -n ci/lib/common.sh` und `bash -n ci/lib/common.sh` | 0 | POSIX-Shell- und Bash-Syntax sind gültig. | Framework-Task-Worktree |
| `make lint` | 0 | Vollständige Framework-Lint-, Security-, Provenance-, Runtime-Contract-, Workflow-, Evidence- und Dokumentations-Suite besteht. | Framework-Task-Worktree |

## Sicherheitsauswirkung

Der ursprüngliche Duplicate-State-Pfad wurde vor dem Fix reproduziert und
besteht danach. Eine alternative echte doppelte Active-Pin-Zeile schlägt
weiterhin fail-closed fehl; das gilt auch für eine direkte
`ENVOY_VERSION`-Abweichung, eine fremde URL, einen veränderlichen Ref und einen
falschen genehmigten Commit vor dem Verbrauch eines Fake- oder System-Git-
Kommandos. Diese Reparatur entfernt nur Re-Entry-Metadaten und lockert keine
Provenance-Validierung.

## Dokumentation und Runtime-Evidenz

Dieses gepaarte Change Record und seine Index-Einträge sind die einzigen
leserorientierten Dokumentationsänderungen. Die aufgeführten Checks sind
hermetische Framework-Contract-Evidenz; es wird kein Hosted-Parent-
Connector-Runtime-, Request- oder Matrix-Erfolg behauptet.

## Nicht ausgeführte Prüfungen

- Ein reales `make fetch-modsecurity-v3` wurde nicht ausgeführt, weil es die
  Upstream-Source und rekursive Submodule herunterlädt; die hermetische
  Contract-Suite deckt die geänderte Guard-Grenze ohne unbegrenzte Acquisition
  ab.
- Hosted-Framework-PR-, SonarQube-Cloud- und Review-Prüfungen sind bis zur
  Auslieferung ausstehend.

## Einschränkungen und Restrisiko

Der Parent bleibt auf seinen bestehenden Framework-Gitlink gepinnt. Ein
separates Parent-Pointer-Update und Reruns der betroffenen Parent-Workflows
sind erforderlich, um das Hosted-Runtime-Ergebnis zu prüfen. Es wird kein
Sicherheitsrisiko akzeptiert.

## Finaler Diff- und Review-Status

Vor dem Commit bestanden der task-eigene Framework-Diff, die Whitespace-
Prüfung, der fokussierte Security-Review, vollständiges `make lint` und die
aufgeführten lokalen Contracts. Keine Secrets, Raw-geerbten Umgebungswerte,
Credentials oder Request-Payloads werden dokumentiert. Der Framework-Branch
existiert; sein Draft-PR ist ausstehend.
