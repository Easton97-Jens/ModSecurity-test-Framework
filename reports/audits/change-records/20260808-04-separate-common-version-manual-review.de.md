# Change Record: 20260808-04-separate-common-version-manual-review

**Sprache:** Deutsch | [English](20260808-04-separate-common-version-manual-review.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260808-04-separate-common-version-manual-review` |
| UTC-Datum | 2026-08-08 |
| Framework-Basisrevision | `a8c7210fe57d4ff4fd0206c6d18554f63b0680b0` |
| Issue oder Pull Request | GitHub-Actions-Lauf [#16](https://github.com/Easton97-Jens/ModSecurity-test-Framework/actions/runs/31274879150); ein vom Benutzer autorisierter Draft-PR wartet auf den finalen Delivery-Preflight. |

## Motivation und Problemstellung

Lauf #16 schlug im read-only-Resolver fehl, weil ein neueres ModSecurity-v3-
Release eine manuelle Tag-plus-immutable-Commit-Provenance-Entscheidung
benötigte. Der Checker stellte diese begrenzte Entscheidung als `unknown` dar;
dadurch stoppte sein strenger Exit-Code das davon unabhängige vollständige
HAProxy-Update aus Version und Digest, bevor ein Kandidat validiert werden
konnte. Der Ergebnis-Job verweigerte den fehlenden Resolver-Output korrekt; er
war nicht die erste Ursache.

## Betroffene Komponenten und Sicherheitsgrenzen

Diese reine Framework-Remediation ändert den Common-Version-Checker, den
geplanten/manuellen Wartungsworkflow, seinen CI-Sicherheitsvertrag und seine
Regressionstests, die Workflow-Sicherheitsdokumentation und diesen gepaarten
Record. Die Grenze beginnt bei Upstream-Release-/Checksum-Metadaten und endet
beim isolierten Kandidaten, dem repositorybegrenzten App-Token-Publisher, dem
festen Draft-Branch und dem PR-Scope nur für `ci/lib/common.sh`. Parent, MRTS,
Gitlinks und `ci/lib/common.sh`-Pins werden von diesem Implementierungs-PR
nicht geändert.

## Akzeptanzkriterien

1. Das strikte Standardverhalten des Checkers bleibt für `unknown`, `blocked`,
   `error` und eine manuelle Provenance-Prüfung fail-closed.
2. Nur ein gültiges CRS- oder ModSecurity-v3-Tupel aus festem Repository, Tag
   und Immutable Commit kann im expliziten Wartungsmodus `review_required`
   werden.
3. Ein sicherer automatischer Plan ist vollständig, von jeder manuellen
   Provenance-Zeile getrennt, erneut geparst, byte-geprüft und unabhängig
   revalidiert, bevor er schreibt.
4. Der Workflow unterscheidet kein Update, nur manuelle Prüfung, sichere
   Updates, sichere Updates mit manueller Prüfung und fatale Ergebnisse ohne
   Credential-Nutzung oder Veröffentlichung für die ersten beiden Ergebnisse.
5. Resolver, Validator, Publisher, Ergebnis-Job und CI-Sicherheitsvertrag
   binden die geprüften Outputs und brechen bei Abweichungen fail-closed ab.
6. Englische/deutsche Dokumentation und ein gepaarter Record beschreiben die
   genaue Grenze, ohne nicht beobachtete Hosted- oder Merge-Ergebnisse zu
   behaupten.

## Untersuchte Alternativen

- Alle `unknown`-Werte als nicht fatal zu behandeln wurde verworfen, weil
  fehlerhafte, nicht erreichbare, widersprüchliche oder nicht vertrauenswürdige
  Upstream-Metadaten veröffentlichbar würden.
- Einen CRS- oder ModSecurity-Release-Tag automatisch zu einem Commit
  aufzulösen wurde verworfen, weil die Immutable-Provenance-Entscheidung
  manuell bleibt.
- APR-util zusammen mit den zwei Tag/Commit-Pfaden aufzuschieben wurde als
  unnötige Scope-Erweiterung verworfen: Sein Provider-/Kompatibilitätstupel
  bleibt eine eigenständig fatale Review-Grenze.
- Eine manuelle Prüfung als fehlendes Update zu behandeln wurde verworfen, weil
  dies die notwendige Provenance-Entscheidung verbergen würde.

## Implementierungsentscheidung

Der Checker fügt einen typisierten Status `review_required` nur hinzu, nachdem
jede explizite CRS- oder ModSecurity-v3-Funktion ihr festes GitHub-Repository,
das erwartete Tag-Format, einen geprüften 40-hex-Commit und Runtime-Aliase
validiert hat. Für diesen Status werden automatische Updates entfernt.
`--defer-reviewed-provenance` aktiviert den Wartungs-Outcome-Klassifizierer;
die Standard-CLI bleibt strikt. Der Klassifizierer weist jede fatale Komponente,
fehlerhafte Review-Metadaten, unvollständigen Plan, doppelte Aktualisierung
oder Überlappung manueller/automatischer Variablen zurück.

Vor dem Anwenden eines sicheren Teilplans rendert und parst der Checker ihn im
Speicher, beweist jede manuelle Source-Zeile byte-identisch, prüft die
Upstream-Komponenten mit einem frischen Client erneut, verlangt für den
Kandidaten nur kein Update oder manuelle Prüfung und schreibt/parst ihn erst
danach. Der Workflow bindet Outcome, SHA-256, automatische Variablen, manuelle
Komponenten und den Digest manueller Pins über seine read-only-Stufen und den
Publisher. Der Draft-PR-Body trennt automatische Änderungen von unveränderten
manuellen Prüfungen.

## Geänderte Dateien und Tests

- `ci/tools/check-common-versions.py` fügt die begrenzten Disposition-,
  Safe-Plan-, Reparse-, Byte-Erhaltungs- und Revalidierungs-Kontrollen hinzu.
- `.github/workflows/check-common-versions.yml` übergibt das geprüfte Outcome
  durch Resolver, Validator, Publisher und Ergebnisbericht.
- `ci/checks/security/check-ci-security-contract.py` bindet den geänderten
  Output-, Gate-, Umgebungs- und statischen Workflow-Body-Vertrag.
- `tests/security_regression/test_common_versions_sonar_provenance.py` und
  `tests/security_regression/test_crs_git_ref_provenance.py` decken zulässige
  manuelle Zustände, strikte Defaults, sichere Teilupdates, feste Identität,
  Überlappung, Byte-Erhalt und fatale Negative ab.
- `tests/ci_security/test_ci_security_contract.py` deckt Ergebnis-Outcomes und
  Mutationsresistenz für den neuen Resolver-/Publisher-Vertrag ab.
- `docs/github-actions-workflow-security.md` und `.de.md` beschreiben das
  Sicherheitsverhalten.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Lauf-ID oder zugelassener Evidenzpfad |
| --- | ---: | --- | --- |
| Striktes isoliertes `check-common-versions.py --update --json --write-files --timeout 20` | 2 (erwartet) | ModSecurity v3 war `review_required`; der unabhängige HAProxy-Plan schrieb nicht und die externe Kopie blieb byte-identisch. | Task-eigener Run-#16-Remediation-Pfad |
| Isoliertes `check-common-versions.py --update --defer-reviewed-provenance --json --write-files --timeout 20` | 0 | Klassifizierte `safe_updates_with_manual_review`, behielt den manuellen Pin-Nachweis und änderte genau HAProxy-Version und SHA-256 in einer BUILD_ROOT-begrenzten Kopie. | Task-eigener Run-#16-Remediation-Pfad |
| Fokussierte Common-Version-, CRS-Provenance- und CI-Security-`unittest`-Module | 0 | 67 positive, negative, Terminal-State- und Mutationstests bestanden. | Task-eigener Framework-Checkout |
| `make lint` mit externen Build-/Cache-/Evidenzpfaden | 0 | Vollständiger nativer Lint, 142 CI-Security-Tests, Provenance-Suiten, Workflow-/Dokumentations-/Record-Prüfungen und finaler Diff-Check bestanden. | Task-eigener Run-#16-Remediation-Pfad |
| `ci/checks/documentation/check-workflow-yaml.py` | 0 | Alle Repository-Workflow-YAML-Dateien einschließlich des geänderten Workflows wurden erfolgreich geparst. | Task-eigener Framework-Checkout |
| `ci/checks/security/check-ci-security-contract.py` | 0 | Der exakte geprüfte CI-Sicherheitsvertrag bestand. | Task-eigener Framework-Checkout |
| Ruff-Check und Format-Check | 0 | Geänderter Python-Checker-, Vertrags- und Regression-Scope bestand nach deterministischem Formatieren. | Task-eigenes prüfsummenverifiziertes Tool-Verzeichnis |
| actionlint mit ShellCheck; offline zizmor | 0 | Alle Workflows bestanden actionlint; ShellCheck bestand; zizmor meldete keine Findings (37 dokumentierte Suppressions). | Task-eigenes prüfsummenverifiziertes Tool-Verzeichnis |
| Gitleaks für uncommitted Diff und beide Records | 0 | Keine Leaks gefunden; die Ausgabe war vollständig redigiert. | Task-eigenes prüfsummenverifiziertes Tool-Verzeichnis |

## Sicherheitsauswirkung

Der ursprüngliche Pfad wird durch den Safe-Partial-Control erneut geprüft: Eine
gültige manuelle ModSecurity-v3-Entscheidung verändert ihre Provenance-Zeilen
nicht, während ein unabhängiges HAProxy-Paar aus Version und Digest revalidiert
werden kann. Unknown, blocked, error, Identitätsmismatch, fehlerhafter
Immutable Commit, widersprüchliche Aktualisierung und manuelle
Variablenüberschneidung bleiben nicht veröffentlichbar. Der Publisher erhält
sein App-Token erst, nachdem der unabhängige Kandidat mit allen begrenzten
Nachweiswerten übereinstimmt; seine Prüfungen für Default-Branch, Branch, Titel,
Marker und Pfad bleiben unverändert und exakt.

## Dokumentation und Runtime-Evidenz

Das Dokumentationspaar unterscheidet nun manuelle Prüfung von keinem Update und
erfasst die unabhängigen Vergleichswerte sowie die Draft-PR-Tabellen. Lauf #16
(`31274879150`) lieferte den ursprünglichen Resolver-Exit `2`, übersprungenen
Validator/Publisher und die Evidenz zum fehlenden Output im Ergebnis-Job.
GitHub behielt kein Laufartefakt und keine komponentenweise Resolver-
Zusammenfassung; eine nachfolgende isolierte Ausführung auf derselben
Source-Revision lieferte die stärkste verfügbare Komponentenmatrix.

## Nicht ausgeführte Prüfungen

- Lokales Pyright wurde über das prüfsummengebundene Paket gestartet, ist aber
  blockiert, weil diese Umgebung kein `node`-Programm hat. Es wurde keine
  Runtime installiert; der gehostete PR-Quality-Workflow bleibt die
  erforderliche Pyright-Kontrolle.
- Hosted Exact-Head-Checks, CodeQL, SonarQube, Review und Branch Protection
  können erst laufen, wenn der autorisierte Draft-PR existiert.
- Kein Merge, Parent-Runtime-Test, MRTS-Aktion, Gitlink-Update oder
  Default-Branch-End-to-End-Workflow ist durch diese Aufgabe autorisiert.

## Einschränkungen und Restrisiko

Aktuelle Upstream-Daten sind zeitvariabel und ersetzen nicht das fehlende
Run-#16-JSON-Artefakt. Die Remediation begrenzt diese Unsicherheit auf einen
frischen dreistufigen Kandidatenprozess und bricht bei Abweichung fail-closed
ab. Die manuelle CRS- und ModSecurity-v3-Tag/Commit-Provenance benötigt weiter
eine separate menschliche Prüfung; diese Änderung erzeugt keinen Immutable
Commit.

## Finaler Diff- und Review-Status

Lokale Implementierung, Evidenz und Security-Review sind abgeschlossen. Dieser
Record behauptet keinen Framework-Commit, Push, Draft-PR, Hosted-Check, Review,
Merge, Parent-Änderung, MRTS-Änderung oder Gitlink-Update, bevor dieser
beobachtet wurde.
