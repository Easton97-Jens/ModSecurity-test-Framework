# Change Record: 20260816-02-unify-framework-maintenance-orchestrator

**Sprache:** [English](20260816-02-unify-framework-maintenance-orchestrator.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260816-02-unify-framework-maintenance-orchestrator` |
| UTC-Datum | `2026-08-16` |
| Framework-Basisrevision | `bd0dbdbd0a28e0705c123963209d6e5e410bacad` |
| Issue oder Pull Request | Aufgabenbezogener Framework-Draft-PR; die Remote-Referenz wird nach dem Push eingetragen. Kein Merge und kein Master-Schreiben ist durch diesen Record autorisiert. |

## Motivation und Problemstellung

Der Common-Version-Wartungsablauf konnte einen Komponentenfilter auf die
gesamte Registry anwenden. Ein geplanter oder manuell gestarteter Lauf konnte
dadurch go-ftw, Albedo und kanonische CI-Pins auslassen, sobald eine
Runtime-/Source-Komponente gewählt wurde. Review-only-Beobachtungen hatten
außerdem keinen einzigen typisierten Plan, den Resolver, Validator, Publisher
und Issue-Lifecycle gemeinsam verwenden.

## Betroffene Komponenten und Sicherheitsgrenzen

Die Framework-eigene Dokumentation beschreibt den Common-Version-Orchestrator,
kanonische Runtime-Serien, generierte Views, typisierte Review-Pläne und das
vertrauenswürdige Issue-Reconciliation. Sie betrifft
`ci/tools/resolve-canonical-maintenance.py`, den Common-Version-Workflow und
die zugehörigen CI-/Security-Verträge, ohne eine unabhängige Pin-Autorität in
der Dokumentation zu schaffen. Die relevante Grenze verläuft von offiziellen
Upstream-Metadaten zu generierten Dateien und zum vertrauenswürdigen
Default-Branch-Issue-Writer; Pull-Request-Jobs bleiben read-only. Parent,
Connector-Runtime und MRTS sind außerhalb dieses Records.

## Akzeptanzkriterien

1. Die englische und deutsche Variablendokumentation erklärt, dass go-ftw,
   Albedo und alle kanonischen CI-Pins in jedem geplanten, manuell gestarteten,
   vollständigen und komponentenbezogenen Lauf geprüft werden.
2. Die Dokumentation erklärt, dass `--component` nur zusätzliche
   Runtime-/Source-Komponenten filtert und Runtime-Serien/Root/Basis-URLs
   explizit sind, einschließlich der separaten HAProxy-HTX-Linie.
3. Der Workflow-Security-Leitfaden dokumentiert in beiden Sprachen den
   deterministischen gemeinsamen Plan, Generated-View-Checks, vertrauens-
   würdiges Issue-Reconciliation, fail-closed Hash-/Vollständigkeitsprüfungen
   und fehlendes Auto-Merge.
4. Dieser Change Record besitzt einen deutschen Begleiter und beide Dateien
   enthalten weder Credentials noch flüchtige Runner-Daten.

## Untersuchte Alternativen

- Getrennte go-ftw-, Albedo- und CI-Pin-Workflows wurden verworfen, weil ein
  komponentenbezogener Common-Lauf weiterhin eine unvollständige
  Wartungsentscheidung erzeugen würde.
- Die alten `not_applicable`-Beschreibungen wurden verworfen, weil sie dem
  obligatorischen globalen Resolver-Scope widersprechen würden.
- Issue-Schreibrechte für Pull-Request-Jobs wurden verworfen; das
  Reconciliation gehört ausschließlich in einen vertrauenswürdigen
  Default-Branch-Job, der den validierten Plan konsumiert.

## Implementierungsentscheidung

Die gepaarten Referenzseiten beschreiben nun einen Orchestrator und einen
deterministischen Plan. Sie unterscheiden kanonische `common.sh`-Werte von
generierten Runtime-, Python-, Workflow- und CRS-Views, beschreiben explizite
Lighttpd-/HAProxy-Serien und das unabhängige HTX-Tupel und halten die feste
Draft-PR-/No-Auto-Merge-Grenze fest. Manual-Review-Issues werden als
vertrauenswürdiger Default-Branch-Abgleich beschrieben, nicht als Nebeneffekt
von Resolver- oder Pull-Request-Jobs.

## Geänderte Dateien und Tests

- `docs/reference/variables.md` und `.de.md` dokumentieren den einheitlichen
  Scope, explizite Serien, Artefakt-/Plattform-Identität und Plan-Views.
- `docs/github-actions-workflow-security.md` und `.de.md` dokumentieren
  gemeinsamen Planer, Plan-Revalidierung, Issue-Writer-Grenze und
  fail-closed-Ergebniszustände.
- Dieses englisch/deutsche Change-Record-Paar dokumentiert die
  Framework-eigene Änderung.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder freigegebener Evidenzpfad |
| --- | --- | --- | --- |
| `python -m unittest -v` (11 vereinigte Maintenance-, Pin-, Resolver-, Reconciler- und Fetcher-Module) | `0` | 116 Tests bestanden. | Hash-gesperrte Task-virtuelle Umgebung |
| `python -m unittest -v tests.ci_security.test_ci_security_contract tests.ci_security.test_framework_ci_security_contract` | `0` | 50 CI-Sicherheitsvertrags-Tests bestanden. | Hash-gesperrte Task-virtuelle Umgebung |
| `python -m unittest -v` (sieben Runtime-/Komponenten-Provenance-, Sync-, Lock-, Download- und Traefik-Module) | `0` | 84 Regressionstests bestanden. | Hash-gesperrte Task-virtuelle Umgebung |
| `python -m unittest` (sechs historische Provenance-Module, einschließlich ModSecurity v3 und Sonar-Verträgen) | `0` | 107 Tests bestanden; einer wurde absichtlich übersprungen. | Hash-gesperrte Task-virtuelle Umgebung |
| `ci/tools/check-common-versions.py --validate-canonical`, `sync-runtime-components.py --check`, kanonische Python-/Workflow-Pin-Prüfungen und CI-Sicherheitsvertragsprüfung | `0` | Kanonische Eingaben, generierte Views, Runtime-Inventar und CI-Vertrag bestanden. | Hash-gesperrte Task-virtuelle Umgebung |
| Prüfungen für Dokumentationslinks, Variablen, Workflow-YAML und Change Records | `0` | Alle geprüften Dokumentationsverträge bestanden. | Hash-gesperrte Task-virtuelle Umgebung |
| `git diff --check` und `bash -n ci/lib/common.sh` | `0` | Whitespace und Shell-Syntax bestanden. | Task-Worktree |

## Sicherheitsauswirkung

Die Dokumentation hält eine sicherheitsrelevante Scope-Korrektur fest:
Obligatorische globale Checks dürfen nicht durch einen Runtime-/Source-
Komponentenfilter umgangen werden, und Issue-Schreibvorgänge sind auf einen
vertrauenswürdigen Default-Branch-Job mit typisiertem, hashgebundenem Plan
begrenzt. Die Dokumentationsänderung führt keine Credentials, Berechtigungen,
Auto-Merge-Fähigkeit oder nicht vertrauenswürdigen Schreibpfad ein.

Der finale Provenance-Review bindet außerdem die Upstream-Repository-Identität
von ModSecurity v3 vor jedem Network-Lookup: Die Candidate-URL wird
kanonisiert und muss zu einem unveränderlichen Digest-Anchor der festen
offiziellen Identität passen. Die Kontrollen foreign-repository/no-network und
malformed-anchor bestehen lokal.

## Dokumentation und Runtime-Evidenz

Die englischen und deutschen Referenzseiten und Workflow-Security-Leitfäden
wurden als synchronisiertes Paar aktualisiert. Lokale Orchestrator-, Pin-
Generierungs-, Runtime-, Dokumentations- und CI-Sicherheitsvertragsprüfungen
bestanden in der hash-gesperrten Task-virtuellen Umgebung. Der vertrauens-
würdige Hosted-Issue-Writer bleibt auf seinen Default-Branch-Workflowpfad
begrenzt und wird lokal bewusst nicht ausgeführt.

## Nicht ausgeführte Prüfungen

- Hosted-GitHub-Actions- und SonarQube-Cloud-Prüfungen benötigen den exakten
  Draft-PR-Head und wurden noch nicht ausgeführt.
- Ein lokaler read-only Vollplan kann derzeit nicht dieselbe GitHub-API-
  Evidenz erbringen, da nicht authentifizierte API-Anfragen rate-limited waren;
  der Workflow übergibt seinen minimal berechtigten `github.token` nur an vier
  Resolver-Schritte. Es wurde kein lokaler Token kopiert oder persistiert.
- Keine GitHub-Issue-, Merge-, Parent-Gitlink- oder MRTS-Aktion wurde
  durchgeführt.

## Einschränkungen und Restrisiko

Hosted-App-Token, Default-Branch-Schutz, GitHub-API-Verhalten und SonarQube-
Cloud-Analyse benötigen weiterhin den vertrauenswürdigen CI-Lauf für den
exakten Head und menschliche Review. Diese Kontrollen werden lokal weder
abgeschwächt noch simuliert.

## Finaler Diff- und Review-Status

Der finale Task-Diff umfasst den gemeinsamen Maintenance-Workflow,
kanonische Pin-Autorität und generierte Views, Runtime-Serienprojektionen,
Sicherheitsverträge, Regressionstests, gepaarte Dokumentation und diesen
Change Record. Lokale Whitespace-, Link-, Bilingual-, Change-Record-, Runtime-
und Sicherheitsvertragsprüfungen bestanden. Ein unabhängiger finaler
Security-Diff-Review fand kein berichtspflichtiges High-, Critical- oder
Medium-Issue nach der Remediation. Die historische Provenance-Suite bestand
mit 107 Tests (einer absichtlich übersprungen), einschließlich der
ModSecurity-v3-Regression foreign-repository/no-network. Credentials, Tokens,
Rohlogs und sensible Payloads sind nicht enthalten.
