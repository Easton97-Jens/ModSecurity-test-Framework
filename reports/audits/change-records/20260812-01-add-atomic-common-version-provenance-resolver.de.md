# Change Record: 20260812-01-add-atomic-common-version-provenance-resolver

**Sprache:** Deutsch | [English](20260812-01-add-atomic-common-version-provenance-resolver.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260812-01-add-atomic-common-version-provenance-resolver` |
| UTC-Datum | 2026-08-12 |
| Framework-Basisrevision | `209389022c942d83113f6be88bf31d25637352f0` |
| Issue oder Pull Request | Zum Zeitpunkt der Record-Erstellung keiner; Framework-Delivery und Pull-Request-Erstellung sind ausstehend. |

## Motivation und Problemstellung

Die bisherige Common-Version-Wartungslogik benötigte eine einzige prüfbare
Quelle der Wahrheit für jede erfasste externe Komponenten-Provenance-Eingabe.
Die Änderung führt einen datengetriebenen Resolver ein, der sichere
automatische Updates von Version, URL und Digest von Provenance-Entscheidungen
mit notwendiger Prüfung und von Metadaten unterscheiden kann, die nie zu einer
Updater-Eingabe werden dürfen.

## Betroffene Komponenten und Sicherheitsgrenzen

Die reine Framework-Änderung betrifft `ci/lib/common.sh`,
`ci/tools/check-common-versions.py`, ihren Workflow und Regression-/Security-
Checks sowie die gepaarte Variablenreferenz. Die Grenze beginnt bei offiziellen
Upstream-Metadaten für Release, Listing, Prüfsumme und Git-Tag und endet bei
einem validierten atomaren Kandidaten für `ci/lib/common.sh`. Der Resolver
weist unerwartete URL-Redirects, nicht zugewiesene oder mehrfach besessene
Provenance-Variablen und unsichere Update-Zustände ab. Parent, MRTS, Gitlinks,
Connector-Runtime-Verhalten und Produktions-Deployment liegen außerhalb dieser
Änderung.

## Akzeptanzkriterien

1. Eine Komponenten-Registry deklariert Eigentümer, Resolver-Strategie,
   offizielle Quelle, Update-Policy, Prüfsummenstrategie und atomare
   Update-Gruppe jeder Provenance-Variablen.
2. Automatische Komponenten aktualisieren ihre voneinander abhängigen Werte
   für Version, URL, Asset und SHA-256 als eine validierte Gruppe.
3. CRS und ModSecurity v3 bleiben manuelle Prüfentscheidungen auf Basis
   stabiler Tag- und unveränderlicher aufgelöster Commit-Provenance.
4. Lokale oder nicht zur Beschaffung gehörende Metadaten sind explizit
   `not_applicable`.
5. Exakte Komponenten-Auswahl und Registry-Auflistung sind für CLI und
   optionale manuelle Workflow-Dispatch verfügbar.
6. Englische und deutsche Dokumentation beschreiben denselben Vertrag, ohne
   ein nicht beobachtetes Delivery-Ergebnis zu behaupten.

## Untersuchte Alternativen

- Komponenten-Resolver-Policy in unabhängigen Funktionen zu pflegen wurde
  verworfen, weil Ownership-, Kompatibilitäts- und Atomaritätsregeln driften
  könnten.
- Jede erfasste Variable automatisch erneuerbar zu behandeln wurde verworfen,
  weil geprüfte Tag/Commit-Pins und lokale Hinweise unterschiedliche
  Vertrauensgrenzen haben.
- Eine Version getrennt von abgeleiteten URLs oder Digests zu aktualisieren
  wurde verworfen, weil dies ein inkonsistentes Provenance-Tupel erzeugen kann.

## Implementierungsentscheidung

`COMPONENT_DEFINITIONS` zentralisiert die Komponentenverträge und verteilt auf
kleine strategie-spezifische Resolver. Der Resolver unterscheidet Datensätze
`automatic`, `manual_review` und `not_applicable`, erhält geprüfte Pins und
bricht bei `unknown`, `blocked` und `error` fail-closed ab. Automatische
Änderungen werden als atomare Gruppen gerendert und validiert, einschließlich
dynamischer URLs, die aus der aktualisierten Version abgeleitet werden.
`--list-components` legt exakte Registry-Namen offen; wiederholte exakte
Optionen `--component` begrenzen die Auflösung. Der geplante Workflow löst alle
Datensätze auf, sofern seine optionale `workflow_dispatch`-Eingabe `component`
nicht genau einen Datensatz auswählt.

## Geänderte Dateien und Tests

- `ci/lib/common.sh` enthält die vom Resolver verwendeten erfassten
  Provenance-Standards.
- `ci/tools/check-common-versions.py` enthält Komponenten-Registry,
  Resolver-Dispatch, atomare Kandidatenbehandlung und den CLI-Auswahlvertrag.
- `.github/workflows/check-common-versions.yml` übergibt die optionale
  manuelle Komponenten-Auswahl durch den Resolver-Workflow.
- CI-Security- und Provenance-Regression-Dateien decken den geänderten Vertrag
  ab.
- `docs/reference/variables.md` und `docs/reference/variables.de.md`
  dokumentieren Registry, Policies, Strategien offizieller Quellen, atomare
  URLs, CLI und Workflow-Auswahl.
- Dieser gepaarte Record bewahrt die Framework-eigene Entscheidung und den
  aktuellen Validierungsstatus.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | ---: | --- | --- |
| `git diff --check -- docs/reference/variables.md docs/reference/variables.de.md` | 0 | Keine Whitespace-Fehler in der gepaarten Resolver-Referenzaktualisierung. | Framework-Working-Tree |
| `make check-documentation` | 0 | Dokumentationslinks, Variablendokumentation, Repository-Pfade und Change-Record-Vertrag bestanden vor dem Hinzufügen dieses Record-Paars. | Framework-Working-Tree |
| `git diff --check -- reports/audits/change-records/20260812-01-add-atomic-common-version-provenance-resolver.md reports/audits/change-records/20260812-01-add-atomic-common-version-provenance-resolver.de.md` | 0 | Keine Whitespace-Fehler im gepaarten Change Record. | Framework-Working-Tree |
| `make check-documentation` | 0 | Dokumentationslinks, Variablendokumentation, Repository-Pfade und der finale Change-Record-Vertrag bestanden mit diesem Record-Paar. | Framework-Working-Tree |

## Sicherheitsauswirkung

Dies betrifft die Provenance- und CI-Wartungsgrenze. Es stärkt die Abbildung
von offiziellen Metadaten zu Kandidatenwerten durch zentralisierte Ownership,
Erzwingung atomarer Gruppen und Beibehaltung manueller Prüfung für
unveränderliche Git-Provenance. In diesem Record-Subtask wurden keine
Runtime-Security-Remediation, Exploit-Reproduktion, Connector-Runtime-Behauptung
oder Deployment-Aktion ausgeführt.

## Dokumentation und Runtime-Evidenz

Die gepaarte Variablenreferenz dokumentiert den neuen Resolver-Vertrag auf
Englisch und Deutsch. Keine Host-Runtime, Connector-Lifecycle, GitHub-Actions-
Ausführung, kein Pull Request, Review, Merge, Parent-Aktion, MRTS-Aktion oder
Gitlink-Update wurde beobachtet oder als Evidenz gesammelt.

## Nicht ausgeführte Prüfungen

- Fokussierte Resolver-, CI-Security- und Regressionstests wurden von diesem
  reinen Record-Subtask nicht ausgeführt; ihre Ausführung obliegt dem
  Implementierungs-Owner.
- Hosted-Checks, SonarQube, Review und Branch-Protection-Checks sind bis zu
  einem künftigen autorisierten Pull Request ausstehend.

## Einschränkungen und Restrisiko

Upstream-Release- und Prüfsummendaten sind zeitvariabel. Der lokale Vertrag des
Resolvers ersetzt keinen künftigen geprüften Kandidaten oder eine Hosted-
Validierung. Manuelle CRS- und ModSecurity-v3-Provenance-Entscheidungen bleiben
absichtlich Grenzen menschlicher Prüfung. Dieser Record belegt keine
Connector-Kompatibilität oder Runtime-Reife.

## Finaler Diff- und Review-Status

Dieser Record ist eine uncommittete lokale Framework-Ergänzung. Seine gepaarte
Übersetzung, finale Whitespace-Prüfung und finale Dokumentationsprüfung haben
bestanden. Es werden kein Commit, Push, Pull Request, Hosted-Check, Review,
Merge, Parent-Änderung, MRTS-Änderung oder Gitlink-Update behauptet.
