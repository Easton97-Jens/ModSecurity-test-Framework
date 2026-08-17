# Change Record: 20260817-01-fix-maintenance-plan-optional-fields

**Sprache:** [English](20260817-01-fix-maintenance-plan-optional-fields.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260817-01-fix-maintenance-plan-optional-fields` |
| UTC-Datum | `2026-08-17` |
| Framework-Basisrevision | `b2816eb3e7fcdd974125d801b49e545f43d47f44` |
| Issue oder Pull Request | Neu bestätigter Producer-/Reconciler-Kompatibilitätsfehler; dieses Protokoll stellt keinen Pull-Request- oder Merge-Erfolg fest. |

## Motivation und Problemstellung

Der kanonische Maintenance-Producer gibt die optionalen
`component_results`-Felder `current`, `latest_compatible`, `latest_upstream`
und `source` in seinen Records aus. Wenn kein Wert verfügbar ist, verwendet er
einen leeren String. Der Validate-only-Reconciler muss diese Producer-Ausgabe
als gültige begrenzte Planform akzeptieren und zugleich nicht-leere
`source`-Werte weiterhin als HTTPS-URLs prüfen. Der Fehler wurde nach der
Behebung des Mandatory-Global-Scope-Problems als CI-Vertragslücke bestätigt.

## Betroffene Komponenten und Sicherheitsgrenzen

Betroffen ist die vertrauenswürdige JSON-Plan-Grenze zwischen
`ci/tools/canonical_maintenance.py` und
`ci/tools/reconcile-common-version-review-issues.py` mit fokussierter
CI-Security-Regression. Parent, Connector-Runtime und der schreibgeschützte
Checkout `tools/MRTS` liegen außerhalb des Scopes.

## Akzeptanzkriterien

1. Vom Producer ausgegebene leere Strings für die vier optionalen Ergebnisfelder
   werden von der Validate-only-Normalisierung akzeptiert.
2. Nicht-leere optionale Werte bleiben begrenzt; nicht-leere `source`-Werte
   müssen weiterhin HTTPS-URLs sein.
3. Das Kompatibilitätsverhalten gilt für verbindliche globale sowie
   ausgewählte Runtime-/Source-Records, ohne Plan-, Digest-, Scope- oder
   Issue-Reconciliation-Prüfungen zu schwächen.
4. Englische und deutsche Dokumentation beschreiben denselben Vertrag.

## Untersuchte Alternativen

- Das Entfernen der optionalen Felder aus der Producer-Ausgabe wurde abgelehnt,
  da Planschema und Hosted-Summary-Verbraucher ihre stabile Präsenz nutzen.
- Leere Strings als ungültige Pflichtwerte zu behandeln wurde abgelehnt, weil
  der Producer sie bewusst für nicht verfügbare Hinweisdaten verwendet.
- Die Validate-only-Normalisierung abzuschalten wurde abgelehnt, da dies eine
  fail-closed-Integritätsgrenze des Maintenance-Workflows entfernen würde.

## Implementierungsentscheidung

Der Producer-/Reconciler-Vertrag behält die vier optionalen Felder bei,
akzeptiert ihre begrenzte Darstellung als leere Strings und behält die
HTTPS-Prüfung für nicht-leeres `source` bei. Erforderliche Identitäts-, Scope-,
Digest-, Collection- und Issue-Reconciliation-Prüfungen bleiben unverändert.
Die beiden Sicherheitsleitfäden dokumentieren diese Kompatibilitätsgrenze.

## Geänderte Dateien und Tests

Der Implementierungsscope ist der kanonische Maintenance-/Reconciler-Vertrag
und die fokussierten CI-Security-Regressionstests. Die exakte Source- und
Testdateiliste, Testanzahl und der finale Commit werden im Delivery-Update des
Implementierungsagents festgehalten und hier nicht als abgeschlossen
behauptet.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `git rev-parse HEAD` | `0` | Framework-Task-Basis als `b2816eb3e7fcdd974125d801b49e545f43d47f44` festgestellt. | Framework-Task-Worktree |
| `rtk proxy ./ci/tools/safe-make.sh check-documentation` | `0` | Dokumentationslinks, zweisprachige Variablen-/Pfadreferenzen und der Change-Record-Vertrag bestanden. | Framework-Task-Worktree |
| `rtk proxy git diff --check -- docs/security/ci-security-tooling.md docs/security/ci-security-tooling.de.md reports/audits/change-records/20260817-01-fix-maintenance-plan-optional-fields.md reports/audits/change-records/20260817-01-fix-maintenance-plan-optional-fields.de.md` | `0` | Die begrenzte Whitespace-Prüfung der vier Dokumentations-/Record-Dateien bestand. | Framework-Task-Worktree |

## Sicherheitsauswirkung

Die Kompatibilitätskorrektur erhält die Begrenzung der Felder und die
HTTPS-Schranke für nicht-leere `source`-Werte. Sie fügt keine Berechtigungen,
Credentials, Netzwerkautorität, Artefaktpfade oder automatische
Schreibfähigkeit hinzu und schwächt weder globale Scope- noch
Digest-Prüfungen.

## Dokumentation und Runtime-Evidenz

Die englische und deutsche Sicherheitsdokumentation beschreibt den optionalen
Producer-/Reconciler-Feldvertrag. Dieses Protokoll stellt keine neue Hosted-
Runtime-, Pull-Request-, SonarQube-Cloud- oder Merge-Evidenz fest.

## Nicht ausgeführte Prüfungen

- Fokussierte Reconciler- und Canonical-Maintenance-Tests gehören zur
  Implementierungsarbeit und werden hier nicht als bestanden dargestellt.
- Vollständiger Framework-Lint, Hosted-Checks, SonarQube-Cloud-Analyse und
  Delivery-Prüfungen werden hier nicht als bestanden dargestellt.

## Einschränkungen und Restrisiko

Der Vertrag bleibt in Hosted CI unverifiziert, bis die Implementierung mit
Regressionstests ausgeliefert ist und ein späterer Workflow-Lauf erfolgreich
abschließt. Die vom Benutzer geforderten SonarQube-Cloud-Bedingungen bleiben
vor jedem Merge verbindlich.

## Finaler Diff- und Review-Status

Diese Dokumentations-Teilaufgabe ändert ausschließlich die beiden
Sicherheitsleitfäden und dieses zweisprachige Change Record. Es wurden keine
Source-/Test-, Git-, GitHub-, Parent-Gitlink- oder MRTS-Aktionen ausgeführt.
