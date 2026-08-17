# Change Record: 20260816-07-fix-maintenance-plan-scope-reconciliation

**Sprache:** [English](20260816-07-fix-maintenance-plan-scope-reconciliation.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260816-07-fix-maintenance-plan-scope-reconciliation` |
| UTC-Datum | `2026-08-16` |
| Framework-Basisrevision | `79e2757c4cc99372ce140458a986edc2553f2bd9` |
| Issue oder Pull Request | Resulting-Master-Workflow-Lauf `31979182626`; dieses Protokoll stellt keinen Pull-Request- oder Merge-Erfolg fest. |

## Motivation und Problemstellung

Nach dem Merge der CodeQL-Release-Auflösung löste der Resulting-Master-Lauf
`31979182626` die verbindlichen globalen und ausgewählten Runtime-Scopes auf,
scheiterte aber im schreibgeschützten Review-Plan-Reconciliation-Schritt mit
Exit-Code 2. Der Fehler meldete, dass der Scope jede verbindliche globale
Komponente enthalten müsse. Der Plan stellte konkrete geprüfte Component-IDs
getrennt von aggregierten Ergebnis-Scopes dar; dadurch lehnte der Vergleich
aggregierter Namen mit der Component-ID-Liste eine gültige normalisierte
Ergebnisform ab.

## Betroffene Komponenten und Sicherheitsgrenzen

Betroffen ist die Review-Plan-Validierung in
`ci/tools/reconcile-common-version-review-issues.py` mit Regressionstests in
den CI-Security-Tests des Frameworks. Die relevante Grenze ist die Integrität
des vertrauenswürdigen CI-Maintenance-Plans: Die globale Abdeckung muss auch
bei einem Runtime-/Source-Component-Filter erhalten bleiben. Parent,
Connector-Runtime und der schreibgeschützte Checkout `tools/MRTS` liegen
außerhalb des Scopes.

## Akzeptanzkriterien

1. Eine normalisierte Planstruktur wird akzeptiert, wenn ihre konkreten
   geprüften Component-IDs alle verbindlichen globalen Ergebnis-Scopes abdecken.
2. Aggregierte Scopes werden aus normalisierten Ergebnissen geprüft, die den
   geprüften Component-IDs zugeordnet sind, nicht als Component-IDs.
3. Fehlende verbindliche globale Ergebnis-Scopes bleiben fail-closed.
4. Ein Component-Filter schränkt weiterhin nur zusätzliche Runtime-/Source-
   Komponenten ein; Go-FTW, Albedo und kanonische CI-Pins bleiben enthalten.
5. Doppelte normalisierte Component-IDs und nicht passende feste globale
   Scope-/Component-Zuordnungen werden zurückgewiesen, während die geprüften
   dynamischen Action-/Tool-Component-Familien zulässig bleiben.

## Untersuchte Alternativen

- Das Entfernen der Prüfung auf globale Pflichtergebnisse wurde abgelehnt, da
  jeder Maintenance-Lauf die globale Abdeckung behalten muss.
- Aggregierte Scope-Namen als Component-IDs zu behandeln wurde abgelehnt, weil
  das normalisierte Ergebnis-Modell konkrete Component-IDs und einen
  separaten aggregierten Scope verwendet.
- Component-gefilterte Pläne ohne globale Ergebnisse zuzulassen wurde
  abgelehnt, weil es den gemeinsamen Maintenance-Vertrag verletzen würde.

## Implementierungsentscheidung

Die Reconciliation behält den Vertrag der konkreten `checked_components` bei
und validiert die globale Pflichtabdeckung aus den `scope`-Werten der
normalisierten `component_results`, deren `component_id` geprüft wird. Damit
bleibt die fail-closed-Anforderung erhalten und entspricht dem Ergebnis-Modell
des Resolvers. Der Validator weist zusätzlich doppelte normalisierte
Component-IDs zurück und erzwingt die festen globalen Scope-/Component-
Zuordnungen; für Action- und Security-Tool-Component-Familien gelten explizite
dynamische Präfixe. Die englische und deutsche Sicherheitsdokumentation
beschreibt die globalen Scope- und Filtersemantiken.

## Geänderte Dateien und Tests

Implementierung und Regressionstests decken normalisierte globale
Ergebnis-Scopes, fehlende aggregierte Scopes, doppelte Ergebnis-IDs, nicht
passende feste Zuordnungen, zulässige dynamische Action-/Tool-Component-
Familien, nicht gelistete globale Komponenten, Lifecycle-Reconciliation und
die Planform des Validate-only-CLIs ab. Dieses Protokoll und die beiden
Sprachvarianten des Sicherheitsleitfadens dokumentieren die beobachtete
Störung und die Korrektur.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `gh run view 31979182626 --repo Easton97-Jens/ModSecurity-test-Framework --json headSha,jobs,conclusion` | `0` | Der Resulting-Master-Lauf auf `79e2757c4cc99372ce140458a986edc2553f2bd9` schloss die Scope-Auflösung ab und scheiterte danach in der schreibgeschützten Review-Plan-Reconciliation mit Exit-Code 2. | [Lauf 31979182626](https://github.com/Easton97-Jens/ModSecurity-test-Framework/actions/runs/31979182626) |
| `gh run view 31979182626 --repo Easton97-Jens/ModSecurity-test-Framework --log-failed` | `0` | Der fehlgeschlagene Schritt meldete, dass der Scope jede verbindliche globale Komponente enthalten müsse. | [Lauf 31979182626](https://github.com/Easton97-Jens/ModSecurity-test-Framework/actions/runs/31979182626) |
| `git diff --check -- docs/security/ci-security-tooling.md docs/security/ci-security-tooling.de.md reports/audits/change-records/20260816-07-fix-maintenance-plan-scope-reconciliation.md reports/audits/change-records/20260816-07-fix-maintenance-plan-scope-reconciliation.de.md` | `0` | Keine Whitespace-Fehler in Dokumentation und Change Record. | Framework-Task-Worktree |

## Sicherheitsauswirkung

Die Korrektur erhält die fail-closed-Prüfung der verbindlichen globalen
Abdeckung und schwächt die Grenze des Runtime-/Source-Component-Filters nicht.
Es werden keine neuen Berechtigungen, Credentials, Netzwerkautoritäten oder
Artefaktpfade eingeführt. Doppelte Ergebnis-IDs und unerwartete feste globale
Zuordnungen werden zurückgewiesen; erweiterbar bleiben ausschließlich die
geprüften dynamischen Component-Familien.

## Dokumentation und Runtime-Evidenz

Die englische und deutsche Sicherheitsdokumentation beschreibt, dass Go-FTW,
Albedo, kanonische Sprach-Pins und kanonische CI-Pins an jedem gemeinsamen
Maintenance-Lauf teilnehmen, während Filter nur zusätzliche Runtime-/Source-
Komponenten betreffen. Lauf `31979182626` ist ausschließlich beobachtete
Runtime-Fehler-Evidenz. Er belegt keinen erfolgreichen Korrekturlauf, kein
Pull-Request-Ergebnis, keinen Merge und kein SonarQube-Cloud-Ergebnis.

## Nicht ausgeführte Prüfungen

- Die vollständige fokussierte und gesamte Framework-Validierung gehört zur
  Implementierungsarbeit und wird durch diese Dokumentationsänderung nicht
  als erfolgreich behauptet.
- Ein erfolgreicher nachgelagerter Hosted-Lauf, Pull Request,
  SonarQube-Cloud-Ergebnis oder Master-Merge ist in diesem Protokoll nicht
  festgestellt.

## Einschränkungen und Restrisiko

Die Korrektur bleibt in Hosted CI unverifiziert, bis ein späterer Lauf zeigt,
dass Resolver und Reconciliation erfolgreich abschließen. Die vom Benutzer
geforderten SonarQube-Cloud-Bedingungen bleiben vor jedem künftigen Merge
verbindlich.

## Finaler Diff- und Review-Status

Diese Dokumentations-Teilaufgabe ändert ausschließlich die beiden
Sicherheitsleitfäden und die beiden Change-Record-Dateien. Die Dateien sind
für die Übergabe an den Implementierungsagenten unstaged und uncommitted.
Durch diese Teilaufgabe wurden kein Push, Pull Request, Merge, Parent-Gitlink-
Update oder MRTS-Aktion ausgeführt.
