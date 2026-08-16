# Change Record: 20260816-05-preserve-fatal-maintenance-summary

**Sprache:** [English](20260816-05-preserve-fatal-maintenance-summary.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260816-05-preserve-fatal-maintenance-summary` |
| UTC-Datum | `2026-08-16` |
| Framework-Basisrevision | `5115281e6ba5245ab90ab4cddc926944cab88aba` |
| Issue oder Pull Request | Master-Dispatch `31972254226`; Status eines Follow-up-Reparatur-PRs und Merge sind durch diesen Record nicht belegt. |

## Motivation und Problemstellung

Der Follow-up-Master-Dispatch scheiterte nach dem hash-gesperrten Dependency-
Bootstrap erneut im kanonischen Resolver. Der Hosted-Job zeigte den Resolver-
Fehler, bewahrte den erzeugten Plan aber nicht in seiner Job-Zusammenfassung,
weil die Shell vor dem Summary-Append beendet wurde. Die Korrektur muss
nützliche Plan-Evidenz bewahren und zugleich fatale Resolver-Ergebnisse
nicht-null und fail-closed halten.

## Betroffene Komponenten und Sicherheitsgrenzen

Die betroffene Grenze ist der kanonische Framework-Maintenance-Resolver mit
seinem vertrauenswürdigen GitHub-Actions-Job. Der Resolver darf das bestehende
jobbezogene read-only-Token nur für exakte HTTPS-Requests an `api.github.com`
verwenden. Redirects werden abgewiesen und Geheimnisse nie offengelegt. Der
eigenständige Workflow-Tool-Reader bleibt tokenfrei; die repositorybegrenzte
Publisher-App-Token-Grenze bleibt unverändert. Parent, Connector-Runtime und
MRTS liegen außerhalb des Scopes.

## Akzeptanzkriterien

1. Die erzeugten JSON- und Markdown-Pläne werden auch dann auf Existenz
   geprüft, wenn der Resolver einen fatalen Nicht-Null-Code zurückgibt.
2. Der Markdown-Plan wird vor der Rückgabe dieses Resolvercodes an
   `GITHUB_STEP_SUMMARY` angehängt; der Hosted-Job bleibt damit fehlgeschlagen,
   aber diagnostizierbar.
3. API-Authentifizierung bleibt auf exakte Autorität (`https://api.github.com`)
   beschränkt, ohne Redirects oder Token-Offenlegung.
4. Keine Publisher-, Berechtigungs-, Auto-Merge- oder Direct-Master-Grenze wird
   erweitert.
5. Frische PR-/Hosted-Evidenz beweist finalen Head und resultierenden Master;
   SonarQube Cloud muss null neue Issues und null Duplizierung in neuem Code
   melden.

## Untersuchte Alternativen

- Erfolg nach einem fatalen Resolver-Ergebnis wurde abgelehnt, weil dadurch ein
  unvollständiger Maintenance-Plan veröffentlichbar würde.
- Den Plan bei einem Fehler nicht zusammenzufassen wurde abgelehnt, weil dies
  die Diagnose verpflichtender globaler Scope-Fehler erschwert.
- Das read-only-Token an alle Requests zu senden oder Redirects zu folgen
  wurde abgelehnt, weil dadurch die API-Credential-Grenze überschritten wird.
- Die Token-Berechtigungen des eigenständigen Workflows zu ändern wurde
  abgelehnt, weil dieser Reader bewusst tokenfrei ist.

## Implementierungsentscheidung

Die kanonische Maintenance-Shell merkt sich den Resolver-Exit-Code, lässt den
Resolver seinen erzeugten Plan fertig schreiben, prüft beide Plan-Dateien,
hängt den Markdown-Plan an die Hosted-Job-Zusammenfassung an und beendet sich
anschließend mit demselben Nicht-Null-Code. Der API-Client des Resolvers bleibt
auf exakte HTTPS-Nutzung von `api.github.com` mit dem vorhandenen read-only-
Token begrenzt, weist Redirects ab und gibt das Credential nie aus. Dieser
Record dokumentiert Design und beobachteten Fehler; der Nachweis des
resultierenden Masters bleibt ausstehend.

## Geänderte Dateien und Tests

Der Scope des integrierten Follow-up-PRs umfasst den kanonischen Maintenance-
Workflow und Resolver, ihren Security-Contract, fokussierte Resolver-/HTTP-
Regressionstests sowie die gepaarte englische/deutsche Reader-Dokumentation
und dieses Change Record. Im aktuellen Worktree umfasst er
`.github/workflows/check-common-versions.yml`,
`ci/tools/check-common-versions.py`,
`ci/checks/security/check-ci-security-contract.py`,
`tests/ci_security/test_unified_common_maintenance_workflow.py` und
`tests/security_regression/test_common_version_http_client.py` sowie die vier
Leitfaden-Dateien und diesen gepaarten Record. Source-, Workflow- und
Teständerungen sind parallele Implementierungsarbeit desselben PRs; dieser
Dokumentations-Slice selbst änderte nur Leitfaden- und Change-Record-Dateien.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `gh run view 31972254226 --json ...` | `0` | Master-Lauf scheiterte in `canonical-maintenance` bei der Auflösung mit Exit 2 nach Dependency-Installation und `pip check`; Head `5115281`. | [Lauf 31972254226](https://github.com/Easton97-Jens/ModSecurity-test-Framework/actions/runs/31972254226) |
| `gh run view 31972254226 --log-failed` | `0` | Hosted-Log bestätigt den Resolver-Aufruf mit read-only-Token und Exit 2; die Plan-Summary-Korrektur war in diesem Lauf noch nicht bewiesen. | [Lauf 31972254226](https://github.com/Easton97-Jens/ModSecurity-test-Framework/actions/runs/31972254226) |
| Dokumentations-/Change-Record-Validierung | `0` | Link-, Bilingual-Paar-, Pfadreferenz- und Change-Record-Contracts bestanden. | Task-Worktree |
| `git diff --check` | `0` | Keine Whitespace-Fehler im Dokumentations-Slice. | Task-Worktree |

## Sicherheitsauswirkung

Die Korrektur bewahrt Fehlersemantik und verbessert Fehler-Evidenz. Sie
erweitert weder die API-Token-Autorität noch erlaubt sie Redirects, legt kein
Geheimnis offen und verändert keine Publisher-Fähigkeiten. Hosted-Validierung
des finalen Fixes und SonarQube Clouds Nullmetriken bleiben erforderlich.

## Dokumentation und Runtime-Evidenz

Die englischen/deutschen Leitfäden halten den beobachteten Lauf und das
geplante Verhalten fest. Lauf `31972254226` ist ausschließlich Fehler-Evidenz;
er beweist weder Follow-up-Korrektur, PR-Merge, resultierenden Master noch
SonarQube Clouds Anforderungen von null neuen Issues und null Duplizierung.

## Nicht ausgeführte Prüfungen

- Frische Exact-Head-Hosted-Checks, SonarQube Cloud, Protected-Branch-Merge und
  resulting-master-Dispatches waren bei diesem Record nicht verfügbar.
- Source-Regressionstests liegen außerhalb dieses dokumentationsbezogenen
  Slices.

## Einschränkungen und Restrisiko

Bis ein frischer Hosted-Lauf das Verhalten beweist, bleibt ein fataler
Resolver-Fehler ein Release-/Integrationsblocker. Die Plan-Zusammenfassung muss
sichtbar sein, während der Workflow weiterhin fehlschlägt; SonarQube Cloud muss
vor der Integration unabhängig null neue Issues und null Duplizierung in neuem
Code melden.

## Finaler Diff- und Review-Status

Der integrierte PR enthält den oben aufgeführten Source-, Workflow-,
Regressionstest-, Leitfaden- und Change-Record-Scope. Dieser Agent änderte nur
Leitfaden- und Change-Record-Dateien; hier wurden keine Code-, Workflow- oder
Testdateien geändert. Durch diesen Dokumentations-Slice wurde nichts gestaged,
committed, gepusht, gemerged oder dispatcht. Hosted-Verifikation,
SonarQube-Cloud-Ergebnisse und Delivery liegen beim Parent-Agent und werden
von diesem Record nicht behauptet.
