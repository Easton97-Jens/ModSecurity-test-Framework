# Change Record: 20260816-04-harden-github-api-auth-boundary

**Sprache:** [English](20260816-04-harden-github-api-auth-boundary.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260816-04-harden-github-api-auth-boundary` |
| UTC-Datum | `2026-08-16` |
| Framework-Basisrevision | `a5cbfff185cad3810fcafad534dc334be92a0df8` |
| Issue oder Pull Request | Master-Dispatches `31968050889` und `31968224482`; Reparatur-Branch wartet auf Veröffentlichung. |

## Motivation und Problemstellung

Der kanonische Maintenance-Resolver schlug in den Hosted-Master-Läufen bei
der Auflösung des verpflichtenden globalen Inventars fehl. Die Korrektur muss
das bestehende read-only-GitHub-Token für die API-Aufrufe nutzbar machen, die
Authentifizierung benötigen, und zugleich die Framework-Supply-Chain-Grenze
bewahren: kein Token an Nicht-API-Hosts, keine Credential-Offenlegung, kein
Redirect zu einer anderen Autorität und keine Erweiterung der
Publisher-Berechtigungen.

## Betroffene Komponenten und Sicherheitsgrenzen

Die betroffene Grenze ist der Framework-CI-Maintenance-Resolver mit seinem
GitHub-API-Client. Der eigenständige Reader `update-workflow-tools.yml` bleibt
tokenfrei. Nur die explizit überprüften Resolver-, Reconciliation- und
Re-Resolver-Schritte des kanonischen Maintenance-Workflows dürfen das
bestehende jobbezogene read-only-`GITHUB_TOKEN` erhalten. Das kurzlebige,
repositorybegrenzte App-Token des Publishers und seine Draft-only-Grenze
bleiben unverändert. Parent, Connector-Runtime und MRTS liegen außerhalb des
Scopes.

## Akzeptanzkriterien

1. Ein Bearer-Token wird nur an die exakte HTTPS-Autorität
   `api.github.com` gesendet.
2. Redirects werden vor oder bei der Response-Prüfung abgewiesen, ohne das
   Token an einen weitergeleiteten Host zu kopieren.
3. Tokens erscheinen nie in Plänen, Zusammenfassungen, Diagnosen oder Fehlern.
4. Unerwartete HTTP-Antworten, einschließlich 403/429, bleiben fail-closed;
   Publisher-Rechte bleiben unverändert.
5. Frische Hosted-Checks beweisen Korrektur, resultierenden Masterstand und
   SonarQube Clouds `0` neue Issues sowie `0,0 %` Duplizierung in neuem Code.

## Untersuchte Alternativen

- Den eigenständigen Workflow tokenfähig zu machen wurde abgelehnt, weil dies
  eine unabhängige Reader-Grenze erweitern würde.
- Das Token an jeden HTTPS-Request zu senden wurde abgelehnt, weil Release- und
  Download-Hosts nicht die GitHub-API-Autorität sind.
- Redirects zu folgen wurde abgelehnt, weil ein gültiges API-Token dadurch
  eine nicht vertrauenswürdige Autoritätsgrenze überschreiten könnte.
- Den Resolver-Fehler zu unterdrücken oder die Kontrolle zu schwächen wurde
  abgelehnt, weil das verpflichtende globale Inventar fail-closed bleiben muss.

## Implementierungsentscheidung

`github_payload()` baut nur feste, repositorybezogene HTTPS-GitHub-API-URLs,
akzeptiert nur den überprüften Release-Page-Query und setzt das bestehende
read-only-Credential nur, wenn `GITHUB_TOKEN` vorhanden ist. Es weist
fehlerhafte Token-Control-Zeichen vor dem Aufbau eines Requests zurück,
deaktiviert Redirects, bevor sie Request-Header weiterleiten können, und weist
eine geänderte finale URL vor dem Lesen einer Response ab. Der eigenständige
Workflow bleibt tokenfrei; der Publisher-/App-Token-Vertrag bleibt unverändert.
Hosted-PR-, SonarQube-Cloud-, Merge- und resultierende-Master-Evidenz bleiben
bis zu frischer Beobachtung ausstehend.

## Geänderte Dateien und Tests

- `ci/tools/update-workflow-tools.py` verwendet das bestehende optionale
  read-only-Credential nur für einen festen GitHub-API-Request und weist
  fehlerhafte API-Pfade, Token-Control-Zeichen, Redirects und finale
  URL-Änderungen ab.
- `tests/ci_security/test_update_workflow_tools.py` deckt fehlende/vorhandene
  Credentials, Origin-/Pfadgrenzen, Redirect-Ablehnung und die redigierte
  Ablehnung fehlerhafter Tokens ab.
- `docs/github-actions-workflow-security.md` und sein deutscher Begleiter
  dokumentieren Credential-, Redirect-, Rate-Limit- und Hosted-Evidenz-Grenzen.
- `docs/security/ci-security-tooling.md` und sein deutscher Begleiter trennen
  den tokenfreien eigenständigen Reader vom kanonischen Maintenance-Aufrufer.
- Dieses englische/deutsche Change-Record-Paar hält beobachteten Fehler, lokale
  Korrekturevidenz und noch ausstehende Hosted-Evidenz fest.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `gh run view 31968050889 --json ...` | `0` | Master-Lauf scheiterte in `canonical-maintenance` beim Resolver mit Exit 2 nach Dependency-Bootstrap und `pip check`; Head `a5cbfff`. | [Lauf 31968050889](https://github.com/Easton97-Jens/ModSecurity-test-Framework/actions/runs/31968050889) |
| `gh run view 31968224482 --json ...` | `0` | Derselbe beobachtete Fehler auf demselben Master-Head; nur der Ergebnisjob war erfolgreich, weil er den fehlgeschlagenen Resolver zusammenfasste. | [Lauf 31968224482](https://github.com/Easton97-Jens/ModSecurity-test-Framework/actions/runs/31968224482) |
| `python -m unittest -v tests.ci_security.test_update_workflow_tools` | `0` | 33 Updater-Tests bestanden, einschließlich optionalem Token, ohne Redirect, ungültigem Pfad und Token-Control-Zeichen. | Task-Worktree |
| `python ci/checks/security/check-ci-security-contract.py` | `0` | Bestehender CI-Sicherheitsvertrag bestand ohne Berechtigungs- oder Publisher-Grenzänderung. | Task-Worktree |

## Sicherheitsauswirkung

Die implementierte Änderung verringert Credential-Exposition, weist
fehlerhafte Token-Werte ohne Wiederholung zurück und verhindert
Credential-Weitergabe über Redirects. Sie verändert weder das Connector-
Runtime-Verhalten noch verleiht sie Publisher-Autorität. Die Controls wurden
bei diesem Record noch nicht durch einen frischen Hosted-Lauf bewiesen.

## Dokumentation und Runtime-Evidenz

Der englische/deutsche Workflow-Sicherheitsleitfaden dokumentiert nun die
exakte API-Autorität, read-only-Token-Nutzung, Redirect-Ablehnung,
Token-Nichtoffenlegung, unveränderte Publisher-Grenze und die beiden
beobachteten Master-Fehler. Die Source-Regressionen belegen die lokalen
Korrektur-Controls. Die Läufe belegen weiterhin nur den Fehler; sie beweisen
weder eine erfolgreiche Hosted-Korrektur, einen Merge, den resultierenden
Masterstand noch SonarQube Clouds Nullmetriken.

## Nicht ausgeführte Prüfungen

- Frische PR-Checks, SonarQube Cloud, Protected-Branch-Merge und
  Post-Merge-Master-Dispatches sind bei dieser Record-Aktualisierung noch
  nicht verfügbar.

## Einschränkungen und Restrisiko

Bis zur Veröffentlichung und erneuten Ausführung bleibt der Hosted-Resolver-
Fehler offen. SonarQube Cloud muss unabhängig null neue Issues und null
Duplizierung in neuem Code melden, bevor die Integration als verifiziert gilt.

## Finaler Diff- und Review-Status

Der Task-Diff enthält API-Client und fokussierte Tests, gepaarte
englische/deutsche Sicherheitsdokumentation sowie dieses Change-Record-Paar.
Es wurde nichts gestaged oder committed, kein Branch gepusht und kein PR- oder
Master-Write ausgeführt. Der Parent-Agent ist für Hosted-Verifikation und
Delivery-Entscheidungen zuständig.
