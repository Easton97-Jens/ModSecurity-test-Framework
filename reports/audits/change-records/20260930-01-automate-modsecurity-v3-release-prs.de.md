# Automatische Update-PRs für ModSecurity-v3-Releases vorbereiten

**Sprache:** [English](20260930-01-automate-modsecurity-v3-release-prs.md) | Deutsch

## Änderungsidentität und Status

- Change-ID: `20260930-01-automate-modsecurity-v3-release-prs`
- Zugehöriges Issue: #129
- Status: Implementierungsentwurf; nicht für Integration oder Runtime-Nutzung verifiziert.
- Basisrevision: `5cd7a7f96811b6d3021ce3c1e36bbc5d308806fb`.
- Commit der Kernimplementierung: `6b8f698cf1a8e83767b3cfd45b53da3c9b18e289`.

## Motivation und Problemstellung

Issue #129 meldet den ModSecurity-v3-Releasewechsel von `v3.0.16` auf
`v3.0.17` als manuelle Provenienzprüfung. Der bestehende Wartungsworkflow
ermittelt bereits Abhängigkeitskandidaten und veröffentlicht Update-PRs.
Der ModSecurity-v3-Descriptor und sein spezialisierter Resolver wählen
jedoch noch den manuellen Pfad. Dieser Entwurf veröffentlicht die zuvor
vorbereitete Kernänderung zur Prüfung.

## Framework-eigene Implementierung

In `ci/tools/check-common-versions.py` werden vier Zeilen geändert:
Update-Policy, Kompatibilitätsbeschreibung, Resolver-Docstring und der
Aufruf von `check_manual_git_provenance` zu
`check_automatic_git_provenance`. Diese Änderung hebt keinen Release-Pin an.

Das erlaubte Releaseformat bleibt `v3.x.y`, einschließlich stabiler
Minor-Releases innerhalb von v3, nicht nur Patch-Releases von v3.0.
Andere Hauptversionen werden nicht zur automatischen Anwendung ausgewählt.
Der feste Upstream-Repository-Hash, die aktuelle Tag/Commit-Prüfung, der
Resolver für vollständig aufgelöste Commits, Alias-Prüfungen und die atomare
Tag/Commit-Gruppe bleiben unverändert. Diese Provenienzprüfungen belegen
weder Connector-Kompatibilität noch die Sicherheit eines Upstream-Releases.

## Validierung und Evidenz

Der veröffentlichte Kerncommit wurde über GitHub zurückgelesen. Sein Diff
enthält genau die vier vorgesehenen Zeilenersetzungen in der einen
Implementierungsdatei. Für diesen Entwurf wird keine erfolgreiche
Kompilierung der vollständigen Datei und kein erfolgreicher Unit-,
Integrations- oder Runtime-Test behauptet.

Ein lokaler Repository-Abruf scheiterte daran, dass `github.com` in der
Ausführungsumgebung nicht aufgelöst werden konnte. Die vom Repository
vorgesehene Umgebung und RTK waren nicht verfügbar. Die Veröffentlichung
erfolgte über den GitHub-Connector; das Lesen entfernter Dateien ist keine
Ausführungsevidenz.

## Noch offene Akzeptanzkriterien

- Vorhandene rein manuelle ModSecurity-Testfixtures und Erwartungen anpassen
  und die verbleibende Klassifizierung in `MANUAL_REVIEW_VARIABLES` prüfen.
- Automatische Kandidatenerstellung und einen anschließend aktuellen
  Zustand, atomare Tag/Commit-Updates, annotierte und einfache Tags,
  verschobene Tags, ungültige Repositories, Alias-Abweichungen, Prereleases
  und Releases außerhalb von v3 prüfen.
- Anwendung des kanonischen Plans, Konsistenz generierter Ansichten und
  Review-Issue-Abgleich ohne vorzeitigen Issue-Abschluss verifizieren.
- Die gepaarten Variablenreferenz- und Workflow-Sicherheitsdokumente aktualisieren.
- Betroffene Regressionstests ausführen und erforderliche Runtime-/Smoke-
  Evidenz erheben, bevor die Implementierung als integrationsbereit gilt.

## Dokumentation, Auslieferung und Grenzen

Dieser gepaarte Change Record wird ergänzt. Bestehende Policy-Dokumente
und generator-eigene Ausgaben werden bewusst nicht so umgeschrieben, als
wären die offenen Arbeiten bereits abgeschlossen. Tests und Workflows
bleiben unverändert.

Die Auslieferung beschränkt sich auf den Aufgabenbranch und einen Draft-PR.
Es erfolgen kein Merge, kein direkter `master`-Update, keine Auto-Merge-
Aktivierung und keine Änderung am Branch-Schutz. Issue #129 wird
referenziert, nicht geschlossen. Parent-Auswirkung: keine.
Parent-Gitlink-Disposition: `unchanged`. MRTS-Auswirkung:
`default_read_only`; keine MRTS-Änderungen. Es wird weder eine
Connector-Promotion noch Runtime-Unterstützung behauptet.

## Sicherheit und Restrisiko

Automatisierte Provenienzprüfungen ersetzen die rein manuelle
Kandidatenklassifizierung; sie sind keine menschliche Prüfung von
Migrationshinweisen. Bestehende Sicherheitsprüfungen bleiben erhalten,
aber die Verhaltensänderung bleibt bis zum Abschluss der offenen Tests
und Dokumentationsarbeiten unverifiziert. Die Änderung enthält keine
Secrets, Tokens, privaten Payloads oder Runtime-Logs.
