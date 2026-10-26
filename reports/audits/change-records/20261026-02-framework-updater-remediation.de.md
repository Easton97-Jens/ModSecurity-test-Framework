# Framework-Updater: Bereitschaftsfehler beheben

**Sprache:** [English](20261026-02-framework-updater-remediation.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261026-02-framework-updater-remediation |
| UTC-Datum | 2026-10-26 |
| Framework-Basisrevision | e337869 |
| Issue oder Pull Request | [PR #138](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/138) |

## Motivation und Problemstellung

Die geplante Common-Wartung stoppte an einer leeren Statusnachricht des generierten Katalogs (Lauf 40317131728); die Python-Wartung wählte einen veröffentlichten Patch, bevor dessen setup-python-Runner-Build vorlag (Lauf 40328143037). Dem neuen generierten Sonar-Workflow fehlte außerdem die automatische Publisher-Pfadfreigabe.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-Planer, Python-Metadaten-Preflight, exakte generierte Publisher-Pfade und strenger Checker. Parent-Gitlink unverändert; MRTS bleibt read-only.

## Akzeptanzkriterien

Stille Generatoren behalten ausdrückliche, nicht leere und begrenzte Statusmeldungen; neueste Python-Kandidaten benötigen offizielles Release und exakten gepflegten Runner-Build; alle Sonar-Update-Pfadverträge stimmen überein. Bestehende Pins erhalten; keine Downgrades oder Erweiterung von Token-Scope/Auto-Merge.

## Untersuchte Alternativen

Ein abgeschwächter Reconciler oder breite Workflow-Pfadfreigaben würden Vertragsfehler verstecken. Ein noch nicht veröffentlichter Interpreter lässt sich nicht installieren; stilles Auswählen eines älteren Kandidaten stellt das neueste Release falsch dar.

## Implementierungsentscheidung

Statusproduktion korrigieren, Consumer-Validierung erhalten, nur den Sonar-Workflow-Pfad ergänzen und sein exakt geprüftes Publisher-Profil aktualisieren. Beide Python-Resolver teilen eine begrenzte tokenlose Manifestprüfung ohne Redirects für Ubuntu 24.04/x64; Common- und separater Python-Workflow pinnen diesen Runner; der strenge Common-Vertrag lehnt Runner-Drift ab. Fehlende Builds liefern blockiert und erzeugen keine Quelländerung.

## Geänderte Dateien und Tests

Wartungsproducer, Python-Updater/Manifest-Helfer, Workflow-Tool-Pfadverträge, Common-/Python-Workflows, exakter Security-Checker, Offline-Bereitschafts- und bestehende Regressionen; gepaarte Workflow-Dokumentation.

## Befehle und Ergebnisse

Producer-/Consumer- sowie Pfad-/Bereitschaftsregressionen reproduzierten die ursprünglichen Fehler vor der Korrektur. 156 fokussierte Updater-/Security-Methoden bestanden danach; nach Abschluss des Runner-Vertrags bestanden 74 betroffene Workflow-/Installierbarkeits-/Security-Methoden. Logs liegen im externen Task-Evidenzverzeichnis. Der read-only Live-Python-Resolver meldete nach Aufholen des offiziellen Runner-Manifests aktuell 3.14.8, Kandidat 3.14.10, update_available und updated=false.

## Sicherheitsauswirkung

Keine Secret-Werte oder schreibfähigen Provider-Aktionen. Strenger begrenzter Reconciler, exakte Publisher-Pfade, App-Scopes, Draft-Pflicht und unabhängige Kandidatenvalidierung bleiben erhalten. Der Verfügbarkeits-Preflight ersetzt tatsächliche Installation/Kandidatenprüfung nicht.

## Dokumentation und Runtime-Evidenz

Gepaarte GitHub-Actions-Security-Dokumentation aktualisiert. Keine Connector-/Runtime-Tests oder neue Lifecycle-Evidenz.

## Nicht ausgeführte Prüfungen

Geplante Default-Branch-Veröffentlichung und tatsächlicher Wartungs-PR bleiben nach separat autorisierter Masterintegration ausstehend; keine Live-Veröffentlichung ausgelöst.

## Einschränkungen und Restrisiko

Offizielles Release und Runner-Manifest können unabhängig voneinander verfügbar werden; fehlende oder fehlerhafte Manifeste brechen sicher ab. Ein Offline-Test oder read-only Resolver beweist keinen erzeugten Wartungs-Branch oder PR.

## Finaler Diff- und Review-Status

Lokale Implementierung und fokussierte Evidenz zur Koordinatorprüfung und normalem PR-Follow-up vorbereitet. Keine Git-/Provider-Mutation durch diesen Worker.
