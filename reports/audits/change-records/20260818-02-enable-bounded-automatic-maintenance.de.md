# Begrenzte automatische CRS-, HTX- und Node-Wartung aktivieren

**Sprache:** [English](20260818-02-enable-bounded-automatic-maintenance.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260818-02-enable-bounded-automatic-maintenance |
| UTC-Datum | 2026-08-18 |
| Framework-Basisrevision | de3fee7df541c3015609d6b46d04ac9e80973f59 |
| Issue oder Pull Request | Bei Abschluss der lokalen Validierung kein Pull Request; die Veröffentlichung eines Draft-PRs ist der nächste Delivery-Schritt. |

## Motivation und Problemstellung

Die angeforderte Wartungs-Policy macht CRS-v4-Releases, die unabhängige
HAProxy-HTX-Serie und Node.js-Updates automatisch. Die vorherigen Verträge
hielten CRS und HTX manuell und stoppten Node an einer Major-Review, was das
gewünschte Wartungsverhalten nicht erfüllte.

## Betroffene Komponenten und Sicherheitsgrenzen

- ci/tools/check-common-versions.py besitzt die Planung fester
  Origin-/Release-/Digest- und atomarer Updates für CRS und HAProxy HTX.
- ci/tools/canonical_maintenance.py wählt den kanonischen Node.js-Pin, den
  generierte Workflow-Ansichten verwenden.
- ci/lib/common.sh bleibt die kanonische Pin-Autorität; kein Pin-Wert und kein
  generierter Runtime-Lock wurden durch diese reine Policy-Änderung verändert.

Die relevante Grenze führt von externer Release-Metadaten zu kanonischen Pins
und danach zu Provisioning oder CI. Die Änderung erhält Host-Allowlist,
Stable-Release-Filter, unveränderliche aufgelöste Commits, SHA-256 pro Asset,
atomare Pläne und das unabhängige HTX-Profil.

## Akzeptanzkriterien

1. Nur stabile CRS-Tags, die v4.x.x entsprechen, dürfen das feste
   Repository-Tag und seinen aufgelösten Commit als atomares Paar aktualisieren.
2. HTX löst automatisch ausschließlich seine eigene konfigurierte
   HAProxy-Serie auf und ändert oder verwendet nie das generische HAProxy-Tuple.
3. Node wählt das neueste stabile numerische Release über Major-Linien hinweg,
   während generierte Workflows weiterhin einen exakten Literal-Pin erhalten.
4. Fehlerhafte, Prerelease-, unvollständige, fremde oder partielle Eingaben
   scheitern fail-closed.
5. Englische und deutsche Variablen-Dokumentation beschreiben denselben
   Wartungsvertrag.

## Untersuchte Alternativen

- Ein dynamischer Workflow-Wert node-version latest wurde abgelehnt, weil
  Workflow-Ausführungen mit Literal-Pins reproduzierbar bleiben müssen.
- Automatische CRS-v5-Übergänge wurden abgelehnt, weil die Anfrage auf v4.x.x
  begrenzt ist.
- Die Wiederverwendung generischer HAProxy-Werte für HTX wurde abgelehnt, weil
  beide Runtime-Profile unabhängige Provenance- und Kompatibilitäts-Tuples haben.
- Alle drei Pfade manuell oder nur innerhalb derselben Major-Linie zu lassen,
  würde die ausdrücklich ausgewählte Wartungs-Policy nicht erfüllen.

## Implementierungsentscheidung

CRS zählt die offizielle Release-Seite auf, akzeptiert nur explizite boolesche
Non-Draft-/Non-Prerelease-Einträge, meldet spätere Upstream-Majors und wählt
nur das neueste stabile Ziel v4.x.x. Sein Tag und aufgelöster Commit werden
gemeinsam geplant; der generische automatische Plan-Validator weist ein
partielles Paar ab.

HTX verwendet nun die gleiche serienbegrenzte automatische Disposition wie
normaler HAProxy, behält aber Descriptor und Variablen für sich. Die optionale
Checksum-URL-Eingabe wurde explizit gemacht, damit eine künftige literale
HTX-Source-URL nicht durch eine Checksum-URL ersetzt werden kann. Nodes neueste
kompatible Version ist sein neuestes stabiles Upstream-Release einschließlich
Major-Übergang; die Workflow-Synchronisierung rendert weiterhin die daraus
entstehende Literal-Version. Ein `ci/lib/common.sh`-Kandidat trifft außerdem
auf den Pull-Request-Pfad der CI-Security-Quality-Prüfung, die Pyright mit
dieser Literal-Node.js-Kandidatenlaufzeit ausführt, bevor der Draft-PR für
Hosted-Checks und eine separat autorisierte Integration betrachtet werden kann.

## Geänderte Dateien und Tests

- ci/tools/check-common-versions.py
- ci/tools/canonical_maintenance.py
- .github/workflows/ci-security-quality.yml
- tests/security_regression/test_crs_git_ref_provenance.py
- tests/security_regression/test_common_versions_sonar_provenance.py
- tests/security_regression/test_runtime_component_sync.py
- tests/ci_security/test_canonical_maintenance.py
- tests/ci_security/test_sync_canonical_workflow_pins.py
- tests/ci_security/test_unified_common_maintenance_workflow.py
- docs/reference/variables.md und docs/reference/variables.de.md
- Dieses englische/deutsche Change-Record-Paar.

Die neue Regression-Abdeckung umfasst fehlerhafte GitHub-Stabilitätsfelder,
ein stabiles CRS-v5-Release, das nicht gewählt wird, die Ablehnung partieller
atomarer Pläne, unabhängige HTX-Updates, einen Versuch der Verwechslung einer
literalen HTX-Source-URL mit einer Checksum-URL, die Trennung gleichversioniger
HTX-/generischer Profile sowie einen Node-Major-Übergang mit
Prerelease-/fehlerhaften Alternativen. Sie beweist außerdem, dass eine
Kandidatenänderung am kanonischen Node-Pin den Pull-Request-Quality-Workflow
auslöst, einen Literal-Pin statt `latest` behält und Pyright unter dieser
Node-Kandidatenlaufzeit ausführt.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Fokussierte Canonical-Maintenance-Resolver-Tests | 0 | 11 Tests bestanden, einschließlich latest-stable Node-Major und fehlerhafter/Prerelease-Fälle. | Task-eigene externe Validierungsumgebung |
| Fokussierte Workflow-Pin-Tests mit hash-gesperrtem PyYAML | 0 | 12 Tests bestanden; Node 25.0.0 wurde als literaler Workflow-Wert gerendert. | Task-eigene externe Validierungsumgebung |
| CRS-Provenance-Regression-Suite | 0 | 20 Tests bestanden, einschließlich des automatischen atomaren v4-Paars, unveränderlicher Repository-Identitätsbindung und Filterung fehlerhafter Stabilitätsfelder. | Task-eigene externe Validierungsumgebung |
| Common-Version-Provenance-Suite | 0 | 32 Tests bestanden auf dem final CRS-gehärteten Quellstand. | Task-eigene externe Validierungsumgebung |
| Node-PR-Head-Quality-Vertrag, Workflow-Pin- und CI-Security-Vertrag-Suiten | 0 | 63 Tests bestanden; der literale Node-Kandidatenpin wird mit Pyright auf dem Pull-Request-Head geprüft. | Task-eigene externe Validierungsumgebung |
| Kanonische-, Workflow-Pin- und Runtime-Projektionsprüfungen | 0 | Kanonische Pins, Workflow-Ansichten und Runtime-Komponenten bestanden. | Task-eigene externe Validierungsumgebung |
| Python-Kompilierung und Whitespace-Diff-Prüfung | 0 | Geänderte Python-Dateien kompilierten, und es wurden keine Whitespace-Fehler gemeldet. | Task-eigene externe Validierungsumgebung |
| Vollständiges natives Framework-Lint | 0 | Repository-natives Lint sowie kanonische-/Runtime-/Workflow-, Dokumentations- und Change-Record-Prüfungen bestanden mit expliziten Task-Worktree-Roots. | Task-eigene externe Validierungsumgebung |

## Sicherheitsauswirkung

Dies ist eine Supply-Chain-Policy-Änderung, keine Lockerung von
Vertrauensgrenzen. Das ursprüngliche Risiko einer HTX-Source-zu-Checksum-
Verwechslung wird ausdrücklich erneut getestet, und die alternative
CRS-Metadaten-Umgehung mit fehlenden oder nicht booleschen Stabilitätsfeldern
wird abgewiesen. Automatische Ergebnisse bleiben von fester Provenance,
Integrität und vollständigen atomaren Updates abhängig.

## Dokumentation und Runtime-Evidenz

Die gepaarten Variablen-Referenzen beschreiben die begrenzten CRS-v4-, die
unabhängigen HTX- und die latest-stable-Node-Verträge in Englisch und Deutsch.
Es wurde keine Connector-Runtime ausgeführt, und es wird keine Connector-
Unterstützungs-, Produktions-, GitHub-App-, Credential- oder Merge-Evidenz
behauptet.

## Nicht ausgeführte Prüfungen

- Der terminale Security-Diff-Review und sein versiegelter Evidenzreport stehen
  gegen diesen finalen lokalen Source-Snapshot noch aus.
- Hosted-PR-Checks und SonarQube Cloud stehen aus, bis ein exakter Task-Head-
  Draft-PR existiert.

## Einschränkungen und Restrisiko

Die CRS-Release-Listenabfrage ist auf die erste offizielle Seite begrenzt und
scheitert fail-closed, wenn dort kein stabiles v4-Release vorhanden ist.
Künftige Node-Major-Releases können die Kompatibilität von CI-Tools
beeinflussen; der konfigurierte Updatepfad erzeugt jedoch weiterhin einen
reviewbaren Literal-Pin-Draft-PR und führt Pyright mit dessen
Node.js-Kandidatenlaufzeit aus, statt einen laufenden Workflow zu ändern.

## Finaler Diff- und Review-Status

Die lokale Source-Validierung ist abgeschlossen und der Framework-Diff hat
eine saubere Whitespace-Prüfung. Zu diesem Zeitpunkt der lokalen Validierung
existieren kein Commit, Push, Pull Request, Merge, Parent-Gitlink- oder
MRTS-Änderung. Der terminale Security-Evidenznachweis und die exakte
Hosted-Head-Validierung bleiben Delivery-Voraussetzungen; dieser Record
behauptet oder autorisiert keinen Merge.
