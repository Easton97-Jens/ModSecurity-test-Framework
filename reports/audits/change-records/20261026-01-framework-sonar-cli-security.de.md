# Framework Sonar CLI security analysis

**Sprache:** [English](20261026-01-framework-sonar-cli-security.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261026-01-framework-sonar-cli-security |
| UTC-Datum | 2026-10-26 |
| Framework-Basisrevision | 99a7985 |
| Issue oder Pull Request | [PR #138](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/138) |

## Motivation und Problemstellung

Framework-eigene Sonar-CLI-Sicherheitsanalyse aller gepflegten Sprachen statt ausschließlicher Abhängigkeit von externer automatischer Analyse.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-Workflow, Scanner-Properties, native Compiler-Erfassung, Workflow-Secret-Grenze, kanonische Action-Quelle/Lock und gepaarte Dokumentation. Parent/Gitlink unverändert; MRTS bleibt read-only und als unabhängiges Repository ausgeschlossen.

## Akzeptanzkriterien

Gesamtes Repository im Scope; reale native Kompilierungsdatenbank; exakte SHA; begrenzter Scanner-Token; Warten auf Server/Gate; ausdrücklicher Coverage-Verzicht. Live-Scanner-/Server-Evidenz steht aus.

## Untersuchte Alternativen

AutoConfig ermöglicht keine CFamily-Taint-Analyse. Clang -MJ scheiterte mit nativen C99/-Werror-Flags an einem doppelten Typedef in Drittanbieter-Headern. Tatsächliche GCC-Befehlserfassung behält die ursprünglichen Flags und kompiliert das vollständige Inventar aus einer Einheit.

## Implementierungsentscheidung

Gepinnte offizielle Scanner-Action/CLI. Compile-only über natives Make erfasst nur real erfolgreich ausgeführte Compiler-Argumente und lehnt abweichendes Quelleninventar ab; keine erfundenen Records, Runtime-Ausführung oder Warnungsunterdrückung. Ausschließlich Coverage wird auf expliziten Benutzerwunsch ausgeschlossen.

## Geänderte Dateien und Tests

Neu: sonarqube.yml, sonar-project.properties, prepare-sonar-cfamily.py, prepare-sonar-sdk.sh und test_sonar_analysis_contract.py; enge Workflow-Checker-Ausnahme; kanonische Sonar-Action-Gruppe plus generiertes Lock; exakte Registrierung der generierten Workflow-Ansicht in check-common-versions.py; gepaarte Security-Dokumentation.

## Befehle und Ergebnisse

Realer GCC-Compile-only-Build über natives Make: Exit 0, eine reale Quelle, unveränderte strenge Flags; mit dem echten kanonischen nativen SDK-Build-Layout wiederholt. Vierzehn fokussierte Testmethoden bestanden (40 expandierte Prüfungen), einschließlich der Ablehnung eines ersetzten SDK-Producers, vermischter SDK-Layouts, Ausführungs-Overrides auf Workflow-Ebene und Staging-Symlinks. Bestehende Workflow-Security-Suite: 9 bestanden; kanonische Workflow-Pin-Suite: 12 vor der Hosted-Remediation bestanden. Kanonische Common-Validierung reproduzierte den Hosted-Fehler für kopierte Pins und bestand nach Registrierung ausschließlich des neuen generierten Workflows. Evidenz: external task run `framework-sonar-cli-security-20261026`. Lokales Python 3.14.4 ist eine Alternative zum exakten Hosted-Python 3.14.8; in untersuchten Toolchain-Pfaden wurde kein exakter Interpreter gefunden.

## Sicherheitsauswirkung

Kein Security-PASS behauptet. Ein bei der Integrationsprüfung bestätigter Checker-Bypass wurde behoben: drei Varianten (zweiter Checkout, eingefügtes git checkout und veränderter geprüfter Skripttext) wurden zunächst vom vollständigen Checker fälschlich akzeptiert und nach der Korrektur abgelehnt. Die exakte geprüfte Schrittfolge verhindert zusätzliche Actions, Umgebungen und Wrapper. Action-SHAs folgen ausschließlich dem validierten kanonischen Source-/Lock-Vertrag; ein Regressionstest prüft dessen Update und ablehnendes Verhalten bei Drift. Private Output-Verzeichnisse und Symlink-Ablehnung schützen vorhandene externe Sentinel-Dateien; wiederholte reale Kompilierung besteht. PR-Guard für dasselbe Repository, exakter Checkout, lesende GitHub-Rechte und Token nur im gepinnten Scanner-Schritt sind geprüft; privilegierte Trigger, Token-Wiederverwendung und abweichende Argumente werden abgelehnt.

## Dokumentation und Runtime-Evidenz

docs/security/ci-security-tooling.md und .de.md aktualisiert. Keine Connector-Runtime- oder Lifecycle-Evidenz erhoben. Native Kompilierung belegt ausschließlich den Compiler-Kontext.

## Nicht ausgeführte Prüfungen

Live-Sonar-Upload, CE-Abschluss, Findings-/Hotspot-Readback und Gate der exakten Head-SHA: ausstehende Provider-Ausführung durch den Koordinator. Der erste Hosted-Lauf verwendete das exakte Python 3.14.8, scheiterte aber vor dem Scan an fehlenden gepflegten C-API-Deklarationen im Distributions-SDK; die strengen Flags lehnten dies korrekt ab. Das Follow-up baut stattdessen das bestehende kanonisch freigegebene SDK. Dieser Hosted-SDK-Build und der Live-Scanner stehen aus. Breite Runtime-/Matrix-Tests sind außerhalb des Auftrags.

## Einschränkungen und Restrisiko

Automatische Analyse muss im bestehenden Sonar-Projekt vor CLI-Analyse deaktiviert werden; Token-Existenz belegt keine Berechtigung. Sprach-/Regelverfügbarkeit und abschließende Analyse/Gate benötigen Live-Evidenz. Coverage-Ziele sind ausdrücklich außerhalb des Auftrags.

## Finaler Diff- und Review-Status

Erste geprüfte Implementierung in Draft-PR #138 bei 47ebce8 veröffentlicht. Fokussierte lokale Hosted-Remediation-Prüfungen abgeschlossen; Follow-up-Koordinatorprüfung/Übergabe und Live-Analyse der exakten Head-SHA stehen aus. Kein Merge ist autorisiert, der Task bleibt teilweise erledigt.
