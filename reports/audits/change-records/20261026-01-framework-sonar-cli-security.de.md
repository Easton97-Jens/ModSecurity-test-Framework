# Framework Sonar CLI security analysis

**Sprache:** [English](20261026-01-framework-sonar-cli-security.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261026-01-framework-sonar-cli-security |
| UTC-Datum | 2026-10-26 |
| Framework-Basisrevision | 99a7985 |
| Issue oder Pull Request | Nicht erstellt; Prüfung durch Koordinator ausstehend |

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

Neu: sonarqube.yml, sonar-project.properties, prepare-sonar-cfamily.py und test_sonar_analysis_contract.py; enge Workflow-Checker-Ausnahme; kanonische Sonar-Action-Gruppe plus generiertes Lock; gepaarte Security-Dokumentation.

## Befehle und Ergebnisse

Realer GCC-Compile-only-Build über natives Make: Exit 0, eine reale Quelle, unveränderte strenge Flags. Zwölf fokussierte Testmethoden bestanden (37 expandierte Prüfungen), einschließlich Shell-/Umgebungs-Mutationen auf Workflow-Ebene und beider SDK-Staging-Verzeichnis-Symlink-Varianten; bestehende Workflow-Security-Suite: 9 bestanden; kanonische Workflow-Pin-Suite: 12 bestanden. Python-/Workflow-Contracts bestanden. Evidenz: external task run `framework-sonar-cli-security-20261026`. Lokales Python 3.14.4 ist eine Alternative zum exakten Hosted-Python 3.14.8; in untersuchten Toolchain-Pfaden wurde kein exakter Interpreter gefunden.

## Sicherheitsauswirkung

Kein Security-PASS behauptet. Ein bei der Integrationsprüfung bestätigter Checker-Bypass wurde behoben: drei Varianten (zweiter Checkout, eingefügtes git checkout und veränderter geprüfter Skripttext) wurden zunächst vom vollständigen Checker fälschlich akzeptiert und nach der Korrektur abgelehnt. Die exakte geprüfte Schrittfolge verhindert zusätzliche Actions, Umgebungen und Wrapper. Action-SHAs folgen ausschließlich dem validierten kanonischen Source-/Lock-Vertrag; ein Regressionstest prüft dessen Update und ablehnendes Verhalten bei Drift. Private Output-Verzeichnisse und Symlink-Ablehnung schützen vorhandene externe Sentinel-Dateien; wiederholte reale Kompilierung besteht. PR-Guard für dasselbe Repository, exakter Checkout, lesende GitHub-Rechte und Token nur im gepinnten Scanner-Schritt sind geprüft; privilegierte Trigger, Token-Wiederverwendung und abweichende Argumente werden abgelehnt.

## Dokumentation und Runtime-Evidenz

docs/security/ci-security-tooling.md und .de.md aktualisiert. Keine Connector-Runtime- oder Lifecycle-Evidenz erhoben. Native Kompilierung belegt ausschließlich den Compiler-Kontext.

## Nicht ausgeführte Prüfungen

Live-Sonar-Upload, CE-Abschluss, Findings-/Hotspot-Readback und Gate der exakten Head-SHA: ausstehende Provider-Ausführung durch den Koordinator. Hosted-Ausführung mit exaktem Python-Patch und Ubuntu-SDK steht aus. Breite Runtime-/Matrix-Tests sind außerhalb des Auftrags.

## Einschränkungen und Restrisiko

Automatische Analyse muss im bestehenden Sonar-Projekt vor CLI-Analyse deaktiviert werden; Token-Existenz belegt keine Berechtigung. Sprach-/Regelverfügbarkeit und abschließende Analyse/Gate benötigen Live-Evidenz. Coverage-Ziele sind ausdrücklich außerhalb des Auftrags.

## Finaler Diff- und Review-Status

Koordinatorprüfung und fokussierte lokale Prüfungen abgeschlossen. Draft-PR-Übergabe und Live-Analyse der exakten Head-SHA stehen aus; kein Merge ist autorisiert, der Task bleibt teilweise erledigt.
