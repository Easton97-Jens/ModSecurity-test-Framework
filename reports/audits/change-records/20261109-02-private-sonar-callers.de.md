# Unveränderliche private Sonar-Aufrufer

**Sprache:** Deutsch | [English](20261109-02-private-sonar-callers.md)


Die aktuelle Aufruferänderung bindet ausschließlich die getrennt veröffentlichte Revision `9ae8ecc4f686e9cc70413e5494bc098a24eb18d7` mit Main-SHA-256 `3865be06f1ccfaf2c2757b0fc29bfd0ae0c0a0374aec9f09342292402d592a1b` und unveränderten Action-Metadaten. Die vorherige Rolle `865e4ec4fd0a745d1d125b3f43b3dd8d56b3ca7a` ist nur für die exakte native Lock-Migration zugelassen; die ältere 5181-Rolle bleibt abgelehnt. Alle drei veröffentlichten Laufzeitreferenzen bleiben erhalten, einschließlich `refs/heads/codex/preparation-private-sonar-cfamily-attribution-20261110`. Die bereits geprüften 44 integrierten Node-Gruppen gelten für die unveränderte Implementierung; die aktuelle Bindung bestand 97 Vertragsmethoden (einschließlich 14 Produzenten- und 29 Zulassungsmethoden), 11 Projektionsmethoden und alle 56 physischen Updater-Methoden ohne Skips. Die tatsächliche Quellprüfung ließ 20 Composites und die geprüfte Node-Aktion zu. Parent-eigenes Python, primäre Sicherheits-/native CI-Verträge, kanonische und Wartungsaktualität, Ruff-Prüfung und Formatprüfung über den 44-Dateien-Umfang sowie festgesetztes Pyright bestanden; Pyright meldete keine Fehler oder Warnungen. Die Updater-Fixture meldete eine ResourceWarning (zwei Textvorkommen) ohne Unterdrückung. Native Generierung änderte genau sieben vorhandene Skalare und bewahrte sämtliche Mitgliedschaften und Reihenfolgen, 100 Standardfälle, 80 Selektoren und 8316 Archivdefinitionen. Frühere bestandene Bindungsabsätze beschreiben die vorherige 865-Migration. Aktuelle Auslieferung, neue gehostete Aufruferverifikation und das passende committete Parent-Paar stehen aus. Weder Parent-Gitlink noch Index werden hier verändert; das passende committete Parent-Paar steht weiterhin aus.

## Identität

| Field | Value |
| --- | --- |
| Change ID | 20261109-02-private-sonar-callers |
| UTC | 2026-11-09 |

## Motivation und Problemstellung

Gehostete Scans mit vollem Umfang zeigen Parser-Auslassungen ohne ausreichende Ursachenfakten. Die geprüfte private Diagnoseaktion muss aus einem vorher veröffentlichten unveränderlichen Quellcommit laufen. Der bestehende Aktionsquellprüfer schickt außerdem ihre Node-Metadaten fälschlich durch einen reinen Composite-Renderer.

## Betroffene Komponenten und Sicherheitsgrenzen

Das Framework verantwortet seinen Scanner-Aufrufer, die eigene native Datenrolle, das generierte Lock, Quellprüfer und Regressionstests. Parent verantwortet seinen getrennten Scanner-Aufrufer und nicht ausführende Projektionslogik. Die geschützte Parent-Closure aus fünf Quellen importiert keinen ausführbaren Framework-Code. MRTS bleibt unverändert.

## Akzeptanzkriterien

Die veröffentlichte Aktion wird auf `9ae8ecc4f686e9cc70413e5494bc098a24eb18d7` festgesetzt. Upstream-Scanneridentität/-version, Signaturprüfung, voller Analyseumfang, Framework-cfd5-Fixture, Parent-Standards/-Projekte/-Gate-Semantik und alle 23 Integrationsprojektionen bleiben erhalten. Alle Composite-Quellen werden weiterhin geprüft; ungeprüfte Node-/Docker-Aktionen und Metadatenaliase werden abgelehnt.

## Untersuchte Alternativen

Lokale Token-Ausführung am PR-Head, breite Ausnahmen für denselben Eigentümer, erfundene Release-Tags, öffentliches rohes DEBUG, Umfangsreduktion und ausführbare Imports im geschützten Parent-Publisher werden verworfen.

## Implementierungsentscheidung

Die eigene Quellrolle bleibt von releaseverwalteten Aktionsrepositories getrennt. Zwei vollständige geprüfte Scanner-Mappings erlauben die gestufte Migration: ursprüngliche offizielle Aktion oder exakter geprüfter Remote-Wrapper mit denselben Eingaben. Die Quellauflösung bewahrt nur die festgesetzte Parent-Scannerrolle. Der Parent-Publisher prüft ihren exakten Datenblock lokal und bewahrt ihren SHA während der Projektion der Integrationsrevision. Node-Metadaten und Hauptimplementierung müssen den unabhängig geprüften Hashes entsprechen; alle anderen Aktionen erhalten weiterhin die tatsächliche Composite-Prüfung mit actionlint/ShellCheck. Parent-Zusammenfassungen bewahren Analyseergebnisse und verwenden begrenzte Identitätsfakten des Wrappers statt Report-URLs auszugeben.

Der getrennte Parent-Security-Tools-Updater erfasst den verwalteten offiziellen Upstream erst nach Prüfung des vollständigen festgesetzten Aufrufers. Checkout- und Tool-Updates bewahren dessen exakte Bytes. Änderungen am aktuell festgelegten Sonar-Upstream werden bewusst vor jedem Schreibzugriff abgelehnt und benötigen eine getrennt geprüfte Vertragsänderung; zentrales SonarSource-Lock und Resolver-Verwaltung bleiben erhalten.

Gehostete Kandidatenvalidierung zeigte drei Fehler wegen eines fehlenden Pakets, die ein geerbter lokaler Python-Pfad verdeckt hatte. Framework startet dieselben vertrauenswürdigen Prüfer und den kanonischen Produzenten jetzt in isolierten Kindinterpretern und bindet Imports an den privaten vorgeschlagenen Baum. Beide kopierten Paketeingaben müssen regulär und bytegleich mit den vertrauenswürdigen reinen Lesequellen bleiben; fehlende oder veränderte Kopien werden vor der Ausführung abgelehnt. Geerbte Python-Pfade werden entfernt, Bytecode-Schreiben wird deaktiviert und die Schreib-Allowlist des Publishers bleibt unverändert. Die bestehende Closure-Regression führt jetzt die echten nativen Grenzen aus und prüft fehlende sowie veränderte Kopien; aktuelle Validierung ohne geerbten Paketpfad bleibt erforderlich.

## Geänderte Dateien und Tests

Scanner-Workflows, native Framework-Daten/Lock-Produzent, Vertragsmodul für vollständige Aufrufe, Workflow-/Quellprüfer, Parent-Projektion/-Fixtures und gezielte Regressionen. Die vorher veröffentlichte Aktionsimplementierung und ihre 44 Offline-Tests bleiben durch diese Aufruferintegration unverändert. Der Standardfallbestand bleibt unverändert.

Der native Lock-Produzent lässt nur die exakte vorher geprüfte Rolle zur direkten Migration auf die neu festgesetzte Rolle zu. Doppelte Diagnose-YAML-Schlüssel, Merge-Schlüssel, nicht skalare Felder und veränderte Strukturen werden vor Laden oder Ersetzen abgelehnt. Beide unabhängigen CI-Vertragsprüfungen validieren den vollständigen kanonischen Scannerschritt; allgemeine Release- und Repository-Prüfungen bleiben aktiv. Echte Proposed-Tree-Fixtures kopieren die erforderliche Paketclosure.

Zwei inerte Shell-Fixtures im Hauptquellumfang unterscheiden sich nur durch ein Leerzeichen nach dem Lese-/Schreibumleitungsoperator. Eine Verhaltensregression führt beide mit sh und bash gegen neue reguläre Dateien aus und prüft Ausgabe, Exit und Deskriptorschließung. Der gepflegte Scheduler erhält dieselbe einzelne Leerzeichenänderung. Erst gehostete Analyse muss zeigen, ob der Abstand das Parserverhalten verändert; gültige Syntax allein belegt diese Ursache nicht.

## Befehle und Ergebnisse

Die getrennt geprüfte Drei-Ereignis-Implementierung wurde regulär unter `865e4ec4fd0a745d1d125b3f43b3dd8d56b3ca7a` veröffentlicht, mit Main-SHA-256 `234bb01ea1a24e03ea374bd37dbf65a6c04dc2a80d4f98ecec14e8afe6ea8fe8` und unveränderten Action-Metadaten. Ihre tatsächliche integrierte Offline-Suite bestand 33 Gruppen ohne externe Quellwurzelüberschreibung. Diese Aufrufermigration bindet ausschließlich diese neue Identität. Die native Lock-Migration erlaubt nur die vollständige vorherige Rolle `5181cedba82af8d83de4b123080fb80ff414de15`; ältere, unbekannte oder fehlerhafte Rollen bleiben abgelehnt. Die neue veröffentlichte Referenz `refs/heads/codex/preparation-private-sonar-three-event-20261109` und die historische Cache-Referenz bleiben erhalten. Aktuelle Rollen-/Aufruferprüfungen bestanden wie unten dokumentiert; gehostete Analyse und das passende committete Parent-Paar stehen aus; das historische Ergebnis mit 703 Methoden gilt ausschließlich für `d521ea718149e6b5fc719a0dc4fecf07eb733e7f`. Diese reine Rollenänderung materialisiert keinen Gitlink und führt keine Integrationsprojektion aus.

Die gehostete Revision `ce1039a90f5f2fa0fb7c06634157b3fbcf6c5639` beendete Scanner und Serververarbeitung mit erwartetem Projekt, Fixture und tatsächlichem Verbose-Modus. Ihr Gate bestand alle fünf Bedingungen ohne Hotspots; alle sieben vorherigen Python-Befunde wurden als behoben geschlossen. Zwei neue Komplexitätsbefunde im Prüfer der kanonischen gemeinsamen Quelle erforderten die Helper-Auslagerungen. Der getrennte Workflow-Sicherheitsjob scheiterte weiterhin an drei isolierten Kandidatenimports; die lokale Reproduktion ohne geerbten Paketpfad bestätigte diese drei Fehler vor der Korrektur der Importgrenze. Danach bestanden vier echte Methoden ohne geerbten Paketpfad. Die unten dokumentierte betroffene Prüfmatrix ging der anschließend beschriebenen Evidenz des committeten Folgestands voraus.

Der committete Folgestand `d521ea718149e6b5fc719a0dc4fecf07eb733e7f` bestand das vollständige native Lint-Ziel: 19 Gruppen und 703 Methoden ohne Testfehler, übersprungene Tests oder ResourceWarnings. Der äußere PYTHONPATH wurde entfernt; das native Makefile setzte seine expliziten Framework-Paketbindungen. Die gehosteten Prüfungen endeten mit 19 erfolgreichen und drei bedingt übersprungenen Prüfungen. Der Server-Readback bestätigte dieselbe Revision, den Verbose-Modus, alle fünf bestandenen Gate-Bedingungen, keine Hotspots, beide als behoben geschlossenen Komplexitätsbefunde, einen offenen S5906-Befund zum Assertionsstil und keine akzeptierten Befunde. Die reine Assertionsfolgeänderung ersetzt die gleichwertige negierte Mitgliedschaftsprüfung durch assertNotIn und bewahrt beide Operanden sowie die Fehlermeldung, ohne eine Testmethode hinzuzufügen. Ihre gehostete Bestätigung am exakten Head steht aus; die vollständige native Evidenz gilt für die oben genannte committete Revision.

Derselbe gehostete Diagnosebericht bleibt unvollständig: neun Warnungen und sieben nicht klassifizierte Vorkommen des Worttokens ERROR bei Scanner-Exit 0. Diese Tokenvorkommen belegen keine sieben fatalen Analysefehler. Der Bericht erfasst 85 vollständige Übersetzungseinheiten sowie Parserfehler in 60 von 1120 Funktionen und 443 von 19635 Anweisungen. Beide minimalen Shell-Fixtures mit und ohne Abstand und der gepflegte Scheduler melden weiterhin Parserfehler; die Leerzeichenänderung behebt den Parserfehler daher nicht. Die Migrationsbaseline wird direkt als nicht parsebar identifiziert, ihr Codepoint-Limitsignal bleibt jedoch ungebunden. Diese Fakten liefern engere Reproduktionen, schließen die Analyzer-Lücken aber nicht.

Die aktuelle Folgeänderung bestand die vollständige Workflow-Sicherheitsgruppe mit 401 Methoden ohne geerbten PYTHONPATH, alle 56 Parent-Updater-Methoden und 19 gezielte Produzenten-/Aufrufer-/Shell-Methoden ohne übersprungene Tests. Tatsächliche Composite- und Node-Zulassung, primäre CI-Verträge, kanonische Aktualität und Aktualität der Wartungsansichten, Dokumentationsprüfungen, der gehostete Ruff-Umfang mit 44 Dateien und festgesetztes Pyright bestanden; Pyright meldete keine Fehler oder Warnungen. Die bestehende Parent-HTTPError-Fixture meldete weiterhin eine ResourceWarning ohne Unterdrückung. Der native Produzent der Wartungsansichten bewahrte den Bestand, alle 100 Standardfälle und 80 Selektoren, jede Archivdefinition und die Zahl 8316; keine Methoden wurden ergänzt oder entfernt. Frühere Ergebnisse unten gelten für ihre ursprünglichen Quellrevisionen.

Der frühere lokale vollständige native Lauf für die gehostete Revision verwendete den richtigen Ausgabewurzelpfad und endete mit 0: 19 Gruppen, 703 Methoden, keine Testfehler, übersprungenen Tests oder ResourceWarnings. Sein geerbter Python-Pfad verdeckte dennoch die drei isolierten Importfehler aus der gehosteten CI. Ein noch älterer Lauf beendete 703 Methodenzusammenfassungen, endete jedoch mit 2 wegen eines Aufrufs mit unzulässigem Ausgabewurzelpfad; dieser historische Lauf bleibt fehlgeschlagen. Das oben dokumentierte spätere Ergebnis des committeten Folgestands ist von beiden historischen Läufen getrennt.

Native kanonische Generierung und Aktualitätsprüfung endeten mit 0. Gezielte Prüfungen bestanden mit 4 Aufrufer-, 25 Quell-/Node-Zulassungs-, 14 kanonischen Pin-, 20 Sonar-Grenz- und 9 Workflow-Sicherheitstests. Die tatsächlich installierten und den nativen Pins entsprechenden Versionen actionlint v1.7.12 und ShellCheck v0.11.0 prüften alle 20 Composite-Quellen; die exakt geprüfte Node-Quelle wurde getrennt erfasst. Native Workflow-, Change-Record-, Link- und Zweisprachigkeitsprüfungen bestanden. Echte unveränderliche Git-Objektfixtures korrigierten drei veraltete Projektionstests. Die vollständige Parent-Gruppe führte 59 Methoden aus: 42 bestanden, 17 lehnten die aktuell nicht übereinstimmenden Parent-/Framework-Integrationspins ab. Diese 17 benötigen den synchronisierten Zyklus mit committeten Zielständen und sind keine bestandenen Tests.

Die vollständige Updater-Gruppe bestand alle 56 Methoden einschließlich aller fünf neuen Rollen-/Atomaritätskontrollen und der echten Proposed-Tree-Integration. Der native Produzent der Wartungsansichten aktualisierte zehn bestehende Quellbindungs-Digests und das generierte Archiv; seine Aktualitätsprüfung bestand. Alle 100 Standardfälle und 80 Ausführungsselektoren bleiben unverändert. Das Archiv bewahrt jede bestehende Definition und ergänzt 16 tatsächliche Regressionsmethoden; die Zahl seiner On-Demand-Definitionen steigt von 8292 auf 8308. Native Extraktionsidentität und erhaltene native Definitionen bleiben unverändert. Parent-eigenes Python 3.14.4 bestand unabhängig die tatsächliche Workflow-/Upstream-Erfassung und Ablehnung festgesetzter Änderungen ohne ausführbare Framework-Imports. Eine bestehende HTTPError-Testfixture meldete eine ResourceWarning; sie wurde nicht unterdrückt.

## Sicherheitsauswirkung

Token-Zugriff bleibt auf eine unveränderliche Remote-Aktion begrenzt. Falsche Pins, Metadatenhashes, Implementierungen, Eigentümerprofile, Scannereingaben, Aliase, Symlink-Quellen und zusätzliche Rollenvorkommen werden geschlossen abgelehnt. Hooks, Berechtigungen, Compilerwarnungen, Tests, Analyseprofile und Gates werden weder deaktiviert noch geschwächt. Rohe Scannerausgabe bleibt unter dem getrennt geprüften Aktionsvertrag privat.

## Dokumentation und Runtime-Evidenz

Dieses Berichtspaar beschreibt Vorbereitung und Offline-Validierung. Gehostete Diagnosen und Qualitätsprüfungen des aktuellen Heads bleiben unabhängige Evidenz; Connector-Laufzeit oder Deployment werden nicht behauptet.

Die vorherige 865-Bindungsprüfung bestand 97 Vertragsmethoden einschließlich 14 nativer Produzenten- und 29 Zulassungsmethoden; auch 11 echte Projektionsmethoden und alle 56 physischen Updater-Methoden bestanden. Die tatsächliche Quellprüfung ließ 20 Composites und die eine geprüfte Node-Aktion zu. Beide JavaScript-Syntaxprüfungen und alle 33 Node-Tests bestanden ohne Quellwurzelüberschreibung (0 Fehler, 0 Skips; 1786,674 ms). Parent-eigenes Python bestand seinen nativen Nachweis unabhängig. Kanonische Aktualität und Wartungsaktualität, primäre Sicherheits-/native CI-Verträge, Ruff-Prüfung und Formatprüfung über 44 Dateien sowie festgesetztes Pyright bestanden. Der erste Projektionsaufruf scheiterte an fehlendem RUNNER_TEMP; der korrigierte Aufruf mit externem Verzeichnis bestand alle 11 Methoden ohne Quelländerung. Die native Generierung änderte nur einen Lock-Commit, zwei Inventar-Digests und vier Archiv-Skalare; sämtliche Mitgliedschaften, 100 Standardfälle, 80 Selektoren und 8316 Archivdefinitionen bleiben unverändert. Gehostete Verifikation und der synchronisierte committete Parent-Zielstand stehen aus.

## Nicht ausgeführte Prüfungen

Synchronisierte Parent-/Framework-Prüfungen mit committeten Zielständen sowie gehosteter Qualitäts-/Readback der reinen Assertionsfolgeänderung stehen aus. Der private Diagnosebericht des committeten Folgestands bleibt unvollständig und schließt die Parser-Auslassungen nicht. Lokale Syntax-/Lint-Evidenz ersetzt spätere gehostete Prüfungen nicht.

## Einschränkungen und Restrisiko

Die privaten Diagnosefakten können weiterhin unbekannte Ursachen melden. Ein bestandenes Gate belegt keine Parser-Vollständigkeit; ähnliche Parent-/Framework-Zähler beweisen keine gemeinsamen Ursachen. Beide Repositories benötigen getrennte Veröffentlichung und Integrationsprüfung.

## Finaler Diff- und Review-Status

Die Evidenz des vollständigen nativen Laufs und der gehosteten Folgeprüfung ist oben dokumentiert. Veröffentlichung der reinen Assertionsfolgeänderung, Integrationsprüfungen mit committeten Zielständen und ihre gehostete Prüfung am exakten Head stehen aus. Geschlossene Analyzer-Lücken werden nicht behauptet.
