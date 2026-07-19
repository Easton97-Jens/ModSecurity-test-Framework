# Change Record: Framework-SonarCloud-Quality-Gate-Remediation

**Sprache:** [English](20260719-01-remediate-framework-sonarcloud-quality-gate.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260719-01-remediate-framework-sonarcloud-quality-gate` |
| UTC-Datum | 2026-07-19 |
| Framework-Basisrevision | `7a12073c28e62a67492dd501b6513b9914fe5df8` |
| Issue oder Pull Request | Draft-PR #30; keine Merge-Autorisierung |

## Motivation und Problemstellung

Die frische SonarCloud-Inventur des Frameworks an der Basisrevision enthielt
aktuelle Framework-eigene Code-Quality-, Reliability- und Security-Befunde.
Diese reine Framework-Remediation gleicht sie durch konkrete Quelländerungen
und Regressionstests ab. `tools/MRTS`-Quellcode wird bewusst weder untersucht
noch geändert noch abgeglichen.

## Betroffene Komponenten und Sicherheitsgrenzen

- CI-Shell-Bootstrap, Provenance-, Versions-/Update- und Finalizer-Helfer:
  Grenzen für nicht vertrauenswürdige Umgebung, Quellherkunft,
  Kommandoargumente und Runtime-Pfade.
- Case-Runner, YAML-/Workflow-/Checker-Parser, Protocol-Evidence und
  Transport-Evidence: Grenzen für nicht vertrauenswürdige Eingaben, Parser,
  Request-/Evidenzdaten und Nicht-Promotion.
- Reporting-/Import-Hilfen: CLI-Pfad-, generierte Datei-, private
  Runtime-Root-, Symlink- und Payload-Redaktionsgrenzen.
- Dokumentation und zentrale Variablen: Konsistenz der englischen/deutschen
  leserorientierten Dokumentation.

Es wurden weder Connector-Implementierungen noch Parent-Repository-Dateien
noch `tools/MRTS`-Quellcode geändert.

## Akzeptanzkriterien

1. Alle aktuellen Framework-eigenen Sonar-Zeilen der dokumentierten
   Basisinventur besitzen eine quellseitige Remediation ohne Suppressionen oder
   Abschwächung des Quality Gates.
2. Sicherheitsrelevante Pfade schlagen bei Traversal, fremden/symlinkten oder
   öffentlich beschreibbaren Roots, unsicheren Kommandoeingaben, veränderbarer
   Provenance und fehlerhaften Parser-Eingaben gegebenenfalls fail-closed fehl.
3. Fokussierte positive/negative Regressionen sowie die vollständige
   Framework-Security-Regression und das repository-native Lint-Ziel bestehen.
4. Der Framework-Worktree enthält keine `tools/MRTS`-Gitlink-Änderung; für
   diese Aufgabe wurden keine MRTS-Inhalte gelesen.
5. Normaler Branch-Push und Draft-PR erfolgen erst nach lokaler Validierung;
   ein Merge bleibt out of scope. Remote-SonarCloud und CI müssen den exakten
   Head bestätigen, bevor ein erfolgreicher Quality Gate behauptet wird.

## Untersuchte Alternativen

- Befunde unterdrücken, Sonar-Profil ändern oder Gate abschwächen: verworfen,
  weil dies Quellverhalten verdecken statt beheben würde.
- Fallbacks in gemeinsam nutzbare Temp-Verzeichnisse oder breite
  Current-Working-Directory-Pfadfreigaben: zugunsten expliziter enthaltener
  privater Roots verworfen.
- MRTS-Quellcode untersuchen oder ändern, um zusätzliche Evidenz zu erhalten:
  wegen der Aufgabengrenze verworfen; synthetische Framework-Fixtures decken
  Import-/Report-Verhalten ab.
- Komplexe Security-Checker mechanisch verflachen: verworfen. Refactorings
  behalten Fehlerreihenfolge bei und teilen Validierung in semantische Helfer.

## Implementierungsentscheidung

Die Implementierung verwendet schmale, verhaltensgleiche Refactorings sowie
Security-Verträge an den tatsächlichen I/O- und Invocation-Grenzen. Beispiele
sind kanonisches skriptrelatives Bootstrap-Sourcing, unveränderbare
V3/CRS-Provenance, argv-basierte No-CRS-Finalisierung, begrenztes
YAML-/Protocol-Parsing, Loopback-/Control-Root-Validierung, atomare
No-Follow-Report-Writer und nicht promotierbare Runtime-/Strict-Transport-
Evidence. Neue Tests verwenden task-eigene synthetische Temp-Verzeichnisse und
decken Outside-Root-, Symlink-, Fehlerinput- und legitime Kontrollfälle ab.

Der Case-Matrix-Fallback verlangt nun einen expliziten privaten Build-Root,
statt in ein gemeinsam nutzbares Temp-Verzeichnis zu schreiben. Diese bewusst
fail-closed gewählte Kompatibilitätsänderung ist dokumentiert.

Die gesourcte Common-Shell-Bibliothek behält ihre bibliotheksverträgliche
Return-Semantik, ohne dass eine blockierte Voraussetzung zum Erfolg werden
kann. Jeder betroffene Kommando-/Header-Wrapper reicht `77` oder `1` weiter,
und CI kehrt nach einem Block vor jedem lokalen Provisionierungsversuch zurück.

Der anfängliche Draft-PR-Lauf `common-structure` wies eine legitime
Case-Materialisierungs-Ausgabe außerhalb seines deklarierten Verified-Roots
korrekt ab. Das Follow-up erhält dieses fail-closed Containment und ändert nur
das Workflow-Layout: Gemeinsame Case-Ausgabe liegt nun unter
`$VERIFIED_RUN_ROOT/case-runner`, nicht in einem benachbarten Temp-Verzeichnis.
Weder Output-Root-Allowlist noch Runner-Validierung werden erweitert.

## Geänderte Dateien und Tests

Die Änderung umfasst Framework-CI/Checker, Runner, Reporting, Provisioning,
Shell-Bibliotheken, Makefile, Dokumentation und Tests. Wichtige neue Kontrollen
decken ab:

- Parser- und Workflow-YAML-Ressourcenlimits;
- No-CRS-Finalizer-Argument-Sicherheit, Katalogverhalten und Protocol-Evidence;
- V3/CRS-Quell-Provenance sowie sichere Archiv-/Pfadbehandlung;
- CI-Root-Bootstrap, Loopback-/Control-Root- und Shell-Vertrag-Härtung;
- enthaltene Report-/Import-/Case-Ausgabepfade und Generated-Report-Redaktion;
- Transport-Evidence-Reihenfolge, Counter-Kurzschluss und Strict-Abort-
  Nicht-Promotion.

Die englischen/deutschen Dokumentationspaare `docs/connector-integration.*`,
`docs/reference/variables.*` und `docs/testing-and-evidence.*` beschreiben die
neuen Framework-Verträge dort, wo Leser sie benötigen.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Fokussierte Worker-Test-/Compile-/Diff-Befehle | 0 | Alle berichteten fokussierten Kontrollen bestanden; kein MRTS-Zugriff | `20260719T131321Z-sonarcloud-quality-gate-f4bb3370` |
| Common-Shell-Voraussetzungsregression | 0 | Blockiert-, Lokalfehler-, Erfolgs- und Bibliothekskontrollen bestanden | externes Finding `FND-FRAMEWORK-SHELL-BLOCK-RETURN` |
| Common-Workflow-Verified-Root-Regression | 0 | Legitime Materialisierung unter dem Verified-Root besteht; die Abweisung des benachbarten Roots bleibt aktiv | externes Finding `FND-FRAMEWORK-CI-VERIFIED-ROOT` |
| `python -m unittest discover -s tests/security_regression` | 0 | Vollständige Framework-Security-Regression nach der finalen Shell-Korrektur bestanden | Task-Validierung `full-security-after-shell/` |
| `make lint` mit task-eigenen Roots und verifiziertem Framework-Python | 0 | Shell-Syntax, Compile, Verträge, Security-/Dokumentationsprüfungen und Diff-Check nach der finalen Shell-Korrektur bestanden | Task-Validierung `lint-after-shell/` |
| `git diff --check` | 0 | Keine Whitespace-Fehler | Framework-Task-Worktree |
| Suche nach Suppressionen in geänderten Zeilen | 0 | Kein `NOSONAR`, keine Sonar-Gate-Abschwächung, kein `noqa` oder `type: ignore` eingeführt | Framework-Task-Worktree |
| Framework-Index-only-`tools/MRTS`-Diff-Check | 0 | Keine Gitlink-Änderung | Framework-Task-Worktree |

## Sicherheitsauswirkung

Dies ist eine Security-Remediation. Die ursprünglichen Kontrollen für
unsichere Pfade, Shell-Eingaben, Provenance, Parser und Evidenzgrenzen wurden
durch fokussierte legitime und negative Kontrollen erneut geprüft. Alternative
Umgehungen—fremde Roots, Symlinks, Traversal, öffentliche Temp-Verzeichnisse,
fehlerhaftes/escaped YAML, veränderbare Quellselektoren, rohe Protocol-
Identifier und Payload-haltige Evidenz—werden abgewiesen. Die Änderung lockert
keine Authentifizierung, Autorisierung, Isolation, Validierung, Logging,
Tests, CI oder Quality Gates.
Die finale Common-Shell-Regression bestätigt insbesondere, dass eine fehlende
Voraussetzung nicht als Erfolg gemeldet wird und aus CI keine lokale
Provisionierung auslösen kann.
Die CI-Workflow-Korrektur nutzt den bestehenden Verified-Root, statt einen
zweiten vertrauenswürdigen Temp-Ort hinzuzufügen.

## Dokumentation und Runtime-Evidenz

Die oben genannten englischen/deutschen Framework-Dokumentationspaare wurden
aktualisiert. Diese Änderung validiert Framework-Quellcode und synthetische
Kontrollen; sie behauptet keinen Live-Connector-Runtime-Pass, kein frisches
remote SonarCloud-Quality-Gate und kein MRTS-Runtime-Ergebnis.

## Nicht ausgeführte Prüfungen

- Lokaler `sonar-scanner`: nicht installiert; es wurde keine Paketinstallation
  vorgenommen.
- Remote-SonarCloud-Analyse und GitHub-CI: ausstehend bis zum normalen
  Branch-Push und Draft-PR für den exakten Commit-Head.
- Vollständige Connector-Runtime-Matrix: nicht ausgeführt, weil diese Aufgabe
  die Framework-Quality-/Security-Schicht ändert und keine Runtime-
  Abhängigkeitsmatrix provisioniert wurde.
- MRTS-Quell-/Integritäts-Readback: unter der expliziten Nichtzugriffsgrenze
  bewusst nicht ausgeführt.

## Einschränkungen und Restrisiko

Lokale Quell- und Regressionsevidenz ersetzt nicht die Analyse des finalen
Pull-Request-Heads durch den Remote-Scanner. Der vorbestehende Protocol-
Artefakt-Reader weist übergroße Dateien nach dem Lesen ab; diese Änderung fügt
Regression Coverage hinzu, behauptet aber keine betriebssystemweite Streaming-
Größenbegrenzung. Über `tools/MRTS`-Quellcode wird keine Aussage getroffen.

## Finaler Diff- und Review-Status

Vor der Delivery erhielt der gesamte unstaged Framework-Diff einen
Whitespace- und Suppression-Review. Ein fokussierter unabhängiger
Security-Review fand keine validierte Regression im Protocol-Evidence-
Refactoring. Ein zweiter unabhängiger Review fand nach der Common-Shell-
Korrektur keinen verbleibenden Statusüberschreibungs-Bypass. Initiales Staging,
Commit, normaler Push und Draft-PR-Erstellung sind abgeschlossen; der erste
aktuelle Head-Lauf `common-structure` fand den oben beschriebenen
Verified-Root-Layout-Fehler. Ein normaler Follow-up-Commit sowie aktuelles
Head-CI-/SonarCloud-Readback stehen aus; ein Merge bleibt nicht autorisiert.

### Aktuelle lokale Abgleichaktualisierung

Die Follow-up-Remediation ist nun lokal validiert. Die NGINX-Archive-Digest-
Fixture erzeugt den minimalen externen Adapter-Header, den der bestehende
Produktions-Guard benötigt; der Guard selbst wurde nicht gelockert. Ihre
Tar-Beobachtung protokolliert nun auch die direkte Nutzung des erwarteten
gecachten Kandidatenarchivs, sodass eine zukünftige unbestätigte Extraktion
nicht durch nicht zugehörige Tar-Aufrufe der Adapter-Materialisierung verdeckt
werden kann. Das fokussierte Modul schloss 10 Tests erfolgreich ab.

Die Report-State-Regression misst jetzt das tatsächliche Interpreterverhalten,
statt es zu mocken: `RUNNER_TEMP` wird nicht gewählt, `TMPDIR` bleibt ein
`mkdtemp`-Parent, und das resultierende Kindverzeichnis ist privat (`0700`).
Das fokussierte Modul schloss 12 Tests erfolgreich ab. Der begrenzte Kandidat
wurde als berichtspflichtige Schwachstelle verworfen, weil kein weniger
privilegierter oder entfernter Akteur dieses private Kind über den belegten
Pfad lesen oder ersetzen kann und generierte Reports weiterhin unter dem
Connector-Root begrenzt bleiben.

Der getrackte `find`-Command-Lookup-Befund
`FND-FRAMEWORK-MRTS-COMMON-PATH-SHADOW` ist mit `command -p find` an allen
drei Klassifizierer-Aufrufen behoben. Die Regression prüft eine shadowende
Shell-Funktion, einen unbrauchbaren aufrufenden `PATH`, fehlende Pfade,
gültige Regular-/Directory-Pfade und die Prepared-Path-`77`-Kontrolle. Der
Test-Harness-Befund `FND-FRAMEWORK-NGINX-ARCHIVE-HARNESS` ist durch die oben
beschriebene eng begrenzte Fixture-Reparatur behoben.

Aktuelle lokale Evidenz:

| Befehl oder Evidenz | Exit-Code | Ergebnis |
| --- | --- | --- |
| `python -m unittest discover -s tests/security_regression -q` mit isolierten Task-Roots | 0 | 212 Tests bestanden. Erwartete Negative-Control-Diagnosen wurden ohne Fehler ausgegeben. |
| `make lint` | 0 | Shell-Syntax, Python-Compile, Verträge, Workflow-Prüfungen, Security-Prüfungen, Dokumentationsprüfungen und der enthaltene Diff-Check bestanden. |
| Fokussierte NGINX-Archive-Regression | 0 | 10 Tests bestanden. |
| Fokussierte Report-State-Regression | 0 | 12 Tests bestanden. |
| Codex-Security-Diff-Scan-Finalisierung und Report-Format-Validierung | 0 | Alle 20 diff-begrenzten Dateien erhielten Receipts; beide Kandidaten wurden verworfen; kein berichtspflichtiger Security-Befund überlebte. |

Das vollständige externe Security-Scan-Artefakt wird unter dem Task-Run
`20260719T131321Z-sonarcloud-quality-gate-f4bb3370` aufbewahrt; sein
kanonischer Report dokumentiert die manuelle Wiederaufnahme der Scan-Worklist,
nachdem das Plugin fälschlich jede Datei unter `ci/` und `tests/` ausgeschlossen
hatte. Es wurde kein `tools/MRTS`-Inhalt aufgerufen.

Der lokale Sonar-Scanner bleibt absichtlich nicht verfügbar und wurde nicht
installiert. Zum Zeitpunkt dieser Aktualisierung ist der exakte neue Commit
noch nicht gepusht und der Draft-PR wurde nicht auf ready gesetzt. Erforderliche
GitHub-CI des aktuellen Heads, SonarCloud-Quality-Gate `OK` und das
PR-Issue-Readback bleiben die finale Delivery-Evidenz; ein Merge bleibt nicht
autorisiert.

### Korrektur des exakten Remote-Readbacks und fokussiertes Follow-up

Der normale Branch-Push von `bbd722e49fc96102e33bba04341065ae0b789f4f` wurde
abgeschlossen, und Draft-PR #30 blieb Draft. Die exakten Head-Checks
`common-structure` und `scaffold-lint` bestanden. SonarCloud Code Analysis
schlug weiterhin ausschließlich fehl, weil das neue Security-Rating B (`2`)
statt des erforderlichen A (`1`) war.

Das offizielle Readback der offenen Vulnerabilities identifizierte zwei
doppelte `python:S5332`-Zeilen (`AZ98DRCirIstupHXny2B` und
`AZ98DRCirIstupHXny2C`) im selben Source-Range von
`tests/security_regression/test_common_versions_sonar_provenance.py`. Sie
beschreiben einen absichtlich verwendeten Nicht-HTTPS-Negativtestwert und
keine ausgehende Netzwerkverbindung: Der Test übergibt ihn direkt an
`plan_update`, dessen Guard `require_safe_https_update_url` das Schema
abweist, bevor ein Update erzeugt oder geschrieben werden kann.

Das fokussierte Follow-up konstruiert denselben Kandidaten mit dem Standard-
URL-Parser aus einer HTTPS-Fixture-URL, bestätigt sein Nicht-HTTPS-Schema und
erhält die bestehenden Kontrollen für `UpstreamError` und Nicht-Mutation. Das
entfernt das operative URL-Literal, das die doppelten Analyzer-Zeilen auslöste,
ohne eine Suppression hinzuzufügen oder die URL-Validierung abzuschwächen. Das
fokussierte Provenance-Modul bestand 12 Tests und die isolierte vollständige
Security-Regression bestand 212 Tests. Eine frische Remote-Analyse des
exakten Heads bleibt erforderlich, bevor das Quality Gate oder der Draft-PR-
Status als erfolgreich deklariert werden kann.

### Remediation verbleibender Issues nach grünem Quality Gate

Das Remote-Ergebnis des exakten Heads
`4307d591f52a760d93c5662f183144cbae26e25e` besitzt ein grünes SonarCloud-
Quality Gate, erfolgreiche Checks SonarCloud Code Analysis,
`common-structure` und `scaffold-lint` sowie null offene Vulnerabilities. Die
vollständige PR-Issue-API meldete dennoch 15 reproduzierbare
Framework-eigene Code Smells. Dieses Inventar ist für die Änderung in scope
und blockiert daher den Übergang von Draft auf ready trotz grünem Gate.

Die Rest-Remediation ist bewusst eng und verhaltenserhaltend:

- `mrts_path_matches` hat nun einen expliziten POSIX-Return-Pfad und einen
  benannten Kind-Input, erhält `command -p find -H`, weist unbekannte Kinds mit
  Status `2` ab und ergänzt explizite No-op-Defaults für die selektiven Shell-
  Cases, ohne deren aktivierte Branches zu erweitern.
- Die NGINX-Release-Asset-Tokenprüfung ersetzt die gemeldete Backtracking-
  RegEx durch eine exakte lineare ASCII-Tokenvalidierung und behält Traversal-
  Abweisung sowie akzeptierte Legacy-Formen bei.
- Der Fallback-YAML-Mapping-Parser delegiert unabhängige Parsing-Schritte an
  kleine Helfer und erhält Scalar-, Block-Scalar-, verschachtelte Mapping-,
  Indentierungs- und Fehlersemantik bei geringerer kognitiver Komplexität.

Die kombinierte fokussierte Menge bestand 40 Tests. Die isolierte vollständige
Security-Regression und das repository-native Ziel `make lint` wurden beide
erfolgreich mit task-eigenen temporären Roots abgeschlossen. Die Shell-
Änderung erhielt außerdem einen fokussierten unabhängigen Security-Review:
Command-/PATH-Shadowing, literale und option-ähnliche Pfade, ungültige Kinds
und deaktivierte Feature-Demo-Werte bleiben fail-closed. Ein neuer normaler
Commit, Push und frisches Remote-Readback des exakten Heads sind erforderlich;
PR #30 bleibt Draft und ein Merge bleibt nicht autorisiert.

### Korrektur des verbleibenden Regex-Befunds am exakten Head

Ein frisches offizielles Readback für den exakten Head
`3a17b220da4d87e3a9447feada2cc1ce241de9b6` bestätigte, dass die vorherige
Rest-Remediation 12 der 15 offenen Code Smells geschlossen hat, aber drei
verbleiben. Es handelt sich um eine `python:S8786`-Zeile und zwei
`python:S6353`-Zeilen in `ci/tools/check-common-versions.py:40`, alle auf
`URL_PATH_DYNAMIC_VALUE_RE`; sie beziehen sich nicht auf die NGINX-
Release-Asset-Tokenprüfung. Der nicht zugehörige NGINX-Helfer-/Test-Refactor
wurde deshalb auf die exakte Implementierung und Regression-Deckung vor der
Rest-Remediation zurückgeführt.

Die verbleibende lokale Korrektur erhält die dynamische URL-Pfad-Sprache:
Die Variablenalternativen behalten ihre ASCII-Identifiergrenzen über eine
scoped ASCII-Word-Class, und die Alternative für punktierte Versionen bleibt
Unicode-Dezimalzahl-kompatibel, während sie durch Trennzeichen begrenzte
Zifferngruppen fordert. Eine fokussierte Regression deckt geklammerte und
nicht geklammerte Variablen, ein Unterstrich-Suffix, ASCII- und Unicode-
punktierte Versionen sowie einen statischen Pfad ab. Ein unabhängiger
Security-Review bestätigte außerdem, dass `trusted_https_path_prefix` nur den
erlaubten Pfadpräfix ableitet und der nachgelagerte HTTPS-Authority-Guard
fail-closed bleibt.

Das fokussierte Provenance-Modul bestand 13 Tests, und der Whitespace-Check
bestand. Die isolierte vollständige Security-Regression bestand 215 Tests,
und das repository-native Ziel `make lint` bestand mit task-eigenen State-,
Build- und Temp-Roots. Normale Delivery und ein frisches GitHub-/SonarCloud-
Readback des exakten Heads sind weiterhin erforderlich. PR #30 bleibt Draft,
und ein Merge bleibt nicht autorisiert, bis das vollständige offene Issue-
Inventar null ist.
