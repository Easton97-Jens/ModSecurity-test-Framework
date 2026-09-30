# Integration des tatsächlich gepinnten MRTS-Generators

**Sprache:** [English](CR-20260929-mrts-real-integration.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `CR-20260929-mrts-real-integration` |
| Datum (UTC) | 2026-09-29 |
| Basis-Revision | `37315b43366d1f56045d3e9dc91d9d05782ff285` |
| Lieferziel | Bestehender Framework-Draft-PR #128; kein Merge |

## Motivation und Problemstellung

Das Merge-Review verlangt echte Generator-/Korpusnachweise zusätzlich zu den
Launchertests mit harmlosem Ersatzgenerator. Der Nutzer hat diese begrenzte
Integrationsarbeit freigegeben. Andere Findings und Repositorys gehören nicht dazu.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-Shelleinstieg und Guard rufen den separat gepinnten MRTS-Generator auf.
MRTS-Quellcode und Gitlink bleiben unverändert. Testdaten und Ausgaben liegen in
einem neuen privaten RUNNER_TEMP-Unterverzeichnis, nie in den Quellverzeichnissen.

## Akzeptanzkriterien

Upstream-config-tests und Feature-demo müssen nichtleere Rule-/FTW-Inventare
mit denselben Pfaden und Bytes wie die direkte Generierung liefern. Die
geprüfte Quellidentität muss sauber bleiben. Undokumentierte globale Schlüssel
expdir/testdir/content müssen die konkrete Guard-Ablehnung auslösen und äußere
Kontrolldateien unverändert lassen. Absolute Pfade, Traversal und Symlink-Ausbrüche
müssen die echte Generator-Pfadprüfung erreichen, ohne äußere Kontrolldateien
zu ändern. Ein beliebiger Fehlercode genügt nicht als bestandene Prüfung.

## Untersuchte Alternativen

Weitere Ersatzgeneratortests schließen die Kompatibilitätslücke nicht.
Generatoränderungen würden die Zuständigkeitsgrenze verletzen. Eine volle
Connectormatrix ist für diesen Eingangsvertrag nicht erforderlich und wird
nicht als ausgeführt behauptet.

## Implementierungsentscheidung

Der bestehende Read-only-Exact-Head-Workflow wird erweitert. Vorhandener
Unittestbefehl, Action-Pins, Dependency-Lock und Publisherregistrierungen bleiben
erhalten. Nur der aufgezeichnete MRTS-Gitlink wird im frischen Runner initialisiert,
ohne Auswahl eines entfernten Branches. Ein begrenzter Python-Check führt den
echten Shelleinstieg und Generator aus, vergleicht Inhalts-Hashes und prüft
konkrete Ablehnungsdiagnosen. Prozesse haben Zeitgrenzen; private Logs verbleiben
im Runner-Temporärverzeichnis. Gedruckt wird nur ein kleiner Metadatennachweis.

## Geänderte Dateien und Tests

- `ci/checks/security/check-mrts-definition-integration.py`
- `.github/workflows/ci-findings-regressions.yml`
- Dieses englisch/deutsche Change-Record-Paar.

## Befehle und Ergebnisse

Einstieg, Generator und Pfadhelfer wurden am tatsächlichen Quellstand gelesen.
Der neue Check wurde als Python-AST geparst, nicht lokal ausgeführt. In der
Bearbeitungsumgebung fehlen RTK und provisionierter Checkout. Die bestehenden
Launcher-Unittests bleiben unverändert. CI am neuen Head muss Unittests und
Integration ausführen; zukünftige Ergebnisse werden nicht vorausgesetzt.

## Sicherheitsauswirkung

Negativfälle betreffen nur eigene temporäre Testpfade. Installierte Dienste,
MRTS-Dateien, Gitlinks, CI-Tokenrechte und bestehende Gates bleiben unverändert.
Die konkrete Ablehnungsdiagnose verhindert, dass Umgebungsfehler als bestandene
Containment-Prüfung erscheinen.

## Dokumentation und Runtime-Evidenz

Eine erfolgreiche Integration schreibt einen SHA-gebundenen Metadatennachweis
mit Korpusanzahlen, Bytegleichheit, abgelehnten Schlüsseln und erhaltenen
Kontrolldateien. Rohregeln, ursprüngliche Scanpayloads und Diagnoselogs werden
nicht automatisch veröffentlicht. Dies ist Generatorintegration, kein
ModSecurity-Host-Enforcementnachweis und kein vollständiger B03-Fix.

## Nicht ausgeführte Prüfungen

Lokale Projekttests und Korpusgenerierung liefen mangels Pflichtwrapper und
Checkout nicht in der Bearbeitungsumgebung. Tatsächliche CI-/Sonarergebnisse
müssen für den veröffentlichten Folgecommit abgerufen werden.

## Einschränkungen und Restrisiko

Direkter MRTS-Aufruf bleibt außerhalb des Guards. Keine feindliche Same-UID-
Isolation oder vollständige Connectorsicherheit wird behauptet. Der offene
B03-Status des bisherigen Records bleibt gültig. Kein Parent-Gitlink wird geändert.

## Finaler Diff- und Review-Status

Nur Integrationscheck, Workflowanbindung und dieses Record-Paar werden ergänzt.
Der PR bleibt Draft; kein Merge, Findingabschluss oder gelockerter Check.
