# Change Record: 20260816-01-canonical-active-upstream-pins

**Sprache:** [English](20260816-01-canonical-active-upstream-pins.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260816-01-canonical-active-upstream-pins` |
| UTC-Datum | 2026-08-16 |
| Framework-Basisrevision | `3cb33609626ff689c54b6dc0f31fb7e9401fe75e` |
| Issue oder Pull Request | Draft-PR beim Erstellen dieses Records ausstehend; keine Issue wird geschlossen. |

## Motivation und Problemstellung

Aktive Upstream-Pins hatten sich über Shell-Provisioner, Runtime-Manifest-/
Lock-Views, CI-Workflows, Python-/Tool-Locks, CRS-Contract-Views und
Dokumentation verteilt. Dadurch konnte ein geprüftes Tupel driften, ohne dass
ein generischer Checker jeden aktiven Konsumenten erkannte. Das konkrete
Beispiel war ein Lighttpd-Runtime-Manifest mit `1.4.84`, während das geprüfte
Shell-Tupel bereits `1.4.85` enthielt.

Das Framework benötigt eine manuell gepflegte aktive Pin-Quelle und
deterministische abgeleitete Views. Die Delivery bewahrt außerdem die
vorherige Security-Remediation: nicht vertrauenswürdige Make-Steuerungen,
veränderliche Runtime-Cache-Übergaben und Runtime-Provenance müssen
fail-closed bleiben und dürfen nicht zur Vereinfachung der Generierung gelockert
werden.

## Betroffene Komponenten und Sicherheitsgrenzen

Der Framework-eigene Scope umfasst `ci/lib/common.sh`, generische Pin-Parser
und Generatoren, Runtime-Provisioning- und Lock-/Manifest-Contracts,
CI- und Workflow-Pin-Views, CRS-Views, Make-Einstiegspunkte, Tests und
gepaarte technische Dokumentation. Die Sicherheitsgrenze beginnt bei
geprüften Version-/Ref-/Asset-/Plattform-/Digest-Tupeln und endet beim
Konsumenten, der die abgeleitete View provisioniert, validiert oder
veröffentlicht. Parent-Produktcode, Parent-Gitlink, Connector-Host-Runtime-
Claims, MRTS, globale Installation und Deployment sind ausgeschlossen.

## Akzeptanzkriterien

1. `ci/lib/common.sh` ist die einzige manuell gepflegte aktive Pin-Autorität.
2. Runtime-Manifest und Lock sowie Python-/Tool-/Workflow-Pins und CRS-Views
   werden deterministisch aus dieser Autorität erzeugt oder validiert.
3. Fehlende, unbekannte, doppelte, veraltete, plattform- oder URL-abweichende
   oder fehlerhaft geformte Runtime-Einträge schlagen fail-closed fehl.
4. Aktives Provisioning bewahrt Digest-/Provenance-Bindung, private geprüfte
   Archivmaterialisierung und sicheres Make-Caller-Input-Handling.
5. Fokussierte Regressionen, generische Checker, Idempotenz, Lint und die
   vollständige native Unit-Test-Evidenz bestehen ohne Netzwerk-Pin-Discovery
   oder Dependency-Installation.
6. Parent-Gitlink und MRTS bleiben unverändert.
7. Python- und CRS-View-Tooling akzeptieren nur nicht-symlinkierte,
   enthaltene Roots und verwenden an jedem Dateisystem-Sink den validierten
   Pfad; das Python-Synchronizer-`--root` muss dem Checkout entsprechen, der
   das Tool enthält.

## Untersuchte Alternativen

- Unabhängige Literale in jedem Konsumenten wurden verworfen, weil sie die
  nicht erkennbaren Drift-Grenzen erneut erzeugen.
- Das Sourcen von `common.sh` aus Python-Generatoren wurde verworfen, weil es
  Shell-Ausführungsautorität für die Eingabe einer generierten View erteilt;
  der finale Parser ist nicht ausführend und allowlisted.
- Das weitere Extrahieren von Runtime-Artefakten aus Shared-Cache-Orten nach
  der ersten Hash-Prüfung wurde verworfen, weil eine Austausch-Race die
  Review-Grenze überschreiten kann.

## Implementierungsentscheidung

`common.sh` definiert kanonische Descriptor-artige Tupel und leitet Asset-/URL-
Werte sicher ab. `sync-runtime-components.py` parst nur das geprüfte
Assignment-/Expansion-Subset, erzeugt atomare deterministische Runtime-Views
und besitzt einen Kompatibilitäts-Wrapper für die frühere Traefik-only-
Schnittstelle. Dedizierte Generatoren/Checker decken Python-, Workflow- und
CRS-Views ab. Der generische Lock-Checker validiert descriptor-deklarierte
Manifest-Mitgliedschaft, exakte URLs und kanonische Plattformwerte.

Runtime-Artefakte werden verifiziert, kopiert, erneut gehasht, extrahiert,
gebaut, gestaged und in task-privaten `BUILD_ROOT`-Orten aufgezeichnet.
`safe-make.sh` entfernt und verwirft GNU-Make-Pre-Parser-Steuerungen, während
unterstützte CI-/Helper-Einstiegspunkte diese Grenze verwenden. Bestehende
EN/DE-Dokumente benennen nun kanonische gegenüber abgeleiteten Views, statt
aktive Pins unabhängig zu deklarieren.

CRS-View-Tooling validiert einen vom Caller übergebenen Fixture-Root und jeden
festen View-Pfad auf lexikalisches und aufgelöstes Containment, nicht
symlinkierte Komponenten und regulären Dateityp. Der Validator gibt nur den
geprüften aufgelösten Pfad zurück; alle CRS-Lese-, Vergleichs- und atomaren
Schreibzugriffe verwenden diesen Wert, sodass kein roher CLI-abgeleiteter Pfad
einen dieser Dateisystem-Sinks erreicht.

Der Python-Pin-Synchronizer verwendet den Checkout, der das Tool enthält, als
vertrauenswürdigen Root: `--root` wird nur akzeptiert, wenn er diesem Root
entspricht, und `read_utf8()` wiederholt die Containment- und
Nicht-Symlink-Pfadvalidierung unmittelbar vor jedem Text-Lesezugriff. Die
temporären Fixture-Tests kopieren das Tool in die Fixture, sodass akzeptierter
Root und Tool-Provenienz übereinstimmen.

### SonarQube-Cloud-Remediation-Follow-up

Die vorhergehende PR-Analyse meldete 44 neue Code Smells und 16 duplizierte
New-Code-Zeilen (0,3 %). Dieses Follow-up verwendet weder einen
Accepted-Issue-Status noch Scanner-Ausschlüsse, Regelunterdrückungen oder
rein metrische Umgehungen. Es zerlegt Cognitive-Complexity-Stellen,
zentralisiert wiederholte Validierungs-/Fehlerpfade, macht Shell-Case-Defaults
explizit, verwendet kurze ASCII-bewusste Regexe und nutzt einen
Runtime-Test-Helper statt duplizierter Testblöcke.

Der Parser liest weiterhin nur die deklarative Runtime-Assignment-Grammatik
und sourct common.sh niemals. Eine direkte unzulässige
Assignment-Expression wird ohne Ausführung verworfen. Er wird bewusst nicht
als vollständiger Interpreter oder Verifizierer beliebiger späterer
Shell-Ausführung dargestellt; die PR- und Wartungs-Workflow-Trust-Boundaries
stellen den getrennten Ausführungsschutz bereit.

Die erste Exact-Head-Analyse nach diesem Refactoring identifizierte fünf
Restbefunde. Dieses source-native Follow-up beseitigt die beiden
Fixed-Condition-Meldungen, den leeren f-String und den
Lock-Checker-Complexity-Befund und macht zugleich Root-Provenienz und direkte
Read-Sink-Grenze des Python-Synchronizers explizit. Es verwendet weder
Accepted-Issue-Status, Suppression, Scanner-Exclusion noch eine Änderung des
Quality Gates.

## Geänderte Dateien und Tests

- Kanonische Quelle und Runtime-Contracts: `ci/lib/common.sh`,
  `ci/lib/runtime-component-common.sh`, Runtime-Provisioner, Runtime-Manifest/
  Lock und Smoke-/Provenance-Helper.
- Neue Generator-/Security-Tools: `ci/tools/common_canonical_pins.py`,
  `crs_contract_pins.py`, `safe-make.sh`, `sync-runtime-components.py`,
  `sync-canonical-python-pins.py`, `sync-canonical-workflow-pins.py` und
  `sync-crs-contract-views.py`.
- Konsumenten-Contracts: `Makefile`, V3-Smoke-Make-/Runtime-Skripte,
  CI-Workflows, Runtime-/CI-Security-Checker, Python-/Tool-Lock-Views und
  Katalog-Checks.
- Dokumentation: gepaarte Connector-, Workflow-Security-, Variablen-,
  CI-Tooling- und Testing-/Evidence-Referenzen.
- Tests: neue Generator-/Runtime-Synchronisations-Regressionen sowie
  erweiterte Provenance-, Private-Materialization-, Safe-Make-, Lock-,
  Download-, Bootstrap-, CRS- und CI-Contract-Abdeckung einschließlich
  CRS-Root-Traversal- und Symlink-Root-Verwerfung mit legitimem
  temporären-Fixture-Control.
- Sonar-Remediation: Framework-native Refactorings in Canonical-Pin-,
  Workflow-, Runtime-, Common-Version-, CI-Contract- und Shell-Control-Pfaden
  mit fokussierter Regressionsabdeckung für lexikalisches Containment,
  ASCII-only-Releases/-Tags, explizite Shell-Defaults und
  Runtime-Metadaten-Contracts.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | ---: | --- | --- |
| `python -m unittest -v` für Runtime-Lock-/Sync-/Download-/Smoke-/Bootstrap-Module | 0 | 86 fokussierte Security-/Runtime-Tests bestanden. | Lokaler Canonical-Pin-Validierungsbeleg |
| `python -m unittest -v` für Provenance- und Generator-Module | 0 | 46 Generator-/Atomic-Provenance-Tests bestanden. | Lokaler Canonical-Pin-Validierungsbeleg |
| `python -m unittest -q` für NGINX-/APR-/CRS-/V3-/PCRE2-Provenance-Module | 0 | 78 breite Provenance-Tests bestanden. | Lokaler Canonical-Pin-Validierungsbeleg |
| `make lint` mit task-eigenen externen Roots | 0 | Bestehende Lint-/Contract-Kette bestand. | Lokaler Canonical-Pin-Validierungsbeleg |
| `python -m unittest discover -q` | 0 | 98 native Full-Suite-Tests bestanden. | Lokaler Canonical-Pin-Validierungsbeleg |
| Generische Canonical-/Synchronizer-/Lock-/Catalog-/Shell-Syntax- und `git diff --check`-Prüfungen | 0 | Generierte Views und Source-Contracts waren sauber und idempotent. | Lokaler Canonical-Pin-Validierungsbeleg |
| Fokussierte CRS-Root-Containment-, Canonical-Python- und Workflow-Synchronizer-Tests | 0 | 26 Tests bestanden, einschließlich Traversal- und Symlink-Root-Negativfällen. | Draft-PR-Remediation-Validierung |
| Framework-safe-make lint mit dem ausgewählten absoluten Virtual-Environment-Python | 0 | Vollständige native Lint-, Contract-, Provenance-, Runtime-, Workflow-, Dokumentations- und Whitespace-Kette bestand. | Lokale Sonar-Remediation-Validierung |
| Fokussierte Runtime-Sync-/Lock-/Traefik-Testmodule plus generischer Runtime-Synchronizer-Check | 0 | 35 Tests bestanden; direkte unzulässige Deklaration und No-Execution-Controls bestanden. | Lokale Sonar-Remediation-Validierung |
| Follow-up Canonical-Python-/CRS-/Runtime-/Workflow-Module | 0 | 66 fokussierte Tests bestanden, einschließlich Checkout-Root-Bindung und direkter Symlink-Read-Rejection. | Lokale Sonar-Residual-Remediation-Validierung |

## Sicherheitsauswirkung

Dies ist eine Security-Hardening- und Supply-Chain-Provenance-Änderung.
Regression-Controls decken bösartige Shell-Eingaben im Parser, bösartige
GNU-Make-Steuerzuweisungen/-Optionen, veraltete oder manipulierte Provenance,
falsche Runtime-URLs und Manifest-Mitgliedschaft, gefälschte Checksum-Tools
und Shared-Cache-Handoff-Versuche ab. Legitime kontrollierte Eingaben bestehen
weiterhin. Sie decken außerdem CRS-Root-Traversal und Symlink-Root-
Substitution ab, bevor eine View gelesen oder geschrieben werden kann. Der
finale Review fand keine bestätigte High- oder Critical-Impact-Schwachstelle
in unterstützten aktiven Einstiegspunkten.

Der Python-Synchronizer bindet seinen akzeptierten Root nun an den Checkout,
der das Tool enthält, und wiederholt Root-Containment, Komponenten-
Symlink-Rejection und Regular-File-Validierung am direkten Text-Read-Sink.
Damit wird die verbleibende Pfad-Provenienz-Mehrdeutigkeit beseitigt, ohne
einem Caller eine beliebige `--root`-Auswahl zu gewähren.

Das Follow-up bestätigte nach den Maintainability-Refactorings unabhängig
lexikalisches Containment und ASCII-only-Release-/Tag-Validierung. Die
überprüfte Runtime-Parser-Vollständigkeitsfrage hatte keinen
untrusted-to-privileged-Workflow-Pfad: PR-Jobs sind read-only und
privilegierte Wartungsjobs verwenden einen vertrauenswürdigen
Default-Branch-Checkout. Sie ist daher als nicht anwendbar erfasst und nicht
als behauptete behobene Schwachstelle.

## Dokumentation und Runtime-Evidenz

Gepaarte englische/deutsche Framework-Dokumentation beschreibt die kanonische
Quelle und die abgeleiteten Views. Die Tests sind lokale Source-, Generator-
und Contract-Evidenz. Es wurde kein Connector-Host gestartet und kein
Host-Runtime-`PASS` behauptet. Parent kann diese Framework-Revision nur über
einen separat autorisierten Parent-Gitlink-Lifecycle konsumieren.

## Nicht ausgeführte Prüfungen

- `pytest -q` wurde versucht, aber die bereitgestellte Framework-Umgebung
  enthält kein `pytest`-Modul; es wurde keine Dependency installiert. Die
  native vollständige `unittest`-Discovery ist der verfügbare Fallback.
- Keine netzwerkbasierte Latest-Version-Discovery oder echter Upstream-
  Artefakt-Download wurde ausgeführt; deterministische Fixtures schützen den
  geprüften Pin-Contract.

## Einschränkungen und Restrisiko

Ein direkter Aufruf von `/usr/bin/make` bleibt Caller-Autorität außerhalb der
unterstützten `safe-make.sh`-/CI-/Helper-Grenze. Der task-private Build-Root
muss nach dem finalen Hash für einen Angreifer nicht schreibbar bleiben. Ein
neues Plattform- oder Runtime-Profil benötigt ein geprüftes kanonisches Tupel
und Regression-Abdeckung. Das Python-Synchronizer-`--root` ist absichtlich
kein beliebiger Fixture-Selektor: es muss den Checkout bezeichnen, der dieses
Tool enthält, und Fixture-Tests kopieren das Tool in ihren kontrollierten
Checkout. Wie bei den anderen lokalen Dateiprüfungen setzt die
Containment-Garantie voraus, dass kein gleichzeitiger feindlicher Writer eine
geprüfte Datei zwischen Validierung und Dateisystemoperation ersetzt.

## Finaler Diff- und Review-Status

Der ursprüngliche kanonische Diff, die CRS-Root-Containment-Remediation und
die native Sonar-Remediation bestanden auftragsbezogenen Whitespace-Review,
Generated-View-Idempotenz, fokussierten Security-Review und vollständiges
lokales Lint. Das erste ausgelieferte Follow-up beseitigte die ursprünglichen
44 Code Smells und die Duplizierung, aber sein exakter Hosted-Head meldete
fünf Restbefunde, einschließlich eines High-Security-
Path-Provenance-Reports; er wird nicht als sauber behauptet. Dieses zweite
source-native Follow-up bestand die vollständige lokale Lint-Kette. Draft-PR
#82 bleibt offen; normaler Push, Remote-/PR-Head-Identität und die
Exact-Head-Hosted-Analyse sind noch erforderlich, bevor dieses Record ein
Zero-Issue-Ergebnis beanspruchen kann. Dieses Record beansprucht kein Merge-,
Parent-, MRTS- oder Gitlink-Ergebnis.
