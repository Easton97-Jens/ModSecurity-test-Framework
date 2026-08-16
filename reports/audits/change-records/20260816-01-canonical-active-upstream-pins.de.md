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
7. CRS-View-Tooling akzeptiert nur nicht-symlinkierte, enthaltene Fixture-
   Roots und verwendet an jedem Dateisystem-Sink den validierten aufgelösten
   Pfad.

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
und Regression-Abdeckung. Das `--root`-Fixture-Verzeichnis bleibt Caller-
Autorität; die Containment-Garantie setzt voraus, dass kein gleichzeitiger
feindlicher Writer die geprüften Dateien zwischen Validierung und
Dateisystemoperation ersetzt.

## Finaler Diff- und Review-Status

Der ursprüngliche kanonische Diff und die CRS-Root-Containment-Remediation
bestanden ihren auftragsbezogenen Whitespace-Review,
Generated-View-Idempotenz, fokussierten Security-Review und die lokale
Validierung. Draft-PR #82 ist offen; der nächste Commit und normale Push
werden nach der Delivery gegen die Remote- und PR-Heads verifiziert. Der
fehlgeschlagene SonarQube-Cloud-Security-Gate auf dem vorherigen PR-Head ist
der Grund für diese Remediation; hier wird kein Hosted-Ergebnis für den
aktuellen Head behauptet. Dieses Record beansprucht kein Merge-, Parent-,
MRTS- oder Gitlink-Ergebnis.
