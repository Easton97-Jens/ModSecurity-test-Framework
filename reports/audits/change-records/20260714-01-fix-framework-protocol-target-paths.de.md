# Change Record: 20260714-01-fix-framework-protocol-target-paths

**Sprache:** [English](20260714-01-fix-framework-protocol-target-paths.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260714-01-fix-framework-protocol-target-paths` |
| UTC-Datum | 2026-07-14 |
| Framework-Basisrevision | `ef6b6d516d63c05beb8bb4e872a8568c9fded75d` |
| Issue oder Pull Request | Keines; gezielte Framework-Reparatur |

## Motivation und Problemstellung

Die öffentlichen Make-Targets `protocol-client`, `check-protocol-evidence` und
`check-transport-hardening-evidence` verwendeten standardmäßig nicht
vorhandene Python-Dateinamen mit Bindestrichen. Die gepflegten Dateien
verwenden Unterstriche. Der historische Commit
`428dfb2741785adabad7a6280882ea5251e00324` verschob die drei Implementierungen
in ihre aktuellen `ci/checks/`-Verzeichnisse und führte dabei die falschen
Dateinamen mit Bindestrichen in den Makefile-Standards ein.

## Betroffene Komponenten und Sicherheitsgrenzen

Dies ändert die Framework-Makefile-Pfadauflösung, einen statischen
Makefile-Vertrag und gepaarte Framework-Dokumentation. Es ändert keinen
Connector, Host-Adapter, kein Capability-Manifest, Evidence-Schema,
Transport-Assertion oder eine Promotionsentscheidung. Die vorhandenen
Protokoll- und Transport-Evidence-Validatoren bleiben unverändert; die
relevante Grenze verhindert, dass ein fehlendes lokales Tool ihren etablierten
Aufrufvertrag unbemerkt bricht.

## Akzeptanzkriterien

1. Alle drei beibehaltenen öffentlichen Targets lösen zu ihrem vorhandenen
   gepflegten lokalen Runner oder Checker auf.
2. Es werden weder Ersatz-Runner, Produktdateien, Parent-Dateien noch der
   Parent-Gitlink geändert.
3. Fehlende Target-Voraussetzungen behalten einen klaren Nicht-Erfolgsstatus
   und Exit-Code.
4. Ein statischer Test weist fehlende vom Makefile referenzierte lokale Python-
   oder Shell-Skripte nach, einschließlich der ursprünglichen Regression mit
   Bindestrichen.
5. Englische und deutsche Dokumentation sowie Change Records beschreiben
   denselben Target-Vertrag und dieselbe Runtime-Evidenzgrenze.

## Untersuchte Alternativen

- Hyphenierte Wrapper-Skripte wurden verworfen, weil sie einen Runner
  duplizieren oder erfinden würden, statt die veralteten Pfade zu reparieren.
- Das Umbenennen der öffentlichen Targets wurde verworfen, weil Parent-
  Makefile-Forwarder und die Parent-Protokoll-CI genau diese Namen aufrufen.
- Eine Änderung des Parent wurde verworfen, weil der Fehler und die gepflegten
  Runner vollständig dem Framework gehören.

## Implementierungsentscheidung

Die drei Makefile-Standards zeigen nun auf die vorhandenen Dateien mit
Unterstrichen: `protocol_client.py`, `check_protocol_evidence.py` und
`check_transport_hardening_evidence.py`. Öffentliche Target-Namen, Rezepte,
Argumente und Voraussetzungsguards bleiben unverändert.

`test-makefile-contract` durchsucht direkte lokale Python- und Shell-
Skriptreferenzen sowie `$(CI_ROOT)`-Standards im Top-Level-Makefile. Es weist
fehlende, ausbrechende oder nicht reguläre Dateien zurück, prüft die drei
vorgesehenen Zuordnungen und enthält einen synthetischen Negativfall für
`protocol-client.py`. `make lint` ruft dieses statische Target auf.

## Geänderte Dateien und Tests

Versionierte Framework-Änderungen:

- `Makefile`.
- `tests/makefile_contract/test_makefile_local_scripts.py`.
- `docs/reference/variables.md` und `docs/reference/variables.de.md`.
- `docs/testing-and-evidence.md` und `docs/testing-and-evidence.de.md`.
- `docs/development.md` und `docs/development.de.md`.
- Dieses gepaarte Change Record.

Die fokussierte statische Suite deckt alle aktuellen lokalen
Skriptreferenzen des Makefiles, die drei korrigierten Protokoll-Standards und
den ursprünglichen fehlenden Pfad mit Bindestrichen ab. Vorhandene Tests für
Protocol-Client und Transport-Hardening behalten ihre positiven und negativen
Runner-Semantiken.

## Befehle und Ergebnisse

Alle schreibfähigen Befehle verwendeten einen aufgabenspezifischen Nachfahren
der Framework-Temp-Wurzel; Pfade werden absichtlich nicht in diesem Record
aufgeführt.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | ---: | --- | --- |
| `rtk make test-makefile-contract` | 0 | 3 statische Vertragstests bestanden | Nur task-lokale temporäre Ausgabe |
| `rtk make test-protocol-client` | 0 | 16 Protocol-Client-/Evidence-Tests bestanden | Nur task-lokale temporäre Ausgabe |
| `rtk make test-no-crs-contract` | 0 | 81 No-CRS- und Transport-Hardening-Vertragstests bestanden | Nur task-lokale temporäre Ausgabe |
| `rtk make protocol-client` | 2 | Klarer Voraussetzung-Fehler für `PROTOCOL_URL` | Nicht zutreffend |
| `rtk make check-protocol-evidence` | 2 | Klarer Voraussetzung-Fehler für `PROTOCOL_ARTIFACT_DIR` | Nicht zutreffend |
| `rtk make check-transport-hardening-evidence` | 2 | Klarer Voraussetzung-Fehler für `CONNECTOR` | Nicht zutreffend |
| `rtk make -n` für die drei reparierten Targets | 0 | Alle druckten die gepflegten lokalen Tool-Pfade mit Unterstrichen | Nicht zutreffend |
| `rtk make check-bilingual-docs` | 0 | 38 zweisprachige Paare geprüft | Nicht zutreffend |
| `rtk make check-doc-links` | 0 | Getrackte Dokumentationslinks bestanden | Nicht zutreffend |
| `rtk make check-repository-path-references` | 0 | 382 gepflegte Dateien geprüft; keine veralteten Pfade | Nicht zutreffend |
| `rtk make lint` | 0 | Statische Checks, der neue Vertrag, Katalog-, Dokumentations- und Diff-Checks bestanden | Nur task-lokale temporäre Ausgabe |
| `rtk git diff --check` | 0 | Keine Whitespace-Fehler | Nicht zutreffend |

## Sicherheitsauswirkung

Es änderten sich weder Security-Remediation, Produktverhalten, Autorisierung,
Validierungsregel noch Evidence-Policy. Die Korrektur erhält die vorhandenen
begrenzten Protokoll- und Transport-Checker, statt sie zu umgehen. Es war kein
erneuter Test eines Security-Angriffspfads oder alternativen Bypass erforderlich,
weil sich keine Security-Kontrolle änderte.

## Dokumentation und Runtime-Evidenz

Gepaarte englische/deutsche Referenz-, Test- und Entwicklungsdokumentation
nennt jetzt die stabilen öffentlichen Target-Namen, die Runner mit
Unterstrichen, das Voraussetzung-Verhalten mit Exit 2 und die Grenze zwischen
statischer und Runtime-Evidenz. Dieser Record ist auf Englisch und Deutsch
gepaart.

Es wurde keine Connector-Runtime- oder Lifecycle-Evidenz erfasst. Eine bewusst
nicht bediente Loopback-Ausführung und leere isolierte Artefaktverzeichnisse
übten nur die Target-Dispatches aus und lieferten erwartungsgemäß keinen Erfolg;
sie sind keine H1-, H2-, H3-, Connector- oder Produktions-Evidenz.

## Nicht ausgeführte Prüfungen

- H1-, H2- und H3-Connector-Runtime-Checks sind blockiert: Es wurden kein
  Connector-eigener Host-Endpunkt, Harness, Zertifikat, ALPN- oder QUIC-
  Umgebung bereitgestellt.
- CRS/MRTS-Connector-Matrizen werden nicht ausgeführt, weil diese statische
  Pfadreparatur keinen Katalog, keine Matrixauswahl und kein Connector-
  Verhalten ändert und Parent-eigene Runtime-Voraussetzungen benötigt.
- Aktualisierung generierter Berichte und Matrix-Checks werden nicht
  ausgeführt, weil sich keine Generatorquelle änderte und diese Targets
  generierte Dateien umschreiben können.
- C/C++- und gehärtete Diagnose-Builds sind nicht anwendbar: Es änderten sich
  weder C/C++-Quellcode noch ein Build-Vertrag.

## Einschränkungen und Restrisiko

Der neue Vertrag prüft Standardwerte für statisch referenzierte lokale
Skriptpfade; vom Aufrufer gelieferte Tool-Overrides bleiben beim Aufrufer. Er
kann nicht beweisen, dass ein Connector-Host, Client-Feature-Set, TLS/ALPN oder
eine QUIC-Umgebung verfügbar ist. Diese Bedingungen bleiben separate
Runtime-Evidenzvoraussetzungen.

## Finaler Diff- und Review-Status

Der unstaged Framework-Diff wurde auf Scope, Whitespace, generierte Dateien
und sensible Inhalte geprüft. `git diff --check` bestand. Dieser Task erstellt
keinen Commit. Parent-Repository und Gitlink bleiben außerhalb des
Änderungsscope.
