# Change Record: 20260718-01-fix-framework-nginx-archive-digest

**Sprache:** [English](20260718-01-fix-framework-nginx-archive-digest.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260718-01-fix-framework-nginx-archive-digest` |
| UTC-Datum | 2026-07-18 |
| Framework-Basisrevision | `cdc91a398d6c156eaff927d742b23018a3817fb6` |
| Issue oder Pull Request | Framework-Draft-PR ausstehend; dieser Record wird vor dem Delivery-Status `verified_pr` aktualisiert. |

## Motivation und Problemstellung

`NGINX_SHA256` konnte leer sein. Der NGINX-Prepare-Pfad zeichnete einen
lokalen Hash auf, übersprang den Vergleich und extrahierte das ausgewählte
Release-Archiv. Ein ersetztes Archiv konnte somit ohne einen überprüften,
passenden Digest die Build-Verarbeitung erreichen.

## Betroffene Komponenten und Sicherheitsgrenzen

Die Änderung ist auf die Framework-NGINX-GitHub-Release-Archive-Integrity-
Grenze beschränkt: Konfiguration in `ci/lib/common.sh`, Archive-Auswahl,
Cache/Refresh, Verifikation, Staging und Extraction in
`prepare-nginx-build.sh`. Sie ändert keinen Connector, keinen Parent-Source
oder Gitlink, kein MRTS und nicht FND-FRAMEWORK-0005.

## Akzeptanzkriterien

1. Ein nicht leerer, syntaktisch gültiger SHA-256-Digest ist vor NGINX-
   Latest-Resolution, Archive-Cache-Nutzung, Download, Extraction oder
   Build-Arbeit erforderlich.
2. Das ausgewählte Archiv und das private an `tar` übergebene Archiv passen
   beide zum konfigurierten Digest.
3. Leere, nur-Whitespace-, mit nachgestelltem Whitespace versehene,
   malformed und abweichende Werte stoppen ohne `tar`-Aufruf.
4. Ein passendes lokales Archiv ist erfolgreich; Latest, Release-/Source-
   Overrides, vorhandener Cache, Refresh und ein Archive-Austausch sind
   abgedeckt.
5. Englische/deutsche Dokumentation und dieses gepaarte Record beschreiben
   dieselbe Konfigurations- und Evidenzgrenze.

## Untersuchte Alternativen

- Ein nicht überprüfter Repository-Standard-Digest wurde verworfen. Dieser
  Task hat keine freigegebene NGINX-Digest-Pflegequelle und führt absichtlich
  keinen echten Netzwerk-Download aus; ein spekulativer Wert würde die
  Herkunft abschwächen.
- Eine Verifikation nur für ein heruntergeladenes Archiv wurde verworfen, weil
  gecachte Archive und Austausch nach der ersten Verifikation unsicher blieben.
- Die direkte Übergabe des zuerst geprüften Cache-Pfads an `tar` wurde
  verworfen, weil dies den Digest nicht an die tatsächliche Extraction-Eingabe
  bindet.

## Implementierungsentscheidung

Die Konfiguration bleibt absichtlich standardmäßig nicht gesetzt, ist nun aber
eine verpflichtende, überprüfte Aufrufer-Eingabe. `prepare-nginx-build.sh`
validiert Digest und relevante Referenzen vor der NGINX-Preparation und
wiederholt die Validierung am Archive-Use-Point. Es validiert feste und per
`latest` aufgelöste Tags, bevor der Candidate-Pfad gebildet wird.

Das Skript verwendet einen vorhandenen Candidate nur wieder, wenn `REFRESH`
nicht `1` ist; Refresh lädt in einen temporären Pfad und platziert den
Candidate atomar. In beiden Fällen verifiziert es den Candidate, kopiert ihn in
ein isoliertes Verzeichnis `verified-archives/` unterhalb von
`NGINX_BUILD_DIR`, verifiziert die Staging-Kopie vor und nach der finalen
Platzierung und übergibt ausschließlich diese private verifizierte Kopie an
`tar`.

## Geänderte Dateien und Tests

Versionierte Framework-Änderungen:

- `ci/lib/common.sh`.
- `ci/provisioning/prepare-nginx-build.sh`.
- `tests/security_regression/test_nginx_archive_digest.py` und isolierte lokale
  Payload-, Digest- und Latest-Release-Fixtures unter
  `tests/fixtures/nginx-archive-digest/`.
- `docs/reference/variables.md` und `docs/reference/variables.de.md`.
- Dieses gepaarte Change Record.

Der fokussierte Test ruft den echten Prepare-Einstiegspunkt mit
deterministischen lokalen Archiven, einer kontrollierten Download-Grenze, dem
echten Programm `tar` und einem `tar`-Sentinel auf. Er deckt leere, nur-
Whitespace- und mit nachgestelltem Whitespace versehene Digests, malformed,
Mismatch, passend, Archive-Swap, Latest-Cache, Release-/Source-Override,
vorhandenen Cache und Refresh ab.

## Befehle und Ergebnisse

Alle schreibfähigen Befehle verwendeten das task-eigene temporäre Run-
Verzeichnis; kein echtes NGINX-Release wurde heruntergeladen oder gebaut.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | ---: | --- | --- |
| `rtk env TMPDIR=<task-run>/tmp python3 -B -m unittest tests.security_regression.test_nginx_archive_digest -v` vor dem Fix | 1 | Die verwundbare Baseline verletzte die erforderlichen Fail-Closed-Assertions. | `20260718T092116Z-fnd-framework-0006-nginx-digest-5251a4f1` |
| `rtk sh -n ci/lib/common.sh ci/provisioning/prepare-nginx-build.sh` | 0 | Beide geänderten Shell-Dateien wurden erfolgreich geparst. | `20260718T092116Z-fnd-framework-0006-nginx-digest-5251a4f1` |
| `rtk env TMPDIR=<task-run>/tmp python3 -B -m unittest tests.security_regression.test_nginx_archive_digest -v` nach dem Fix | 0 | Sieben fokussierte Tests bestanden, einschließlich aller erforderlichen Negativ- und legitimen Kontrollfälle. | `20260718T092116Z-fnd-framework-0006-nginx-digest-5251a4f1` |
| `rtk env BUILD_ROOT=<task-run>/build TMPDIR=<task-run>/tmp PYTHONDONTWRITEBYTECODE=1 FRAMEWORK_ROOT=<task-worktree> make lint` | 0 | Native Framework-Shell-, Python-, Security-, Catalog- und Dokumentations-Lintprüfungen bestanden. | `20260718T092116Z-fnd-framework-0006-nginx-digest-5251a4f1` |
| `rtk make check-documentation` und `rtk git diff --check` | 0 | Dokumentations- und Whitespace-Prüfungen bestanden. | `20260718T092116Z-fnd-framework-0006-nginx-digest-5251a4f1` |
| `rtk shellcheck -x ci/lib/common.sh ci/provisioning/prepare-nginx-build.sh` | 1 | Ausschließlich bereits in der unveränderten Framework-Basis vorhandene Diagnosen; keine task-eigene Diagnose hinzugefügt. | `20260718T092116Z-fnd-framework-0006-nginx-digest-5251a4f1` |

## Sicherheitsauswirkung

Dies behebt FND-FRAMEWORK-0006. Der ursprüngliche Pfad mit nicht gesetztem
Digest blockiert nun vor NGINX-Archive-Auswahl/Download/Extraction; malformed-,
Whitespace- und Mismatch-Werte haben dasselbe Fail-Closed-Ergebnis. Der
Review alternativer Umgehungen deckt Latest-Resolution, Release- und Source-
Overrides, Cache/Refresh, vorhandene Archive, Derived-Archive-Path-Replacement
und einen Austausch zwischen dem ersten Candidate-Hash und der Private-Copy-
Verification ab. Letzterer blockiert vor `tar`.

## Dokumentation und Runtime-Evidenz

Die gepaarte englische/deutsche Variablendokumentation verlangt jetzt einen
überprüften 64-Hex-Zeichen-Digest für das exakte `github-release`-Archiv und
erklärt, dass der Standard absichtlich nicht für Provisioning verwendbar ist.

Der fokussierte Test ist kontrollierte lokale Runtime-Evidenz nur für die
Archive-Handling-Grenze. Er behauptet weder einen echten Upstream-NGINX-
Download, NGINX-Runtime, Connector-Runtime, CI-Lifecycle noch Produktions-
Evidence.

## Nicht ausgeführte Prüfungen

- Vollständige Framework- und Connector-Matrizen wurden nicht ausgeführt: Die
  Änderung ist auf die NGINX-Archive-Trust-Boundary beschränkt und es wurden
  keine Connector-Runtime-Voraussetzungen bereitgestellt.
- Ein echter Release-Download/-Build wurde nicht ausgeführt: Er liegt außerhalb
  des autorisierten lokalen Fixture-Scopes und würde keine überprüfte
  Digest-Herkunft belegen.
- Delivery-, PR-Checks, Reviews und Sonar-Status bleiben ausstehend, bis der
  ausschließlich Framework-eigene Branch committed ist und ein Draft-PR
  existiert.

## Einschränkungen und Restrisiko

Ein Aufrufer muss den Digest für jedes ausgewählte NGINX-Archiv beschaffen und
prüfen; das Framework erfindet absichtlich keinen. Die Staging-Kopie bindet den
getesteten Candidate-Replacement-Fall an die Extraction-Eingabe, aber kein
lokaler Test ersetzt externe Upstream-Release-Governance oder Produktions-
Runtime-Evidenz.

## Finaler Diff- und Review-Status

Implementierung, fokussierter Test, gestagter Scope sowie finaler Whitespace-/
Dokumentations-Review sind lokal validiert. Delivery- und Current-Head-PR-
Reviews bleiben ausstehend und werden vor `verified_pr` dokumentiert.
