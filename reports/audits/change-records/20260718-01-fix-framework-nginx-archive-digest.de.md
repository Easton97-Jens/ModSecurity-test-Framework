# Change Record: 20260718-01-fix-framework-nginx-archive-digest

**Sprache:** [English](20260718-01-fix-framework-nginx-archive-digest.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260718-01-fix-framework-nginx-archive-digest` |
| UTC-Datum | 2026-07-19 |
| Framework-Basisrevision | `c5e7553cf5f3eb7c5535e392798e03ae21f81981` |
| Issue oder Pull Request | Framework-Draft-PR [#25](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/25) gegen `master`; dieser Record wird vor dem Delivery-Status `verified_pr` aktualisiert. |

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

1. Die normale feste Source-Build-Konfiguration enthält einen nicht leeren,
   überprüften SHA-256 für genau ein offizielles NGINX-Release-Asset.
2. Release-Tag, passender Source-Ref, Asset-Name und Digest sind ein atomisches
   Konfigurations-Tupel; ein fester Source-Ref oder Asset-Name kann nicht vom
   Release-Tag abweichen.
3. Das ausgewählte Archiv und das private an `tar` übergebene Archiv passen
   beide zum konfigurierten Digest. Explizit leere, nur-Whitespace-,
   fehlerhafte, abweichende und tupel-inkonsistente Werte stoppen vor
   Netzwerknutzung oder `tar`.
4. Der Versionsprüfer verifiziert das konfigurierte offizielle Release-Asset
   und den von GitHub veröffentlichten SHA-256-Digest, aktualisiert aber nie
   nur den Tag.
5. Englische/deutsche Dokumentation und dieses gepaarte Record beschreiben
   dieselbe Konfigurations- und Evidenzgrenze.

## Untersuchte Alternativen

- Ein erzeugtes GitHub-Tag-Archiv wurde verworfen, weil dessen URL nur einen
  Tag benennt und nicht den hier erforderlichen überprüften Release-Asset-
  Vertrag bereitstellt.
- Ein Fixture-Hash oder ein aus einem nicht überprüften Kandidaten berechneter
  Digest wurde als Provenance verworfen; beides ist keine unabhängige
  Upstream-Release-Evidenz.
- Eine Verifikation nur für ein heruntergeladenes Archiv wurde verworfen, weil
  gecachte Archive und Austausch nach der ersten Verifikation unsicher blieben.
- Die direkte Übergabe des zuerst geprüften Cache-Pfads an `tar` wurde
  verworfen, weil dies den Digest nicht an die tatsächliche Extraction-Eingabe
  bindet.

## Implementierungsentscheidung

Der feste Standard ist das überprüfte offizielle GitHub-Release-Tupel
`release-1.31.2` / `nginx-1.31.2.tar.gz` /
`af2a957c41da636ddc4f883e4523c6d140b4784dbce42000c364ae5092aa473c`.
Das Release-Asset wird vom exakten GitHub-Release-Download-Pfad geladen,
nicht von einem erzeugten Tag-Archiv. `prepare-nginx-build.sh` validiert dieses
Tupel vor der NGINX-Preparation und wiederholt die Digest-Prüfung am
Archive-Use-Point. Bei einem festen Release muss der Source-Ref dem Release-Tag
entsprechen und der Asset-Name das abgeleitete NGINX-Release-Asset für diesen
Tag sein.

Die Vorprüfung vom 2026-07-19 fragte die offiziellen GitHub-Release-Metadaten
für `release-1.31.2` ab; sie nennen das ausgewählte Asset und den obigen
SHA-256. Ein direkter HTTPS-Download stimmte damit überein. Der annotierte Git-
Tag löst auf Commit `2fd01ed47a1fd2965754c83f53b33a789d0e07f1` auf, wird von
GitHub jedoch als unsigniert markiert. Dieser Record erhebt daher keinen
Anspruch auf PGP-Signaturprüfung.

`check-common-versions.py` verifiziert das konfigurierte Release, die
Asset-URL und den veröffentlichten Digest. Gibt es ein anderes aktuelles
Release, meldet der Prüfer `unknown` ohne generierte Änderungen: Tag, Asset-
Name und Digest müssen gemeinsam geprüft und geändert werden.

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
- `ci/tools/check-common-versions.py`.
- `tests/security_regression/test_nginx_archive_digest.py`,
  `tests/security_regression/test_nginx_release_provenance.py` und isolierte
  lokale Payload-, Digest- und Latest-Release-Fixtures unter
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

Alle schreibfähigen Befehle verwenden das task-eigene temporäre Run-
Verzeichnis. Die Fortsetzung vom 2026-07-19 lud genau ein offizielles
Release-Asset nur zur Digest-Prüfung herunter; NGINX wurde nicht gebaut oder
ausgeführt.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | ---: | --- | --- |
| `rtk gh api repos/nginx/nginx/releases/tags/release-1.31.2` | 0 | Offizielle Release-Metadaten identifizierten `nginx-1.31.2.tar.gz` und den GitHub-Digest `sha256:af2a…aa473c`. | `20260719T081017Z-framework-pr-resolution-20260719-840082e0`, `evidence/nginx-release-1.31.2-provenance.md` |
| `rtk proxy curl` für das exakte offizielle Release-Asset, danach `rtk sha256sum` | 0 | Der direkte HTTPS-Download ergab `af2a957c41da636ddc4f883e4523c6d140b4784dbce42000c364ae5092aa473c`. | `20260719T081017Z-framework-pr-resolution-20260719-840082e0`, `evidence/nginx-release-1.31.2-asset-verification.md` |
| `rtk env TMPDIR=<task-run>/tmp PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest tests.security_regression.test_nginx_archive_digest tests.security_regression.test_nginx_release_provenance -v` | 0 | Zwölf fokussierte Archiv- und Release-Provenance-Tests bestanden. | `20260719T081017Z-framework-pr-resolution-20260719-840082e0` |
| `rtk sh -n ci/lib/common.sh ci/provisioning/prepare-nginx-build.sh` und `rtk python3 -B -m py_compile ci/tools/check-common-versions.py tests/security_regression/test_nginx_archive_digest.py` | 0 | Die geänderten Shell- und Python-Quellen wurden erfolgreich geparst. | `20260719T081017Z-framework-pr-resolution-20260719-840082e0` |
| `rtk env ... make ... lint` mit allen Framework-, Connector-, CI-, Source-, Build-, Temp-, Log- und Output-Wurzeln unter der registrierten Task-Wurzel | 0 | Der native Framework-Lint bestand: Shell/Python, Makefile/Workflow/Security/Catalog, Dokumentation/Pfadreferenzen und Whitespace. | `20260719T081017Z-framework-pr-resolution-20260719-840082e0`, `evidence/pr25-release-provenance-local-validation.md` |
| `rtk env BUILD_ROOT=<task-run>/build python3 -B ci/tools/check-common-versions.py --check --json --timeout 20` | 0 | Konfiguriertes Release-Asset und Digest entsprachen offiziellen Metadaten; neueres `release-1.31.3` ergab `unknown` ohne Update-Änderungen. | `20260719T081017Z-framework-pr-resolution-20260719-840082e0`, `evidence/pr25-release-provenance-local-validation.md` |
| `rtk env TMPDIR=<task-run>/tmp python3 -B -m unittest tests.security_regression.test_nginx_archive_digest -v` vor dem Fix | 1 | Die verwundbare Baseline verletzte die erforderlichen Fail-Closed-Assertions. | `20260718T092116Z-fnd-framework-0006-nginx-digest-5251a4f1` |
| `rtk sh -n ci/lib/common.sh ci/provisioning/prepare-nginx-build.sh` | 0 | Beide geänderten Shell-Dateien wurden erfolgreich geparst. | `20260718T092116Z-fnd-framework-0006-nginx-digest-5251a4f1` |
| `rtk env TMPDIR=<task-run>/tmp python3 -B -m unittest tests.security_regression.test_nginx_archive_digest -v` nach dem Fix | 0 | Sieben fokussierte Tests bestanden, einschließlich aller erforderlichen Negativ- und legitimen Kontrollfälle. | `20260718T092116Z-fnd-framework-0006-nginx-digest-5251a4f1` |
| `rtk env BUILD_ROOT=<task-run>/build TMPDIR=<task-run>/tmp PYTHONDONTWRITEBYTECODE=1 FRAMEWORK_ROOT=<task-worktree> make lint` | 0 | Native Framework-Shell-, Python-, Security-, Catalog- und Dokumentations-Lintprüfungen bestanden. | `20260718T092116Z-fnd-framework-0006-nginx-digest-5251a4f1` |
| `rtk make check-documentation` und `rtk git diff --check` | 0 | Dokumentations- und Whitespace-Prüfungen bestanden. | `20260718T092116Z-fnd-framework-0006-nginx-digest-5251a4f1` |
| `rtk shellcheck -x ci/lib/common.sh ci/provisioning/prepare-nginx-build.sh` | 1 | Ausschließlich bereits in der unveränderten Framework-Basis vorhandene Diagnosen; keine task-eigene Diagnose hinzugefügt. | `20260718T092116Z-fnd-framework-0006-nginx-digest-5251a4f1` |
| `rtk gh pr checks 25` | 1 | `scaffold-lint` und SonarCloud bestanden; `test-common/common-structure` scheiterte, weil der unveränderte Workflow 141 YAML-Fälle erwartet und 179 findet. Derselbe Check scheitert bereits auf `master`. | `20260718T092116Z-fnd-framework-0006-nginx-digest-5251a4f1` |

## Sicherheitsauswirkung

Dies behebt FND-FRAMEWORK-0006 mit einem nutzbaren überprüften Standard statt
nur mit einem Fail-Closed-Aufrufer-Override. Fester Release-Tag, Asset und
Digest sind vor NGINX-Archive-Auswahl/Download/Extraction gebunden. Ein
explizit leerer Override, malformed-/Whitespace-Wert, Mismatch, falscher
Source-Ref oder falscher Asset-Name blockiert vor Netzwerknutzung oder `tar`.
Der Review alternativer Umgehungen deckt Latest-Resolution, Release-/Source-
Overrides, Cache/Refresh, vorhandene Archive, Derived-Archive-Path-Replacement
und einen Austausch zwischen dem ersten Candidate-Hash und der Private-Copy-
Verification ab. Letzterer blockiert vor `tar`.

## Dokumentation und Runtime-Evidenz

Die gepaarte englische/deutsche Variablendokumentation dokumentiert das
überprüfte feste Release-Tupel und erklärt, dass künftige Änderungen an Tag,
Asset und Digest eine atomare Prüfung erfordern. Die aktuelle Fortsetzung
bewahrt die offiziellen Metadaten und den direkten Asset-Digest-Vergleich als
Task-Evidenz auf.

Der fokussierte Test ist kontrollierte lokale Runtime-Evidenz für die Archive-
Handling-Grenze und den Updater-Vertrag. Der direkte Asset-Vergleich ist nur
Release-Asset-Provenance-Evidenz; keine Prüfung behauptet eine NGINX-Runtime,
Connector-Runtime, einen CI-Lifecycle oder ein Produktionsergebnis.

## Nicht ausgeführte Prüfungen

- Vollständige Framework- und Connector-Matrizen wurden nicht ausgeführt: Die
  Änderung ist auf die NGINX-Archive-Trust-Boundary beschränkt und es wurden
  keine Connector-Runtime-Voraussetzungen bereitgestellt.
- Ein vollständiger NGINX-Source-Build wurde nicht ausgeführt; der Task
  verifizierte den offiziellen Archive-Digest, behauptet aber keine Build- oder
  Runtime-Abdeckung.
- GitHub-Checks, SonarCloud, Review-Status und Delivery-Checks für den exakten
  neuen Head bleiben bis zum Push dieser Fortsetzung ausstehend.

## Einschränkungen und Restrisiko

Der feste Standard stützt sich auf GitHubs veröffentlichten Release-Asset-
Digest und die Verfügbarkeit der HTTPS-Metadaten. Künftige Releases erfordern
ein neues überprüftes Tag-/Asset-/Digest-Tupel und eine erneute Upstream-
Prüfung. Die Staging-Kopie bindet den getesteten Candidate-Replacement-Fall an
die Extraction-Eingabe, aber kein lokaler Test ersetzt externe Upstream-
Release-Governance oder Produktions-Runtime-Evidenz.

## Finaler Diff- und Review-Status

Die Release-Provenance-Implementierung, fokussierten Tests, der vollständige
native Lint, Dokumentations-/Whitespace-Review und die aktuellen lokalen
Boundary-Checks sind validiert. Ein fokussierter unabhängiger Security-Review
fand keine reportable Source-to-Sink-Regression; seine Traceability-Beobachtung,
dass der neue Test gestaged sein muss, erfüllt dieser gestagte Neun-Dateien-
Change-Set. Externe Gate-Evidenz für den exakten neuen Head ist noch
erforderlich, bevor der Draft-PR integrationsfähig sein kann. Kein Waiver oder
unabhängiger CI-Change ist autorisiert.
