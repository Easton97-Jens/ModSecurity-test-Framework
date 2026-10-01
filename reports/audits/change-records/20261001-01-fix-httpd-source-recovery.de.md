# Change Record: Wiederherstellung gepinnter HTTPD-Quellen

**Sprache:** [English](20261001-01-fix-httpd-source-recovery.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261001-01-fix-httpd-source-recovery |
| UTC-Datum | 2026-10-01 |
| Framework-Basisrevision | 9181dc77dfb0685d87fa109e6800dc6052d77cc9 |
| Issue oder Pull Request | Framework-PR noch nicht erstellt; externer Integrationsverbraucher: Parent PR #370 |

## Motivation und Problemstellung

Der kanonische Archiv-Endpunkt für HTTPD 2.4.68 liefert HTTP 404, während das
offizielle Apache-Archiv denselben Release mit der freigegebenen literalen
Prüfsumme vorhält. Der Framework-Apache-Preparer löschte zuvor ein bereits
geprüftes bereitgestelltes Archiv vor dem erneuten Zugriff auf die nicht
verfügbare URL. Dieser Framework-eigene Bezugsfehler blockiert den externen
Apache-Quellenbuild-Verbraucher im Parent.

## Betroffene Komponenten und Sicherheitsgrenzen

`ci/provisioning/prepare-apache-build.sh` besitzt die HTTPD-Grenze zwischen
Download und Extraktion. Netzwerk- und Cache-Bytes müssen die kanonische
geprüfte Quellidentität, erforderliche Prüfsumme, sichere Root-Begrenzung und
TLS-Prüfung erhalten. Gemeinsames Downloader-Verhalten, Upstream-Pins,
APR-util-Provenienz und MRTS bleiben unverändert.

## Akzeptanzkriterien

Freigegebene vorhandene HTTPD-Archive werden ohne Netzwerkzuschreibung erneut
geprüft; ein fehlendes Archiv darf ausschließlich nach direktem kanonischem
HTTP 404 vom selben offiziellen Archivdateinamen wiederhergestellt werden.
Andere Fehler bleiben blockierend. Literale und kanonische Metadatenprüfsummen
gehen der erneuten Prüfung der privaten Kopie und der Extraktion voraus.
Fokussierte Positiv-, Negativ- und Aufrufer-Regressionsprüfungen müssen bestehen;
Framework-Delivery-Prüfungen des exakten Heads bleiben von Host-Runtime-Abnahme
getrennt.

## Untersuchte Alternativen

Kanonische Pins zu ändern oder Prüfsummenmetadaten abzuschalten würde die
geprüfte Identität verändern oder die Validierung schwächen. Ein generischer
Fallback würde Vertrauensgrenzen anderer Komponenten erweitern. Framework-
Provisioner-Logik in den Parent zu kopieren würde die Repository-Zuständigkeit
verletzen. Die schmale Apache-HTTPD-Grenze vermeidet diese Änderungen.

## Implementierungsentscheidung

Das geprüfte Tupel bleibt unverändert und wird vor Cache-/Download-Operationen
validiert. Nur ein sicheres reguläres Archiv mit passender erforderlicher
literaler Prüfsumme wird wiederverwendet; jeder neue Download wird unabhängig
klassifiziert. Nur direktes kanonisches HTTP 404 erlaubt den offiziellen
Recovery-Endpunkt desselben Dateinamens. Cache-Wiederverwendung oder tatsächlicher
Transfer werden getrennt von der kanonischen Identität dokumentiert.
Metadatenprüfungen bleiben erhalten; vor der Extraktion wird das Archiv im
task-lokalen Build-Root eingefroren und erneut geprüft. APR- und APR-util-Bezug
bleiben unverändert.

## Geänderte Dateien und Tests

Apache-Preparer; fokussierte `tests/security_regression/test_httpd_source_recovery.py`;
nativer Make-Target und Lint-Einbindung; gepaarte `docs/development.md` /
`docs/development.de.md`; dieser gepaarte Change Record. Tests decken kanonische
und wiederhergestellte Downloads, Cache-Integrität, Fehlerklassifikation,
Provenienz-/Pfad-Grenzen, verpflichtende Metadaten und die produktive Aufrufkette
ab.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Begrenzter kanonischer HTTPD-/APR-/APR-util-Metadaten-Preflight | 0 | HTTPD-Metadaten redirecten zum offiziellen Archiv und passen zur literalen Prüfsumme; APR-/APR-util-Metadaten passen zu ihren literalen Pins | pr370-ready-without-nginx-20261001 |
| `rtk proxy env HTTPD_RECOVERY_BASELINE=1` plus die beiden fokussierten primären Regressionen an der unveränderlichen Basis | 1 (erwartet) | Beide scheitern mit HTTP 404/Exit 77 des echten begrenzten Helfers; geprüfte Cache-Kopie wird nicht wiederverwendet | framework-httpd-tests |
| `rtk proxy make test-httpd-source-recovery test-apr-util-provenance test-runtime-component-download` mit explizitem Framework-Python und externen Roots | 0 | 18 HTTPD-, 13 APR-util- und 20 gemeinsame Download-Tests bestanden; unabhängig vom Koordinator erneut ausgeführt | framework-httpd-validation |
| `rtk proxy make test-runtime-component-lock test-runtime-component-sync check-canonical-common-pins test-makefile-contract test-ci-security-contract` mit explizitem Framework-Python und externen Roots | 0 | Lock-/Sync-/Kanonisch-/Make-Prüfungen bestanden; CI-Security-Suite 308 Tests bestanden | framework-httpd-validation |
| `rtk proxy sh framework-httpd-real-source-probe.sh` (task-eigene externe Diagnose) | 0 | Frischer Bezug vom offiziellen Archiv, Literal-/Kanonisch-Metadaten-Prüfung, privates Rehash und geprüfte Cache-Wiederverwendung bestanden | framework-httpd-validation/real-source |
| `rtk proxy env TAR_OPTIONS=--no-same-owner timeout 600 sh framework-httpd-real-source-probe.sh --build-httpd` | 0 | Nativer HTTPD-2.4.68-/APXS-Build bestanden; HTTPD-/APR-/APR-util-Literal- und Metadatenprüfungen erhalten; System-PCRE nur für diesen Diagnosebuild verwendet | framework-httpd-validation/real-source |
| `rtk proxy make check-documentation` mit explizitem Framework-Python | 0 | Links, zweisprachige Referenzen, Pfade und Change-Record-Prüfungen bestanden | framework-httpd-validation |
| `rtk proxy sh -n ci/provisioning/prepare-apache-build.sh`; `rtk proxy git diff --check` | 0 | Syntax und Whitespace bestanden; unabhängiges Security-Diff-Review ohne blockierenden Defekt | Framework-Worktree |

Die obigen Befehle nutzten die Framework-eigene Python-3.14.7-Umgebung; keine
Pakete oder Pins wurden geändert. Eine wiederhergestellte HTTP-404-Diagnose des
ersten Versuchs ist nicht das terminale Ergebnis der erfolgreichen Quellen-
Bezugsprobe. Diese Probe beweist Archivintegrität und Übergabe, keinen
Host-Runtime-PASS.

## Sicherheitsauswirkung

Verfügbarkeitskorrektur an einer vorhandenen sicherheitsrelevanten Bezugsgrenze,
keine Remediation einer validierten remote ausnutzbaren Schwachstelle. Kein
Kontrollmechanismus wird unterdrückt. Erforderliche Negativprüfungen umfassen
unsichere Pfade, ersetzte Inhalte, veraltete Fehlerklassifikation, Nicht-404-
Fehler und abweichende Metadaten.

## Dokumentation und Runtime-Evidenz

Entwicklungsanleitung und dieser Change Record besitzen vollständige englische/
deutsche Partner. Diese Framework-Änderung erfasst keine Connector-Host-Runtime-
oder vollständige Lifecycle-Evidenz; externe Parent-Runtime-CI ist ein separater
Integrationsschritt. Keine Connector-Reife-Hochstufung wird behauptet.

## Nicht ausgeführte Prüfungen

Das vollständige lokale `make lint` enthält NGINX-spezifische Regressionen
außerhalb des aktuell vom Benutzer gewählten Umfangs; fokussierte Nicht-NGINX-
Targets werden ohne Abschwächung der CI verwendet. Vollständige Connector-
Runtime- und G1–G9-Kampagnen sind keine Framework-Abnahmeevidenz und bleiben
externe Parent-Verantwortung. Generierte Berichte bleiben unverändert.
Der erste optionale native Buildversuch endete mit Exit 77, weil dieses
id-gemappte Dateisystem die Wiederherstellung der Archiv-UID/GID verweigert; die
bereits im Parent-Profil verwendete sichere Einstellung `TAR_OPTIONS=--no-same-owner`
ermöglichte den dokumentierten Build-Retry. Kein Root-Worker- oder Runtime-
Berechtigungsworkaround wurde eingeführt.

## Einschränkungen und Restrisiko

Beide freigegebenen Upstream-Endpunkte können nicht verfügbar werden;
Nicht-404-Fehler bleiben blockierend. Cache-Wiederverwendung beweist keinen neuen
Transfer. Framework-Quellen, Tests und CI beweisen für sich nicht das
Host-Verhalten des externen Verbrauchers.

## Finaler Diff- und Review-Status

Fokussierte Implementierungsprüfungen und unabhängiges Security-Diff-Review
bestanden. Finaler scoped Diff und Whitespace wurden geprüft; keine Änderungen
an Pins, gemeinsamem Downloader, APR-util, NGINX oder MRTS liegen vor. Separate
Framework-Commit-/Push-/PR-Delivery folgt der lokalen Validierung; Hosted-Checks
des exakten Heads und externe Parent-Integration bleiben ausstehend. Kein Merge
wurde durchgeführt. Nur task-eigene Framework-Änderungen werden gestaged;
Secrets, rohe Bodies oder unbegrenzte Logs werden hier nicht erfasst.
