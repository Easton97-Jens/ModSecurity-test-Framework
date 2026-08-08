# Change Record: 20260808-02-fix-apr-util-provenance

**Sprache:** [English](20260808-02-fix-apr-util-provenance.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260808-02-fix-apr-util-provenance` |
| UTC-Datum | 2026-08-08 |
| Framework-Basisrevision | `54460837def44f13d37e63faa8363cbc8ff16410` |
| Issue oder Pull Request | Task-Branch `fix/apr-util-164-provenance`; der Framework-Pull-Request wird erst nach lokaler Prüfung erstellt. |

## Motivation und Problemstellung

Der aktive Apache-Download-Dienst liefert für das zuvor gepinnte
`apr-util-1.6.3.tar.bz2` HTTP 404. Beide historischen Parent-Full-Smoke-
Varianten stoppten deshalb bei der APR-util-Beschaffung, bevor eine Apache- oder
NGINX-Runtime vorbereitet werden konnte. Die frühere Framework-
Runtime-Konfiguration ließ zudem eine beliebige HTTPS-APR-util-URL oder einen
leeren Literal-Digest zu und schwächte damit die beabsichtigte Source- und
Archiv-Integritätsgrenze.

## Betroffene Komponenten und Sicherheitsgrenzen

Diese reine Framework-Änderung betrifft die APR-util-Grenze von Provider über
Download bis Extraktion in `ci/lib/common.sh` und
`ci/provisioning/prepare-apache-build.sh`, außerdem den zentralen
Versionsprüfer, fokussierte Regressionstests und die zweisprachige
Dokumentation. Der vertrauenswürdige Provider ist das überprüfte aktuelle
Apache-Asset `https://downloads.apache.org/apr/apr-util-1.6.4.tar.bz2` mit
seinen veröffentlichten SHA-256-Metadaten. Parent-Cache-Records,
Parent-Full-Smoke-Evidenz, Parent-Gitlink und MRTS sind getrennte Grenzen und
werden hier nicht geändert.

## Akzeptanzkriterien

1. Das zentrale Tupel ist exakt APR-util 1.6.4, die kanonische
   `downloads.apache.org`-Asset-URL, deren `.sha256`-URL und
   `3e2ae08f40efa0c3701e54a954cefa08242de22a69f91a8ae44fc1e624ba309b`.
2. Abweichungen bei Version, Host, Pfad, Asset, Literal-Digest, Checksum-URL
   und nicht überprüften Provider-Redirects schlagen vor Apache-Provisionierung,
   Cache-Nutzung, Download oder Extraktion fehl.
3. Der Literal-Digest ist vor der ersten APR-util-Extraktion erforderlich,
   valide hexadezimal und passend; die Checksum-URL bleibt ergänzende
   Metadaten, nie ein Fallback.
4. Die Versionsprüfung verifiziert das genehmigte Tupel mit In-Memory-
   Antworten des offiziellen Providers und verlangt für eine künftige Version
   eine manuelle atomare Prüfung.
5. Fokussierte Tests decken den gültigen Kontrollfall sowie stale-, Mirror-,
   Pfad-, Asset-, fehlende/fehlerhafte/abweichende-Digest- und
   Checksum-URL-Bypässe ab.
6. Englische und deutsche Dokumentation sowie dieser gepaarte Record bleiben
   äquivalent.

## Untersuchte Alternativen

- Das Beibehalten der 1.6.3-URL oder die Behandlung ihres 404 als optional
  wurde verworfen, weil damit ein nicht reproduzierbarer defekter Providerpfad
  bliebe.
- Ein Fallback auf archive.apache.org oder einen beliebigen Mirror wurde
  verworfen, weil historische Inhalte nicht der aktive überprüfte Provider sind
  und ein Mirror den kanonischen Asset-Vertrag umgeht.
- Eine aufruferspezifische Source oder ein aufruferspezifischer Digest wurde
  verworfen, weil ein passender angreiferkontrollierter Digest die überprüfte
  Source nicht mehr beweisen würde.
- Ein Parent-Workflow-Override für APR-util wurde verworfen, weil der Fehler
  und die sichere Kontrolle dem Framework gehören.

## Implementierungsentscheidung

`common.sh` besitzt nun vier überprüfte APR-util-Pin-Werte und bewahrt
explizite Aufruferwerte nur so lange auf, dass jede Tupelabweichung abgelehnt
werden kann. Der Guard leitet Asset- und Checksum-Endpunkt aus der gepinnten
Version ab, validiert einen 64 Zeichen langen hexadezimalen Literal-Digest und
akzeptiert nur Werte, die exakt dem überprüften Tupel entsprechen.
`prepare-apache-build.sh` ruft den Guard vor der V3-Source-Vorbereitung auf,
lädt APR-util nur vom direkten kanonischen Endpunkt ohne Redirect-Folge und
nutzt vor der APR-util-Extraktion einen erforderlichen Literal-Digest-Helper.
Der Versionsprüfer aktualisiert dieses atomare Tupel nicht mehr mechanisch;
eine künftige Version braucht eine explizite Kompatibilitäts- und
Provenance-Prüfung.

## Geänderte Dateien und Tests

- `ci/lib/common.sh` besitzt und erzwingt das unveränderliche APR-util-Tupel.
- `ci/provisioning/prepare-apache-build.sh` ruft den Guard vor Seiteneffekten
  auf und verlangt den APR-util-Digest vor `tar`.
- `ci/tools/check-common-versions.py` validiert das geprüfte/Runtime-Tupel und
  deaktiviert mechanische Tupel-Updates.
- `tests/security_regression/test_apr_util_provenance.py` prüft Shell-Guard und
  direkten Downloader ohne Redirect-Folge sowie die Reihenfolge des realen
  Preparers; `test_common_versions_sonar_provenance.py` deckt Offline-Provider-
  und Abweichungsfälle ab. `test_pcre2_archive_digest.py` aktualisiert seine
  isolierte Fixture auf dieselbe kanonische APR-util-Identität und behält dabei
  seinen eigenen synthetischen Archiv-Digest.
- `Makefile` integriert die fokussierte Regression in lint.
- `docs/reference/variables.md` und `docs/reference/variables.de.md`
  dokumentieren dieselbe Grenze.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder freigegebener Evidence-Pfad |
| --- | ---: | --- | --- |
| `make test-apr-util-provenance` mit task-eigenen Wurzeln und `PYTHON=python3` | 0 | 5 APR-util-Tupel-, Guard-Reihenfolge- und Direkt-ohne-Redirect-Tests bestanden. | Task-eigener Framework-Worktree |
| `python3 -B -m unittest tests.security_regression.test_common_versions_sonar_provenance -v` | 0 | 18 Offline-Provenance-/Checker-Tests bestanden. | Task-eigener Framework-Worktree |
| `python3 -B -m unittest discover -s tests/security_regression -p 'test_pcre2_archive_digest.py' -v` | 0 | 3 Digest-Grenztests bestanden. | Task-eigener Framework-Worktree |
| `sh -n ci/lib/common.sh ci/provisioning/prepare-apache-build.sh` | 0 | Die geänderten POSIX-Shell-Dateien wurden erfolgreich geparst. | Task-eigener Framework-Worktree |
| `python3 -B ci/tools/check-common-versions.py --check --json --timeout 20` | 1 | APR-util ist aktuell und sein offizieller SHA-256 stimmt überein; nicht zugehörige bestehende ModSecurity-v3-/manuelle und HAProxy-Update-Zustände machen den Aggregat-Checker nichtnull. | Task-eigener Framework-Worktree |
| `make lint` mit task-eigenen Wurzeln und `PYTHON=python3` | 0 | Diagnostischer Lint sowie Contract-, Workflow-, Dokumentations-, Cache- und Provenance-Suiten bestanden; Change-Record-Contract und Diff-Checks wurden nach dem Eintragen dieses Ergebnisses erneut ausgeführt. | Task-eigener Framework-Worktree |
| Exakte CPython-3.14.6-Fokusprüfungen | ausstehend | Lokal ist Python 3.14.4 vorhanden; exakte GitHub-CI auf dem eingereichten Head ist erforderlich. | `.python-version` und Task-Plan |

## Sicherheitsauswirkung

Die erste PR-#64-Analyse für Commit
`b02dc979f9716c96a642611e6782fdc11309bb76` hatte ein bestandenes Quality Gate,
meldete aber sechs neue offene Code Smells. Vier `shelldre:S7679`-Befunde
betrafen Wrapper-Positionsparameter in den Required-Digest-Helpern; zwei
`python:S3415`-Befunde betrafen die vertauschte Actual-/Expected-Assertion-
Reihenfolge im neuen Tupeltest. Sie wurden weder unterdrückt noch akzeptiert.
Das Follow-up verwendet benannte lokale Shell-Variablen und Actual-first-
Assertions. Vor einem Merge ist eine neue Sonar-Analyse des exakten Heads
erforderlich.

Der ursprüngliche 404-Pfad und die alternativen Mirror-/Leer-Digest-Bypässe
werden abgelehnt, bevor der Apache-Preparer die Source-Beschaffung startet. Der
direkte kanonische APR-util-Downloader folgt keinem Provider-Redirect, und die
Reparatur macht die Literal-Digest-Prüfung zu einer Voraussetzung vor der
Extraktion. Der finale Record muss die Hosted-Ergebnisse des exakten
eingereichten Heads nachtragen.

## Dokumentation und Runtime-Evidenz

Die gepaarten Variablenreferenzen nennen den zentralen Provider, den
obligatorischen Literal-Digest, die Rolle der Checksum-URL und das
Ablehnungsverhalten. Unabhängige Task-Evidenz dokumentiert bereits, dass das
offizielle 1.6.4-Asset und der veröffentlichte SHA-256 übereinstimmen; dieser
Record behauptet keine Framework-Connector-Runtime, keinen Parent-Full-Smoke
und kein Produktionsdeployment.

## Nicht ausgeführte Prüfungen

- Lokale diagnostische Prüfungen mit Python 3.14.4 liefern nützliche
  Regressionsevidenz, ersetzen jedoch nicht das vom Repository verlangte
  CPython-3.14.6-Ergebnis.
- Kein echter Apache-Build läuft lokal; exakte Hosted-Checks und spätere
  Parent-Full-Smokes bleiben zwingend.

## Einschränkungen und Restrisiko

Der zentrale Pin verlangt bewusst eine manuelle Prüfung für jede künftige
APR-util-Version. Guard und fokussierte Tests ersetzen weder einen Hosted-Build
gegen das offizielle Asset noch CI-Review, SonarQube-Analyse, Framework-Merge
oder separat verantwortete Parent-Runtime-Evidenz. MRTS bleibt unverändert.

## Finaler Diff- und Review-Status

Der Task-eigene Framework-Worktree ist nicht committet, gepusht oder zur
Prüfung eingereicht. Branch-Protection, Approval, CI, SonarQube, Merge,
Parent-Gitlink, Parent-PR und Finding-Lifecycle werden hier nicht behauptet.
