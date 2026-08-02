# Change Record: 20260802-01-pin-nginx-release-1.31.3

**Sprache:** [English](20260802-01-pin-nginx-release-1.31.3.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260802-01-pin-nginx-release-1.31.3` |
| UTC-Datum | 2026-08-02 |
| Framework-Basisrevision | `5cb371949ceafec6685cf716ba50a75d0f448bd1` |
| Issue oder Pull Request | Framework-Draft-PR ausstehend; lokale Validierung ist vor dem ersten Task-Commit dokumentiert. |

## Motivation und Problemstellung

Der geprüfte NGINX-Mainline-Standard des Frameworks war `release-1.31.2`. Offizielle Upstream-Metadaten identifizieren `release-1.31.3` als aktuelles Mainline-Release. Tag, abgeleiteter Source-Ref, Release-Asset und veröffentlichter SHA-256 müssen gemeinsam aktualisiert werden, statt ein Mitglied des Provenance-Tupels driften zu lassen.

## Betroffene Komponenten und Sicherheitsgrenzen

Die Änderung ist auf die Framework-Grenze für NGINX-Release-Archiv-Provenance begrenzt: den Standard in `ci/lib/common.sh`, Default-/Provenance-Regressionsverträge und die paarige Referenzdokumentation. Die vorhandene Fail-closed-Validierung vor Cache-Nutzung, Download oder Extraktion bleibt unverändert. Kein Connector, keine Parent-Quelle und kein Parent-Gitlink, kein MRTS und keine GitHub-Einstellung werden geändert.

## Akzeptanzkriterien

1. Der Standard ist das exakte geprüfte Tupel `release-1.31.3`: passender abgeleiteter Ref, `nginx-1.31.3.tar.gz` und veröffentlichter SHA-256.
2. Tests decken das aktuelle Tupel, ein neueres ungeprüftes Release und die vorhandenen Digest-/Tupel-Negativkontrollen ab.
3. Englische/deutsche Dokumentation und dieses Change-Record-Paar stimmen überein.
4. Fokussierte Prüfungen bestehen für den finalen Framework-PR-Head ohne Parent- oder MRTS-Änderung.

## Untersuchte Alternativen

- Ein reines Tag-Update wurde verworfen, weil es den Asset-/Digest-Vertrag inkonsistent machen würde.
- Ein Wechsel auf NGINX Stable wurde verworfen, weil der bestehende Standard Mainline ist und 1.31.3 sein direkter offizieller Nachfolger ist.
- Das Entfernen des separat getesteten Runtime-Overrides `NGINX_RELEASE_TAG=latest` wurde als brechende, nicht vom Scope gedeckte Policy-Änderung verworfen.
- Die Aktualisierung des Parent-Full-Smoke-Overrides `latest` wurde als out of scope verworfen: Er ist Parent-eigen und folgt einer separaten Git-Tag-Archivroute.

## Implementierungsentscheidung

Der Framework-Standard wird atomar auf `release-1.31.3` / `nginx-1.31.3.tar.gz` / `a7657c50811c2d92d9895395e8b873ef60398142c4db21eb647811c38f6dd525` angehoben. `NGINX_SOURCE_GIT_REF` bleibt aus `NGINX_RELEASE_TAG` abgeleitet und löst daher ohne duplizierte Literale auf denselben exakten Tag auf. Der bestehende generische Provisioning- und Versionsprüfcode erzwingt bereits Fixed-release-Konsistenz, verifiziert den Digest vor und nach privatem Staging und verweigert automatische Tupel-Updates.

Offizielle GitHub-Release-Metadaten und ein direkter HTTPS-Download des Release-Assets meldeten denselben SHA-256. Die Release-API markiert ihr Objekt nicht als unveränderlich; dieser Record behauptet daher den geprüften Tag, Asset, veröffentlichten Digest und die vorhandene Digest-Verifikation, nicht eine unbelegte Upstream-Unveränderlichkeit.

## Geänderte Dateien und Tests

- `ci/lib/common.sh` aktualisiert das geprüfte Standardtupel.
- `tests/security_regression/test_nginx_release_provenance.py` aktualisiert das aktuelle Tupel und behält die Kontrolle für ein neueres ungeprüftes Release bei 1.31.4.
- `tests/security_regression/test_nginx_archive_digest.py` aktualisiert die Default-Tupel-Assertion; Kontrollen für fehlerhafte/fehlende/nicht passende/inkonsistente Werte bleiben erhalten.
- `docs/reference/variables.md` und `docs/reference/variables.de.md` aktualisieren das paarige dokumentierte Tupel.
- Dieses paarige Change Record dokumentiert Evidenz und Grenze.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | ---: | --- | --- |
| `rtk proxy gh api repos/nginx/nginx/releases/tags/release-1.31.3` | 0 | Offizielle Metadaten meldeten `nginx-1.31.3.tar.gz`, 1.344.885 Bytes und `sha256:a7657c…dd525`. | `20260802T112428Z-framework-nginx-pin-1.31.3`, privates Run-Manifest |
| `rtk proxy curl --proto =https --proto-redir =https … nginx-1.31.3.tar.gz`; `rtk proxy sha256sum` | 0 | Exaktes offizielles HTTPS-Asset ergab `a7657c…dd525`; keine Extraktion und kein Build. | `20260802T112428Z-framework-nginx-pin-1.31.3`, private temporäre Evidenz |
| `check-common-versions.py --check --json --timeout 20` | 1 | NGINX selbst ist mit exaktem Asset/Digest `current`; der Aggregatlauf meldet unabhängige vorhandene unknown/outdated-Komponenten. | `20260802T112428Z-framework-nginx-pin-1.31.3`, privater Befehlsauszug |
| `python -B -m unittest tests.security_regression.test_nginx_release_provenance -v` | 0 | 3/3 Tests für aktuelles Tupel, Mismatch und neueres ungeprüftes Tupel bestanden. | `20260802T112428Z-framework-nginx-pin-1.31.3` |
| `make test-nginx-archive-digest` | 0 | 15/15 Archive-Integrity-, Fixed/default-, `latest`-, Cache-, Symlink- und Swap-Kontrollen bestanden in 288,612 Sekunden. | `20260802T112428Z-framework-nginx-pin-1.31.3` |
| `sh -n …`; `shellcheck -x ci/lib/common.sh` | 0 | Syntax der geänderten Shell-Defaults und Provisionierung ohne Diagnose geprüft. | `20260802T112428Z-framework-nginx-pin-1.31.3` |
| `make test-change-record-contract`; `make check-documentation` | 0 | Change-Record-Vertrag und englisch/deutsche Dokumentationschecks bestanden. | `20260802T112428Z-framework-nginx-pin-1.31.3` |
| `make lint` | 0 | Native Framework-Checks für statische Analyse, Sicherheit, Verträge, Regression und Dokumentation bestanden. | `20260802T112428Z-framework-nginx-pin-1.31.3` |

## Sicherheitsauswirkung

Die Änderung erhält die Release-Archiv-Integritätskontrolle und aktualisiert ihren geprüften Standard. Vorhandene Negativkontrollen blockieren fehlende, fehlerhafte, nicht passende oder tupel-inkonsistente Werte weiterhin vor Netzwerknutzung oder `tar`. Der explizite Runtime-Kompatibilitätszweig `latest` bleibt getrennt und kann vom statischen Provenance-Prüfer nicht als geprüfter Standard dargestellt werden.

## Dokumentation und Runtime-Evidenz

Paarige englische/deutsche Variablendokumentation nennt dasselbe Tupel. Der direkte Asset-Hash ist Release-Asset-Provenance-Evidenz und fokussierte Tests sind kontrollierte lokale Vertragsevidenz; keines behauptet ein NGINX-, Connector-, Parent-Full-Smoke- oder Produktionsruntime-Ergebnis.

## Nicht ausgeführte Prüfungen

- Vollständige Framework-/Connector-Runtime-Matrizen werden nicht ausgeführt: Dies ist eine Aktualisierung eines geprüften Default-/Konfigurationsvertrags, keine Connector-Runtime-Änderung.
- Ein vollständiger NGINX-Build wird nicht ausgeführt: Das Asset wird verifiziert, aber nicht extrahiert/gebaut.
- Parent-Full-Smoke wird nicht ausgeführt oder verändert: Sein `latest`-Override und seine Git-Tag-Archiv-Provenance sind eine separate Parent-Entscheidung.

## Einschränkungen und Restrisiko

Zukünftige Releases benötigen weiterhin frische offizielle Evidenz und eine atomare Tag-/Asset-/Digest-Prüfung. Der Framework-PR schließt den Parent-Full-Smoke-Override `latest` nicht, der den Framework-Standard umgehen kann und eine andere Archivform nutzt. F-GS-003 bleibt daher teilweise offen, bis eine separat autorisierte Parent-Lösung vorliegt.

## Finaler Diff- und Review-Status

Fokussierte und breitere lokale Validierung bestanden. Ein unabhängiger Diff-Review fand keine plausible Security-Regression und bestätigte die atomare Tupeländerung. Staged-Diff-Review, erster Task-Commit, Remote-Gleichheit, Draft-PR und CI-/Read-back für den aktuellen Head stehen noch aus; ein Merge ist nicht autorisiert.
