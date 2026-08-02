# Change Record: 20260802-01-pin-nginx-release-1.31.3

**Sprache:** [English](20260802-01-pin-nginx-release-1.31.3.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260802-01-pin-nginx-release-1.31.3` |
| UTC-Datum | 2026-08-02 |
| Framework-Basisrevision | `5cb371949ceafec6685cf716ba50a75d0f448bd1` |
| Issue oder Pull Request | [Framework-PR #60](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/60) auf `agent/pin-nginx-current-release-20260802`. Der aktuelle Auftrag fordert eine kontrollierte Integration nach frischer Exact-Head-Evidenz; an diesem Dokumentationszeitpunkt ist kein Merge-Ergebnis dokumentiert. |

## Motivation und Problemstellung

Der Framework-Standard wurde auf `release-1.31.3` angehoben, aber der NGINX-
Pfad akzeptierte weiterhin fließendes `latest` und konnte es über
`/releases/latest` auflösen. Dadurch waren das ausgewählte Asset und sein
Digest nicht reproduzierbar und eine alte Cache-Identität lag außerhalb des
geprüften festen Tupels.

F-GS-003 verlangt eine geprüfte Auswahl aus Source-Repository, Release-Tag,
Source-Ref, Asset-Name und SHA-256, die vor Cache-Nutzung, Netzwerkanfrage,
Download oder Extraktion fail-closed scheitert.

## Betroffene Komponenten und Sicherheitsgrenzen

Dieser Framework-Record deckt die NGINX-Release-Archiv-Provenance-Grenze in
`ci/lib/common.sh`, `ci/provisioning/prepare-nginx-build.sh`,
`ci/tools/check-common-versions.py`, fokussierten Regressionsverträgen und
paariger Dokumentation ab. Er betrifft Upstream-Auswahl, Cache-Identität,
Archivintegrität und die Vertrauensgrenze vor der Extraktion.

Parent-Full-Smoke-Resolver, Parent-Runtime-Evidenz und Parent-Gitlink sind
separate Parent-eigene Deliverables. MRTS bleibt unverändert und read-only.
Dieser Record behauptet kein Connector- oder Produktionsruntime-Ergebnis.

## Akzeptanzkriterien

1. Der geprüfte Standard lautet `https://github.com/nginx/nginx`,
   `github-release`, `release-1.31.3`, `release-1.31.3`,
   `nginx-1.31.3.tar.gz` und
   `a7657c50811c2d92d9895395e8b873ef60398142c4db21eb647811c38f6dd525`.
2. NGINX weist `latest` für Tag und Ref sowie fehlende, leere, fehlerhafte,
   abweichende oder tupel-inkonsistente Werte vor Cache-Auswahl, Netzwerk,
   Download oder Extraktion zurück.
3. NGINX-spezifische Provisionierungs- und Provenance-Abfragen rufen niemals
   `/releases/latest` auf; Metadaten werden nur über `/releases/tags/<tag>`
   aufgelöst.
4. Cache-Wiederverwendung verlangt einen Full-Tuple-Key und ein passendes
   nicht verlinktes Manifest; ein alter Latest-Cache kann nicht verwendet
   werden. SHA-256 ist vor Staging und Extraktion verpflichtend und wird nach
   dem Staging erneut geprüft.
5. Final-Head-Tests decken die feste Kontrolle, `latest`-Ablehnung, fehlerhafte
   Eingaben, Mismatch-Kontrollen, keine Latest-Route-Anfrage und die
   Nichtwiederverwendung alter Caches ab. EN/DE-Dokumentation bleibt äquivalent.

## Untersuchte Alternativen

- Das Beibehalten der NGINX-`latest`-Kompatibilität wurde verworfen, weil es
  eine fließende Auswahl außerhalb des geprüften Asset-/Digest-Tupels erzeugt.
- Die Suche nach dem neuesten NGINX-Release über `/releases/latest` wurde
  verworfen, weil ein neues Release eine atomare manuelle Prüfung erfordert.
- Ein nur über Dateinamen oder alte Latest-Response gebundener Cache wurde
  verworfen, weil er die vollständige Provenance-Identität nicht beweisen kann.
- Generisches Latest-Verhalten anderer Komponenten liegt außerhalb dieser
  NGINX-spezifischen Behebung und kann keinen NGINX-Latest-Pfad reaktivieren.

## Implementierungsentscheidung

Der Framework-NGINX-Pfad verwendet ausschließlich `github-release` mit
`https://github.com/nginx/nginx`. Er löst das direkte getaggte Asset
`https://github.com/nginx/nginx/releases/download/release-1.31.3/nginx-1.31.3.tar.gz`
auf. Ein nicht gesetzter Source-Ref wird aus dem geprüften Tag abgeleitet; ein
explizit übergebener leerer Wert scheitert fail-closed. `latest` ist weder für
NGINX-Tag noch für Source-Ref gültig.

Cache-Key und Manifest binden Repository, Mode, Tag, Ref, Asset-Name und
kanonischen erwarteten SHA-256. Der Digest wird vor Staging oder Extraktion
und nach dem Staging geprüft. Der NGINX-Versionscheck löst nur den
konfigurierten Tag auf und aktualisiert das Tupel nicht automatisch.

## Geänderte Dateien und Tests

- `ci/lib/common.sh` erhält explizit leere Eingabe für fail-closed-Validierung.
- `ci/provisioning/prepare-nginx-build.sh` validiert die feste NGINX-Quelle,
  löst das direkte getaggte Asset auf und bindet Cache-Wiederverwendung an das
  vollständige Tupel.
- `ci/tools/check-common-versions.py` verwendet eine NGINX-Abfrage nur über
  den konfigurierten Tag.
- `tests/security_regression/test_nginx_archive_digest.py` und
  `tests/security_regression/test_nginx_release_provenance.py` müssen vor
  Delivery mit dem finalen PR-Head und beobachteten Ergebnissen abgeglichen
  werden.
- `docs/reference/variables.md`, `docs/reference/variables.de.md` und dieses
  paarige Change Record beschreiben den leserseitigen Vertrag.

## Befehle und Ergebnisse

Frühere PR-#60-Evidenz deckte einen unterstützten NGINX-`latest`-Zweig ab.
Sie validiert diese Behebung nicht und ist keine bestehende Pass-Evidenz für
den geänderten Head.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | ---: | --- | --- |
| `sh -n ci/lib/common.sh ci/provisioning/prepare-nginx-build.sh` | `0` | PASS: finaler Shell-Syntax-Check. | Pre-Commit-Log des Task-Worktrees |
| `git diff --check` | `0` | PASS: keine Whitespace-Fehler im geänderten Framework-Diff. | Pre-Commit-Log des Task-Worktrees |
| `shellcheck -x ci/lib/common.sh ci/provisioning/prepare-nginx-build.sh` | `1` | BLOCKED durch vorhandene, nicht zugehörige Diagnosen in Provisioner-Zeilen 4, 5, 7, 8, 44, 49, 54 und 420; keine liegt im Remediation-Diff. | Pre-Commit-Log des Task-Worktrees |
| `make test-nginx-archive-digest` | blocked | Lokal BLOCKED: Diese Framework-Revision verlangt CPython `3.14.6`; die verfügbare Framework-Umgebung ist `3.14.4`, und keine Erstellung/Reparatur einer Repository-Umgebung ist autorisiert. Exact-Interpreter-PR-CI ist erforderlich. | aktuelle `.python-version` und Framework-Python-Policy |
| `python -B -m unittest tests.security_regression.test_nginx_release_provenance -v` | blocked | Lokal BLOCKED wegen derselben Exact-Interpreter-Voraussetzung; frühere 3.14.4-Beobachtungen sind nur diagnostisch und keine Delivery-Evidenz. | aktuelle `.python-version` und Framework-Python-Policy |
| `make check-documentation`, `make test-change-record-contract`, `make lint` | blocked | Lokal BLOCKED wegen derselben Exact-Interpreter-Voraussetzung; diese Checks bleiben für den gepushten Exact-Head erforderlich. | aktuelle `.python-version` und Framework-Python-Policy |

## Sicherheitsauswirkung

Diese Source-Provenance- und Archivintegritätsbehebung entfernt den fließenden
NGINX-Release-Zweig, weist ungültige Konfiguration vor Aktionen an der
Vertrauensgrenze zurück, verhindert Cache-Wiederverwendung zwischen Tupeln und
verlangt einen gültigen SHA-256 vor der Extraktion. Tests müssen zeigen, dass
der ursprüngliche Latest-Pfad und ein alternativer Source-Ref-Bypass blockiert
sind, während das geprüfte feste Tupel erfolgreich ist.

## Dokumentation und Runtime-Evidenz

Die paarigen Variablenreferenzen dokumentieren das vollständige Tupel,
Ablehnungsregeln, das NGINX-spezifische Verbot von `/releases/latest`,
Cache-Manifest-Bindung und das SHA-256-Gate. Die offiziellen taggebundenen
Release-Metadaten und ein frischer direkter HTTPS-Asset-Download wurden für
diese Aufgabe unabhängig beobachtet: Das benannte Asset und das lokale Archiv
haben beide den Hash
`a7657c50811c2d92d9895395e8b873ef60398142c4db21eb647811c38f6dd525`, und
`src/core/nginx.h` meldet `NGINX_VERSION "1.31.3"`. Dieser Record besitzt keine
Connector-, Parent-Full-Smoke- oder Produktionsruntime-Evidenz.

## Nicht ausgeführte Prüfungen

- Exact-Interpreter-Current-Head-NGINX-Regression, Dokumentations- und breitere
  Framework-Checks stehen in GitHub CI aus, weil lokales CPython `3.14.6`
  fehlt und kein nicht kanonischer Interpreter ersetzt wird.
- Es wird kein vollständiges NGINX-Build- oder Connector-Matrix-Ergebnis
  behauptet.
- Parent-Full-Smoke, Parent-Runtime-Evidenz und Parent-Gitlink-Arbeit sind
  separate Parent-eigene Arbeit, keine Framework-Validierung.

## Einschränkungen und Restrisiko

Zukünftige NGINX-Releases erfordern frische offizielle Metadaten, einen
tatsächlichen Archivdownload mit Hash-Prüfung und eine atomare Prüfung des
vollständigen Tupels. Bis finale Exact-Head-Tests, PR-Checks, SonarQube-
Ergebnis, Reviews, kontrollierter Framework-Merge und separat eigene Parent-
Behebung beobachtet sind, ist F-GS-003 nicht geschlossen.

## Finaler Diff- und Review-Status

Die Framework-Behebung ist lokal in Arbeit. Dieses Change Record dokumentiert
keinen geänderten-Head-Commit, Push, CI-Status, SonarQube-Ergebnis, Review-
Status oder Merge. Framework-PR #60 darf erst integriert werden, wenn seine
aktuellen Exact-Head-, Review-, CI-, SonarQube- und Master-Integration-Gates
bestehen; der kontrollierte Merge ist ausstehend, nicht abgeschlossen.
