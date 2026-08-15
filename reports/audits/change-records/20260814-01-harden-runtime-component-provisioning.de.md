# Change Record: 20260814-01-harden-runtime-component-provisioning

**Sprache:** [English](20260814-01-harden-runtime-component-provisioning.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260814-01-harden-runtime-component-provisioning` |
| UTC-Datum | 2026-08-14 |
| Framework-Basisrevision | `1260aaae411ecf88cf50dc480b80e2e20ac47901` |
| Issue oder Pull Request | Draft-PR ausstehend. Keine Issue wird geschlossen. Addresses F-GS-004. |

## Motivation und Problemstellung

F-GS-004 identifizierte Versionsdrift zwischen Framework-Runtime-Metadaten und
Konsumenten, einschließlich Envoy `1.38.2` gegenüber `1.39.0`, Traefik
`3.7.5` gegenüber `3.7.10` und einer generischen HAProxy-Version, die die
exakte HAProxy-HTX-Runtime `3.2.21` nicht ersetzen darf. Der gemeinsame
Downloader hatte außerdem keinen begrenzten Connect- oder Gesamt-Timeout,
konnte leere oder checksum-invalidierte Artefakte behalten und gab in einigen
BLOCKED-Diagnosen vollständige vom Aufrufer kontrollierte URLs aus.

Der PR-Follow-up wurde erforderlich, weil SonarCloud dreizehn offene neue
Maintainability-Befunde im auftragseigenen Shared Helper und Lock-Checker
meldete. Die Bereinigung darf diese Befunde ohne Suppressions, Quality-Profile-
Änderungen oder Lockerung eines fail-closed Runtime-Provisioning-Controls
entfernen.

## Betroffene Komponenten und Sicherheitsgrenzen

Der Framework-eigene Scope umfasst den geprüften Runtime-Lock, den gemeinsamen
Runtime-Artefakt-Downloader, den HAProxy-Source-Preparer, den NGINX-Archiv-
Provisioner, den Apache-Source-Provisioner, ihre lokalen Regressionstests und
das geprüfte Manifest. Die Grenze beginnt mit einem geprüften HTTPS-Release-
Tupel und endet erst, nachdem ein nicht-leeres Artefakt seine erforderliche
SHA-256-Prüfung besteht. Parent, Parent-Gitlink, Connector-Host-Claims, MRTS,
globale Installationen und Deployment bleiben außerhalb dieser Änderung.

## Akzeptanzkriterien

1. Der Lock enthält NGINX, HAProxy HTX, HAProxy SPOE/SPOP, Envoy `ext_authz`,
   Envoy `ext_proc`, Traefik `forwardauth` und native Traefik-Tupel.
2. Der Checker blockiert die bekannte Drift NGINX `1.31.2`, Envoy `1.38.2`
   und Traefik `3.7.5`, falsche Architektur-/Asset-Werte sowie fehlende oder
   ungültige SHA-256-Werte.
3. HAProxy HTX bleibt exakt `3.2.21` mit
   `0cb8818a26c5f888e0cb1c40f1b3acb9fb952527d1733f769ce688fedd680339`,
   unabhängig von HAProxy SPOE/SPOP `3.2.22`.
4. Downloads behalten TLS-Verifikation, verwenden begrenzte Connect-/Gesamt- /
   Retry-Zeit, klassifizieren Fehler sicher und entfernen leere, partielle,
   fehlende-Pin- und checksum-invalidierte Artefakte vor jedem Staging.
5. Lokale Fehler-Fixtures und ein legitimer geprüfter Download-Control-Pfad
   bestehen ohne Netzwerkzugriff oder globale Installation.
6. Der Follow-up-PR-Head hat für diese Änderung null offene neue SonarCloud-
   Befunde, ohne Rule-Suppression, Quality-Gate-Änderung oder Lockerung eines
   Sicherheits-Controls.

## Untersuchte Alternativen

- Das Duplizieren von Versions-Tupeln in jedem Preparer wurde verworfen, weil
  es die Drift-Grenze erneut erzeugt.
- Das Wiederholen aller curl-Fehler wurde verworfen, weil TLS-, permanente
  HTTP-, SHA- und Konfigurationsfehler Abhilfe statt weiterer Requests brauchen.
- Das Behalten fehlgeschlagener Artefakte für Diagnosen wurde verworfen, weil
  eine veraltete partielle oder checksum-inkorrekte Datei später als
  vertrauenswürdige Eingabe gestaged werden könnte.

## Implementierungsentscheidung

`ci/provisioning/runtime-component-lock.json` ist der kanonische geprüfte
Lock. `ci/tools/check-runtime-component-lock.py` validiert die gemeinsamen
Defaults und das Envoy-/Traefik-Inventar-Manifest dagegen; normales
`make lint` führt diese Prüfung und ihre Regressionen aus. Runtime-Preparer
validieren ihr effektives NGINX-, Envoy-, Traefik-, generisches HAProxy- und
HAProxy-HTX-Environment-Tupel, bevor sie eine lokale Binary oder einen
Opt-in-Download akzeptieren. Das HTX-
Tupel wird durch die separaten `HAPROXY_HTX_*`-Variablen repräsentiert und
kann keine generischen `HAPROXY_VERSION`-Metadaten verwenden.

Der gemeinsame Downloader ruft curl mit vorangestelltem `--disable` auf,
sodass eine umgebungsweite curl-Konfiguration die geprüften Flags nicht
schwächen kann. Er verwendet HTTPS-only curl mit `--connect-timeout`,
`--max-time`, begrenzter Retry-Zeit, temporären Dateien von `mktemp`,
Metrik-Erfassung, HTTPS-only-Redirect-Protokollen und keiner unsicheren
Option. Vom Aufrufer gesetzte Timeout-Werte müssen positive Ganzzahlen
innerhalb der geprüften Connect- (`60` Sekunden), Gesamt- (`900` Sekunden)
und Retry-Grenzen (`300` Sekunden) sein; die Retry-Zeit darf die Gesamtzeit
nicht übersteigen. Er schreibt eine bereinigte maschinenlesbare `runtime_diagnostic` mit
Status `BLOCKED`, stabilem Reason-Code, sicherem Host, Artefakt-Identifier,
Abhilfe und wahrheitsgetreuem `tls_verification` (`verified`, `failed`,
`not_confirmed` oder `not_attempted`). Der HAProxy-Source-Preparer, der
NGINX-Archiv-Provisioner und die Apache-/PCRE2-/APR-/APR-util-Provisioner
verwenden denselben begrenzten geprüften Transfer. APR-util behält den
geprüften No-Redirect-Modus. URL-Userinfo und Query-Inhalt werden auch bei
abgelehnten HTTPS-URL-Prüfungen nicht in Diagnosen behalten.

Der reine SonarCloud-Follow-up gibt den zwei positionellen Shell-Parametern
lokale Namen, lässt jede betroffene Helper-Funktion bewusst zurückkehren und
erhält delegierte Fehlerwerte mit `return $?`. Der optionale Metrics-Reader
gibt erst nach Initialisierung seiner dokumentierten Defaults Erfolg zurück.
Der Lock-Checker entfernt eine unbenutzte lokale Variable und verschiebt den
unveränderten Envoy-/Traefik-Manifestvergleich in einen benannten Helper;
root-gebundene Dateizugriffe, Validierungsbedingungen, Fehlermeldungen und
das Exit-`77`-Mapping bleiben unverändert.

## Geänderte Dateien und Tests

- `ci/lib/common.sh` definiert und exportiert das exakte HAProxy-HTX-Tupel.
- `ci/provisioning/runtime-component-lock.json` definiert den kanonischen
  Profil-Lock; `runtime-components.manifest.json` entspricht jetzt Envoy
  `1.39.0` und Traefik `3.7.10`.
- `ci/tools/check-runtime-component-lock.py` validiert Tupel, Plattform,
  Asset, Download-URL, SHA-256, Provenance und Manifest-Drift.
- `ci/lib/runtime-component-common.sh` härtet begrenzte Transfers,
  curlrc-Isolation, Timeout-Policy-Validierung, Diagnosen, Cleanup,
  No-Redirect-Modus und Integritätsbehandlung; `prepare-haproxy-runtime.sh`,
  `prepare-nginx-build.sh` und `prepare-apache-build.sh` verwenden ihn.
- `tests/security_regression/test_runtime_component_lock.py` und
  `test_runtime_component_download.py` decken Drift, effektive
  Tupel-Erzwingung, Timeout-Policy-Ablehnung, Fehler-Fixtures, Cleanup,
  Redaction und den legitimen Staging-Pfad ab.
- `tests/security_regression/test_nginx_archive_digest.py` übt den NGINX-
  Archivcache- und Provenance-Contract über den gemeinsamen Downloader aus.
- `tests/security_regression/test_apr_util_provenance.py` behält den APR-util-
  Provenance-/No-Redirect-Contract über den gemeinsamen Downloader bei.
- `Makefile` bietet die fokussierten Lock- und Download-Testtargets und
  schließt sie in normales Lint ein.
- Der SonarCloud-Follow-up ändert nur
  `ci/lib/runtime-component-common.sh` und
  `ci/tools/check-runtime-component-lock.py` sowie dieses gepaarte Change
  Record: Er fügt keine Suppression hinzu und ändert kein Quality Profile.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | ---: | --- | --- |
| `sh -n ci/lib/common.sh ci/lib/runtime-component-common.sh ci/provisioning/prepare-haproxy-runtime.sh ci/provisioning/prepare-nginx-build.sh ci/provisioning/prepare-envoy-runtime.sh ci/provisioning/prepare-traefik-runtime.sh` | 0 | Geänderte Shell-Dateien bestanden die Syntaxprüfung. | `f-gs-004-framework-20260814` |
| `python3 -m json.tool ci/provisioning/runtime-component-lock.json` | 0 | Kanonischer Lock ist gültiges JSON. | `f-gs-004-framework-20260814` |
| `make BUILD_ROOT=<task-owned-external-root>/build TMP_ROOT=<task-owned-external-root>/tmp test-runtime-component-lock` | 0 | Checker plus acht deterministische Lock-Drift- und effektive-Environment-Tests bestanden. | `f-gs-004-framework-20260814` |
| `make BUILD_ROOT=<task-owned-external-root>/build TMP_ROOT=<task-owned-external-root>/tmp test-runtime-component-download` | 0 | Zehn lokale Download-Fehler-/Control-, Timeout-Policy-, curlrc-Isolations-, TLS-Status-, Redaction-, No-Redirect- und Preparer-Adoption-Tests bestanden. | `f-gs-004-framework-20260814` |
| `make BUILD_ROOT=<task-owned-external-root>/build TMP_ROOT=<task-owned-external-root>/tmp test-apr-util-provenance` | 0 | Dreizehn APR-util-Provenance-/No-Redirect-Regressionstests bestanden nach der Shared-Downloader-Adoption. | `f-gs-004-framework-20260814` |
| `make BUILD_ROOT=<task-owned-external-root>/build TMP_ROOT=<task-owned-external-root>/tmp test-nginx-archive-digest` | 0 | Einundzwanzig NGINX-Archivcache-, Provenance-, HTTPS-only-Redirect-, Lock-, Checksum- und Extraktionsregressionen bestanden über den Shared Downloader. | `f-gs-004-framework-20260814` |
| `shellcheck -x ci/lib/runtime-component-common.sh` | 0 | Der geänderte Shared Downloader hat keine ShellCheck-Befunde. | `f-gs-004-framework-20260814` |
| `make BUILD_ROOT=<task-owned-external-root>/lint-build-final TMP_ROOT=<task-owned-external-root>/lint-tmp-final lint` | 0 | Die vollständige Framework-Lint- und Contract-Suite bestand nach der Apache-, Lock-Enforcement- und TLS-Status-Härtung. | `f-gs-004-framework-20260814` |
| `make PYTHON=<task-owned-venv>/bin/python BUILD_ROOT=<task-owned-external-root>/build TMP_ROOT=<task-owned-external-root>/tmp test-runtime-component-lock` | 0 | Zehn Lock-/Profil-Akzeptanz- und Drift-Ablehnungstests bestanden nach dem SonarCloud-Refactoring. | `pr-79-sonar-new-issues` |
| `make PYTHON=<task-owned-venv>/bin/python BUILD_ROOT=<task-owned-external-root>/build TMP_ROOT=<task-owned-external-root>/tmp test-runtime-component-download` | 0 | Zehn Downloader-Erfolgs-/Fehler-, Redirect-, Timeout-, Cleanup-, Redaction- und Wrapper-Tests bestanden nach der Explicit-Return-Bereinigung. | `pr-79-sonar-new-issues` |
| `make PYTHON=<task-owned-venv>/bin/python BUILD_ROOT=<task-owned-external-root>/build TMP_ROOT=<task-owned-external-root>/tmp lint` | 0 | Die vollständige Framework-Lint- und Contract-Suite bestand; der Response-Body-Promotion-Guard lief zusätzlich mit expliziten Framework-Wurzeln. | `pr-79-sonar-new-issues` |

## Sicherheitsauswirkung

Die fokussierte Remediation nutzt kontrollierte Fake-curl-Eingaben, um DNS-,
Connect-, Timeout-, TLS-, HTTP-, leere, partielle und checksum-inkorrekte
Fehler zu reproduzieren. Jeder Fehler entfernt das Kandidat-Artefakt und
hinterlässt eine `BLOCKED`-Diagnose; der valide Control-Pfad verifiziert und
staged ein nicht-leeres passendes Artefakt. Die alternativen Bypass-Klassen
URL-Userinfo-/Query-Redaction, Invalid-URL-Ablehnung, APR-util-Redirects,
umgebungsweite curl-Konfiguration sowie unbegrenzte oder Null-Timeout-
Overrides sind abgedeckt. TLS- und SHA-256-Erzwingung wurden verstärkt, nicht
gelockert; ein TLS-Fehler meldet `tls_verification=failed` statt eines
falschen Erfolgs. Kein Secret, Token, private URL oder netzwerkgeladenes
Artefakt wird erfasst.

Der Follow-up ist nur eine Maintainability-Bereinigung. Seine expliziten
Returns erhalten die Lock-Checker- und Downloader-Fehlerstatus; der eine
erfolgreiche Default-Pfad gehört zu optionalen bereits initialisierten
Metrics. Der fokussierte Security-Diff-Review fand keine reportable Regression
bei Root-Confinement, TLS, Checksum, Timeout, Cleanup oder Diagnostic-
Redaction.

## Dokumentation und Runtime-Evidenz

Dieses gepaarte Change Record dokumentiert die Framework-Entscheidung auf
Englisch und Deutsch. Die Tests sind nur lokale Helper- und Lock-Contract-
Evidenz. Kein NGINX-, HAProxy-, Envoy- oder Traefik-Hostprozess wurde
gestartet, daher wird kein Hostruntime-`PASS` behauptet. Parent konsumiert
diesen Lock erst nach seiner separaten Abhängigkeit und autorisierten
Gitlink-Lifecycle.

## Nicht ausgeführte Prüfungen

- Ein echter externer Komponenten-Download wurde nicht ausgeführt: Die lokale
  Fixture-Matrix ist deterministisch und vermeidet unkontrollierte
  Netzwerk-Akquisition.
- Parent-eigene NGINX-, HAProxy-SPOE/SPOP-, Envoy- und Traefik-Hosttests wurden
  in dieser Framework-Änderung nicht ausgeführt; fehlende Host-Infrastruktur
  bleibt eine komponentenspezifische `BLOCKED`-Bedingung, nicht `FAIL`.

## Einschränkungen und Restrisiko

Der Checker schützt den geprüften Linux-amd64-Profil-Contract; ein neues
Betriebssystem- oder Architekturprofil benötigt sein eigenes geprüftes Tupel
und einen Test. Curls Standard-Retry-Policy wird absichtlich nicht mit
`--retry-all-errors` erweitert; Upstream-Verhalten bleibt eine externe
Abhängigkeit. Der Framework-Draft-PR ist nicht gemergt, deshalb bleibt der
Parent-Gitlink unverändert und der Lock ist noch nicht in Parents
aufgezeichneter Submodule-Revision vorhanden.

## Finaler Diff- und Review-Status

Der auftragseigene Diff-, Whitespace-, Secret-, Dokumentations- und fokussierte
Security-Diff-Review bestand nach der SonarCloud-Bereinigung. Hosted
SonarCloud muss den exakten gepushten Head noch analysieren, bevor das
Null-offene-neue-Befunde-Kriterium behauptet wird. Dieses Record autorisiert
oder behauptet keinen Merge, Parent-Change, MRTS-Change oder Gitlink-Update.
