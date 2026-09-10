# Change Record

**Sprache:** [English](20260827-01-http2-http3-provenance-reader-boundary.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260827-01-http2-http3-provenance-reader-boundary` |
| UTC-Datum | 2026-08-27 |
| Framework-Basisrevision | `86451b45ae7bb7953baf9f81f2c2dad07395a808` |
| Issue oder Pull Request | Parent-Draft-PR `#348` bleibt unverändert; Framework-Draft-PR `#112` ist geöffnet und bleibt separat. |

## Motivation und Problemstellung

Der Benutzer hat Framework-Arbeit autorisiert, weil `ci/lib/common.sh` die
geprüften Komponenten-Versionen des Parent-Workstreams für HTTP/1.1-, HTTP/2-
und HTTP/3-Parität besitzt. OpenSSL 4.0.1 lag als NGINX-spezifisches doppeltes
Tupel vor, obwohl es eine generische Quellidentität ist. Für AWS-LC fehlte trotz
der vom Benutzer gelieferten unveränderlichen Tag-/Commit-Identität ein
kanonischer Datensatz für eine künftig geprüfte Nutzung. Zusätzlich wurden
ausgewählte Protocol-Sidecar- und Evidence-Dateien vollständig gelesen, bevor
ihre Größenbegrenzung und der reguläre Dateityp geprüft wurden.

## Betroffene Komponenten und Sicherheitsgrenzen

- `ci/lib/common.sh` ist die einzige Framework-Autorität für aktive
  Quellidentitäten sowie ihre Inherited-/Post-source-Active-Pin-Kontrollen.
- `ci/tools/check-common-versions.py` prüft kanonische Ownership,
  unveränderliche GitHub-Tag-/Commit-Provenance, OpenSSL-Release-Assets und
  abgeleitete Aliase.
- `ci/checks/protocol/protocol_client.py` und
  `ci/checks/protocol/check_protocol_evidence.py` verarbeiten vom Aufrufer
  gewählte Sidecar-/Evidence-Pfade an einer Datei-Lesegrenze.
- Die englische/deutsche Variablenreferenz beschreibt ausschließlich
  Framework-Metadaten.

Es werden keine Connector-Build-Auswahl, keine AWS-LC-Beschaffung, kein
curl/ngtcp2/nghttp3-Provisioning, kein Parent-Gitlink, kein MRTS-Inhalt, keine
Workflow-Credentials und keine Runtime-Promotion geändert.

## Akzeptanzkriterien

1. Das generische OpenSSL-Tupel zeichnet `4.0.1`, `openssl-4.0.1`, die
   offizielle Release-Asset-URL und die vom Benutzer gelieferte SHA-256 auf;
   die NGINX-Aliase werden daraus abgeleitet.
2. AWS-LC-Repository, Tag `v5.5.0` und vollständiger aufgelöster Commit sind
   kanonische unveränderliche Metadaten; ein unabhängiger
   Repository-Identitäts-Hash weist ein ersetztes GitHub-Repository vor jedem
   Upstream-Lookup zurück.
3. Exportierte geerbte OpenSSL-Overrides und Post-source-AWS-LC-Manipulationen
   schlagen mit dem Repository-Blocked-Status fehl; das Standardprofil H1
   bleibt unverändert.
4. Protocol-Reader konsumieren nur per Descriptor-Walk erreichte,
   nicht-symlinkende reguläre Dateien und behalten höchstens die konfigurierte
   Grenze plus ein Byte.
5. EN/DE-Dokumentation, fokussierte Tests und kanonische Validierung stimmen
   überein, ohne eine nicht ausgeführte HTTP/2- oder HTTP/3-Runtime zu
   behaupten.

## Untersuchte Alternativen

- Ein zweites NGINX-only-OpenSSL-Tupel wurde verworfen, weil zwei aktive
  Literale auseinanderlaufen können, obwohl sie dieselbe Quelle beschreiben.
- AWS-LC als NGINX-TLS-Bibliothek zu aktivieren wurde verworfen: Das aktuelle
  Provisioning unterstützt explizit nur OpenSSL, und es gibt weder eine
  autorisierte noch eine geprüfte AWS-LC-Build-/Runtime-Architektur.
- Einen beweglichen AWS-LC-Tag als ausreichend zu behandeln wurde verworfen;
  der Tag ist im `github_tag_commit`-Checker-Vertrag an den gelieferten
  vollständigen Commit gebunden.
- Pfad-Vorprüfungen mit anschließendem vollständigem Lesen wurden verworfen,
  weil sie Blocking durch Spezialdateien, unbegrenzte Allokation und
  Path-Replacement-Rennen ermöglichen.

## Implementierungsentscheidung

`OPENSSL_*` ist nun das kanonische Release-Tupel. Die bisherigen
`NGINX_QUIC_TLS_*`-Werte sind abgeleitete Aliase; der Checker verifiziert diese
Beziehung vor jedem Resolver-Lookup. `AWS_LC_*` zeichnet nur Provenance auf:
Sein geparstes Repository muss vor dem Lookup einem unabhängigen genehmigten
Identitäts-Hash entsprechen; es ist ausdrücklich keine ausgewählte Bibliothek
und keine bestätigte Fähigkeit.

Die Datei-Lesegrenze öffnet jede Verzeichniskomponente ohne Symlink-Following,
öffnet die finale Datei nonblocking und no-follow, fordert mittels `fstat()`
eine reguläre Datei und liest nicht mehr als `maximum + 1` Bytes. Bestehende
Aufrufer ordnen ungültige, nicht verfügbare und zu große Eingaben ihren
etablierten Fehlern zu.

## Geänderte Dateien und Tests

- `ci/lib/common.sh`
- `ci/tools/check-common-versions.py`
- `ci/checks/protocol/protocol_client.py`
- `ci/checks/protocol/check_protocol_evidence.py`
- `tests/security_regression/test_common_version_atomic_provenance.py`
- `tests/security_regression/test_common_shell_sonar_contracts.py`
- `tests/protocol_client/test_protocol_client.py`
- `tests/protocol_client/test_check_protocol_evidence.py`
- `docs/reference/variables.md`
- `docs/reference/variables.de.md`
- dieses gepaarte englische/deutsche Change Record

Fokussierte negative Abdeckung enthält die Ablehnung kopierter kanonischer
Pins, ersetzter AWS-LC-Repositories und fehlerhafter Commits, aller vier
abweichenden OpenSSL-Aliase, geerbter und Post-source-Pin-Manipulationen,
finaler und übergeordneter Symlinks, FIFOs, zu großer Dateien sowie das normale
H3-Observation-Parsing.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk proxy git ls-remote https://github.com/aws/aws-lc.git 'refs/tags/v5.5.0*'` | 0 | Der gelieferte AWS-LC-Tag löste auf `991e67ff4cf04df4dd89e407f8b920c6936cb56a` auf. | Task-Transcript, 2026-08-27 |
| `rtk proxy sh -n ci/lib/common.sh` | 0 | Die geänderte kanonische Shellquelle lässt sich parsen. | Isolierter Framework-Worktree |
| `rtk proxy python3 -B ci/tools/check-common-versions.py --validate-canonical` | 0 | Der lokale kanonische Pin-Vertrag besteht ohne HTTP-Lookup. | Isolierter Framework-Worktree |
| `rtk proxy python3 -B -m unittest tests.security_regression.test_common_version_atomic_provenance -v` | 0 | 27 Provenance-Vertragstests bestehen. | Isolierter Framework-Worktree |
| `rtk proxy python3 -B -m unittest tests.security_regression.test_common_shell_sonar_contracts -v` | 0 | 8 Shell-Grenzentests bestehen, einschließlich Inherited-/Post-source-Manipulationskontrollen. | Isolierter Framework-Worktree |
| `rtk proxy python3 -B -m unittest tests.protocol_client.test_protocol_client tests.protocol_client.test_check_protocol_evidence -v` | 0 | 31 Bounded-Reader- und Protocol-Client-Tests bestehen. | Isolierter Framework-Worktree |
| `rtk proxy python3 -B ci/checks/documentation/check-variable-documentation.py` | 0 | Die EN/DE-Variablenreferenz-Parität besteht. | Isolierter Framework-Worktree |
| `rtk proxy git diff --check` | 0 | Keine Whitespace-Fehler im abgegrenzten Diff. | Isolierter Framework-Worktree |

## Sicherheitsauswirkung

Die Änderung entfernt eine doppelte Quellidentität, bindet das vom Benutzer
gelieferte AWS-LC-Repository/Tag an eine unabhängige Repository-Identität und
einen vollständigen unveränderlichen Commit und wandelt die betroffenen
Protocol-Dateilesen in begrenzte Lesevorgänge regulärer Dateien um. Ein
unabhängiges Post-fix-Review prüfte Races mit übergeordneten/finalen Symlinks
und FIFOs ohne Escape- oder Blocking-Pfad.

Es löst nicht die separat identifizierten Evidence-Integrity-Einschränkungen:
strikte H3-Sidecar-Transport-/Reset-Felder sind weiterhin self-attested,
TLS-`--insecure`-Provenance wird nicht in der Evidence kodiert, und die
aktuelle Client-Auswahl/PATH-Provenance ist eine Hardening-/Reproduzierbarkeits-
Lücke. Keine davon wird durch dieses Record als behoben oder promoted behauptet.

## Dokumentation und Runtime-Evidenz

Die englische und deutsche Variablenreferenz dokumentiert dieselbe
OpenSSL-/AWS-LC-Ownership und erklärt ausdrücklich, dass AWS-LC keine aktuelle
Build-Auswahl ist. In diesem Framework-Worktree wurde keine Connector-, HTTP/2-,
HTTP/3-, QUIC-, AWS-LC- oder MRTS-Runtime gestartet. Der Parent benötigt nach
einer expliziten Gitlink-Entscheidung separate Exact-Head-Runtime-Evidenz.

## Nicht ausgeführte Prüfungen

- Kein AWS-LC-Download, -Build, -Installation oder NGINX-Bibliotheksauswahl
  wurde ausgeführt; diese Implementierung liegt außerhalb dieses
  Provenance-Records.
- Kein Managed-curl/ngtcp2/nghttp3-Provisioning wurde versucht, weil geprüfte
  Versionen, Assets, Checksummen und eine Richtlinienentscheidung fehlen.
- Vollständige Framework-Test-/Lint-Matrizen, Hosted CI, SonarCloud und die
  Framework-Draft-PR-Checks stehen bis zur Auslieferung aus.
- Kein Parent- oder MRTS-Test wurde ausgeführt und kein Parent-Gitlink geändert.

## Einschränkungen und Restrisiko

Der Pin-Vertrag beweist nur eine geprüfte Quellidentität; er kann keinen nicht
implementierten AWS-LC-Build nutzbar machen oder HTTP/3-Support beweisen. Eine
nicht sicherheitsrelevante Robustheitskante bleibt im Reader-Helper: Wird ein
relativer Pfad aufgelöst, nachdem das aktuelle Arbeitsverzeichnis des Prozesses
gelöscht wurde, kann vor dem bestehenden aufruferspezifischen Error-Mapping ein
Fehler auftreten. Alle bekannten produktiven Aufrufer verwenden konfigurierte
Artifact-Pfade; dies wird dokumentiert, statt den Scope still zu erweitern.

## Finaler Diff- und Review-Status

Bei Erstellung dieses Records liegen alle Änderungen im externen
aufgabeneigenen Framework-Worktree und sind bis zum finalen abgegrenzten Diff-,
Secret- und unabhängigen Provenance-Review nicht gestagt. Kein Commit, Push,
Pull-Request-Erstellen, Merge, Parent-Gitlink-Move oder MRTS-Aktion ist erfolgt.
Der autorisierte nächste Delivery-Schritt ist ausschließlich ein separater
Framework-Draft-PR.

**SonarQube-Cloud-Remediation (Kandidat).**

Am exakten Head
`630449ed71cadb0915dd82e1831aa08700fbdc2a` von Framework-Draft-PR `#112`
meldete SonarQube Cloud das neue Issue `AaBC6hWexbnbqiQBrl8d`, Regel
`python:S3776`, auf `resolve_component_definition`: kognitive Komplexität
`17`, obwohl `15` zulässig sind. Das Quality Gate war `OK`, der aktuelle
Benutzer hat jedoch ausdrücklich die Behebung des neuen Issues verlangt.

Der Kandidat trennt den bisherigen generischen Resolver-Body in
`resolve_standard_component_definition`. `resolve_component_definition`
dispatcht CRS und ModSecurity v3 weiterhin zuerst und delegiert danach jeden
anderen Descriptor an den unveränderten Body. Insbesondere bleiben die
GitHub-Repository-Kanonisierung und ihre `STATUS_BLOCKED`-Abbildung vor allen
netzwerkgestützten Resolver-Aufrufen; diese Remediation ändert weder Regeln,
Quality Gate, Workflow, Suppression, Exclusion, Pins, Parent-Gitlink noch
MRTS.

**Hinzugefügte Regressionsabdeckung und lokale Validierung.**

`tests/security_regression/test_common_version_atomic_provenance.py` prüft nun,
dass die zwei spezialisierten Komponenten den Standard-Dispatcher umgehen,
ein GitHub-Kanonisierungsfehler vor einer Client-Nutzung blockiert bleibt und
eine unbekannte Strategie ihre `UpstreamError`-Meldung behält.

| Befehl | Exit-Code | Kurzes Ergebnis | Evidenz |
| --- | --- | --- | --- |
| `rtk proxy python3 -B -m unittest -v tests.security_regression.test_common_version_atomic_provenance` | 0 | 30 hermetische Provenance-Tests bestehen, einschließlich der drei neuen Dispatcher-Kontrollen. | Isolierter Framework-Worktree, 2026-08-27 |
| `rtk proxy python3 -B -m unittest -v tests.security_regression.test_common_version_descriptor_series tests.security_regression.test_crs_git_ref_provenance.FetchCrsProvenanceTests.test_version_checker_automatically_updates_only_the_crs_v4_tuple tests.security_regression.test_crs_git_ref_provenance.FetchCrsProvenanceTests.test_version_checker_repairs_a_stale_crs_rule_digest tests.security_regression.test_crs_git_ref_provenance.FetchCrsProvenanceTests.test_version_checker_rejects_an_invalid_candidate_rule_file tests.security_regression.test_crs_git_ref_provenance.FetchCrsProvenanceTests.test_version_checker_rejects_foreign_crs_repository_before_network tests.security_regression.test_common_versions_sonar_provenance.CommonVersionProvenanceTests.test_modsecurity_v3_release_requires_reviewed_tag_and_commit_pair tests.security_regression.test_common_versions_sonar_provenance.CommonVersionProvenanceTests.test_modsecurity_v3_release_blocks_missing_or_malformed_immutable_anchor tests.security_regression.test_common_versions_sonar_provenance.CommonVersionProvenanceTests.test_unknown_results_fail_closed_while_local_policy_entries_are_not_applicable` | 0 | 11 Descriptor-, CRS-, ModSecurity-v3- und alternative Ergebnis-Kontrollen bestehen. | Isolierter Framework-Worktree, 2026-08-27 |
| `rtk proxy python3 -B ci/tools/check-common-versions.py --validate-canonical` | 0 | Der Offline-Pin-Vertrag für kanonisches `common.sh` besteht. | Isolierter Framework-Worktree, 2026-08-27 |
| `rtk proxy git diff --check` | 0 | Keine abgegrenzten Whitespace-Fehler. | Isolierter Framework-Worktree, 2026-08-27 |

Zwei unabhängige Read-only-Reviews verfolgten die Resolver-Pfade vor und nach
dem Patch. Das Post-Patch-Review fand keinen neuen validierten Sicherheits-
oder Kompatibilitätsbefund: CRS-/ModSecurity-v3-Reihenfolge,
Kanonisierung-vor-Netzwerk, `STATUS_BLOCKED`-Abbildung, alle übrigen
Strategie-Branches und das Exception-Mapping von `check_all` bleiben erhalten.
Das Review vermerkte eine bereits bestehende, nicht zum Scope gehörende
NGINX-Repository-Identitäts-Designfrage zur separaten Triage; sie wurde durch
diese Refaktorierung weder eingeführt noch geändert.

**Delivery-Evidenzgrenze.**

Der lokale Kandidat wurde vor der normalen Successor-Delivery validiert. Ein
frischer Nachfolger von Framework-PR `#112` muss per exaktem
Local-/Remote-/PR-Head-SHA, aktueller SonarQube-Cloud-Issue-Abfrage, Quality
Gate und anwendbaren Hosted Checks verifiziert werden, bevor dieses Record
oder der Befund als behoben markiert werden kann. Das vollständige
Framework-`make lint` und breitere Matrizen wurden für diese enge
Dispatcher-Refaktorierung nicht ausgeführt; `ruff` ist lokal nicht installiert
und es wurde keine Dependency-Installation vorgenommen. Daraus folgt keine
Runtime-, Parent- oder MRTS-Validierung.
