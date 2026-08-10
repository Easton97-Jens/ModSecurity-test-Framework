# Change Record

**Sprache:** [English](20260810-01-add-five-connectors-with-crs-no-mrts-contract.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260810-01-add-five-connectors-with-crs-no-mrts-contract` |
| UTC-Datum | 2026-08-10 |
| Framework-Basisrevision | `03880bf` (beobachteter Task-Worktree-HEAD; vollständiger Delivery-SHA ausstehend) |
| Issue oder Pull Request | Zum Zeitpunkt der Erstellung keiner dokumentiert. |

## Motivation und Problemstellung

Einen wiederverwendbaren, fail-closed Framework-Evidenzvertrag für das
separate With-CRS-/No-MRTS-Profil hinzufügen, ohne statische Validierung als
Connector-Runtime-Aussage darzustellen.

## Betroffene Komponenten und Sicherheitsgrenzen

Der Vertrag validiert kontrollierte, vom Host bereitgestellte Evidenz an der
Framework-/Connector-Grenze. Er hat eine geschlossene Fünf-Connector-Liste:
`apache`, `haproxy`, `envoy`, `traefik` und `lighttpd`. NGINX ist nur von
diesem Profil ausgeschlossen, nicht von der allgemeinen Sechs-Connector-Grenze.
MRTS bleibt eine schreibgeschützte externe Abhängigkeit: Jeder akzeptierte
normalisierte Record und sein typisierter Raw-Cleanup-Record binden den
expliziten No-MRTS-Zustand des Profils, doch dieser Record behauptet keine
hostseitige MRTS-Prozessbeobachtung.

## Akzeptanzkriterien

- Das Profil ist auf genau die fünf Connectors begrenzt und weist NGINX ab.
- Die kanonische CRS-Fixture bindet die Allow-Kontrolle und die
  Regel-`942270`-`deny`-Kontrolle an den offiziellen CRS-Tag `v4.28.0`, dessen
  gepeeltes Objekt dem Commit `55b09f5acfd16413e7b31041100711ceb7adc89c`
  entsprechen muss.
- Der Validator schlägt für unvollständige, abweichende, unsichere oder nicht
  No-MRTS-konforme Evidenz fail-closed fehl, bindet strikte Raw-Request-/Block-/
  Cleanup-Records und überschreibt keine Ergebniswege. Jeder geparste
  Artefaktinhalt und sein gespeicherter Digest stammen aus einem no-follow-
  Dateideskriptor-Snapshot; ein gleichzeitiger Namenswechsel schlägt fehl.
- Ausgabeartefakte sind `CONTRACT_VALIDATED` und `UNATTESTED`; sie können durch
  diese reine Framework-Änderung nicht zu einem Connector-Host-Runtime-PASS
  hochgestuft werden.
- Englische und deutsche Reader-Dokumentation benennt Evidenzgrenze und
  kanonische CLI-Schnittstelle.

## Untersuchte Alternativen

Die Wiederverwendung eines allgemeinen Sechs-Connector-Ergebnisses oder die
Behandlung des NGINX-Ausschlusses als globale Fähigkeitsänderung wurde
abgelehnt, weil jedes Profil eine unabhängige Aussage ist.

## Implementierungsentscheidung

`ci/checks/catalog/five_connectors_with_crs_no_mrts.py` mit getrennten
Operationen `profile`, `verify-fixture`, `validate` und `aggregate` verwenden.
Das Tool validiert vom Host bereitgestellte Evidenz; es provisioniert keinen Host und
führt kein MRTS aus. Es verlangt frische CRS-Topologie, unveränderlichen
Commit, Release-Tag-Peel, Regeldatei-Digest, Regel-Fingerprint, feste
Adapteridentität, typisierte Raw-Records, geschlossene Schemas, private
no-follow-Evidenzpfade, deskriptorgebundene Inhalte/Digests und Create-only-
Ausgaben.

## Geänderte Dateien und Tests

Diese Änderung ergänzt oder aktualisiert die folgenden Framework-eigenen
Komponenten:

- `ci/checks/catalog/five_connectors_with_crs_no_mrts.py` und die feste
  Make-zu-Validator-Brücke `ci/tools/run-five-connectors-with-crs-no-mrts.py`
- `tests/cases/security/crs/crs_sqli_anomaly_block.yaml` und die vier
  geschlossenen Schemadateien unter `tests/schemas/five-connectors-with-crs-no-mrts/`
- `ci/provisioning/fetch-crs.sh`, `ci/provisioning/crs-provenance.sh`,
  `ci/lib/common.sh` und `ci/checks/catalog/check-crs-version-pinning.sh`
- `Makefile` und den nur lesenden Profilworkflow
- `.github/workflows/ci-security-quality.yml`,
  `.github/workflows/update-workflow-tools.yml`,
  `ci/checks/security/check-ci-security-contract.py`,
  `ci/tools/update-workflow-tools.py` und `pyrightconfig.json`, die den neuen
  Verifier/Workflow in den bestehenden Qualitäts- und Workflow-Update-
  Verträgen halten
- `tests/ci_security/test_five_connector_with_crs_no_mrts_contract.py` und
  `tests/security_regression/test_crs_git_ref_provenance.py`
- `tests/no_crs/test_no_crs_baseline.py`, dessen Testsetup nun das vom
  gehärteten Renderer benötigte private Audit-Verzeichnis erzeugt
- `docs/testing-and-evidence.{md,de.md}`
- `docs/connector-integration.{md,de.md}`
- `docs/reference/variables.{md,de.md}`
- `docs/github-actions-workflow-security.{md,de.md}`
- diesen gepaarten Change Record und die Change-Record-Indizes.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `make BUILD_ROOT=<task-build> test-five-connectors-with-crs-no-mrts-contract` | 0 | 24 fokussierte positive und adversarielle Vertragstests bestanden, einschließlich der Ablehnung von Gleich-UID-Namenswechseln, Top-Level-Fixture-Semantikdrift, ungültigem Runner-argv/fehlender Umgebung, tatsächlicher Make-Target-Importabdeckung sowie Make-Dollar-Normalisierung ohne Shell. | Lokale externe Task-Build-/Tmp-Wurzeln; keine Runtime-Evidenz. |
| `make BUILD_ROOT=<task-build> SOURCE_ROOT=<task-build>/runtime/src check-five-connectors-with-crs-no-mrts-fixture` | 0 | Ein frischer Checkout holte den überprüften Tag `v4.28.0`, prüfte seinen Peel zu `55b09f…c89c` und fand Regel `942270`. | Task-eigene lokale `fixture-verify-final`-Source-Wurzel. |
| `python -m unittest …test_default_release_tag_is_fetched_and_peeled_to_the_approved_commit …test_rejects_missing_or_moved_reviewed_release_tag -v` | 0 | Beide gezielten CRS-Tag-Provenance-Regressionen bestanden. | Lokale externe Task-Build-/Tmp-Wurzeln; Fake-Git-Transportfixture. |
| `make BUILD_ROOT=<task-build> TMP_ROOT=<task-build>/tmp test-no-crs-contract` | 0 | 98 No-CRS-Vertrags- und Transport-Hardening-Regressionen bestanden. | Lokale Task-eigene Build-/Tmp-Wurzeln; keine Host-Runtime. |
| `make BUILD_ROOT=<task-build> TMP_ROOT=<task-build>/tmp test-crs-provenance-contract` | 0 | 19 CRS-Provenance-Regressionen bestanden, einschließlich Ablehnung eines fehlenden/verschobenen geprüften Tags. | Lokale Task-eigene Build-/Tmp-Wurzeln; Fake-Git-Transportfixture. |
| `make BUILD_ROOT=<task-build> TMP_ROOT=<task-build>/tmp lint` | 0 | Vollständiges repositoryeigenes Lint-Ziel bestand: Shell-/Python-Syntax, Vertrags-Suiten, Provenance, Workflow, Data-Flow, Catalog, Dokumentation und Diff-Prüfungen. | Lokale Task-eigene Build-/Tmp-Wurzeln; keine Host-Runtime. |
| `make BUILD_ROOT=<task-build> check-documentation` | 0 | Links, zweisprachige Variablendokumentation, Repository-Pfade und der gepaarte Change-Record-Vertrag bestanden. | Lokaler Framework-Worktree. |
| `make BUILD_ROOT=<task-build> test-ci-security-contract` | 0 | 171 CI-Security-Vertragsregressionen bestanden. | Lokale Task-eigene Build-/Tmp-Wurzeln. |
| `python -m unittest tests.security_regression.test_mrts_common_sonar -v` | 0 | 6 No-MRTS-Helferregressionen bestanden ohne Corpus-Zugriff. | Lokale Task-eigene Build-/Tmp-Wurzeln; kein MRTS-Corpus/keine MRTS-Runtime. |
| `python -m unittest tests.security_regression.test_generate_case_matrix_sonar -v` | 0 | 17 Generator-/Report-Vertragsregressionen bestanden. | Lokale Task-eigene Build-/Tmp-Wurzeln; kein generierter Report-Refresh. |

## Sicherheitsauswirkung

Dies ist eine Härtung des Framework-Vertrags. Sie ergänzt fail-closed
Identitäts-, Release-Tag-zu-Commit-Provenance-, typisierte Raw-Evidenz-
Korrelation-, Containment-, No-Overwrite-, No-MRTS-, Cleanup- und
deskriptorgebundene Evidenzprüfungen. Ein Gleich-UID-Namenswechsel zwischen
Evidenzhash und Parser-Read oder während der frischen CRS-Checkout-/Regel-
Prüfung schlägt nun fail-closed fehl; veröffentlichte JSON-Digests stammen aus
exakt den geschriebenen Bytes und die Aggregation parst/hasht jede Ausgabe
über einen Dateideskriptor-Snapshot. Die Make-Targets neutralisieren geerbte
Dollar-Syntax vor jeder Make-Auswertung und rufen einen repositoryeigenen
Runner auf, der ausschließlich geschlossene argv-Vektoren bildet; kein
aufruferwählbarer Toolpfad erreicht eine Shell. Dieser Record behauptet keine
Host-Exploit-Reproduktion oder Umgehungsprüfung. Der Validator prüft die
strukturelle Konsistenz gelieferter Host-Records, authentifiziert ihren
Erzeuger jedoch nicht kryptographisch; jedes erfolgreiche Framework-Artefakt
bleibt daher ausdrücklich nicht promotbar.

## Dokumentation und Runtime-Evidenz

Englische und deutsche Dokumentation beschreibt das Profil und seine Grenzen.
Durch diese Dokumentationsänderung wurde keine Fünf-Host-, Produktions-,
Lifecycle- oder MRTS-Prozess-Evidenz erhoben.

## Nicht ausgeführte Prüfungen

Der lokale Interpreter ist Python `3.14.4`, während `.python-version` `3.14.6`
fordert. Der repositoryeigene Konfigurationsvertrag besteht, doch die exakte
Interpreterausführung muss weiterhin vom gehosteten Exact-Version-Workflow
belegt werden. Pyright kann lokal nicht laufen, weil seine repositoryverwaltete
Node-Voraussetzung fehlt; das checksum-verifizierte Hosted-Gate bleibt
erforderliche Evidenz und wird nicht als lokaler Pass behauptet. ShellCheck war
verfügbar, meldete jedoch bestehende Diagnosen auf unveränderten eingebundenen
Script-Zeilen; der repositoryeigene `bash -n`-Lint-Schritt bestand.
Refresh-/Checks generierter Reports wurden nicht ausgeführt, weil sie
generator-owned sind, generierten Output schreiben können und diese
Framework-Änderung absichtlich keinen Fünf-Host- oder MRTS-Runtime-Input hat.
Parent-eigene Fünf-Host-Kompositions-E2E, Runtime-Matrix und Produktions-
Evidenz liegen außerhalb des Framework-Scopes.

## Einschränkungen und Restrisiko

Ein gültiges geliefertes Evidenz-Bundle belegt nur den begrenzten Vertrag des
Validators. Connector-Owner müssen weiterhin authentische Host-, Lifecycle-
und Betriebs-Evidenz für jede Runtime- oder Promotion-Aussage erzeugen und
aufbewahren.

## Finaler Diff- und Review-Status

Die finale lokale Validierung und der Abschluss des fokussierten Security-Diff-
Reviews laufen noch. Die bereits getestete strukturelle Host-Evidenz bleibt
ausdrücklich nicht promotbar. Commit, Draft-PR, Review, gehostete CI,
SonarQube Cloud und Exact-Head-Delivery-Fakten werden erst nach Beobachtung
dokumentiert.
