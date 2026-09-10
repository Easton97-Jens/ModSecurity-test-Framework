# Change Record

**Sprache:** [English](20260909-01-remediate-modsecurity-v3-multipart.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260909-01-remediate-modsecurity-v3-multipart |
| UTC-Datum | 2026-09-09 |
| Framework-Basisrevision | 86451b45ae7bb7953baf9f81f2c2dad07395a808 |
| Issue oder Pull Request | Draft PR [#115](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/115) ist offen von `security/audit-2026-09-09-framework-fix` beim ersten Delivery-Commit `9592e325ca3e60153b047872f408c9c2e0b9b689`. Vor diesem Delivery-Evidence-Update stimmten lokaler, Remote- und PR-Status beim exakten Head `dd175abeae39675bbe103ac0e00abeab207945dc` überein, 14 terminale Checks bestanden, 3 Scope-unterstützte Checks waren übersprungen, und SonarQube Cloud meldete Quality Gate `OK` mit `0` `OPEN,CONFIRMED`-PR-Befunden. Die aktuelle Nutzeranweisung „kannst beide in den master bringen“ autorisiert ausschließlich die geschützte Integration von Framework PR #115 und Parent PR #360. Dieses reine Evidence-Follow-up erfordert vor einem normalen Squash-Merge einen frischen Exact-Head-Zyklus; ein Merge wird hier nicht behauptet. Parent-Gitlink-Arbeit, MRTS-Arbeit, Release, Deployment, direkte Default-Branch-Writes und Bypässe bleiben out of scope. |

## Motivation und Problemstellung

Die wiederverwendbare Framework-Dependency- und Multipart-Regressionsgrenze benötigte ein gepatchtes ModSecurity-v3-Provenance-Tuple und bytegenaue Controls für Newline-Repräsentationen. Dies ist eine Framework-only-Änderung für Engine-Validierung. Sie behauptet weder Connector-Loading, Backend-Byte-Delivery noch Client-Verhalten oder ein Parent-Gitlink-Update und schließt den privaten Audit sowie Roh-Payloads aus.

Das Follow-up löst außerdem den task-eigenen SonarQube-Cloud-Befund `c:S3776`
und den durch die drei neuen Multipart-Cases veralteten erzeugten Framework-
Katalog, ohne Scanner, Quality Gate, Workflow oder Test-Control zu verändern.

## Betroffene Komponenten und Sicherheitsgrenzen

- `ci/lib/common.sh` besitzt das genehmigte ModSecurity-v3-Tag-/Commit-Tuple.
- `src/v3-api-smoke/` und der Multipart-Case-Katalog üben die Engine-Parser-zu-`ARGS`-Grenze aus.
- `tests/runners/runner_core.py` materialisiert Quoted-Scalar-Escapes für den wiederverwendbaren YAML-Case-Pfad.

Die Sicherheitsinvariante lautet: Vom Engine erhaltene Multipart-Field-Bytes müssen Rule-Evaluation ohne stillen Verlust oder Normalisierung erreichen. Dieser Record leitet aus der Engine-Evidence kein Connector- oder Backend-Ergebnis ab.

## Akzeptanzkriterien

- Das genehmigte Dependency-Tuple ist `v3.0.16` bei `7ea9fefbe0ba409d8733b4d682c8c4c059cd028d`.
- Exakte CRLF- und LF-Controls lösen eine Engine-Intervention aus; das `AB`-Control bleibt für die Newline-Regel erlaubt und wird durch eine exakte `AB`-Regel abgelehnt.
- Der wiederverwendbare YAML-Katalog und Runner bewahren diese Byte-Unterscheidungen.
- `run_scenario` bleibt verhaltensgleich, während sein Request-Header-Setup
  unterhalb des Sonar-Cognitive-Complexity-Limits bleibt, und der erzeugte
  Katalog enthält alle drei neuen Multipart-Cases.
- Fokussierte Framework-Source-, Regressions-, Provenance-, Dokumentations-, Link- und Path-Checks bestehen, ohne generierte historische Reports zu verändern.
- Die Implementierung bleibt Framework-only. Die Nutzeranweisung autorisiert
  nur einen geschützten Squash-Merge von Framework PR #115 und Parent PR #360
  nach ihren aufgefrischten Exact-Head-Nachweisen; Parent-Gitlink, MRTS,
  Release, Deployment, direkte Default-Branch-Writes und Bypass-Aktionen sind
  nicht enthalten.

## Untersuchte Alternativen

Eine Aktualisierung nur der Dependency-Provenance würde keinen reproduzierbaren Grenztest für die betroffene Repräsentationsklasse bewahren. Breite Connector- oder Runtime-Behauptungen würden die Framework-Ownership überschreiten. Der gewählte Ansatz aktualisiert das genehmigte Tuple und ergänzt eng begrenzte Engine- und wiederverwendbare Katalog-Controls.

## Implementierungsentscheidung

Das Common-Version-Tuple wählt nun den genehmigten v3.0.16-Commit. Der C-API-Smoke ergänzt exakte CRLF-, LF-, Allow- und Exact-Representation-Controls. Die YAML-Cases und der Runner verwenden kompatible Quoted-Scalar-Decodierung für Byte-Sequenzen; der Regressionstest lädt den aktuellen Multipart-Katalog. Die Dokumentation begrenzt das Ergebnis auf Engine-Evidence.

Das Follow-up extrahiert das Request-Header-Setup nach
`add_request_headers()`, bewahrt aber die bestehende Header-Reihenfolge,
Meldungen, Rückgabewerte und caller-owned Cleanup. Der repository-eigene
Kataloggenerator erfasst die drei neuen YAML-Cases, und der öffentliche
Contract-Count-Test prüft nun die daraus resultierenden Summen.

## Geänderte Dateien und Tests

- Provenance: `ci/lib/common.sh`.
- Engine-Smoke: `src/v3-api-smoke/v3_api_smoke.c`.
- Erzeugter Katalog: `modsecurity_test_framework/data/framework-contract-catalog.json`.
- Öffentlicher Katalog-Contract: `tests/contract_api/test_public_contract_api.py`.
- Wiederverwendbare Case-Materialisierung: `tests/runners/runner_core.py`.
- Multipart-Cases: `tests/cases/body/multipart/multipart_crlf_field_deny_v3_0_16.yaml`, `multipart_lf_field_deny_v3_0_16.yaml` und `multipart_ab_field_allow_v3_0_16.yaml`.
- Regression: `tests/security_regression/test_multipart_newline_runtime_difference.py`.
- Dokumentation: `docs/architecture.md`, `docs/architecture.de.md`, dieser gepaarte Change Record und die gepaarten Change-Record-Indizes.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk proxy env MODSECURITY_V3_DIR=<task-built-v3.0.16> BUILD_ROOT=<task-owned-build-root> make -C src/v3-api-smoke run` | `0` | Primary-Control, exakte CRLF-/LF-Denies, `AB`-Allow und Exact-`AB`-Deny bestanden gegen die task-gebaute Library. | `security-audit-20260909` |
| `rtk proxy env PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest tests.security_regression.test_multipart_newline_runtime_difference tests.security_regression.test_runner_core_output_containment tests.security_regression.test_modsecurity_v3_git_ref_provenance tests.security_regression.test_common_version_atomic_provenance` | `0` | 56 fokussierte Tests bestanden, einschließlich des aktuellen YAML-Katalog-Loads. | `security-audit-20260909` |
| `rtk proxy make check-documentation` | `0` | Dokumentations-Links, bilinguale Variable-Dokumentation, Repository-Pfade und Change-Record-Contract bestanden. | `security-audit-20260909` |
| `rtk proxy python3 ci/tools/check-common-versions.py --validate-canonical` | `0` | Kanonische Common-Version-Provenance bestand. | `security-audit-20260909` |
| `rtk proxy git diff --check` | `0` | Es wurde kein Whitespace-Fehler gemeldet. | `security-audit-20260909` |
| `rtk proxy env PYTHONNOUSERSITE=1 PIP_REQUIRE_VIRTUALENV=true PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1 <framework-venv-python> -B ci/tools/generate-framework-contract-catalog.py --check` | `0` | Der repository-eigene erzeugte Katalog ist aktuell. | `security-audit-20260910` |
| `rtk proxy env PYTHONNOUSERSITE=1 PIP_REQUIRE_VIRTUALENV=true PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1 <framework-venv-python> -B -m unittest tests.contract_api.test_public_contract_api tests.security_regression.test_multipart_newline_runtime_difference` | `0` | 22 öffentliche Katalog- und Multipart-Repräsentations-Controls bestanden. | `security-audit-20260910` |
| `rtk proxy cc -std=c17 -Wall -Wextra -Werror -I<task-built-v3.0.16>/headers -c src/v3-api-smoke/v3_api_smoke.c -o <task-owned-output>` | `0` | Der refaktorierte C-Source bestand die explizite C17-Warnings-as-Errors-Kompilierung. | `security-audit-20260910` |
| `rtk proxy make -C src/v3-api-smoke run MODSECURITY_V3_DIR=<task-built-v3.0.16> BUILD_ROOT=<task-owned-output>` | `0` | Der gelinkte Smoke bestand Primary-Phase-2-, CRLF-/LF-Deny-, `AB`-Allow- und Exact-`AB`-Deny-Controls. | `security-audit-20260910` |

## Sicherheitsauswirkung

Die Änderung aktualisiert die genehmigte Engine-Provenance und macht Repräsentations-Controls an der Parser-zu-Rule-Grenze explizit. Sie prüft die ursprüngliche Newline-Klasse, eine LF-Variante und ein Exact-Representation-Control erneut, ohne eine breite Substring-Regel zu verwenden oder einen vorhandenen Test abzuschwächen. Die Evidence etabliert nur Engine-Verhalten; sie ist keine Connector-, Backend- oder Client-Evidence.

## Dokumentation und Runtime-Evidenz

`docs/architecture.md` und `docs/architecture.de.md` stellen die begrenzte Engine-only-Schlussfolgerung dar. Der task-gebaute C-API-Smoke ist kontrollierte Engine-Evidence, kein Framework-Hosted-Lifecycle- oder Connector-Runtime-Ergebnis. Es wurde kein Produktionsdienst kontaktiert.

## Nicht ausgeführte Prüfungen

- Kontrollierte Connector-/Backend-Evidence für die exakte Task-Library und ausgelieferte Bytes ist in dieser Umgebung nicht verfügbar.
- Generierte Framework-Reports bleiben unverändert: Eine Regeneration in einer Staging-Kopie würde historische Runtime-Klassifikationen außerhalb dieses Task-Scopes umschreiben.
- Das Delivery-Evidence-Follow-up selbst benötigt nach seinem normalen Push
  einen frischen Current-Head-Readback von GitHub, Review und SonarQube. Die
  erfolgreichen Ergebnisse für `dd175abeae39675bbe103ac0e00abeab207945dc`
  bleiben als Prior-Head-Evidence erhalten und gelten nicht als Proof für den
  neuen Commit.

## Einschränkungen und Restrisiko

Die kompatible Quoted-Scalar-Decodierung des Runners erreicht mehr als die drei neuen Cases; der vollständige aktuelle Katalog-Load bestand, aber zukünftige nicht JSON-kompatible Scalar-Konventionen benötigen eine separate Review. Engine-Proof etabliert nicht das Verhalten eines Connectors, Backends oder externen Clients. Das Finding bleibt lokal behoben mit ausstehender Connector-/Backend-Validierung und wird nicht auf `verified` hochgestuft.

## Finaler Diff- und Review-Status

Eine unabhängige Scoped-Review fand keinen konkreten Bypass und kein
abgeschwächtes Security-Control im Framework-Kandidaten. Die Sonar-Remediation
bewahrt die Header- und Cleanup-Grenze, und der Katalog wurde erzeugt statt von
Hand editiert. Am Prior-Head
`dd175abeae39675bbe103ac0e00abeab207945dc` waren alle terminalen PR-Kontexte
erfolgreich oder Scope-unterstützt übersprungen, und das SonarQube-Cloud-
Quality-Gate war grün. Dieses reine Dokumentations-Follow-up bewahrt diese
beobachteten Fakten und muss vor dem durch den Nutzer autorisierten geschützten
Squash-Merge eine neue Exact-Head-Review abschließen. Kein Parent-Gitlink,
MRTS, Release, Deployment, direkter Default-Branch-Write oder Bypass ist
autorisiert.
