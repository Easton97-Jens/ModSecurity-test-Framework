# Change Record

**Sprache:** [English](20260909-01-remediate-modsecurity-v3-multipart.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260909-01-remediate-modsecurity-v3-multipart |
| UTC-Datum | 2026-09-09 |
| Framework-Basisrevision | 86451b45ae7bb7953baf9f81f2c2dad07395a808 |
| Issue oder Pull Request | Draft PR [#115](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/115) ist offen und ungemergt vom `security/audit-2026-09-09-framework-fix`-Branch beim ersten Delivery-Commit `9592e325ca3e60153b047872f408c9c2e0b9b689`; lokaler, Remote- und PR-Head stimmten bei der Erstellung überein. Dieses Record-Update ist ein Follow-up-Commit und kann sein eigenes finales Git-Objekt nicht selbst referenzieren; Task-Delivery-Evidence dokumentiert den exakten finalen lokalen/Remote-/PR-Head-SHA nach dem Push. |

## Motivation und Problemstellung

Die wiederverwendbare Framework-Dependency- und Multipart-Regressionsgrenze benötigte ein gepatchtes ModSecurity-v3-Provenance-Tuple und bytegenaue Controls für Newline-Repräsentationen. Dies ist eine Framework-only-Änderung für Engine-Validierung. Sie behauptet weder Connector-Loading, Backend-Byte-Delivery noch Client-Verhalten oder ein Parent-Gitlink-Update und schließt den privaten Audit sowie Roh-Payloads aus.

## Betroffene Komponenten und Sicherheitsgrenzen

- `ci/lib/common.sh` besitzt das genehmigte ModSecurity-v3-Tag-/Commit-Tuple.
- `src/v3-api-smoke/` und der Multipart-Case-Katalog üben die Engine-Parser-zu-`ARGS`-Grenze aus.
- `tests/runners/runner_core.py` materialisiert Quoted-Scalar-Escapes für den wiederverwendbaren YAML-Case-Pfad.

Die Sicherheitsinvariante lautet: Vom Engine erhaltene Multipart-Field-Bytes müssen Rule-Evaluation ohne stillen Verlust oder Normalisierung erreichen. Dieser Record leitet aus der Engine-Evidence kein Connector- oder Backend-Ergebnis ab.

## Akzeptanzkriterien

- Das genehmigte Dependency-Tuple ist `v3.0.16` bei `7ea9fefbe0ba409d8733b4d682c8c4c059cd028d`.
- Exakte CRLF- und LF-Controls lösen eine Engine-Intervention aus; das `AB`-Control bleibt für die Newline-Regel erlaubt und wird durch eine exakte `AB`-Regel abgelehnt.
- Der wiederverwendbare YAML-Katalog und Runner bewahren diese Byte-Unterscheidungen.
- Fokussierte Framework-Source-, Regressions-, Provenance-, Dokumentations-, Link- und Path-Checks bestehen, ohne generierte historische Reports zu verändern.
- Delivery bleibt auf einen separaten Framework-Draft-PR beschränkt; Parent, MRTS, Gitlink, Merge, Release und Deployment sind nicht enthalten.

## Untersuchte Alternativen

Eine Aktualisierung nur der Dependency-Provenance würde keinen reproduzierbaren Grenztest für die betroffene Repräsentationsklasse bewahren. Breite Connector- oder Runtime-Behauptungen würden die Framework-Ownership überschreiten. Der gewählte Ansatz aktualisiert das genehmigte Tuple und ergänzt eng begrenzte Engine- und wiederverwendbare Katalog-Controls.

## Implementierungsentscheidung

Das Common-Version-Tuple wählt nun den genehmigten v3.0.16-Commit. Der C-API-Smoke ergänzt exakte CRLF-, LF-, Allow- und Exact-Representation-Controls. Die YAML-Cases und der Runner verwenden kompatible Quoted-Scalar-Decodierung für Byte-Sequenzen; der Regressionstest lädt den aktuellen Multipart-Katalog. Die Dokumentation begrenzt das Ergebnis auf Engine-Evidence.

## Geänderte Dateien und Tests

- Provenance: `ci/lib/common.sh`.
- Engine-Smoke: `src/v3-api-smoke/v3_api_smoke.c`.
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

## Sicherheitsauswirkung

Die Änderung aktualisiert die genehmigte Engine-Provenance und macht Repräsentations-Controls an der Parser-zu-Rule-Grenze explizit. Sie prüft die ursprüngliche Newline-Klasse, eine LF-Variante und ein Exact-Representation-Control erneut, ohne eine breite Substring-Regel zu verwenden oder einen vorhandenen Test abzuschwächen. Die Evidence etabliert nur Engine-Verhalten; sie ist keine Connector-, Backend- oder Client-Evidence.

## Dokumentation und Runtime-Evidenz

`docs/architecture.md` und `docs/architecture.de.md` stellen die begrenzte Engine-only-Schlussfolgerung dar. Der task-gebaute C-API-Smoke ist kontrollierte Engine-Evidence, kein Framework-Hosted-Lifecycle- oder Connector-Runtime-Ergebnis. Es wurde kein Produktionsdienst kontaktiert.

## Nicht ausgeführte Prüfungen

- Kontrollierte Connector-/Backend-Evidence für die exakte Task-Library und ausgelieferte Bytes ist in dieser Umgebung nicht verfügbar.
- Generierte Framework-Reports bleiben unverändert: Eine Regeneration in einer Staging-Kopie würde historische Runtime-Klassifikationen außerhalb dieses Task-Scopes umschreiben.
- Frische Exact-Head-Hosted-Checks, Review und SonarQube-Disposition existieren beim Erstellen des Pre-Delivery-Records noch nicht.

## Einschränkungen und Restrisiko

Die kompatible Quoted-Scalar-Decodierung des Runners erreicht mehr als die drei neuen Cases; der vollständige aktuelle Katalog-Load bestand, aber zukünftige nicht JSON-kompatible Scalar-Konventionen benötigen eine separate Review. Engine-Proof etabliert nicht das Verhalten eines Connectors, Backends oder externen Clients. Das Finding bleibt lokal behoben mit ausstehender Connector-/Backend-Validierung und wird nicht auf `verified` hochgestuft.

## Finaler Diff- und Review-Status

Eine unabhängige Scoped-Review fand keinen konkreten Bypass und kein abgeschwächtes Security-Control im Framework-Kandidaten. Draft PR #115 ist offen; dieses Follow-up verlangt nach seinem normalen Push einen frischen Exact-Head-Readback. Hosted-Ergebnisse, Review und jeder Merge liegen weiter außerhalb der aktuellen Evidence. Release, Deployment, Parent-Gitlink-Update und MRTS-Change sind nicht autorisiert.
