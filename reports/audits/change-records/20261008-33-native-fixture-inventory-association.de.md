# Change Record

**Sprache:** [English](20261008-33-native-fixture-inventory-association.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261008-33-native-fixture-inventory-association |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | 74e7e52831ba01f64c4831a777b307c9dde582be |
| Issue oder Pull Request | Parent-NGINX-All-Required-Integration; kein separates Framework-Issue |

## Motivation und Problemstellung

Die tatsächliche zurückgestellte NGINX-YAML `phase4_body_reject` deklariert
bewusst keine HTTP-Erwartung. Die Inventarerzeugung leitete sie fälschlich zur
generischen YAML-Erwartungskonstruktion und scheiterte mit
`missing declared expectation`.

## Betroffene Komponenten und Sicherheitsgrenzen

Nur Framework-Inventargenerator, Paketressource, Contract-API-Tests und
zweisprachige Dokumentation ändern sich. Inventar-Provenienz darf nicht zum
nativen Ausführungsnachweis werden. Parent, MRTS, Canonical-Validatoren und
Produktverträge in Katalog/Schema bleiben unverändert.

## Akzeptanzkriterien

Die tatsächliche Fixture wird ihrer bestehenden No-CRS-ID und ihrem expliziten
geschlossenen nativen Deskriptor zugeordnet. Fremde Identitäten, Pfade, Fixture-
Klassen, Rules, Status und Deskriptoren scheitern. Generische Erwartung, Phase,
Fähigkeiten und Anwendbarkeit bleiben unverändert; keine neue öffentliche
Erwartung entsteht.

## Untersuchte Alternativen

Eine Standard-HTTP-Erwartung oder die Wiederherstellung der überholten
Rule-basierten Ablehnung würde Semantik erfinden. Eine neue native Erwartungs-
API erforderte einen separaten Produktvertrag. Die gewählte Korrektur ergänzt
nur Provenienz.

## Implementierungsentscheidung

Nur der exakt bekannte Quellpfad darf `native_operation_fixture` verwenden.
Typisierte Fixture-Metadaten, tatsächliche Engine-Direktiven und der aktuelle
Katalogdeskriptor müssen dem geschlossenen Schema und unterstützten Reject-
Vertrag entsprechen. Der bestehende generische API-Vertrag bleibt erhalten;
ausgewählte native Deskriptoren und strikte Original-Receipts bleiben alleiniger
tatsächlicher nativer Canonical-Nachweis.

## Geänderte Dateien und Tests

Generator und generierte Paket-JSON, zweisprachige Contract-API-Dokumentation,
neue `test_native_fixture_source_association.py`, bestehende öffentliche
API-Inventarzahl-/Quellassertions und dieses Record-Paar ändern
sich. Sechs fokussierte Tests prüfen positive Provenienz, API-Form,
deterministische payloadfreie Serialisierung und Widersprüche in Identität,
Pfad, Deskriptor oder Fixture. Die Regeneration übernimmt außerdem bereits
eingecheckte Config3-Verträge und elf Event/P4/MIME-YAML-Inventareinträge; dies sind
Quellaktualisierungen, keine neuen Runtime-Aussagen oder manuell geänderten
Erwartungen. Alle elf zusätzlichen Identitäten besitzen einen passenden
bestehenden eingecheckten YAML-Pfad. Die exakten Inventarzahlen sind 350 gesamt
und 200 YAML-Memberships: elf neue Identitäten und die zusätzliche YAML-
Membership der bestehenden Reject-ID.

## Befehle und Ergebnisse

Befehle verwenden RTK, Framework-Python, explizites `FRAMEWORK_ROOT` und externe
Cache-/Temp-Wurzeln. Logs liegen unter
`/var/tmp/codex/ModSecurity-conector/analysis/nginx-all-required-20261008T124555Z/`.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `python -m unittest -v tests.contract_api.test_native_fixture_source_association` vor Korrektur | 1 | RED: sechs fehlschlagende Controls | `stream-c-source-association-red.log` |
| Derselbe Befehl nach Korrektur | 0 | Sechs Tests grün, inklusive Rules-/Direktivenwidersprüchen | `stream-c-source-association-green3.log` |
| `python ci/tools/generate-framework-contract-catalog.py` | 0 | Ressource aus tatsächlichen Quellen regeneriert | `stream-c-source-association-generate.log` |
| `make test-contract-api PYTHON=/var/tmp/codex/ModSecurity-test-Framework/venv/bin/python FRAMEWORK_ROOT=/var/tmp/codex/ModSecurity-conector/worktrees/all-required-framework-source-association-20261008 BUILD_ROOT=/var/tmp/codex/ModSecurity-conector/analysis/nginx-all-required-20261008T124555Z/build TMP_ROOT=/var/tmp/codex/ModSecurity-conector/analysis/nginx-all-required-20261008T124555Z` | 2 | 29 grün; veraltete Inventarzahl 339 statt tatsächlich 350 scheitert | `stream-c-source-association-api.log` |
| Derselbe Make-Befehl nach Aktualisierung exakter Zahl-/Quellassertions | 0 | Alle 30 Contract-API-Tests und Generatorprüfung grün | `stream-c-source-association-api-green.log` |
| `python -m unittest -v tests.no_crs.test_nginx_native_selection tests.no_crs.test_nginx_native_canonical_binding` | 0 | 23 Tests grün | `stream-c-source-association-focus.log` |
| `python -m py_compile ci/tools/generate-framework-contract-catalog.py tests/contract_api/test_native_fixture_source_association.py` | 0 | Syntax grün | Task-Befehlsausgabe |
| `python ci/checks/documentation/check-doc-links.py` | 0 | Links grün | `stream-c-source-association-links.log` |
| `python ci/checks/documentation/check-variable-documentation.py` | 0 | Variablen-/Sprachpaarprüfung grün | `stream-c-source-association-vars.log` |
| `python ci/checks/documentation/check-change-records.py` | 0 | Struktur des Record-Paars grün | `stream-c-source-association-records.log` |
| `python ci/tools/generate-framework-contract-catalog.py --check` | 0 | Generierte Ressource entspricht aktuellen Quellen | Task-Befehlsausgabe |
| `rtk proxy git diff --check` | 0 | Whitespace grün | Task-Befehlsausgabe |

## Sicherheitsauswirkung

Keine Security-Remediation oder Connector-Verhaltensänderung wird behauptet.
Der Guard lehnt Quellersetzung und widersprüchliche Vertragsmetadaten ab, ohne
Rules, Payloads oder native Erwartungen ins öffentliche Inventar zu kopieren.

## Dokumentation und Runtime-Evidenz

Englische/deutsche Contract-API-Dokumentation erklärt die Provenienzgrenze.
Keine native Runtime-, Engine-Aufnahme- oder Lifecycle-Evidenz wurde erhoben.

## Nicht ausgeführte Prüfungen

Native Build/E2E und breite Repository-Prüfungen liegen außerhalb des begrenzten
Tasks. Ruff konnte nicht laufen: weder Framework-Umgebung noch PATH enthalten
es; Paketinstallation war nicht autorisiert. Python-Syntaxprüfung lief stattdessen.

## Einschränkungen und Restrisiko

Die enge Zuordnung scheitert bewusst bei Änderung des unterstützten Quellvertrags.
Die generische API-Erwartung ist nicht der NGINX-native Variantenvertrag.
Native Runtime-Lücken bleiben ungeprüft.

## Finaler Diff- und Review-Status

Fokussierter finaler Diff-, Whitespace- und Payload-Review erhält generische
Verträge. Alle 30 Contract-API-Tests, 23 Selection-/Canonical-Fokustests und
Dokumentationsprüfungen sind grün. Keine Secrets oder sensiblen Rohdaten wurden
dokumentiert. Der normale atomare Framework-Commit wird bei Übergabe angegeben.
