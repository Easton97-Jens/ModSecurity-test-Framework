# Change Record: NGINX-Size-Configtest-Vertrag

**Sprache:** [English](20261003-01-nginx-size-configtest.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20261003-01-nginx-size-configtest` |
| UTC-Datum | `2026-10-03` |
| Framework-Basisrevision | `c4f53e183ddc9eb69259f7a4b5a200fad784f6c6` |
| Issue oder Pull Request | Externer Parent-PR #396 bleibt OPEN/DRAFT/UNMERGED; kein Framework-PR erstellt |

## Motivation und Problemstellung

Dem Pflichtcase `invalid_size` fehlte eine konkrete NGINX-Konfigurationsrealisierung.
Vorheriger Boolean-only-Deskriptor und kanonischer Zielpfad konnten eine
unabhängige Size-Operation nicht ohne Vermischung von Identität oder aufbewahrten
Dateien validieren.

## Betroffene Komponenten und Sicherheitsgrenzen

Katalogauswahl, Receipt-Validierung, verwaltete Artefaktaufbewahrung und generierter
öffentlicher Vertragskatalog gehören dem Framework. Parent besitzt echte
Hostausführung und Collection. MRTS und Parent-Gitlinks bleiben unverändert.
Die Grenze trennt behauptete Receipt-Metadaten von autorisierten echten Bytes.

## Akzeptanzkriterien

Echte case-gebundene Size-Configtest-Evidence und exakten Exit 1 mit beiden
Size-Parserdiagnosen verlangen. Boolean-Relabeling, falsche Module, Mismatches
von Digests/Templates/Identitäten und nichtganzzahlige erwartete Exits abweisen.
Beide expliziten Cases getrennt aufbewahren; keine Ausnahme für beliebige
Phase-0- oder Request-Cases einführen.

## Untersuchte Alternativen

Generische Nonzero-Akzeptanz, Boolean-Receipt-Wiederverwendung und verkleinerte
Required-Auswahl würden den Vertrag beseitigen. Ein zweiter allgemeiner
Treiber/ein zweites Schema sind unnötig: Das vorhandene begrenzte Operations-
Receipt kann zwei explizit geschlossene Cases bedienen.

## Implementierungsentscheidung

`invalid_size` mit `modsecurity_phase4_body_limit maybe;`, Fehlerklasse
`invalid_size`, erwartetem Exit 1 und Fragmenten
`"modsecurity_phase4_body_limit" directive` und
`invalid value for modsecurity_phase4_body_limit` registrieren. Geschlossenes
case-spezifisches Template prüfen und jedes Bundle unter
`inventory/configtests/invalid_boolean` oder `inventory/configtests/invalid_size`
aufbewahren. Boolean-Semantik und globale
HTTP-/Event-/Full-Lifecycle-Prüfung erhalten. Generierten Vertragskatalog durch
seinen Generator aktualisieren, nicht durch manuelle Output-Änderungen.

## Geänderte Dateien und Tests

- `ci/checks/catalog/no_crs_baseline.py`
- `tests/cases/no-crs-baseline/catalog.json`
- `tests/no_crs/test_configtest_size.py`
- `modsecurity_test_framework/data/framework-contract-catalog.json` (generiert)
- `docs/testing-and-evidence.md` / `.de.md`
- Dieses Record-Paar und Archive-Index-Paar

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk proxy` um owning CPython 3.14.7 und die fünf expliziten Configtest-Unittest-Module | 0 | 34 Tests bestehen, einschließlich Zwei-Case-Isolation | Externe Coordinator-Validierung |
| `rtk proxy` um externes `analysis/check-nginx-config-size.py` mit owning Interpreter und explizitem Diagnose-Root | 0 | Individuelles PASS/FAIL, acht Validatoren mit null Fehlern | `nginx-config-size-retained-6si2byjk` |
| RTK-gewrappte Prüfung aufbewahrter `SHA256SUMS` | 0 | Alle 47 Einträge geprüft | `nginx-config-size-retained-6si2byjk` |
| `rtk proxy` um `make test-no-crs-contract` | 0 | 166 Tests bestehen in 111.503 s | Externe Coordinator-Validierung |
| `rtk proxy` um `make test-contract-api` | 0 | 23 Tests bestehen in 28.847 s | Externe Coordinator-Validierung |
| `rtk proxy` um `make check-documentation` mit owning Interpreter und externen Build-/Temp-Roots | 0 | Links, bilinguale Variablen, Repository-Pfade und Change Records bestehen | Dokumentationsübergabe Session 39793 |
| `rtk proxy git diff --check` | 0 | Whitespace-Prüfung besteht | Framework-Task-Worktree |
| `rtk proxy` um `make lint` | 0 | Vollständiges Precommit-Framework-Lint besteht | Externes Analyse-Log `framework-config-size-precommit-lint-20261003.log` und Exit-Receipt |

Der Fokus umfasst echte Artefaktbindung, getrennte Case-Bundles, Diagnose-
Mismatch und strenge Typkontrollen für den erwarteten Exit. Der anschließende
Size-Fokus bestand mit sieben Tests, einschließlich dauerhafter Shared-Finalizer-
Abdeckung: Zwei Cases bewahren zehn getrennte Manifest-Einträge auf; Cross-Case-
Aliase und Bundle-Wiederverwendung bleiben abgewiesen. Vollständiges Precommit-
Framework-Lint und finales fokussiertes Review bestanden. Das separat verlangte
Postcommit-Lint wird nach dem lokalen Commit in externer Run-Evidence erfasst
und hier nicht als künftiges PASS vorweggenommen.

## Sicherheitsauswirkung

Keine Validator-Abschwächung und keine synthetische Runtime-Evidence.
Bestehende nichtfolgende Regular-File-, begrenzte Input-/Copy- und Source-
Authority-Kontrollen bleiben erhalten. Beide Diagnosen und echte aufbewahrte
Byte-Digests müssen den konkreten Vertrag erfüllen; ein fremder Exit 1 bleibt
FAIL. Request-/Event-Anforderungen bleiben unverändert.

## Dokumentation und Runtime-Evidenz

Das Testing-Guide-Paar dokumentiert beide geschlossenen Verträge und getrennte
case-spezifische Aufbewahrung. Die echte externe Parent-getriebene Diagnose
`nginx-config-size-retained-6si2byjk` führt echtes NGINX, Collection und
kanonische Finalisierung aus. `invalid_size` erhält individuelles PASS;
Wrong-Module-Kontrolle bleibt FAIL trotz beider Exits von 1. Jede bewahrt fünf
Operationsdateien auf und besteht acht kanonische Validatoren. Beide Aggregate
bleiben FAIL; keine Starts, HTTP-Requests oder Events fanden statt. Dies ist
eine Precommit-Diagnose mit verändertem Source-Worktree und aufbewahrten
gecachten C-Artefakten, kein neuer Exact-Head-Build, Full Lifecycle oder
Framework-Runtime-Zertifizierung.

## Nicht ausgeführte Prüfungen

Full E2E und Protocol-Arbeit sind für diesen Teil verboten. Kein Gitlink-Update,
Push, PR-Write oder Merge wurde durchgeführt. Postcommit-Lint ist eine separate
Folgeprüfung. Root/nobody-Worker-Assertions gelten
nicht für einen reinen Configtest.

## Einschränkungen und Restrisiko

Acht Konfigurationspfade bleiben unerfüllt. Frisches externes
`measure-nginx-config-size.py` prüft echte Bytes, Run-Identitäten, alle acht
Validatoren und alle 47 Checksums erneut: Open Paths sanken 52 → 51 und
Konfiguration 9 → 8 bei unveränderter Required-Auswahl von 97.
Vertrauenswürdige gecachte Binary-/Modulinputs und unabhängiges Source-/Run-
Binding bleiben nötig; ausgeführte Snapshots beweisen keinen neuen quellgenauen
C-Build.

## Finaler Diff- und Review-Status

Unabhängiges Security-Review fand keinen Blocker. Dokumentations- und Whitespace-
Prüfungen und vollständiges Precommit-Lint bestehen. Der fokussierte Diff wurde
für einen separaten lokalen Framework-Commit geprüft. Keine Secrets, rohen sensiblen Inhalte, Remote-Delivery oder E2E PASS sind
aufgezeichnet. Framework-Delivery bleibt vom Parent getrennt; dieser Record
autorisiert kein Parent-Pointer-Update oder MRTS-Änderung.
