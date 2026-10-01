# NGINX-Vertrag für kanonische Abdeckung

**Sprache:** [English](20260930-01-nginx-canonical-coverage-contract.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260930-01-nginx-canonical-coverage-contract |
| UTC-Datum | 2026-09-30 |
| Framework-Basisrevision | `cc36b37d0f6a0fbc3512f3878a691751e91c5fbb` |
| Issue oder Pull Request | Parent-Draft-PR #396; noch kein Framework-PR |

## Motivation und Problemstellung

Ein NGINX-HTTP/1-Full-Lifecycle-Lauf selektierte 112 Fälle, aber nur 34 hatten
kanonische Evidenz. Zwei Katalog-Voraussetzungen fehlten, 13 reine H2/H3-Claims
waren im H1-Lauf selektiert, für sechs engere Claims fehlte eine deterministische
Wiederverwendung, und 54 nicht selektierte `NOT_EXECUTED`-Records blockierten
den Gesamtstatus. Unabhängig davon fehlten für 57 selektierte Pflicht-Claims
eigene Ausführungen oder ausführbare Basiscases.

## Betroffene Komponenten und Sicherheitsgrenzen

Betroffen sind Framework-Katalog, No-CRS-Selector/Finalizer/Validator, drei
Case-Fixtures, Tests und die zweisprachige Testdokumentation. Die Grenze ist
die Integrität kanonischer Claims: Weder deklarierte Fähigkeiten noch nicht
selektierte Records dürfen Runtime-PASS erzeugen. Parent-Host-Dispatch und
MRTS bleiben unverändert.

## Akzeptanzkriterien

- Fehlende Voraussetzungen verletzen den Katalogvertrag; H1 schließt reine
  H2/H3-Claims aus.
- Explizite Wiederverwendung verlangt eine validierte echte Basisidentität
  und, falls nötig, ein eindeutig passendes kanonisches Event; negative
  Abweichungen bleiben unerfüllt.
- Nur tatsächlich nicht selektierte `NOT_EXECUTED`-Records werden beim
  Gesamtstatus ignoriert; fehlende selektierte Fälle, globale FAIL/BLOCKED
  und Exit 77 verhindern PASS weiterhin.
- Jeder verbleibende selektierte Pflichtfall braucht vor einem Exact-Head-PASS
  einen echten Ausführungspfad und Host-Evidenz.

## Untersuchte Alternativen

Die 57 nicht angesetzten Verpflichtungen als optional umzuklassifizieren,
Events zu synthetisieren oder Status-/Protokollvalidatoren zu lockern, wurde
verworfen. Der Benutzer verlangt echte Runner und Requests. Drei gezielte
Fixtures prüfen einen echten Lowercase-Header-Deny, eine Phase-1-Regelkette
für zwei Header und einen eigenen Request mit generierter Transaction-ID.
Event-gestützte Claims verlangen zusätzlich zum HTTP-Status passende echte
Runtime-Metadaten.

## Implementierungsentscheidung

Der Katalog deklariert Szenario-Voraussetzungen und zwei eigenständige
ausführbare Header-Fixtures. Der Multiple-Header-Case verlangt `event_jsonl`,
einen eindeutigen Regeltreffer und native Event-Identität; ein reiner
Audit-Fallback wird vom Full-Lifecycle-Validator abgelehnt.
NGINX-`full_lifecycle`-`select` und `init` verlangen dasselbe deklarierte
Downstream-Protokoll. Fünf explizite
Wiederverwendungen und ein bestehender Alias sind an eine validierte Basis
des aktuellen Laufs gebunden; sie bedeuten keinen neuen Request. Finalizer
und Validator leiten die Auswahl erneut aus Katalog und Capability-Inventar
ab. Der Gesamtstatus nutzt selektierte Fälle, erhält alle Record-Zähler und
bewahrt das Verhalten der alten unscoped API. Eine spätere Regression zeigte
die Akzeptanz von Events mit fremder Run-ID oder falscher Phase bei einfachen
Cases. Normalisierung, Manifest-Bindung und Vollständigkeitsprüfung lehnen
diese Abweichungen jetzt ab. Native Events dürfen ihre optionale Run-ID gemäß
dem bestehenden Vertrag für runlokale Quelldatei- und Transaktionsprovenienz
weglassen.

## Geänderte Dateien und Tests

`tests/cases/no-crs-baseline/catalog.json`,
`tests/cases/no-crs-baseline/case_insensitive_header_name.yaml`,
`tests/cases/no-crs-baseline/multiple_headers.yaml`,
`tests/cases/no-crs-baseline/transaction_id_generated_or_fallback.yaml` und
`ci/checks/catalog/no_crs_baseline.py` tragen die Änderungen. Die öffentliche
Ressource `modsecurity_test_framework/data/framework-contract-catalog.json`
wurde aus eingecheckten Quellen neu generiert; ihr exakter Inventartest unter
`tests/contract_api/` wurde angepasst. Fokustests unter `tests/no_crs/`
prüfen Voraussetzungen, Protokollprofile, exakte
Wiederverwendung und Gegenproben, ausgewählte Statusbereiche/Manipulationen,
Runner-Verarbeitung sowie Audit-only-/Ohne-Event-Gegenproben für den
Multiple-Header-Runner, generierte Transaktionsidentität und Gegenproben mit
explizit fremder Event-Run-ID oder falscher Phase.
`tests/no_crs/test_no_crs_baseline.py`
aktualisiert das exakte Runner-Inventar.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `make test-no-crs-contract` mit externem Build-Root | 0 | 130 Tests nach dem Event-Bindungs-Fix bestanden | Lokaler Framework-Worktree |
| `make test-contract-api` mit bestehender Framework-venv | 0 | Generierter Katalogcheck und 20 API-Tests bestanden | Lokaler Framework-Worktree |
| `make check-documentation` | 0 | Links, zweisprachige Variablen, Repository-Pfade und Change Records bestanden | Lokaler Framework-Worktree |
| Fokussierte Unit Tests für Voraussetzungen, Protokoll, Wiederverwendung, Status und Runner | 0 | Positive und negative Fälle nach Rot-Grün-Prüfung bestanden | Lokaler Framework-Worktree |
| `python3 ci/checks/catalog/no_crs_baseline.py catalog-check` | 0 | 166 Katalogfälle bestanden | Lokaler Framework-Worktree |
| Lesende Exact-Reuse-Probe mit aufbewahrten kanonischen Artefakten | 0 | Sechs Ableitungen passend; kein neuer E2E-Lauf | Aufbewahrter Lauf `20260930T164146Z` |
| NGINX-H1-Preflight für selektierte Runner | 1 | Erwartet rot: Nach drei neuen Fixtures fehlen noch 54 Pflicht-Ausführungspfade | Task-eigene externe Analyse |
| `make lint` mit System-Python | 2 | PyYAML fehlt im System-Interpreter; kein Source-Lint-Ergebnis | Lokaler Framework-Worktree |
| Erster `make lint` mit bestehender Framework-venv | 2 | Security-/Provenance-Tests bestanden; der generierte Contract-Katalog war veraltet und wurde inzwischen neu erzeugt | Lokaler Framework-Worktree |
| Vollständiges `make lint` mit bestehender Framework-venv, vor der zweiten Fixture | 0 | Breite Lint-, Security-/Provenance-, Contract-API-, Katalog- und Dokumentationsprüfungen bestanden | Lokaler Framework-Worktree |
| `make lint` mit bestehender Framework-venv und explizitem Worktree-Root, vor der dritten Fixture | 0 | Gesamtsuite, kanonischer Pin-Abgleich, Katalog-, Security- und Dokumentationsprüfungen nach der zweiten Fixture bestanden | Lokaler Framework-Worktree |
| Finaler `make lint` nach dritter Fixture und Event-Bindungs-Fix | 0 | Gesamtsuite am Source-Commit `8c11a24d0c74570e817bacae2374e9323b2532dd`, einschließlich Katalog-, Security-/Provenance- und Dokumentationsprüfungen | Lokaler Framework-Worktree |
| Zwei isolierte NGINX-Case-Host-Proben | jeweils 0 | Echte HTTP 403/200, Root-Master/nobody-Worker, erwartete Audit-Regeln; nur Diagnose, kein kanonischer PASS | `nginx-case_insensitive_header_name-PIeMWckO`, `nginx-multiple_headers-wcDcPOJy` |
| Drei isolierte Case-Proben mit vorhandenem nativen Lifecycle-Sink | jeweils 0 | HTTP 403/200/200 und echte native Events für Regeln 1100001/1100501/1100502; unveränderter Parent-Collector erzeugte passende Source-Beobachtungen | `nginx-case_insensitive_header_name-gnW0pwi3`, `nginx-multiple_headers-Hn1AlFLy`, `nginx-transaction_id_generated_or_fallback-ekML06xT` |
| Event-Identitätsregression, zunächst rot und dann behoben | 1 → 0 | Zehn Gegenproben mit fremdem Run/falscher Phase zunächst fehlgeschlagen; fünf Testmethoden jetzt grün, einschließlich fehlender Source-Identität und kompatibler Phasenlabels | Lokaler Framework-Worktree |
| `git diff --check` | 0 | Keine Whitespace-Fehler im verfolgten Diff | Lokaler Framework-Worktree |

## Sicherheitsauswirkung

Dies ist eine Härtung der Evidenzintegrität, keine deklarierte
Schwachstellenbehebung. Manipulierte Plan-Status werden durch semantische
Neuauswahl abgelehnt; ein fehlender selektierter Fall oder fremde
Reuse-Identität kann nicht zu PASS werden. Audit-only-Fallback und fehlendes
Event beim neuen Runner bleiben FAIL. Event-gestützte Claims lehnen explizit
fremde Runs und abweichende Katalog-Phasen auch bei finaler Manifest-Bindung
und Validierung gespeicherter Resultate erneut ab. Das deklarierte Protokoll muss im
Parent noch an beobachteten Host-Traffic gebunden werden.

## Dokumentation und Runtime-Evidenz

`docs/testing-and-evidence.md` und `.de.md` erklären Protokollbereich,
selektierten Statusbereich, begrenzte Wiederverwendung und
Event-Identitätsprüfungen. Erste isolierte Proben beobachteten Audit-Regeln
ohne generischen nativen Sink. Die Wiederholung aller drei neuen Cases mit
dem vorhandenen Lifecycle-Sink `location_if_missing` erzeugte echte native
Events; der unveränderte Parent-Collector las diese Events ein. Diese
Diagnoseläufe bilden keinen kanonischen Full-Lifecycle oder Exact-Head-E2E.
Aufbewahrte Events wurden nur lesend für die Ableitungsprobe genutzt.

## Nicht ausgeführte Prüfungen

Kein neuer Root-zu-nobody-Full-Lifecycle oder Exact-Head-E2E wurde ausgeführt:
Das Pflicht-Runner-Coverage-Gate ist rot. Parent-Gitlink-Aktualisierung,
integrierte Parent-Fokussuite gegen diesen neuen Pin, kanonisches PASS und
SHA256SUMS stehen aus. Eine separate uncommittete Parent-Aufrufkorrektur
bestand einen echten Framework-Select/Init-Preflight ohne Hoststart.
Der finale vollständige Framework-Lintlauf nach dritter Fixture und
Event-Bindungs-Fix bestand mit Exit 0.

## Einschränkungen und Restrisiko

Für 54 selektierte H1-Verpflichtungen fehlen echte Pfade (52 direkte
Szenarien und zwei abhängige Ableitungen). Einige benötigen
Parent-Host-Driver-Fähigkeiten oder zusätzliche Producer-Metadaten; ein
generisches Überspringen im Parent-Dispatch ist nicht nachgewiesen.
Die Codeprüfung zeigte zudem festes Reject im NGINX-Response-Body-Planner,
während ein selektierter Case ProcessPartial verlangt. Für diese verbleibenden
Szenarien wird weder frischer Runtime-Nachweis noch Producer-Korrektur behauptet.
Der vorhandene Sink erzeugte für alle
drei neuen einfachen Cases native Events bei Lifecycle-Konfiguration. Zudem
ist ein separater Parent-Harness-Evidenzpfadfehler sichtbar: Case-Resultate
benennen ein Audit unter privaten Case-Logs, das validierte Audit liegt aber
unter Worker-Server-Logs. Ein Parent-Fix ist nicht enthalten. Die H2/H3-Auswahl
bleibt bis zur Bindung an tatsächlichen Traffic ein deklariertes Laufprofil.

## Finaler Diff- und Review-Status

Task-eigener Worktree-Diff und Whitespace wurden geprüft; keine Secrets oder
fremden Source-Änderungen beobachtet. Unabhängige lokale Framework-Commits
erhalten die getrennten Ursachen und die spätere Event-Bindungskorrektur.
Parent-Gitlink-Delivery bleibt wegen des roten
Pflicht-Ausführungsgates zurückgestellt.
