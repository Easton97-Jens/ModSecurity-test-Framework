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

Betroffen sind Framework-Katalog, No-CRS-Selector/Finalizer/Validator, zwei
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
verworfen. Der Benutzer verlangt echte Runner und Requests. Zwei gezielte
Fixtures prüfen einen echten Lowercase-Header-Deny und eine Phase-1-Regelkette
für zwei Header; der HTTP-Status allein erzeugt keinen kanonischen PASS.

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
bewahrt das Verhalten der alten unscoped API.

## Geänderte Dateien und Tests

`tests/cases/no-crs-baseline/catalog.json`,
`tests/cases/no-crs-baseline/case_insensitive_header_name.yaml`,
`tests/cases/no-crs-baseline/multiple_headers.yaml` und
`ci/checks/catalog/no_crs_baseline.py` tragen die Änderungen. Die öffentliche
Ressource `modsecurity_test_framework/data/framework-contract-catalog.json`
wurde aus eingecheckten Quellen neu generiert; ihr exakter Inventartest unter
`tests/contract_api/` wurde angepasst. Fokustests unter `tests/no_crs/`
prüfen Voraussetzungen, Protokollprofile, exakte
Wiederverwendung und Gegenproben, ausgewählte Statusbereiche/Manipulationen,
Runner-Verarbeitung sowie Audit-only-/Ohne-Event-Gegenproben für den
Multiple-Header-Runner. `tests/no_crs/test_no_crs_baseline.py`
aktualisiert das exakte Runner-Inventar.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `make test-no-crs-contract` mit externem Build-Root | 0 | Vollständige No-CRS-Suite nach finalen Source-/Fixture-Änderungen bestanden | Lokaler Framework-Worktree |
| `make test-contract-api` mit bestehender Framework-venv | 0 | Generierter Katalogcheck und 20 API-Tests bestanden | Lokaler Framework-Worktree |
| `make check-documentation` | 0 | Links, zweisprachige Variablen, Repository-Pfade und Change Records bestanden | Lokaler Framework-Worktree |
| Fokussierte Unit Tests für Voraussetzungen, Protokoll, Wiederverwendung, Status und Runner | 0 | Positive und negative Fälle nach Rot-Grün-Prüfung bestanden | Lokaler Framework-Worktree |
| `python3 ci/checks/catalog/no_crs_baseline.py catalog-check` | 0 | 166 Katalogfälle bestanden | Lokaler Framework-Worktree |
| Lesende Exact-Reuse-Probe mit aufbewahrten kanonischen Artefakten | 0 | Sechs Ableitungen passend; kein neuer E2E-Lauf | Aufbewahrter Lauf `20260930T164146Z` |
| NGINX-H1-Preflight für selektierte Runner | 1 | Erwartet rot: Nach zwei neuen Fixtures fehlen noch 55 Pflicht-Ausführungspfade | Task-eigene externe Analyse |
| `make lint` mit System-Python | 2 | PyYAML fehlt im System-Interpreter; kein Source-Lint-Ergebnis | Lokaler Framework-Worktree |
| Erster `make lint` mit bestehender Framework-venv | 2 | Security-/Provenance-Tests bestanden; der generierte Contract-Katalog war veraltet und wurde inzwischen neu erzeugt | Lokaler Framework-Worktree |
| Vollständiges `make lint` mit bestehender Framework-venv, vor der zweiten Fixture | 0 | Breite Lint-, Security-/Provenance-, Contract-API-, Katalog- und Dokumentationsprüfungen bestanden | Lokaler Framework-Worktree |
| Finales `make lint` mit bestehender Framework-venv und explizitem Worktree-Root | 0 | Gesamtsuite, kanonischer Pin-Abgleich, Katalog-, Security- und Dokumentationsprüfungen nach der zweiten Fixture bestanden | Lokaler Framework-Worktree |
| Zwei isolierte NGINX-Case-Host-Proben | jeweils 0 | Echte HTTP 403/200, Root-Master/nobody-Worker, erwartete Audit-Regeln; nur Diagnose, kein kanonischer PASS | `nginx-case_insensitive_header_name-PIeMWckO`, `nginx-multiple_headers-wcDcPOJy` |
| `git diff --check` | 0 | Keine Whitespace-Fehler im verfolgten Diff | Lokaler Framework-Worktree |

## Sicherheitsauswirkung

Dies ist eine Härtung der Evidenzintegrität, keine deklarierte
Schwachstellenbehebung. Manipulierte Plan-Status werden durch semantische
Neuauswahl abgelehnt; ein fehlender selektierter Fall oder fremde
Reuse-Identität kann nicht zu PASS werden. Audit-only-Fallback und fehlendes
Event beim neuen Runner bleiben FAIL. Das deklarierte Protokoll muss im
Parent noch an beobachteten Host-Traffic gebunden werden.

## Dokumentation und Runtime-Evidenz

`docs/testing-and-evidence.md` und `.de.md` erklären Protokollbereich,
selektierten Statusbereich und begrenzte Wiederverwendung. Zwei isolierte
Root-zu-nobody-HTTP-Requests wurden mit passenden Audit-Regeln beobachtet;
sie waren aber kein kanonischer Full-Lifecycle-Lauf und erzeugten für diese
Änderung kein kanonisches Resultat. Aufbewahrte Events wurden nur lesend für
die Ableitungsprobe genutzt.

## Nicht ausgeführte Prüfungen

Kein neuer Root-zu-nobody-Full-Lifecycle oder Exact-Head-E2E wurde ausgeführt:
Das Pflicht-Runner-Coverage-Gate ist rot. Parent-Selection-Wiring,
Gitlink-Aktualisierung, Parent-Fokussuite, kanonisches PASS und SHA256SUMS
stehen aus. Ein finaler vollständiger Framework-Lintlauf mit bestehender
geprüfter venv nach der zweiten Fixture ist bestanden.

## Einschränkungen und Restrisiko

Für 55 selektierte H1-Verpflichtungen fehlen echte Pfade (53 direkte
Szenarien und zwei abhängige Ableitungen). Einige benötigen
Parent-Host-Driver-Fähigkeiten und möglicherweise zusätzliche
Connector-Event-Produktion; ein Parent-Dispatch-Defekt ist nicht belegt. Die
direkten Minimal-Host-Proben erzeugten kein natives kanonisches Event. Zudem
ist ein separater Parent-Harness-Evidenzpfadfehler sichtbar: Case-Resultate
benennen ein Audit unter privaten Case-Logs, das validierte Audit liegt aber
unter Worker-Server-Logs. Ein Parent-Fix ist nicht enthalten. Die H2/H3-Auswahl
bleibt bis zur Bindung an tatsächlichen Traffic ein deklariertes Laufprofil.

## Finaler Diff- und Review-Status

Task-eigener Worktree-Diff und Whitespace wurden geprüft; keine Secrets oder
fremden Source-Änderungen beobachtet. Sieben unabhängige lokale
Framework-Source-Commits liegen vor; diese zweisprachige Dokumentation ist
der achte Commit. Parent-Gitlink-Delivery bleibt wegen des roten
Pflicht-Ausführungsgates zurückgestellt.
