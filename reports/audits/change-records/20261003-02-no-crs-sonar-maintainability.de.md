# Change Record: No-CRS-Sonar-Wartbarkeit

**Sprache:** [English](20261003-02-no-crs-sonar-maintainability.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20261003-02-no-crs-sonar-maintainability` |
| UTC-Datum | `2026-10-03` |
| Framework-Basisrevision | `b9b9534b7e0b15edad31393699ebd0617748148d` |
| Issue oder Pull Request | Framework-PR #135; externer Parent-PR #396 bleibt Draft |

## Motivation und Problemstellung

Die aktuelle Sonar-Analyse von Framework-PR #135 bestand das Quality Gate,
behielt aber 28 offene Wartbarkeitshinweise: vier `python:S3776`, siebzehn
`python:S9073`, drei `python:S1192`, zwei `python:S5713`, einen
`python:S8714` und einen `python:S5778`. Dies ist nicht die unabhängige
historische Parent-PR #135. Ein bestandenes Gate bedeutet nicht Issue-Freiheit.

## Betroffene Komponenten und Sicherheitsgrenzen

`ci/checks/catalog/no_crs_baseline.py` und die dreizehn betroffenen
`tests/no_crs`-Module gehören dem Framework. Selection, Evidence-Matching,
Statusvorrang, Descriptor-gestützte Artefaktautorität und Receipt-Validierung
müssen unverändert bleiben. MRTS bleibt unverändert. Ein späteres Parent-
Gitlink-Update ist eine separat autorisierte Parent-Operation, keine
Framework-Sourceänderung.

## Akzeptanzkriterien

Echte Codeursachen ohne Suppressionen, Exclusions, Regeländerungen,
synthetische Runtime-Evidence oder verkleinerte Required-Auswahl entfernen.
Geordnete Fehlermeldungen, exakte Run-/Case-/Rule-/Phase-Identitäten, echte
aufbewahrte Bytes und Grenzen, geschlossene Config-Templates, No-Follow-
Admission, Cleanup und explizite Wiederverwendung erhalten. Fokus- und native
Framework-Gates sowie frisches Remote-Readback des exakten Heads verlangen.

## Untersuchte Alternativen

Validator-Abschwächung oder geänderte Sonar-Einstellungen würden die Ursachen
nicht beheben. Eine neue generische Validierungsabstraktion würde den Vertrag
unnötig erweitern. Kleine Helper-Extraktionen, Dateinamenkonstanten im vorhandenen
Stil und eng begrenzte Test-Assertion-/Exception-Hygiene nutzen.

## Implementierungsentscheidung

Die unveränderten Blattnamen `nginx.conf`, `stdout.log` und `stderr.log` in
Konstanten zentralisieren. Nach Ursachen getrennte Commits behandeln
Testdiagnostik und redundante Exception-Unterklassen. Acht eng begrenzte Helper
aus den vier komplexen Funktionen extrahieren; ursprüngliche Signaturen,
Validierungsreihenfolge, Descriptor-Ownership und explizite Evidence-Reuse-
Bedingungen erhalten. Katalog, Schema, Runner-Case, Capability, öffentlicher Vertrag und
Runtime-Verhalten werden nicht absichtlich geändert.

## Geänderte Dateien und Tests

Die genannte Produktdatei, die dreizehn durch Sonar identifizierten Testmodule,
dieses Record-Paar und der gepaarte Archivindex. Tests behalten geordnete
Spec-/Loader-Prüfungen; der Exception-Test bereitet Collaborators vor der einen
werfenden Invocation vor; der positive FIFO-Test behält sein Timeout und
scheitert bei einer unerwarteten Exception unmittelbar.

## Befehle und Ergebnisse

Portable Befehlsabkürzungen bezeichnen die ausgeführten Bindings aus
`A/framework-pr135-sonar-plan.md`: `A` ist das freigegebene externe
Analyseverzeichnis, `FW` der Framework-Task-Worktree, `PY` der Framework-eigene
Interpreter, `P` der separate Parent-Integrations-Worktree und `N` / `L` die
externen Buildverzeichnisse `framework-pr135-sonar-final` /
`framework-pr135-sonar-lint`. Maschinenspezifische absolute Pfade gehören in
dieses externe Record, nicht in dieses versionierte Dokument.
Alle argv und Flags bleiben unten erhalten.

Befehle laufen aus `FW`; Python nutzt `PYTHONNOUSERSITE=1` und
`PYTHONDONTWRITEBYTECODE=1`. Die unveränderte b9-Baseline bestand vor Änderungen
166 Tests (`A/framework-pr135-sonar-baseline-no-crs.log`). Zwischenprüfungen
bestanden 65 betroffene Tests und 25 Config-Tests; Befehle und Umfang stehen
in `A/framework-pr135-test-hygiene-result.md` und
`A/framework-pr135-product-result.md`.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk proxy env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 "$PY" -B "$A/framework-pr135-test-sonar-controls.py" --baseline` / derselbe Befehl ohne `--baseline` | 1 / 0 | Baseline 0/19, korrigierte Tests 19/19 | `A/framework-pr135-test-hygiene-source-red.log` / `A/framework-pr135-test-hygiene-source-green.log` |
| `rtk proxy env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$N/tmp" timeout 300 make test-no-crs-contract PYTHON="$PY" BUILD_ROOT="$N" TMP_ROOT="$N/tmp"` | 0 | 166 Tests bestehen, keine Skips | `A/framework-pr135-sonar-final-no-crs.log` / `.exit` |
| `rtk proxy env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$A" "$PY" -B "$A/framework-pr135-product-parity.py" "$FW"` | 0 | 2.081 Vergleiche nach allen Extraktionen stimmen überein | `A/framework-pr135-product-parity.log` |
| `rtk proxy env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$A" "$PY" -B -m unittest -v tests.no_crs.test_configtest_artifacts tests.no_crs.test_configtest_receipt tests.no_crs.test_configtest_runtime_facts tests.no_crs.test_configtest_size tests.no_crs.test_exact_reuse_mapping tests.no_crs.test_case_event_binding` | 0 | 41 Tests bestehen; Source-/Authority-Review ohne Regressionsblocker | `A/framework-pr135-independent-product-focus.log`; Review `A/framework-pr135-independent-product-review.md` |
| `rtk proxy timeout 600 env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$L/tmp" make lint PYTHON="$PY" BUILD_ROOT="$L" TMP_ROOT="$L/tmp"` | 124 | Budget nach 21 bestandenen ModSecurity-Provenance-Tests erschöpft; kein vollständiger Lint-PASS | `A/framework-pr135-sonar-final-lint.log` / `.exit` |
| `rtk proxy timeout 1800 env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$L/tmp" make lint PYTHON="$PY" BUILD_ROOT="$L" TMP_ROOT="$L/tmp"` | 2 | Geerbtes `FRAMEWORK_ROOT` zeigt auf anderen Checkout; Exact-Root-Guard verweigert dies korrekt | `A/framework-pr135-sonar-final-lint-retry.log` / `.exit` |
| Root-gebundenes natives Target-Preflight, exakter Aufruf in `A/framework-pr135-sonar-plan.md` | 2 | 94 Unit-Prüfungen bestehen; Dokumentation verweigert maschinenspezifische absolute Pfade, in diesem Paar ohne Checkeränderung korrigiert | `A/framework-pr135-sonar-root-preflight.log` / `.exit` |
| `rtk proxy timeout 3600 env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$L/tmp" make lint PYTHON="$PY" CI_ROOT="$FW/ci" FRAMEWORK_ROOT="$FW" CONNECTOR_ROOT="$P" OUTPUT_ROOT="$FW" BUILD_ROOT="$L" TMP_ROOT="$L/tmp"` | 0 | Vollständiges natives Lint mit expliziten Exact-Worktree-Roots und unveränderten Gates besteht, einschließlich API-, Workflow-, Katalog-, Dokumentations- und Diff-Prüfungen | `A/framework-pr135-sonar-final-lint-root-bound.log` / `.exit` |
| `rtk proxy git diff --check` | 0 | Whitespace geprüft | Framework-Task-Worktree |

Dies sind Source-/Unit-Prüfungen, keine Connector-Promotion oder Runtime-
Zertifizierung. Vollständiges natives Lint besteht nach expliziter Bindung der
Worktree-Roots; neue Remote-Analyse steht noch aus. Abgebrochene/verweigerte
Läufe bleiben erhalten. Auch die portable Record-Korrektur besteht sämtliche
nativen Dokumentationsgates.

## Sicherheitsauswirkung

Keine Sicherheitskontrolle wird gelockert und keine Runtime-Evidence erzeugt.
Die Wartbarkeitsarbeit erhält den vorhandenen Autoritäts-/Validierungsvertrag,
statt ihn zu reparieren oder zu erweitern. Descriptor-Lebensdauer, exaktes
Diagnose-Matching und selected-required Missing-Evidence bleiben verbindlich.

## Dokumentation und Runtime-Evidenz

Dieses EN/DE-Record-Paar und der Index dokumentieren den exakten Umfang.
Kein Connector-Lifecycle oder Full Exact-Head E2E wird in diesem Arbeitsschritt
gestartet. Alte Evidence wird nicht als neue Exact-Head-Evidence umetikettiert.

## Nicht ausgeführte Prüfungen

Full E2E ist ausdrücklich verboten. Remote-Prüfungen neu veröffentlichter
Commits stehen aus und dürfen vor echter Ausführung nicht behauptet werden.

## Einschränkungen und Restrisiko

Parity-Fixtures beweisen keine echte Hostausführung. Finale Sonar-Akzeptanz
benötigt den neu veröffentlichten exakten Framework-Head statt Baseline-Gate.
Framework-Delivery und Parent-Integration bleiben getrennt; keines ist ein Merge.

## Finaler Diff- und Review-Status

Der Dateinamenkonstanten-Schritt ist nach Einsetzen der unveränderten Werte für
das gesamte Modul AST-äquivalent. Ursprüngliche APIs und der Modul-AST außerhalb
der vier extrahierten Funktionen und ihrer acht Helper sind unverändert.
Unabhängiges Review, endliche Baseline-/Current-Parity-Kontrollen und finale
No-CRS-Tests und vollständiges natives Lint bestehen. Sonar/CI am neu
veröffentlichten SHA stehen noch aus. Secrets, generierte Runtime-Ergebnisse, MRTS-Änderungen
und Suppression-Konfiguration gehören nicht in diesen Change.
