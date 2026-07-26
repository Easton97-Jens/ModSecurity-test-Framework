# Change Record: MRTS aus Framework-Dokumentations-Link-Checks ausschließen

**Language:** Deutsch | [English](20260726-04-exclude-mrts-from-documentation-link-checks.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260726-04-exclude-mrts-from-documentation-link-checks` |
| UTC-Datum | 2026-07-26 |
| Framework-Basisrevision | `de705a5efb872f95f010346fe2e6143c88876ad4` |
| Issue oder Pull Request | Draft-Framework-PR [#52](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/52) vom Task-Branch `agent/remediate-active-framework-findings-20260726`; kein Merge ist autorisiert. |

## Motivation und Problemstellung

`FND-FRAMEWORK-0010` verlangt, dass das Framework-Dokumentationsaggregat
beweist, niemals das unabhängig besessene MRTS-Submodul zu traversieren. Die
Variablen- und Repository-Pfad-Checks besitzen bereits explizite
`tools/MRTS/`-Ausschlüsse, der Markdown-Link-Checker beruhte bisher jedoch auf
der aktuellen Auslassung von Submodul-Inhalten durch Git. Dieses implizite
Verhalten bot keine direkte Grenzkontrolle, falls ein künftiges Inventar einen
verschachtelten Markdown-Pfad meldet.

## Betroffene Komponenten und Sicherheitsgrenzen

- `ci/checks/documentation/check-doc-links.py` besitzt das Framework-
  Markdown-Inventar für die Prüfung lokaler Links.
- `tools/MRTS` bleibt ein separat besessenes, schreibgeschütztes Submodul. Es
  ist keine Framework-Dokumentation und wird hier weder geparst, validiert
  noch geändert.
- Die Kontrolle begrenzt ausschließlich die Framework-Traversierung; sie
  unterdrückt keine Prüfung getrackter Framework-Markdown-Dateien außerhalb
  der MRTS-Grenze.
- Parent-Quellen und Gitlink, der Framework-zu-MRTS-Gitlink und MRTS-Quellen
  bleiben unverändert.

## Akzeptanzkriterien

- Ein `tools/MRTS/...`-Pfad wird ignoriert, auch wenn das Markdown-Inventar
  ihn explizit meldet.
- Ein getrackter Framework-Markdown-Pfad wird weiterhin vom selben Inventar
  ausgewählt.
- Die fokussierte Regression, das vollständige Framework-
  Dokumentationsaggregat und die Change-Record-Validierung bestehen.
- Keine MRTS-Datei wird von der Regression jenseits ihres task-eigenen
  synthetischen Fixtures gelesen; weder produktive MRTS-Quellen noch Gitlink
  ändern sich.

## Untersuchte Alternativen

- Ausschließlich auf das gegenwärtige Submodul-Verhalten von `git ls-files` zu
  vertrauen, wurde verworfen, da es eine implizite und ungetestete Grenze ist.
- MRTS-Dokumentation rekursiv zu validieren, wurde verworfen, da dies die
  Repository-Eigentumsgrenze überschreitet und MRTS-Inhalte als Framework-
  Dokumentation behandeln würde.
- Die Markdown-Link-Validierung breit zu deaktivieren, wurde verworfen, weil
  Framework-Dokumentation weiterhin abgedeckt sein muss.

## Implementierungsentscheidung

Die Menge der ausgeschlossenen Verzeichnisse des Markdown-Link-Checkers
enthält jetzt explizit `tools/MRTS`. Eine fokussierte Regression liefert ein
synthetisches Git-Inventar mit einem Framework-Guide und einer absichtlich
fehlerhaften MRTS-Markdown-Datei. Sie beweist, dass nur der Framework-Guide
zurückgegeben wird; damit kann das Aggregat das Submodul nicht erreichen,
selbst wenn das Inventar unerwartet erweitert wird.

## Geänderte Dateien und Tests

- `ci/checks/documentation/check-doc-links.py`: expliziter Ausschluss des
  MRTS-Submoduls aus dem Markdown-Inventar.
- `tests/security_regression/test_parser_hardening.py`: direkte Regression für
  ein Inventar mit einem Framework-Dokument und einem MRTS-Pfad.
- Dieser gepaarte englische/deutsche Change Record.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zugelassener Evidenzpfad |
| --- | --- | --- | --- |
| Fokussierte Parser-/Dokumentationsregression | 0 | Elf Tests bestanden, einschließlich des expliziten MRTS-Inventar-Ausschlusses. | Lokale Validierung im Task-Worktree |
| `make check-documentation` auf dem Kandidaten | 0 | Link-, zweisprachige, Pfadreferenz- und Change-Record-Checks bestanden; das Aggregat behielt die MRTS-Submodul-Ausnahme bei. | Lokale Validierung im Task-Worktree |
| `make lint` | 0 | Framework-Syntax, Verträge, Regressionen, Dokumentation und Diff-Checks wurden auf dem Kandidaten abgeschlossen. | Lokale Validierung im Task-Worktree |

## Sicherheitsauswirkung

Dies ist eine Härtung der Eigentums- und Traversierungsgrenze. Sie verhindert,
dass ein Dokument eines unabhängigen Submoduls das Framework-
Dokumentationsergebnis beeinflusst oder den Framework-Checker unbesessenen
Markdown lesen lässt. Sie schwächt weder die Framework-Link-Validierung noch
Workflow-Sicherheit, Provenance-Kontrollen oder Scanner.

## Dokumentation und Runtime-Evidenz

Das Verhalten ist eine statische Kontrolle des Dokumentationsinventars und
behauptet keine Connector-Runtime. Die Regression verwendet nur ein
task-eigenes temporäres Fixture und ein gemocktes Git-Inventar; sie inspiziert
oder führt keine MRTS-Inhalte aus.

## Nicht ausgeführte Prüfungen

- Native Apache-Lifecycle- und NGINX-H2-Ausführung bleiben wegen fehlender
  Host-Tools blockiert und werden nicht durch diese statische
  Dokumentationskontrolle ersetzt.
- Der externe Codex-Security-Rank-Input-Helper ist keine Framework-Quelle, und
  in dieser Task-Umgebung ist keine Codex-Cloud-Scan/Finding-Schnittstelle
  verfügbar.
- Hosted Exact-Head-PR-Checks sind ausstehend, bis der Draft-PR existiert.

## Einschränkungen und Restrisiko

Diese Änderung erzeugt weder die für `FND-FRAMEWORK-0007` oder
`FND-FRAMEWORK-0009` erforderliche native Evidenz noch repariert sie den
External-Plugin-Scope von `FND-FRAMEWORK-0025` oder ersetzt GitHub-Ergebnisse
durch Codex-Cloud-Evidenz für `FND-FRAMEWORK-0029`. Auf aktualisiertem Master
besitzen FND-FRAMEWORK-0013, 0018, 0019, 0031, 0036, 0054 und 0057 bereits ihre
jeweiligen bestehenden Source-Kontrollen; dieser PR dupliziert oder schwächt
sie bewusst nicht.

## Finaler Diff- und Review-Status

Der finale Diff beschränkt sich auf die explizite Framework-
Dokumentationsgrenze, ihre fokussierte Regression und diesen erforderlichen
gepaarten Record. Parent, beide Gitlinks und MRTS liegen außerhalb des Scopes.
Lokaler und Hosted-Finalreview-Status werden vom exakt gepushten Draft-PR-Head
erfasst; kein Merge ist autorisiert.
