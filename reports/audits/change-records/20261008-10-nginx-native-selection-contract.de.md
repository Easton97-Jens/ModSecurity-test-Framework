# Änderungsnachweis

**Sprache:** Deutsch | [English](20261008-10-nginx-native-selection-contract.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change ID | 20261008-10-nginx-native-selection-contract |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | `d86894602079f4f3b5b42e076c464756c1b9031d` |

## Motivation und Problemstellung

Der Capability-Auswahlplan verwarf bisher die 42 nativen Operationsregistrierungen. Eine Eingabeinvariante muss außerdem 31 bestehende authentische Executor- oder engere Ableitungsverträge darstellen; erfundene Runner-Dateien würden diese falsch beschreiben.

## Betroffene Komponenten und Sicherheitsgrenzen

Nur Framework-Auswahlhelper, select_catalog_case/select_cases und neue fokussierte Kontrollen. Normalisierung, Ereignisprüfung, Ableitungsimplementierungen, Schemas und Katalog bleiben in diesem Slice unverändert. Parent-Ausführung und Collector sind read-only Abhängigkeiten. MRTS und Parent-Gitlink bleiben unverändert.

## Akzeptanzkriterien

Die tatsächlichen 97 ausgewählten NGX/H1-IDs und Zustände erhalten, unabhängige Kopien nativer/config/abgeleiteter Eingaben projizieren, fallübergreifende Änderungen und fehlende reale Quellen ablehnen, C-Quellaliasnamen sowie den vollständigen unveränderlichen Planvergleich erhalten. Fehlende Required-Fälle niemals herausfiltern oder aus Dispatch-Eingaben Runtime-PASS ableiten.

## Untersuchte Alternativen

Eine reine runner_case-Pflicht lehnt legitime native/config/abgeleitete Operationen ab. Freie request.reuses-Ableitung erlaubt undeklarierte Substitutionen und Zyklen. Geschlossene funktionsgebundene Deskriptoren beschreiben den vorhandenen Ausführungsgraphen ohne Requests oder Beobachtungen zu erzeugen.

## Implementierungsentscheidung

native_invocation_for_case prüft vor der NGX-Projektion das eingecheckte geschlossene Fallschema. selected_case_invocation_errors verlangt für ausgewählte NGX-Fälle passende native/config/runner/abgeleitete Eingaben. YAML-Alternativen müssen reguläre kataloglokale YAML-Dateien sein. Ein tatsächlicher manifestdeklarierter NGX-full_lifecycle-Plan erzwingt die Invariante per ContractError statt reduziertem Plan.

Reine Capability-Dictionaries bleiben beratende Planungsinputs der API; sie scheitern an der Runtime-Manifestprüfung. Kanonische select/init/finalize laden validierte Manifeste mit verpflichtendem Connector und vergleichen frische vollständige Auswahlsemantik. Fehlende Metadaten umgehen daher die reale Runtime-Plangrenze nicht. Beratende H2/H3-Claims bleiben sichtbar; es entsteht keine Runtime-Promotion.

Die 31 derived_invocation-Deskriptoren enthalten nur operation, source_case_ids und mapping. Geprüfte Phase-, Request-, Regel-, Status-, Ergebnis- und Alias-Eingaben sind geschlossen; generische reuses reichen nicht. Wiederverwendungszyklen scheitern. Direkte Host-/Selbst-IDs bezeichnen Executor-Blätter, keine Ableitungszyklen. Native/config/abgeleitete Dictionaries werden tief kopiert.

## Geänderte Dateien und Tests

Nur Core-Auswahlhelper und zwei geschlossene Konstantentabellen; neue test_nginx_native_selection.py; Begleitnachweis. plan_semantics benötigt keine Änderung, da vollständige Falldictionaries bereits erhalten bleiben.

| Bestehende Grenze | Ausgewählte Verträge | Tatsächliche Zuordnung |
| --- | --- | --- |
| Dedizierte Parent-SAFE/STRICT-Fixtures | Core-Log-only und Abort nach Commit (2) | run_nginx_smoke.sh append_selected_phase4_fixtures; bestehende connectorspezifische YAML-Namen entsprechen kanonischen IDs |
| Synchronisierte Parent-Barriere | First-byte und No-full-buffer (2) | run-native-first-byte.sh und write-first-byte-source-results.py:main; tatsächliche real_host-Barriere und Regel1100301 |
| Strikter Parent-Core-Alias | P3-Response-Header-Core und P4-SAFE-Sicht (2) | collect-no-crs-source.py native_runner_core_case_alias; exakte Rohereignissemantik, niemals bloßer Status |
| Framework-Ereignisclaims | fünf Phase1-Metadatenfelder und Phase2-No-payload (6) | append_derived_event_records; validierte Quellfälle und tatsächlich passende Ereignisse |
| Engere Framework-P4-Fakten | beobachtete Regel, Status- und Aktionsmetadaten (3) | append_derived_phase4_records; exakt fünf bestehende zulässige Basis-IDs, keine umgekehrte Ableitung disruptiver Ergebnisse |
| Explizite Framework-Wiederverwendung | Allow, Deny, P3-Status, Response-No-payload, Strict-Abort-Sicht (5) | append_explicit_reuse_records; gebundener Quellrequest/TX/Run/Modus und Ereignis |
| Veraltete Framework-Sichten | Phase1 fünf, Phase2 zwei, Phase3 eins, Phase4 drei (11) | resolve_deprecated_aliases; exakte bestehende kanonische Ziel-IDs |

## Befehle und Ergebnisse

Anfängliche Projektions-/Invariantenkontrollen scheiterten erwartungsgemäß; separate Ableitungshelper-Kontrollen zeigten zwei fehlende Helper. Nun bestehen zwölf fokussierte Kontrollen. Bestehende Protokollplanung (4) und Selected-scope-Tests (9) bestehen. Der erste breite Lauf mit 217 Tests hatte fünf Fehler synthetischer Capability-Pläne; die Trennung beratender Planung und validierter nativer Ausführung behebt die betroffenen Tests. Der abschließende breite Lauf bestand alle 222 Tests. Catalog-check erhielt 166 Fälle; Dokumentationslinks, zweisprachige Variablendokumentation, Change-Record- und Diff-Prüfungen bestanden.

Die frische reine Quellberechnung mit dem tatsächlichen Parent-Capability-Manifest erhält 97 ausgewählte Fälle: 42 native und 31 bestehende abgeleitete Deskriptoren. Genau drei Null-Eingaben bleiben im eigenständigen Checkout: invalid_status, phase4_invalid_scope_file und phase4_wildcard_scope_rejected. Deren authentische Config-Migrationen bestehen bereits im Koordinator-Checkout und werden hier weder verändert noch ersetzt.

## Sicherheitsauswirkung

Keine erfundenen nativen Beobachtungen, generischen Erwartungsänderungen, Required-Reduktion, erfundene YAML, implizite Alias-Erkennung oder abgeschwächte Normalisierung. Native/abgeleitete Änderungen beeinflussen den unveränderlichen Planvergleich. Runtime-Evidenz bleibt eine unabhängige verpflichtende Grenze.

## Dokumentation und Runtime-Evidenz

Deskriptoren bezeichnen ausschließlich Eingaben und bestehende Evidenzkonsumenten. Die Prüfung las den tatsächlichen Parent-Collector, native Fixture-Auswahl und synchronisierten Writer sowie Framework-Ereignis-/P4-/Reuse-/Deprecated-Implementierungen. Keine neue native Ausführung.

## Nicht ausgeführte Prüfungen

Integrierter vollständiger ausführbarer 97-Fälle-Plan nach Config3-Integration des Koordinators, nativer Build/Runtime und abschließende CI/Sonar bleiben beim Koordinator.

## Einschränkungen und Restrisiko

Der eigenständige vollständige native Plan wirft für die drei nicht integrierten Config-Verträge absichtlich einen Fehler. Quellauswahl belegt keine notwendigen Ereignis-/TX-/Runtime-Fakten der Ableitung. Die unveränderten kanonischen Prüfer müssen diese weiterhin erzwingen.

## Finaler Diff- und Review-Status

Nur fokussierte Auswahl im eigenen Worktree; keine Normalisierungs-/Ereignis-/Ableitungsimplementierungsänderung, Root-Worktree-Mutation, Veröffentlichung, Parent-Gitlink-Aktualisierung oder MRTS-Änderung.
