# Migration der erforderlichen NGINX-Konfigurationstests

Drei bestehende Required-Case-IDs bleiben erforderlich und erhalten einen
expliziten nativen Konfigurationsaufruf. `invalid_status` prüft die bestehende
Ablehnung von `status:not-a-number` durch den Engine-Parser. Die beiden
Scope-Datei-Cases prüfen die Ablehnung der entfernten API
`modsecurity_phase4_content_types_file` mit ihren tatsächlichen, kontrollierten
Source-Fixtures. Sie behaupten weder eine erfundene MIME-Ablehnung der Engine
noch einen ausgeführten HTTP-Request.

Der kanonische Reader verlangt exakte Fixture-Bytes, private reguläre Dateien
mit einem Link, exakte Konfigurations- und Diagnosepfade, beobachteten Exit 1,
aufbewahrte Binary-/Modul-/Config-/Stdout-/Stderr-Prüfsummen sowie passende
Run-/Source-Identitäten. Fehlende, ersetzte oder fremde Artefakte, neu gehashte
falsche Fixtures und die Verwendung einer Receipt für HTTP-Cases bleiben Fehler.

Validierung: 14 Unit-Tests für Migration, Wiring und bestehende Config-Receipts
bestanden im Integrations-Worktree. Drei frühere echte Configtests bestanden
ihre einzelnen strikten kanonischen Prüfungen mit ausdrücklich älterer
Build-Provenienz. Dies ist kein frischer integrierter Exact-Head-E2E-Nachweis.
Alle 97 selektierten Required-IDs bleiben erforderlich; abschließende Runtime,
vollständige Suites und aktuelle Remote-Qualitätsprüfungen stehen noch aus.
