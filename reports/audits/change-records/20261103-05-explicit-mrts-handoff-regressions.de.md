# Change Record

**Sprache:** [English](20261103-05-explicit-mrts-handoff-regressions.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261103-05-explicit-mrts-handoff-regressions |
| UTC-Datum | 2026-11-03 |
| Framework-Basisrevision | 00de6d61122c85120c3a06e84e46906f87165744 |
| Issue oder Pull Request | Framework #167; Parent #443 |

## Motivation und Problemstellung

Die tatsächlich integrierte MRTS-Abhängigkeit erfordert eine ausdrücklich genehmigte verschachtelte Pinübergabe im Parent. Die bestehenden Framework-eigenen Regressionen decken diese eng begrenzte Parent-API-/CLI-Erweiterung ab.

## Betroffene Komponenten und Sicherheitsgrenzen

Nur die vorhandenen Updater-/Kandidatenvertrags-Testmodule, ihre nativen Inventar-/Archivbegleiter und dieses Dokumentpaar ändern sich. Parent-Quellen, gewöhnlicher Lock und geschützte Brokeridentitäten bleiben getrennte Zuständigkeiten.

## Akzeptanzkriterien

Explizites altes/neues Gitobjektpaar, Ablehnung ohne Schreibzugriff, unveränderte verschachtelte Defaultpolitik, Primary-/Staged-Rekonstruktion und unveränderliche Identitäten nachweisen. 100 Standardfälle, 80 Ausführungszeilen und sämtliche Offline-Ausnahmen erhalten.

## Untersuchte Alternativen

Eine alleinige Lockänderung würde den Herkunftsvertrag umgehen. Breite Fixture- oder Regellockerungen würden negative Kontrollen entfernen. Stattdessen die vorhandenen echten Gitobjekt-Fixtures erweitern.

## Implementierungsentscheidung

Temporäre echte Gitcommits mit alten/neuen festen MRTS-Gitlinks verwenden. Die Freigabe durch öffentliche APIs und kopierte CLIs führen. Drei anhand exakter Altobjekte belegte Fixtureannahmen eng korrigieren: zugelassene Inlinecaller-Syntax, Keywordweitergabe im Flock-Callback und konsistenter tatsächlicher Caller-SHA.

## Geänderte Dateien und Tests

`test_update_framework_versions.py` und `test_verify_framework_candidate_contract.py`: sieben neue On-Demand-Tests für gültige/idempotente Übergabe, strikte Defaults, fehlerhafte/fehlende Freigabe, falsche/fehlende Objekte oder Gitlinks, unehrlichen Altlock und Symlinkautorität. Vorhandene Publikations- und Flockprüfungen bleiben aktiv. Quellenbindungen/Archiv über den Maintenance-Koordinator regenerieren.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Beide vorhandenen Updater-/Kandidaten-Unittestmodule | 0 | 79 Tests bestanden, einschließlich sieben neuer Fälle | Integrationslauf 20261103T175654Z-integration; parent-mrts-handoff/final-regressions-green.log |
| Vier gezielte Fixture-Nachprüfungen | 0 | Korrigierte Kontexte bestehen; Altannahmen anhand exakter Gitobjekte belegt | parent-mrts-handoff/fixture-followup.log und fixture-baseline-provenance.json |
| Nativer Maintenance-Writer/-Checker, Inventar und Dokumentation | In PR-Belegen erfasst | Vor Veröffentlichung erforderlich | framework-handoff-checks/commands.json |

## Sicherheitsauswirkung

Keine Scanner-, Gate-, Quellen-/Pfadregel, Negativassertion oder geschützte Identität wird geschwächt. Die optionale ausdrückliche Freigabe wird gegen beide unveränderlichen Frameworkobjekte geprüft; ohne sie lehnt der Verifier den abweichenden MRTS-Pin weiterhin ab. Das unabhängige Quellen-/Trustreview fand keinen materiellen Fehler.

## Dokumentation und Runtime-Evidenz

Dieses EN/DE-Paar dokumentiert ausschließlich Regressionen und Metadaten. Es behauptet keinen Hostverkehr. Die 13 frischen H2/H3-Invokationen am Endpaar folgen der genehmigten Integrationsreihenfolge.

## Nicht ausgeführte Prüfungen

Lokale Sonar-Vorprüfung, Installation und Authentifizierungsreparatur bleiben ausgesetzt. Frische Hosted-Analyse folgt nach Veröffentlichung; Vollabnahme, Reset-/Multiplexkampagne und geschützte Dispatches bleiben außerhalb dieses Auftrags.

## Einschränkungen und Restrisiko

Der getrennte historische Migration-Map-Fehler ist unverändert und auf seiner ursprünglichen Basis unabhängig reproduziert. Diese Regressionen beheben ihn nicht und erklären ihn nicht für bestanden. Endpaar-Runtime und Master-CI benötigen eigene Nachweise.

## Finaler Diff- und Review-Status

Der stabile Quellen-/Testdiff wurde unabhängig geprüft. Finale native Metadaten-, Dokumentations-, Whitespace- und aktuelle PR-Head-CI-Belege werden im PR erfasst. Keine Zugangsdaten oder Digestwerte sind enthalten.
