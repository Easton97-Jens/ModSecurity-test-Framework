# NGINX First-Byte: zwei Originalbeobachtungen zuordnen

**Sprache:** [English](20261010-04-nginx-first-byte-event-pair.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261010-04-nginx-first-byte-event-pair |
| UTC-Datum | 2026-10-10 |
| Framework-Basisrevision | 1bfc4f8e8e4aa9d618c4cfb2205badd5008d8f75 |
| Issue oder Pull Request | Framework-PR #137; Parent-PR #396 |

## Motivation und Problemstellung

Die zwei bestehenden Required-First-Byte-/No-Full-Buffer-Records benötigen eine kausale Barrierbeobachtung und echte Rule1100301-Evidence aus derselben nativen NGINX-Invocation. Der vorgezogene Rulefilter verwarf den echten Pre-EOS-Append17/17; die spätere EOS-Intervention44/44 trug die Rule, aber keine Barrierflags. Ein bestehendes kombiniertes Event-Unitfixture verdeckte diese Form.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-Katalognormalisierung und unabhängige PASS-Nachvalidierung; Identitäts-, Kausalitäts- und Evidenzautoritätsgrenzen bleiben strikt. Keine Connector-Produktänderung oder Security-Remediation wird behauptet.

## Akzeptanzkriterien

Beide echten getrennten Eventrecords validieren ohne erfundene Eventfelder. Fehlende, mehrdeutige, unpassende oder manipulierte Evidence bleibt fail-closed. Bestehende Single-Event-Kontrollen bleiben gültig; Required-IDs und Schemas bleiben unverändert.

## Untersuchte Alternativen

First-Byte-Validierung zu lockern oder die spätere Rule in den Append einzufügen wurde verworfen. Nur den späteren Rulezeugen auszuwählen belegt den kausalen Barrier nicht.

## Implementierungsentscheidung

Originalappend und späteren Rulezeugen über genau eine übergebene Transaktion, Connector/Profil, Phase und versiegelte run-lokale Eventautorität zuordnen. Explizite Runmismatches, mehrdeutige/fehlende/vertauschte Mitglieder, inkompatible Profile und abnehmende/ungültige Counter bleiben fail-closed. Nur die zwei kataloggebundenen Records an native-nginx-http-module verwenden diesen Paarvertrag; bestehende Single-Event-Validierung bleibt unverändert.

Ein Append einer fremden Transaktion im selben versiegelten Run aktiviert keine Paarzuordnung gegen einen legitimen kombinierten Eventnachweis der übergebenen Transaktion. Dieser Fallback durchläuft weiterhin die unveränderte strikte Single-Event-Validierung; fehlende, mehrdeutige oder vertauschte Same-Transaction-Paare erhalten keine Ausnahme.

Nur vorhandene First-Byte-Felder werden vom Barrier übernommen. Entscheidung/Status/Aktion und Lifecycle-EOS bleiben beim späteren Zeugen. Bodycounter bleiben an ihren Originalevents; rohe Counterbehauptungen müssen zum Barrier passen. Keine Rule im Append ergänzt, keine17-Counter auf Intervention kopiert, kein zusammengeführtes Event serialisiert, keine neuen Recordfelder oder Schemaerleichterungen. Beobachtungsfelder sind die explizite Union beider validierter Originalmitglieder. Standalone-PASS-Validierung leitet das Paar erneut ab und erzwingt Katalogmetadaten statt veränderlichen Recordlabels zu vertrauen.

## Geänderte Dateien und Tests

`ci/checks/catalog/no_crs_baseline.py`, `tests/no_crs/test_no_crs_baseline.py` und dieses EN/DE-Recordpaar. Sechs native Testmethoden prüfen beide Records, Originalpaar-Manipulationen, Standalone-Metadaten-/Feld-/Rulemanipulation, ungültige Counter, vorheriges EOS und Legacy-Kontrollen.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Offline genuine AB proposed-regression.py | 1 | Bisheriger Collector: zwei echte Positivfehler (RED) | nginx-full97-followup-20261010T084822Z/first-byte-two-event |
| Offline proposed-regression.py --proposed | 0 | Fünf Tests; echte getrennte Records und Mismatch-Kontrollen | Dasselbe task-eigene Analyseverzeichnis |
| Offline proposed-regression.py --proposed --native | 0 | Neun Tests: sechs vorgeschlagene native Methoden und drei bestehende Kontrollen | Dasselbe task-eigene Analyseverzeichnis |
| Native test_no_crs_baseline.py SeparatedNginxFirstByteTest, nur Tests | 1 | Sechs Methoden, 22 rote Assertionfehler, 0.854s | versioned-red.log im selben Verzeichnis |
| Native test_no_crs_baseline.py SeparatedNginxFirstByteTest, nach Implementierung | 0 | Sechs Methoden, 7.019s | versioned-green.log |
| Native Mixed-Transaction-Legacyregression, vor Korrektur | 1 | Ein echter Matching-Barrier-Fehler | versioned-mixed-tx-red.log |
| Native SeparatedNginxFirstByteTest, finale Korrektur | 0 | Sechs Methoden, 7.445s, keine Skips | versioned-final-green.log |
| make test-no-crs-contract, erste Integration | 0 | 421 Tests, 181.889s, keine Skips | versioned-suite.log |
| make test-no-crs-contract, finale Mixed-Transaction-Korrektur | 0 | 421 Tests, 179.669s, keine Skips | versioned-suite-final.log |
| make check-documentation test-change-record-contract, erster Lauf | 2 | Change-ID ohne Dateinamensuffix; beide IDs korrigiert | versioned-docs.log |
| make check-documentation test-change-record-contract, korrigiert | 0 | Alle Dokumentationsprüfungen und vier CR-Vertragstests | versioned-docs-final.log |
| AST-Parse beider geänderter Pythondateien; git diff --check | 0 | Syntax und Whitespace nach finaler Sourcekorrektur gültig | RTK-Befehlsreceipts |
| Offline genuine AB proposed-regression.py, integrierte Source | 0 | Beide echten Records und Schemas gültig; drei Tests ausgeführt, zwei Proposal-only-Kontrollen übersprungen | Dieselben unveränderten Inputs; native Kontrollen separat ausgeführt |
| RTK-gewrapptes natives make lint, eingefrorene Implementierung auf Basis1bfc | 0 | 604 Ausführungen in19 Suites, keine Skips, 1246.181s; Python-Source-/Testhashes unverändert | checks/firstbyte_framework_lint_workingtree.* im Task-Analyseverzeichnis |

## Sicherheitsauswirkung

Keine Security-Remediation wird behauptet. Die Zuordnung bleibt auf die zwei kataloggebundenen nativen NGINX-Cases begrenzt und prüft Originalevent-Identität, Chronologie, Counter und Standalone-Autorität erneut; keine Validierungsunterdrückung wird eingeführt.

## Dokumentation und Runtime-Evidenz

Echte erhaltene AB-Inputs reproduzieren zwei Fehler am bisherigen Collector; Offlinevalidierung mit integrierter Source validiert beide Records und Caseschemas ohne Inputbytes zu ändern. Native Regressionsergänzungen prüfen Identität/Profil/Run/Phase/Rule, fehlende/mehrdeutige/vertauschte Mitglieder, Counter-/Decisionmismatches, Standalone-Recordmanipulation und bestehende Single-Event-Kontrollen. Dieses EN/DE-Paar dokumentiert die Framework-Reparatur. Replay ist weder neue Invocation noch Full97; diese Änderung sammelte keine neue Runtime-Evidence.

Required-Umfang und IDs unverändert. Parent-Integration/Gitlink und reale Runtime-Nachweise bleiben separate Connector-Aufgaben. MRTS unverändert. Kein Gesamt-Exact-Head- oder Protected-PASS folgt aus dieser Framework-Reparatur.

## Nicht ausgeführte Prüfungen

PR-Sonar am aktuellen Head und eine frische begrenzte Runtime bleiben bis zur koordinierten Veröffentlichung und neuen Artefakten offen. Precommit-Vortex-Einzeldateianalyse war an dieser Verbindung nicht verfügbar (403); das ist keine Analyse ohne Findings. Vollständiger nativer Lint bestand auf der eingefrorenen Implementierung vor dem Commit, nicht auf einer umetikettierten zukünftigen Revision. Kein Full97 oder geschützter Workflow wurde für diese Reparatur ausgeführt.

## Einschränkungen und Restrisiko

Offline-Validierung verwendet unveränderte echte Evidence erneut; sie beweist keine neue Invocation oder vollständige Required-Coverage. Release-/Protected-Infrastruktur bleibt separat.

## Finaler Diff- und Review-Status

Nach versioniertem Tests-only-RED vom sauberen Framework 1bfc4f8e8e4aa9d618c4cfb2205badd5008d8f75 integriert. Genau vier freigegebene Pfade sind geändert/untracked; keine Katalog-/Schema-/Required- oder MRTS-Änderung. Whitespace- und Scopeprüfungen bestehen. Unabhängiges Koordinatorreview identifizierte und verifizierte die korrigierte Mixed-Transaction-Legacyregression; keine weitere materielle Abweichung bleibt. Commit, Remoteveröffentlichung und neue Runtime-Nachweise sind nachfolgende eigenständige Schritte.
