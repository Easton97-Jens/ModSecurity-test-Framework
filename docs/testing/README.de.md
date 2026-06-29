# Testdokumente

**Sprache:** [English](README.md) | Deutsch

Status: umgesetzt

Testdokumente beschreiben das aus der Quelle abgeleitete YAML-Fallmodell und die Kompatibilität
Nachweise, frühere expected-failure/mapped-only-Entscheidungen und anschlussfreie API-Smokegrenze.

## Dokumente

| Dokument | Benutzen |
| --- | --- |
| `compatibility.md` | Aktuelle Connector-Kompatibilitätsmatrix und bewährte Leistungsbereiche |
| `test-import-plan.md` | Richtlinie zum Ableiten von YAML-Fällen aus vorgelagerten Tests |
| `case-matrix.md` | Generiertes Fallinventar und zuletzt beobachtete Connector-Status |
| `response-body-blocking-investigation.md` | Nachweise für die Beibehaltung der `RESPONSE_BODY`, die die früheren expected-failure/mapped-only sperren |
| `pr70-audit-phase-coverage-plan.md` | Plan für die Zuordnung von ModSecurity-Apache PR #70 audit/phase-Tests zur Framework-eigenen YAML-Abdeckung |
| `pr377-test-import-map.md` | Von der Quelle abgeleitete Karte für ModSecurity-nginx PR #377 Phase-4-Tests |
| `v2-vs-v3-compatibility.md` | Architektur und API Unterschiede zwischen ModSecurity v2 und v3 |
| `v2-vs-v3-test-compatibility.md` | V2/V3 Testimportnachweis |
| `v3-api-smoke-test.md` | Konnektorfreie libmodsecurity v3 API Smokenotizen |
| `mrts.md` | Optionale MRTS Generierung, Import und variantenspezifische Laufzeittests |

## Regel

`pass` bedeutet real beobachtetes Verhalten. Die Fälle `former expected-failure` und `mapped-only` bleiben bestehen
außerhalb des normalen `smoke-all`, bis sowohl Apache als auch NGINX das Erwartete beweisen
Verhalten durch echte Verbindungspfade.
