# HAProxy SPOE/SPOA Proposed Report Schema

## Status
schema_status: proposed
implementation_status: not_started
runtime_verified: false
schema_enforced: false
runner_support: false
tests_implemented: false

## Zweck
Dieses Dokument beschreibt ein vorgeschlagenes Report-Zielmodell für spätere HAProxy/SPOE/SPOA-PoC-Evidence.
Es implementiert kein Schema und erzeugt keine Reports.

## Grundsatz
- Reports werden im ModSecurity-test-Framework definiert und erzeugt.
- Das Connector-Repository darf keine Reports lokal erzeugen.
- `runtime_verified` darf nur `true` werden, wenn echte Runtime-Ausführung durch das Framework belegt ist.
- Bis zur Implementierung bleibt `runtime_verified: false`.
- Dieses Dokument ist proposed only.

## Bezug zum Framework-Vertrag
Dieses Schema erweitert den HAProxy/SPOE-Framework-Vertrag um ein vorgeschlagenes Report-Zielmodell.
Es ersetzt keine vorhandenen Summary-Modelle, solange keine Implementierung erfolgt.

## Vorgeschlagenes Top-Level-Objekt

Proposed only:

```json
{
  "connector": "haproxy",
  "integration_model": "spoe_spoa",
  "validation_mode": "poc",
  "runtime_verified": false,
  "schema_version": "proposed-0",
  "generated_by": "ModSecurity-test-Framework",
  "connector_artifact_root": null,
  "tests": [],
  "evidence": [],
  "open_questions": [],
  "response_body_scope": "unknown",
  "summary": {
    "passed": 0,
    "failed": 0,
    "skipped": 0,
    "xfail": 0
  }
}
```

## Beleglage und Grenzen
- Vorhandene Runner-/Summary-Modelle im Repository enthalten aktuell kein vollständiges Feldset mit `integration_model`, `runtime_verified`, `evidence` und `open_questions` in der hier vorgeschlagenen Form. Nicht belegbar aus dem aktuellen Repository.
- Die existierende Summary-Erzeugung im Framework bleibt bis zu einer späteren Implementierung maßgeblich. Nicht belegbar aus dem aktuellen Repository.
- Konkrete HAProxy/SPOE-Artefaktpfade sind Im Connector-Repository zu belegen.
- Externe Interoperabilität/Tooling-Kompatibilität ist Extern zu verifizieren.
