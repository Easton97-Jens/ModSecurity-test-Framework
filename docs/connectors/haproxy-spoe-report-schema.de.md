# HAProxy SPOE/SPOA Vorgeschlagenes Berichtsschema

**Sprache:** [English](haproxy-spoe-report-schema.md) | Deutsch

## Status
schema_status: vorgeschlagen
Implementierungsstatus: nicht_gestartet
runtime_verified: false
schema_enforced: false
runner_support: false
tests_implemented: false

## Zweck
Dieses Dokument beschreibt ein vorgeschlagenes Report-Zielmodell für spätere HAProxy/SPOE/SPOA-PoC-Evidence.
Es implementiert kein Schema und generiert keine Reports.

## Grundsatz
- Berichte werden im ModSecurity-Test-Framework definiert und generiert.
- Das Connector-Repository darf keine Reports lokal erzeugen.
- `runtime_verified` darf nur `true` werden, wenn echte Runtime-Ausführung durch das Framework belegt ist.
- Bis zur Implementierung bleibt `runtime_verified: false`.
- Dieses Dokument wird nur vorgeschlagen.

## Bezug zum Framework-Vertrag
Dieses Schema erweitert den HAProxy/SPOE-Framework-Vertrag um ein vorgeschlagenes Report-Zielmodell.
Es ersetzt keine vorhandenen Summary-Modelle, solange keine Implementierung erfolgt.

## Vorgeschlagenes Top-Level-Objekt

Nur vorgeschlagen:

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
    "former expected-failure": 0
  }
}
```

## Beleglage und Grenzen
- Vorhandene Runner-/Summary-Modelle im Repository enthalten aktuell kein vollständiges Feldset mit `integration_model`, `runtime_verified`, `evidence` und `open_questions` in der hier vorgeschlagenen Form. Nicht belegbar aus dem aktuellen Repository.
- Die existierende Summary-Erzeugung im Framework bleibt bis zu einer späteren Implementierung maßgeblich. Nicht belegbar aus dem aktuellen Repository.
- Konkrete HAProxy/SPOE-Artefaktpfade sind im Connector-Repository zu belegen.
- Externe Interoperabilität/Tooling-Kompatibilität ist Extern zu verifizieren.
