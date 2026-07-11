# Kanonische No-CRS-Baseline für alle Connectoren

**Sprache:** [English](no-crs-baseline.md) | Deutsch

Status: Framework-Vertrag umgesetzt; Connector-Fähigkeiten bleiben von realer Evidence abhängig.

Das Framework besitzt den connector-neutralen Katalog, deterministische lokale
Regeln, Capability-Auswahl, Evidence-Normalisierung, Validierung und die reine
Ergebnis-Zusammenfassung. Das Connector-Repository besitzt weiterhin
Host-Build, Host-Konfiguration, Lifecycle-Steuerung, Request-Ausführung und rohe
Host-Evidence.

## Kanonische Verträge

- Evidence-Stufen: `source_contract`, `compile`, `link`, `config_load`,
  `start_smoke`, `minimal_runtime_smoke`, `no_crs_baseline`, `crs_smoke` und
  `extended_matrix`.
- Capability-Quelle: `connectors/<name>/capabilities.json`.
- Katalog: `tests/cases/no-crs-baseline/catalog.json`.
- Wiederverwendbare HTTP-Fälle: `tests/cases/no-crs-baseline/*.yaml`; bei der
  Auswahl über das alte `case_cli.py` muss `NO_CRS_BASELINE=1` gesetzt sein.
  Acht Katalogeinträge haben derzeit direkte YAML-Runner-Zuordnungen: Allow,
  Deny, alternativer Status, Transaction-ID, gepufferter Request-Body,
  gepufferter Response-Body, Log-only und Redirect. Der Phase-3-Probe bleibt
  plan-only, bis der gemeinsame Harness den kanonischen Upstream-Response-Header
  injizieren kann.
- Regeln: `tests/rules/no-crs-baseline.conf`. Regel `1100001` ist der native
  Kern-Probevertrag: `X-Modsec-Smoke: block` wird in Phase 1 mit HTTP 403
  abgewiesen.
- Schemata: `tests/schemas/no-crs-baseline/`.
- Artefaktlayout: `$EVIDENCE_ROOT/<connector>/<run-id>/` mit `manifest.json`,
  `result.json`, `results.jsonl`, optional `events.jsonl` sowie `logs/`,
  `config/` und `inventory/`.

Die kanonischen Fallstatus sind `PASS`, `FAIL`, `BLOCKED`, `UNSUPPORTED`,
`NOT_APPLICABLE` und `NOT_EXECUTED`. Nicht unterstützte oder nicht ausgeführte
Fälle erhöhen niemals die PASS-Anzahl. Exit 77 gilt ausschließlich für einen
Prerequisite-Blocker vor Beginn der Host-Ausführung.

## Writer- und Validator-Ablauf

```sh
python3 ci/no_crs_baseline.py select \
  --connector envoy \
  --capabilities "$CONNECTOR_ROOT/connectors/envoy/capabilities.json" \
  --output "$RUN_DIR/plan.json"

python3 ci/no_crs_baseline.py init \
  --connector envoy \
  --capabilities "$CONNECTOR_ROOT/connectors/envoy/capabilities.json" \
  --plan "$RUN_DIR/plan.json" \
  --run-dir "$RUN_DIR" \
  --run-id "$RUN_ID" \
  --connector-root "$CONNECTOR_ROOT"

# Hier den echten Host ausführen und danach nur beobachtete Artefakte normalisieren.
python3 ci/no_crs_baseline.py finalize \
  --run-dir "$RUN_DIR" \
  --capabilities "$CONNECTOR_ROOT/connectors/envoy/capabilities.json" \
  --source-result "$RAW_RESULT" \
  --source-events "$CANONICAL_EVENTS" \
  --stdout-log "$STDOUT_LOG" \
  --stderr-log "$STDERR_LOG" \
  --stage-rc "$HOST_RC" \
  --host-version "$HOST_VERSION" \
  --libmodsecurity-version "$LIBMODSECURITY_VERSION"

python3 ci/no_crs_baseline.py validate \
  --evidence-root "$RUN_DIR" \
  --connector envoy \
  --capabilities "$CONNECTOR_ROOT/connectors/envoy/capabilities.json" \
  --check all
```

`finalize` akzeptiert außerdem wiederholbare Argumente
`--source-results-jsonl`, `--source-summary`, `--source-result` und
`--source-log NAME=PATH`. Ein Exitcode null erzeugt keinen PASS. Ein 403-Deny
wird nur mit der zusätzlich beobachteten Regel-ID `1100001` zu PASS; erwartete
Event-Felder verlangen ein tatsächlich beobachtetes Event.
`--source-events` akzeptiert ausschließlich normalisierte, flache kanonische
Metadata-JSONL; host-spezifische rohe Event-Logs müssen zuerst einen
connector-eigenen Normalizer durchlaufen. Zulässig sind Connector-,
Transaction- und Regel-ID, Phase, Status, HTTP-Status, Truncation,
Content-Type sowie geprüfte Body-Größen-/Hash-Metadaten. Unbekannte Felder,
verschachtelte Werte, doppelte JSON-Schlüssel sowie Payload- oder
Credential-Felder werden verworfen, bevor kanonische Evidence geschrieben wird.
`minimal_runtime_smoke` darf nur PASS sein, wenn sein Regel-`1100001`-Event
`connector`, `transaction_id`, `rule_id`, `phase` und `status` enthält, der
Event-Stream keine Body-Nutzlast enthält und konkrete Host- sowie
libModSecurity-Versionen erfasst sind. Das Inventar führt dieselbe
`evidence_stage` und dasselbe `ruleset` wie Manifest und Ergebnis; der Validator
verwirft Abweichungen.

Die einzelnen Validatornamen sind `schema`, `completeness`, `capability`,
`claim-policy`, `layout`, `body-payload` und `status`.

`select` und `init` akzeptieren außerdem
`--evidence-stage minimal_runtime_smoke`. Dieser Modus wählt nur die beiden
Allow-/Deny-Kernfälle, schreibt aber dasselbe Schema und Artefaktlayout. `init`
verlangt ein frisches Laufverzeichnis, kopiert und hasht das Capability-Manifest,
prüft einen extern erzeugten Plan gegen eine frische Auswahl und verbietet
Symlinks im Laufpfad. Alle kanonischen Writes und Artefaktkopien sind atomar und
No-Follow; der Layout-Validator verwirft jeden Symlink und jede nicht im
Manifest deklarierte Datei.

Der kanonische Writer schreibt derzeit `minimal_runtime_smoke` und
`no_crs_baseline`. Separate Current-Run-Artefaktwriter für `compile`, `link`,
`config_load` und `start_smoke` bleiben eine ausdrücklich ausgewiesene Lücke;
Stage-Deklarationen im Capability-Manifest gelten allein nicht als
Ausführungs-Evidence.

## Summary-Richtlinie

`summarize` liest ausschließlich kanonische `result.json`-Dateien der
Connectoren. Fehlende Dateien werden `NOT_EXECUTED`; bei mehreren Läufen ist
`--run-id` Pflicht. Mit `--reports-dir` erzeugt der Befehl die bilingualen
gemeinsamen und connector-spezifischen Berichte. Diese Berichte behaupten
bewusst keine CRS-, Production-Readiness-, Security-, Full-Matrix- oder
allgemeine Response-Body-Verifikation.
