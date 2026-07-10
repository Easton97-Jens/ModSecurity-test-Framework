# Canonical All-Connector No-CRS Baseline

**Language:** English | [Deutsch](no-crs-baseline.de.md)

Status: implemented framework contract; connector capabilities remain evidence-specific.

The framework owns the connector-neutral catalog, deterministic local rules,
capability selection, evidence normalization, validation, and result-only
summary generation. Connector repositories still own host builds, host
configuration, lifecycle control, request execution, and raw host evidence.

## Canonical contracts

- Evidence stages: `source_contract`, `compile`, `link`, `config_load`,
  `start_smoke`, `minimal_runtime_smoke`, `no_crs_baseline`, `crs_smoke`, and
  `extended_matrix`.
- Capability source: `connectors/<name>/capabilities.json`.
- Catalog: `tests/cases/no-crs-baseline/catalog.json`.
- Reusable HTTP cases: `tests/cases/no-crs-baseline/*.yaml`; set
  `NO_CRS_BASELINE=1` when selecting them through the legacy `case_cli.py`.
  Eight catalog entries currently have direct YAML runner mappings: allow,
  deny, alternative status, transaction ID, buffered request body, buffered
  response body, log-only, and redirect. The phase-3 probe remains plan-only
  until the shared harness can inject the canonical upstream response header.
- Rules: `tests/rules/no-crs-baseline.conf`. Rule `1100001` is the native core
  probe: `X-Modsec-Smoke: block` is denied in phase 1 with HTTP 403.
- Schemas: `tests/schemas/no-crs-baseline/`.
- Artifact layout: `$EVIDENCE_ROOT/<connector>/<run-id>/` with
  `manifest.json`, `result.json`, `results.jsonl`, optional `events.jsonl`, and
  `logs/`, `config/`, and `inventory/`.

The canonical case statuses are `PASS`, `FAIL`, `BLOCKED`, `UNSUPPORTED`,
`NOT_APPLICABLE`, and `NOT_EXECUTED`. Unsupported and missing execution never
increase the PASS count. Exit 77 is valid only for a prerequisite blocker
before host execution starts.

## Writer and validator flow

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

# Run the real host here. Then normalize only its observed artifacts.
python3 ci/no_crs_baseline.py finalize \
  --run-dir "$RUN_DIR" \
  --capabilities "$CONNECTOR_ROOT/connectors/envoy/capabilities.json" \
  --source-result "$RAW_RESULT" \
  --source-events "$RAW_EVENTS" \
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

`finalize` also accepts repeatable `--source-results-jsonl`, `--source-summary`,
`--source-result`, and `--source-log NAME=PATH` arguments. It does not derive a
PASS from exit code zero. A 403 denial becomes PASS only when the source also
identifies rule `1100001`; expected event fields require an observed event.
`minimal_runtime_smoke` can be PASS only when its rule-`1100001` event contains
`connector`, `transaction_id`, `rule_id`, `phase`, and `status`, no body payload
is present in the event stream, and concrete host and libModSecurity versions
are recorded. The inventory records the same `evidence_stage` and `ruleset` as
the manifest and result; validators reject a mismatch.

The accepted individual validation checks are `schema`, `completeness`,
`capability`, `claim-policy`, `layout`, `body-payload`, and `status`.

`select` and `init` also accept `--evidence-stage minimal_runtime_smoke`. That
mode selects only the two core allow/deny cases but writes the same schema and
artifact layout. `init` requires a fresh run directory, snapshots and hashes
the capability manifest, verifies an externally prepared plan against a fresh
selection, and rejects symlinks in the run path. All canonical writes and
artifact copies are atomic and no-follow; the layout validator rejects every
symlink and unmanifested file.

The canonical writer currently writes `minimal_runtime_smoke` and
`no_crs_baseline`. Separate current-run artifact writers for `compile`, `link`,
`config_load`, and `start_smoke` remain an explicit gap; capability-manifest
stage declarations alone are not treated as execution evidence.

## Summary policy

`summarize` reads only canonical per-connector `result.json` files. Missing
files become `NOT_EXECUTED`, and multiple runs require an explicit `--run-id`.
It can generate the bilingual common and per-connector reports with
`--reports-dir`. These reports deliberately make no CRS, production-readiness,
security-verification, full-matrix, or universal response-body claim.
