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

## Full-lifecycle no-CRS contract

The same catalog now contains a full-lifecycle foundation for phases 1 through
4. It adds 45 capability-driven catalog entries (104 total), without creating
a second runner or a second evidence model. The declarative fixtures live under
`tests/cases/no-crs-baseline/full-lifecycle/`; content-type scope files live
under `tests/fixtures/no-crs-baseline/`.

Those fixtures deliberately use `status: future` and state
`not_executed_until_real_host`. They are inventory/contracts for a
connector-owned host driver, not synthetic runtime evidence and not direct
`runner_case` mappings. A catalog entry also requires a real host and forbids
synthetic PASS evidence.

The catalog covers:

- phase 1 allow, deny, alternate status, redirect, and transaction ID;
- phase 2 request-body rule, a marker spanning two chunks, exact/over-limit
  and ProcessPartial metadata, and payload-free events;
- phase 3 response-header deny/redirect before commit plus original/visible
  status metadata;
- phase 4 incremental ingestion, explicit end-of-stream evaluation, pre-commit
  denial where supported, and separate `minimal`, `safe`, and `strict`
  late-intervention outcomes;
- in-scope, charset-qualified, out-of-scope, missing, invalid, and wildcard
  content-type scope cases;
- a synchronized first-byte proof: the upstream pauses after its first chunk,
  the client must receive that chunk before release, and only then is the
  later marker sent;
- HTTP/1.1 Content-Length and chunked transport, keep-alive, sequential and
  parallel requests, HTTP/2 where available, and client/upstream aborts;
- request/response body limits plus bounded, payload-free event metadata.

`response_body_incremental_ingest` means that chunks reach the engine without
connector-owned full-response buffering. It does not imply per-chunk rule
evaluation: `phase4_end_of_stream_evaluation` explicitly records the permitted
end-of-stream evaluation model. `no_full_response_buffering` and
`first_byte_before_response_end` can pass only with a canonical event proving
that the first client byte was observed while the upstream response was still
unfinished; a timeout or a claimed duration alone is insufficient.

The canonical metadata vocabulary is intentionally flat and payload-free. It
adds late-intervention mode, content-type scope, limit outcome, chunk/end of
stream flags, first-byte/barrier state, protocol/transfer encoding, connection
reuse, and client/upstream-abort booleans. It never accepts response text,
request text, a match value, or intervention log content.

For compatibility with the bounded Common JSON writer, the event schema also
accepts its fixed metadata fields: timestamps/levels, message and decision
metadata, HTTP reason text, method/URI/client-IP metadata, `response_started`,
`body_truncated`, `redacted`, and sequence/hash counters. These fields remain
in `events.jsonl`; case-result and result projections retain only the reviewed
decision and lifecycle state. A connector normalizer must redact potentially
sensitive free text or request-identifying values before writing an event, and
the payload, match-value, secret, and nested-value rejection rules still apply.
On ingest, Common lifecycle labels normalize to the framework rule phases:
`connection` → 0, `uri`/`request_headers` → 1, `request_body` → 2,
`response_headers` → 3, `response_body` → 4, and `logging` → 5. Unknown
phase values are rejected rather than being silently treated as evidence.

### Opt-in full-lifecycle artifact profile

The default `generic` profile preserves the legacy layout above: `events.jsonl`
and the three host logs remain optional. A connector-owned driver that executes
the catalog's full-lifecycle cases must opt into
`--artifact-profile full_lifecycle` for both `select` and `init` (or set
`NO_CRS_ARTIFACT_PROFILE=full_lifecycle` for the Make targets). The profile is
valid only for the `no_crs_baseline` stage and is recorded in the plan,
inventory, manifest, and result.

For that profile, `finalize` requires host-produced `--source-events`,
`--stdout-log`, `--stderr-log`, and `--host-log` inputs. It then requires the
following produced artifacts: `manifest.json`, `result.json`,
`results.jsonl`, `events.jsonl`, `inventory/run.json`, `logs/stdout.log`,
`logs/stderr.log`, and `logs/host.log`. Empty regular files are valid evidence
for an inconclusive or failed host run, but omitted inputs are rejected rather
than synthesized. This artifact profile establishes complete traceability; it
does not turn a future fixture into executed evidence or grant PASS by itself.

## Writer and validator flow

```sh
python3 ci/checks/catalog/no_crs_baseline.py select \
  --connector envoy \
  --capabilities "$CONNECTOR_ROOT/connectors/envoy/capabilities.json" \
  --output "$RUN_DIR/plan.json"

python3 ci/checks/catalog/no_crs_baseline.py init \
  --connector envoy \
  --capabilities "$CONNECTOR_ROOT/connectors/envoy/capabilities.json" \
  --plan "$RUN_DIR/plan.json" \
  --run-dir "$RUN_DIR" \
  --run-id "$RUN_ID" \
  --connector-root "$CONNECTOR_ROOT"

# Run the real host here. Then normalize only its observed artifacts.
python3 ci/checks/catalog/no_crs_baseline.py finalize \
  --run-dir "$RUN_DIR" \
  --capabilities "$CONNECTOR_ROOT/connectors/envoy/capabilities.json" \
  --source-result "$RAW_RESULT" \
  --source-events "$CANONICAL_EVENTS" \
  --stdout-log "$STDOUT_LOG" \
  --stderr-log "$STDERR_LOG" \
  --stage-rc "$HOST_RC" \
  --host-version "$HOST_VERSION" \
  --libmodsecurity-version "$LIBMODSECURITY_VERSION"

python3 ci/checks/catalog/no_crs_baseline.py validate \
  --evidence-root "$RUN_DIR" \
  --connector envoy \
  --capabilities "$CONNECTOR_ROOT/connectors/envoy/capabilities.json" \
  --check all
```

`finalize` also accepts repeatable `--source-results-jsonl`, `--source-summary`,
`--source-result`, and `--source-log NAME=PATH` arguments. It does not derive a
PASS from exit code zero. A 403 denial becomes PASS only when the source also
identifies rule `1100001`; expected event fields require an observed event.
`--source-events` accepts only normalized, flat canonical metadata JSONL;
host-specific raw event logs must first pass through a connector-owned
normalizer. The accepted fields are the connector, transaction and rule IDs,
phase, status, HTTP status, truncation, content type, and reviewed body
size/hash metadata. Unknown fields, nested values, duplicate JSON keys, and
payload or credential fields are rejected before canonical evidence is written.
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
