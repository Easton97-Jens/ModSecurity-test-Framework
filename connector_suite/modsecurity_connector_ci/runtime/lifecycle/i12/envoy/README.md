# Envoy I12 host evidence

**Language:** English | [Deutsch](README.de.md)

For the current source-checkout commands below, select both checkouts, a
compatible interpreter and existing approved external storage explicitly.
Replace these illustrative paths with actual physical paths; source preparation
still requires the stated independent admission and does not authorize a host run.

```sh
export CONNECTOR_ROOT="/absolute/product/checkout"
export CONNECTOR_REVISION="$(git -C "$CONNECTOR_ROOT" rev-parse HEAD)"
export TEST_ROOT="/absolute/framework/checkout"
export FRAMEWORK_ROOT="$TEST_ROOT"
export FRAMEWORK_PYTHON="/absolute/framework-venv/bin/python"
export CODEX_TEMP_ROOT="/absolute/approved/external/storage"
export I12_TEST_ROOT="$CODEX_TEMP_ROOT"
export CONNECTOR_TEST_OUTPUT_ROOT="$CODEX_TEMP_ROOT"
export PYTHONSAFEPATH=1
export PYTHONPATH="$TEST_ROOT:$TEST_ROOT/connector_suite"
```

This Envoy-only test extension reuses the existing `envoy` capture variant and
common native observer. The [concise PR #410 closeout](https://github.com/Easton97-Jens/ModSecurity-conector/blob/master/docs/pr-410-i12-closeout-20261024.md)
is **PARTIAL**: 284 original IDs are preserved. Four newly approved ext_proc packets
raise the current lifecycle PASS to seven; 118 original oracles remain open.
The central baseline stays unchanged. Synthetic host scenarios do not
automatically qualify original IDs.

All 125 original oracles have individual source reviews. The 33 new fixture-bound
source proposals remain separate from canonical resolution and host acceptance.

## Maintained parser and publication boundary

Current consumers import the maintained `host_log_observations.py` and
`grpc_stream_observations.py` modules from this directory. `--helpers` selects
retained provenance data only: both historical helper hashes must match the
capture manifest, and no helper directory is added to Python's import path.
The object store retains the exact historical helper bytes as lossless JSON
line data. New physical reviews use `current_parser_sha256` for the maintained
modules and `helper_sha256` for historical provenance. New original-case packets
use `current_parser_sha256` and `historical_helper_sha256`; both identities are
rechecked during reproduction. A historical helper identity cannot substitute
for current parser identity. Existing archived reviews, packets and results
retain their original revision binding and are not refreshed by this change.

The maintained host parser uses one unambiguous tag-content scan, including for
unterminated tags. Output publication for transport, physical reviews,
current-base supplements and reconciliation uses create-new descriptor-backed
files inside configured runtime roots. The runner validates matrix labels and
all distinct log destinations before launching a controller, creates private
logs once, and replaces only its admitted checkpoint atomically. Source roots,
traversal, symlinked parents and foreign destinations are rejected by the shared
`ci/lib/i12_path_safety.py` boundary. The normal CLI options remain unchanged;
an output outside configured runtime storage is an error.

The source observer adapter additionally accepts the explicit C successor
`5038d0068cef52f7cf4f2013355cf1b828648061993dd89c51d14f5439cfe387`
under `i12.envoy.preserve-source-observer.v2`. Its receipt records the actual
archived C hash; the existing `0d903fc5…` path retains its original v1 contract
and proof metadata. The historical Envoy capture profile and result identities
remain unchanged. Accepting an input identity supplies no runtime evidence.

## Current acceptance state

| Route | Lifecycle PASS / original IDs | Open original oracles |
| --- | ---: | ---: |
| `envoy-ext-proc` | 5 / 117 | 46 |
| `envoy-ext-authz-request` | 1 / 94 | 39 |
| `envoy-ext-authz-response-companion` | 1 / 73 | 33 |

Of 277 IDs without full lifecycle acceptance, 8 are configuration-only PASS
and 269 are unqualified. The 86 real host measurements include 37 retakes under
33 exact original IDs. The four new individual approvals are:

- `I12::envoy-ext-proc::NEED-request-streaming`
- `I12::envoy-ext-proc::NEED-response-streaming`
- `I12::envoy-ext-proc::NEED-client-response-bytes`
- `I12::envoy-ext-proc::NEED-client-exit-signal`

Four previously proposed qualifications are excluded: request-authorization
`NEED-complete-sample`, `NEED-request-multiple-chunks`,
`NEED-client-response-bytes`, and companion `NEED-allow`. Their Authorization
trailers are not tagged to the corresponding stream, so remote gRPC status
remains unknown and successful completion remains false. The physical host,
client and backend observations remain available, without qualifying those IDs.
Multiple client writes do not imply multiple native Authorization callbacks.

## Producers

| Producer | Evidence boundary |
| --- | --- |
| `reconcile.py` | Revalidates original oracle sources and physical ledger; preserves all 284 exact Envoy IDs |
| `prepare_native.py` | Git-free current source copy, unchanged capture overlays, native/CGo build, Go/race/vet and observer controls |
| `source_inventory.py` | Reconstructs every build input from the hash-bound Git archive and explicit capture additions |
| `evidence_io.py` | Bounds physical reads to approved owned paths; rejects symlinks, private configuration and changes during reads |
| `validate_oracles.py` | Verifies all 125 original-ID reviews and physical references; preserves canonical results |
| `host_scenarios.py` | Sealed independent fixtures, TLS inputs, binary/source binding and private controller; does not start hosts |
| `fault_scenarios.py` | Sealed Response-EOS fault fixture with a separate test proxy; real run `fault-host-v1` remains runner77/controller1/client1, unqualified and without new PASS |
| `bind_originals.py` | Seals fresh exact-original-ID retakes of reviewed fixtures with all inputs inside the current private run |
| `run_host.py` | Bounded launches using the existing nonroot controller; exit codes remain observations |
| `review_runs.py` | Physical hashes, loaded images, client/backend bytes, native/host callbacks, cleanup and transport facts |
| `current_base_evidence.py` | Binds the separate current-Base native/host supplement, rejected and superseded attempts; adds no original-ID qualification |
| `transport.py` | Distinguishes actual local HTTP/2 reset from explicit remote gRPC success |
| `host_log_observations.py` | Maintained extraction of actual nonce-scoped host logger rows |
| `grpc_stream_observations.py` | Maintained extraction of uniquely scoped Process reset and HTTP/2 closure facts |
| `qualify_originals.py` | Stages selected original cases; individual approval requires exact fixture equality, fresh reproduction of all 35 proof fields and the shared validator |
| `write_report.py` | Generates only this task's EN/DE report and exact-ID JSON; does not update shared generators or ledger |

A fresh companion NEED-allow retake binds a separate supplemental source review before execution. Its early backend request-line capture proves exactly one target and one neighbor request; old lower-bound receipts remain unchanged.

## Validation

Run with the explicit source-checkout environment above:

```sh
ON_DEMAND_TESTS=1 rtk proxy "$FRAMEWORK_PYTHON" -P -B -m unittest discover -s "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/i12/envoy" -p 'test_*.py' -v
rtk proxy "$FRAMEWORK_PYTHON" -P -B "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/i12/capture_sources.py" verify
```

The current complete Envoy suite has 257 PASS and 0 skips. Receipt: `ci/final-envoy-controls-257-sonar-v3.json`. Focused fault controls have 16 PASS; separate Go test-proxy controls have 10 PASS. These controls do not automatically qualify the host run.

Each producer exposes `--help`. Native preparation requires a fresh registered
external run root, the current checkout, the existing offline module cache,
the selected real SDK and patched Go toolchain. `--validate-existing` retains
failed setup evidence and reruns checks without silently rebuilding binaries.
Use a short, private, physical temporary path for UDS tests.

Host preparation additionally requires the explicitly hash-bound retained v5
controller/template inputs and the matching native build receipt. These are
external prerequisites, not bundled binaries or permission to install tools.
The controller removes capabilities, enters private namespaces and admits
UID/GID 65534 with NoNewPrivs before running capture programs. The Envoy copy
pins its positively identified PID namespace until after cleanup to prevent
inode reuse from misattributing another run's processes. All original gates
remain active; failed ownership checks remain errors.


The historical qualified native and host evidence source remains
`f27eb59b53beff6f65384fc2e5037881a3052c01`. The exact Base head
`a62296fb57263f9be18c6ac879e36e0ab2a9935c` was merged in
`dfb1a07a863530a53c0006ee204319453d66a2ad`. A separate hash-bound
`current-base-evidence-v1.json` supplement binds the historical final
`current-base-a622-native-v3` and `current-base-a622-host-v3` receipts.
The engine build uses the Base-required Go 1.27.2 and x/net 0.61.0;
the host-installed Go 1.27.3 is a separate environment observation.
The SDK is ModSecurity 3.0.14 and the host is Envoy 1.39.1. All 16 native
checks, including Go/CGo, race, vet and 34 native observer controls, passed.
The earlier Go 1.27.3 build/host attempts remain superseded. A mixed-toolchain
build failed before host launch and remains rejected evidence. Earlier admission
failures retain exit 77 and no cleanup claim.

All three final a622 probes have runner exit 0, two complete backend
requests, physical event logs and verified cleanup without survivors or mount
leaks. Each route observes target request/response 95/96 bytes and independent
neighbor request/response 6/7 bytes. Their contracts remain separate:

- ext_proc observes request chunks 64+31+0 and response chunks 64+32+0 with
  EOS, native Finish/logging/free/cleanup, and local Process reset2. The remote
  Process gRPC status remains unknown.
- Request authorization delivers one complete 95-byte native sample under
  host `max_request_bytes=4096` and native limit 1024. This probe exercises no
  native body-limit decision. Untagged Authorization trailers leave remote
  status unknown; the HTTP/backend observations do not establish gRPC success.
- The companion observes a correlated transaction lease, P3 before Common
  commit, then response-body callbacks/P4, EOS and cleanup. Its target receives a complete HTTP
  entity followed by TCP reset errno104; its neighbor observes EOF. Authorization
  and Process remote statuses remain unknown. P4 Strict support is not claimed.

The following four cases remain unqualified because visible Authorization
trailers are not stream-bound and the remote gRPC status remains unknown:

- `I12::envoy-ext-authz-request::NEED-complete-sample`
- `I12::envoy-ext-authz-request::NEED-request-multiple-chunks`
- `I12::envoy-ext-authz-request::NEED-client-response-bytes`
- `I12::envoy-ext-authz-response-companion::NEED-allow`

The supplement qualifies no original ID and adds no oracle progress. The
historical measurement/retake counts remain unchanged. The retained baseline
and physical sources were revalidated with current central validators; this
Envoy task modified no shared validator. Scoped documentation evidence:
`ci/docs-sonar-v3.json`.

The Base subsequently advanced to `e4c872cde16eb73182de49c09a8ba8ee4219b417`
and `afaf6305bd55646073c3b40632b52fc4e5edf714`; both were integrated by normal
merges. `current-base-e4-evidence-v2-sonar.json` retains the e4 native pass, initial
ext_proc timeout and successful host retake. `current-base-afaf-evidence-v3-sonar.json`
binds that history to the fresh `current-base-afaf-native-v3` receipt and
`current-base-afaf-host-v2/physical-review-sonar-v1.json`. All 16 afaf native steps,
including Go/CGo, race and vet, pass. Engine Go1.27.2, host-environment Go1.27.3,
SDK3.0.14 and Envoy1.39.1 remain independently identified. All 2,196 build sources
and the current registry's 155 objects/10 profiles are verified without editing
the shared manifest. Earlier afaf build/admission failures remain retained.

The delivery Base later advanced by normal merge to
`76672071c3f7665dfde3340bef9e64271d6f6e70`. Its inherited delta changes only
two Parent test fixtures and their own EN/DE Change Record; it changes no Envoy,
runtime, capture, dependency or build input. afaf therefore remains the latest
real Envoy native/host evidence source. No new host execution, lifecycle PASS or
oracle progress is assigned to 766.

The three afaf-host-v2 runners exit0, each with target request/response 95/96
bytes, neighbor 6/7 bytes, two backend requests and physical Finish/free/cleanup
without survivors or mount leaks. ext_proc observes P1–P4 and native chunks
64/31/0-EOS and 64/32/0-EOS; its neighbor is sequential. Authorization delivers
one complete 95-byte sample under the host buffer contract, and exercises no
host reject, native limit decision, intervention or technical runtime failure.
The companion's lease is allocation-bound; wire token equality is unproven.
P3 precedes commit, and the first client entity byte precedes P4. P4 Strict
support is not established. Untagged Authorization trailers and missing remote
Process status remain unknown, successful completion false. These supplementary
runs add no original ID, lifecycle PASS or oracle progress; 7 PASS/118 open,
86 historical host measurements and 37 retakes for 33 IDs remain unchanged.

The real ext_proc fault probe `fault-host-v1` drops only the empty Response-EOS callback and performs an actual half-close. The engine API and Envoy trace unambiguously correlated to the target stream report gRPC status14. The client receives an HTTP200 prefix with 96 body bytes in 64+32, but no zero chunk. Runner77/controller1/client1 remain unqualified; new PASS: 0. The target records P1–P3 and P4=0, a `runtime_finish` attempt with result0 and one logging/free/cleanup each. The healthy neighbor has P1–P4/Finish once each; no survivors or mount leaks remain. Proxy wire status remains unobserved. Missing status is not interpreted as successful completion.

## Claim limits

`max_request_bytes` is Envoy's host buffer limit. Authorization samples,
native limits and technical gRPC errors require separate observations.
Started/aborted backend requests are counted independently of completed receipts.
Multiple client writes alone do not prove multiple native body callbacks.
Complete HTTP framing, TCP reset, gRPC status, EOS, Finish and Free are separate
facts. Missing remote gRPC status is never successful completion.

Read the task report and exact-ID JSON for remaining gaps. Do not change the
shared manifest, original catalog, other connectors or product sources through
this extension. Retain raw artifacts externally; version only reviewed metadata.
