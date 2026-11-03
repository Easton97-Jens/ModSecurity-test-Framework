# Traefik I12 authorization and companion evidence

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

This Framework test producer extends the existing central `traefik-forwardauth`
capture variant in disposable external source copies. Product files, the central
I12 matrix, shared generators, Framework and MRTS remain outside its write scope.
Source preparation never starts a host or qualifies an original requirement.

`prepare.py` verifies and applies the central source contract, admits a finite
synthetic probe list, retains native API observation and independent process
snapshots, and creates a fresh driver. Its generated dynamic configuration is
parsed by the already installed `/usr/bin/python3` PyYAML before host startup;
router structure, request buffering 4096 and authorization-response capacity 32768
are checked separately. No package or toolchain installation is performed.

Preparation requires `CODEX_TEMP_ROOT` to name the existing configured external
storage root. Export it from the active project configuration before these
commands. The output must be a fresh physical descendant; existing ancestors
inside that root must belong to the invoking UID and prohibit group/world writes.

```sh
rtk proxy "$FRAMEWORK_PYTHON" -P -B "$TEST_ROOT/connector_suite/adapters/traefik/harness/i12_auth/prepare.py" --repository "$CONNECTOR_ROOT" --output "$CODEX_TEMP_ROOT/your-run/auth-inputs" --leg traefik-forwardauth-request
ON_DEMAND_TESTS=1 rtk proxy "$FRAMEWORK_PYTHON" -P -B -m unittest -v modsecurity_connector_tests.test_traefik_i12_auth
```

For an independent companion execution select
`--leg traefik-forwardauth-response-companion`. The focused authorization-response
capacity fixture selects `--cases auth-cap-boundary auth-cap-overlimit neighbor`.
These two probes explicitly replace the relay response body with 32768/32769
synthetic bytes after the real engine responds; native and relay response sizes
remain separate. They do not claim an engine decision caused a host limit error.

Execute only after reviewing/sealing source, fixture and host/toolchain ledgers
with the owning private nonroot controller. The retained driver expects the
controller ABI `/mnt/src`, `/mnt/fixtures`, `/mnt/artifacts/traefik`, `/task` and
UID/GID 65534. The controller itself is not duplicated here. Each run requires its
own source/hash binding, effective configuration, admission and final cleanup
receipt; archived binaries or evidence do not become a new execution by copying.

The independent client retains socket bytes and exit receipts. The backend
retains request/response byte hashes. A bounded authorization relay separately
records actual authorization samples and engine statuses. Missing/malformed
handles and an explicitly malformed same-UID MRC1 peer exercise observer failure
boundaries. These injected failures are distinguished from native engine results.
The truncated backend response retains its client parsing failure and still runs
the neighbor probe. A writer return or TCP EOF never establishes native EOS or
actual client commitment.

`review.py` reads physical artifacts and validates Content-Length or complete
chunk framing. `packets.py` proposes 35 prescribed observations for selected
original cases, keeping oracle evaluation, verdict and Root review pending.
It supplies no substitute Framework/MRTS revision when that identity is absent.
Qualification belongs to independent Root review, including the actual expected
metadata fields of the selected original case.

Fresh 15 October 2026 evidence found host request 4097 ->401 before authorization,
native request 1500/4096 ->403, P3 deny ->403, P4 Safe ->200, observer failures ->503,
and a complete 40019-byte application response while authorization-response
capacity remained32768. The capacity control separately measured 32768 ->200 with
backend inclusion and 32769 ->401 with backend exclusion after native allow 200.
Separate request and companion runs each recorded 13 native allocations, logging
calls and frees, then zero pending calls/live mappings and clean process cleanup.

Evidence also retains a metadata mismatch: actual P4 Safe log-only events report
`late_intervention=false` and omit the `late_intervention_mode` field. This is a fully qualified FAIL of the
original Safe metadata oracle. The large-response client received bytes before
native P4, independently demonstrating wire commitment. Client POST requests
produced native Common events with method GET on the authorization request;
original application-method inspection is consequently not established here.
Production diagnosis and any repair belong to the owning handoff, not this
producer. Full coverage of all original IDs is not claimed.

Current preparation exports every committed Parent regular file from the exact
`HEAD` Git tree, with file modes, SHA256 inventory and Gitlink revision metadata.
It excludes Git metadata, symlinks, Gitlink contents and uncommitted/untracked
producers. `CODEX_TEMP_ROOT` must name the configured private external storage
root; the destination must be fresh and physically beneath it. The exporter
writes the complete v2 source identity before applying the existing central
capture variant. The application receipt and frozen pre-capture inventory retain
the actual source revision and instrumentation hashes. Fixture-only changes,
including uncommitted acceptance producers, require separate explicit hashes;
they never inherit a committed-source identity. Preparation starts no host and
proves no runtime qualification.

The current Traefik variants use `../i12/capture_recipe.json` as their reviewed
regeneration input. It pins current product/helper input bytes and independent
observation output bytes. `../i12/regenerate_capture.py` regenerates the central
targets, exact contextual deltas, `capture_contract.json`, and the adapter seal;
`--check` compares every generated byte without writing:

The contextual patches use inert JSON text-line storage (`patch_kind=text_lines`).
Their hashes bind the exact decoded Unified Patch bytes, including whitespace
and context anchors. The registry validates those bytes before exact application.

```sh
rtk bypass "$FRAMEWORK_PYTHON" -P -B "$TEST_ROOT/connector_suite/adapters/traefik/harness/i12/regenerate_capture.py" --check
```

Regeneration requires the selected checkouts and the historical Parent Git
objects named in the recipe. No fetch, installation or host execution occurs.
For an intentional source update, review the source changes, observation anchors
and output bytes before changing the input/output pins; then run the command
without `--check` and review the generated diff. The runtime member relocation
and native commit-error accounting are adapted only in the historical matching
model. The actual current product is retained, including trusted provenance,
cancellation cleanup and incomplete-response guards.

Migrated Framework observer/header/SDK files are absent from a Parent export.
They are separately hash-bound and copied byte for byte from the selected
Framework, preserving current snapshot/finalize and SDK ABI guards. Their hashes
and Framework revision appear in the application receipt; they never become
committed Parent inventory entries. The generated compile command includes the
source root for their logical-root include paths. Obsolete repository-backed
registry objects are retained as byte-identical inert JSON line data with their
original Git provenance, so the global registry verification remains enabled.
Those historical bytes cannot authorize a current-product rollback. Request and
companion preparation still require separate fresh outputs and prove no host run.
