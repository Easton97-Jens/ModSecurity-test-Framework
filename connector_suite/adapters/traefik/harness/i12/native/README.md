# Traefik native I12 host measurements

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

`prepare.py` consumes the existing central `traefik-native` capture objects and
copies historical build scaffolding into an explicitly selected external root.
Every Common/Traefik C/header and native Go build input is refreshed from the
current checkout before the exact hash-checked observation overlays are applied.
The resulting product/capture binding, sealed file ledgers and controller
admission remain separate from runtime qualification.

The seven host probes cover a chunked request, delayed response writes,
P1/P2/P3 denial, late P4 Safe denial, MIME exclusion and an independent neighbor.
The separate client retains socket bytes and the backend retains received entity
bytes. A denied P1/P2 request must have no backend request. MIME/charset decisions,
native EOS, Finish and Free require native observer records. TCP EOF proves only
the transport observation. A client process exiting successfully records a
completed measurement; inspect `oracle_pass` for its actual expected outcome.

Preparation never launches a host:

Preparation requires `CODEX_TEMP_ROOT` to name the existing configured external
storage root. Export it from the active project configuration before these
commands. The output must be a fresh physical descendant; existing ancestors
inside that root must belong to the invoking UID and prohibit group/world writes.

```sh
rtk proxy "$FRAMEWORK_PYTHON" -P -B "$TEST_ROOT/connector_suite/adapters/traefik/harness/i12/native/prepare.py" \
  --repo "$CONNECTOR_ROOT" \
  --historical /absolute/approved/historical/source-run \
  --output "$CODEX_TEMP_ROOT/runs/task/native"
```

Use only the separately reviewed private controller, its unchanged nonroot
admission checks and task-local resource/storage budget. Review `admission.json`
and all sealed bindings before launch. Do not launch archived drivers against
old evidence or a product checkout. The output root must be new for preparation. All three preparation commands
reject symlinked paths, Git checkout destinations and paths outside the configured
external storage before writing; followups also require fresh output targets.

`review.py ATTEMPT_DIRECTORY` summarizes fresh physical client/backend/native
and host records, executable/library maps and controller cleanup. Its output
deliberately keeps qualification false pending independent original-oracle and
complete lifecycle packet review. It does not update the central I12 ledger.
`prepare_followup.py ROOT faults-v3` prepares a separate real-engine UDS relay
fixture for corrupt MSE1 replies, internal error replies, actual opcode10
`AcknowledgeApplied`, a delayed16KiB response with a second-chunk error and an
active client RST. The physical relay log records the exact injected opcode.
`strict` separately tests profile admission; a rejected Strict configuration
does not establish a supported Strict lifecycle. `mime` separately exercises
request/response Content-Type and charset presence/absence and MIME exclusion.

The central host observer admits only its two historical synthetic IDs.
`prepare_host_scope.py ROOT` makes a separate sealed source copy with only that
observer allowlist expanded to the18 declared synthetic IDs. Retake using its
`admission-*-host-v2.json` specs. Earlier runs with nonadmitted IDs remain partial
measurements. `packet.py ATTEMPT LABEL ORIGINAL_CASE_ID` emits all35 prescribed
observation fields for independent review; absent callbacks remain unknown.
It never evaluates the oracle or grants qualification. Real fault outcomes can
include zero client bytes despite a logical host write; report that physical
outcome separately from an HTTP recorder or a native deny decision.

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
