# I12 private capture sources

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

This test-only source contract preserves the exact NGX, HAProxy, Envoy, Apache,
Traefik and lighttpd capture implementations used for I12 review. It neither
changes connector product files nor launches a host. A source application,
configuration load, build or driver exit does not establish runtime qualification.
Root reviews original physical observations and the independently sourced oracle
separately.

`manifest.json` maps logical source names to SHA256 objects. Identical collectors,
clients and backends occur once. Close variants are exact unified deltas against a
shared object. The header and SDK accessor remain repository references; the
historical C base `0d903fc5…` is frozen as lossless line data. Historical C52/H5,
C270/H5 and Ca4/H581 variants remain hash-bound deltas, without copied observer
trees. The live shared observer identity is C `5038d006…`, H `5b7d8fa7…`,
SDK accessor `89ff282b…`; see the manifest
for complete hashes. Historical profile input hashes bind to
`8cc32dceb06121f589150a9794f28878c5e4ba2a`; current-copy revision binding is
separate as described below.
Historical scoped-equivalent revisions and distinct observer ABIs remain explicit.
Stored deltas use zero context; whole-base and result hashes still cover every
byte and native patch application is checked without fuzz. One archived helper
with original trailing whitespace uses transparent JSON-line storage. Export
restores its exact original bytes; source is neither trimmed nor normalized to
pass whitespace checks.

| Source variant | Separate capture scope |
| --- | --- |
| `nginx` | Exact three-TU host overlay, typed host helper, driver/backend and waited client; supported Safe fixture09 |
| `haproxy-direct` | Native HTX binding/filter and SSL-write capture |
| `haproxy-companion-host` | Separate response-companion host variant |
| `haproxy-spop-agent` | Separate diagnostic request-agent/backend variant |
| `envoy` | Shared ext_proc/authz capture source; actual authz backend and distinct ext_proc backend retained separately |
| `apache` | Historical exact three product-TU overlays and APR/native/host helpers |
| `apache-current` | Same Apache capture after-bytes; current native C/H before-pins and mandatory complete v2 export |
| `lighttpd` | Separate stock-sidecar and patched-native fixtures, including original and empty cases |
| `traefik-native` | Actual native-UDS middleware/engine/runtime observation variant |
| `traefik-forwardauth` | Separate authorization/response-observer source variant |

The ten **source-application profiles** comprise nine historical variants plus
`apache-current`. Runtime route counts remain independent. Shared source never
transfers execution, EOS, identity or outcome between logical routes.
Framework and MRTS repositories/gitlinks remain outside this contract. Private
fixture definitions are run-scoped capture inputs, not reusable catalog additions.

## Immutable source records and maintained analysis code

The 61 historical source-like `text` objects and the historical shared C observer
repository anchor are now stored as lossless `text_lines` JSON data. These 62
objects reconstruct 346,634 exact original bytes. Together with the 10 existing
line objects, the registry contains 72 line objects, 16 other text objects,
48 deltas and 19 repository objects. Each JSON string retains its original line
ending and whitespace. The 53,532-byte C observer anchor is authenticated against
commit `30d50a181278904a552e295d9a2c1ae1265e8b87` and retains identity
`0d903fc5e6432769a136931b7ebea16a6f87db941d28d23583ccccf4c75e6537`.
Reconstruction must reproduce the original bytes and SHA256 identity exactly.
Historical profile bindings, before/result hashes and delta identities are
unchanged. The explicit current-copy C pins in `apache-current`,
`traefik-native` and `traefik-forwardauth` bind the live `5038d006…` observer;
they do not change the historical capture after-bytes.
The registry rejects source-code suffixes in plain `text` storage and requires
`.json` storage for `text_lines`. Materializing verified historical bytes in an
explicit disposable copy remains a separate operation and grants no execution
or current-revision qualification.

Current Envoy parsing uses the maintained `envoy/host_log_observations.py` and
`envoy/grpc_stream_observations.py` modules. Current consumers do not execute
modules from the object store or a CLI-selected helper directory. The retained
helper files are read only to authenticate historical provenance. New reviews
and original-case packets record the maintained parser hashes separately from
the historical helper hashes. Historical reports and approvals retain their
original identities; they are not reclassified as results of the new parsers.

The master-owned CI Sonar analysis classifies Python test files through
`sonar-project.properties` and uses Python `3.15`. Maintained sources, validators,
parsers and tests remain analyzable. No issue, source or duplication exclusion
is used for this storage transition.

## Verify and apply

With the explicit source-checkout environment above:

```sh
rtk proxy "$FRAMEWORK_PYTHON" -P -B "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/i12/capture_sources.py" verify
ON_DEMAND_TESTS=1 rtk proxy "$FRAMEWORK_PYTHON" -P -B -m unittest discover -s "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/i12" -p test_capture_sources.py -v
```

Tests require `I12_TEST_ROOT` or `RUNNER_TEMP` to select existing authorized
external storage; they write only temporary data there.
The source application uses the external storage root declared in the manifest.

Prepare a **disposable source copy**, without Git metadata, symlinks or hardlinks.
Copy the required base files listed in the selected variant's `source_targets`;
each non-null `before_sha256` must match exactly. Required SDK/upstream sources,
generated headers and toolchains are separate build inputs, not bundled artifacts.
Create `.i12-disposable-source-copy.json` in that external copy with exactly:

```json
{
  "format": "i12-disposable-source-copy-v1",
  "path": "/absolute/external/disposable-i12-copy",
  "disposable": true,
  "parent_sha": "8cc32dceb06121f589150a9794f28878c5e4ba2a"
}
```

The path must identify the actual physical copy. Then, for example:

```sh
rtk proxy "$FRAMEWORK_PYTHON" -P -B "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/i12/capture_sources.py" apply --profile nginx --source-copy "$CODEX_TEMP_ROOT/disposable-i12-copy"
```

The tool verifies all bases and objects before writing, applies exact-context
deltas without fuzz, and records resulting hashes in
`i12-source-application-receipt.json`. Capture programs are materialized below
`.i12-capture/<variant>/` and are never imported or executed. A missing marker,
changed base, changed delta, Git checkout/metadata, symlink, hardlink, path escape
or existing capture destination is rejected. Git metadata belonging to the
declared external **storage control plane** is outside the disposable subtree;
it does not authorize a checkout nested within that subtree.

## Current revision and complete export inventory

The v1 marker and its fixed historical input baseline remain supported unchanged.
Current source copies use **v2**. A current revision must never be labelled with
that historical baseline. The trusted source producer exports the complete
committed Parent tree with `git archive`, and records `git ls-tree` file modes,
tree identity and gitlink revisions. Gitlink contents are excluded. The producer
binds these Git commands and their exact revision independently; the capture tool
does not authenticate a commit merely because a marker contains 40 hex digits.

The v2 marker has exactly these fields:

```json
{
  "format": "i12-disposable-source-copy-v2",
  "path": "/absolute/external/disposable-current-copy",
  "disposable": true,
  "source_revision": "850879e82ea729f274cb383507b05938df06027a",
  "snapshot_manifest": ".i12-source-export-manifest.json",
  "snapshot_manifest_sha256": "<complete lowercase SHA256 of the frozen inventory>"
}
```

Replace the illustrative path/revision and SHA256 placeholder with the actual
producer-bound values. `.i12-source-export-manifest.json` has exactly `format`
(`i12-source-export-manifest-v1`), `source_revision` (matching the marker),
`git_tree` (complete 40-character lowercase Git tree identity), `files`, and
`gitlinks`. `files` maps **every** exported Parent regular-file path to exactly
`{"mode": 420, "sha256": "<complete lowercase SHA256>"}`; executable Git files
use mode 493 instead of 420. The file hash covers all bytes, including binary
fixtures. `gitlinks` maps each exported gitlink path to its full 40-character
revision; an absent or empty gitlink directory is permitted, its contents are not.
Both mappings use bounded relative paths without Git metadata or path escapes.

Only the marker and inventory themselves are excluded from that complete file
inventory. Duplicate fields, unknown schema fields, revision/hash mismatches,
missing or extra files/directories, wrong file modes, links, special filesystem
objects and gitlink contents are rejected before capture writes. Every selected
profile `before_sha256` is still checked independently; a valid new snapshot
cannot authorize a changed capture base. Validation reads all inventory files and
refuses files that change while being hashed. The full frozen inventory remains
in the copy after capture and describes the **pre-capture** source, not build
outputs. Build in a separate directory after applying capture; a used copy cannot
be submitted as an untouched export again.

Use `--profile apache-current` for the current committed checkout's complete
v2 export. This additive profile changes only the native observer C/H
`before_sha256` pins from `ad8e5e36…`/`f9f63b62…` to
`5038d006…`/`5b7d8fa7…`; all capture after-bytes, product overlays, SDK3.0.14 ABI
and historical `apache` profile remain unchanged. Its declared
`required_source_identity_format` rejects a v1 marker before any writes, even
when the source bytes otherwise match. Registry verification rejects unknown
required formats. The source-application name does not create a new run,
transaction or runtime route: the native profile remains `apache-native`.
Historical package/build provenance stays labelled historical; a new full build
and actual loaded images need their own evidence.

The integrated shared repair preserves five historical HAProxy/lighttpd objects
as lossless text-line objects. Their content hashes and historical output hashes
remain unchanged. Registry verification covers 155 objects; this count does not
count host executions or qualified requirements.

The application receipt records `source_revision`, `source_git_tree`, inventory
SHA256, file count and gitlink metadata separately from
`delivery_product_baseline`. This prevents a current build from inheriting the
historical baseline identity. Preserve that receipt, the inventory, producer
commands and source hashes alongside the instrumentation delta and build/load
evidence. The inventory/receipt prove source application only; they do not prove
a complete build, loaded-module identity or a qualified host transaction.

The current shared observer matches the selected public SDK constructor's
`char *` or `const char *` qualification without dropping compiler warnings.
Historical `ad8e5e36…`/`f9f63b62…` objects remain exact reverse deltas from their
pinned base objects; the C base is frozen independently of the live observer.
All earlier profile and object result hashes remain
unchanged; native ABI variants still require their own complete build binding.

## Build, ABI and evidence boundaries

Retained prepare/build/driver scripts are exact source records. Some contain
historical run paths; others use the sealed controller ABI `/mnt/src`,
`/mnt/fixtures`, `/mnt/artifacts` and `/task`. Inspect them and review relocation
before a new run. Relocated or edited bytes need a new source/hash binding. This
tool does not recreate, relax or bypass the approved controller's UID, peer,
resource, ownership, filesystem or capability checks. Do not execute archived
launchers directly against a product checkout or old evidence directory.

- NGX binds nginx1.31.6, SDK3.0.14 and the original 33 Parent TUs plus one generated
  registration TU. Fixture09 omits native MIME Clear: SDK3.0.14's merge discards
  same-load MIME additions when Clear is set. Preserved fixture08 remains the
  distinct measured MIME-out case. Native limits and MIME decisions remain SDK
  owned. The driver has a real HTTP backend in a dedicated thread; clients are
  separate waited processes. Connection/URI/header-add APIs remain unwrapped.
- HAProxy binds3.2.25, SDK3.0.14, the declared37 GNU wraps and separate SSL_write
  helper. Direct, companion-host and agent sources are distinct. Public
  `openssl.cnf` files are configuration only; no key or certificate is included.
- Envoy binds the recorded Go1.27.2/native SDK3.0.14 contract. The eight exact
  C/Go/build source changes and two source-copy Go regression files remain
  separate from physical host evidence. Existing strict CL/chunked and gRPC
  terminal-parser controls are retained as source and can run after materialization.
- Apache binds2.4.66/APR1.7.6/SDK3.0.14. The historical C17/F-PIC/no-LTO overlay
  relinks baseline module objects using real APR flags/system Apache headers;
  this is not a claim of a clean full module rebuild.
- lighttpd binds1.4.85/SDK3.0.14. Patched native needs the existing repository patch
  `connectors/lighttpd/patches/0001-lighttpd-msconnector-stream-hooks.patch`, exact
  hash in the manifest, and `LIGHTTPD_MSCONNECTOR_STREAM_HOOK_ABI_VERSION=2`.
  Stock modules are incompatible. Use matching generated core headers and the
  existing native build scripts. Borrowed synchronous HTTP/1.x entity callbacks
  occur before transfer framing; HTTP/2 is excluded.
- Traefik native and forwardAuth retain their distinct exact source and observer
  revisions. Their native C/Go/SDK build inputs require the owning native recipe;
  this source export does not establish a fresh build or host version.

Compiler warnings, native pins, SDK-owned body limits, original unknown oracles
and historical observations remain unchanged. The manifest excludes keys,
certificates, binaries, archives, caches, Git metadata and heavy raw evidence.
Any new execution still requires independently bound loaded images, effective
configuration, real clients/backend, native phases/EOS/finish/free, physical logs,
cleanup, neighbor health and Root review.

## Intentional original oracle nulls

The oracle reconciler accepts `intentional_null_fields.visible_status` only for
an original, explicitly present `visible_status: null` without an unresolved
expectation reason. Root must separately interpret that field and supply physical,
versioned primary proof bound to the record's independent sources. The complete
effective oracle must remain byte-semantically identical to the original; this
declaration cannot accompany a correction or replacement expectation. Missing
`native_result`, `phase` or `visible_status` is still rejected. For example, the
original `phase2_over_limit` contract leaves the client status configuration
dependent; its null is distinct from an unknown fixture or missing measurement.

This source-only disposition preserves the original null and awards no lifecycle
qualification. Client/host observations, all applicable lifecycle fields, fresh
execution and separate Root packet review remain mandatory. Other null fields
and unresolved original oracles cannot use this exception.

## Reviewed current Traefik input bases

The existing `traefik-native` and `traefik-forwardauth` variants also accept
`current_before_sha256` for their two shared observer input files, exclusively
following successful complete v2 inventory validation. These are explicit,
reviewed hashes in the manifest, never values inferred from the supplied copy.
The original `before_sha256` and all instrumented result hashes remain unchanged.
A v1 marker cannot select the current alternative. The application receipt records
`actual_before_sha256` for every source target, including `null` for new files.
Unknown source bytes and changes outside the selected targets remain rejected.

Three historical HAProxy repository objects are frozen as lossless `text_lines`
objects authenticated against commit `8cc32dceb06121f589150a9794f28878c5e4ba2a`.
Their identities and all dependent delta/result identities are unchanged. This
preserves historical source verification after unrelated product files advance;
it adds no HAProxy runtime claim or profile extension.

Three historical Traefik anchors (`common/runtime/msconnector_runtime.c`,
`common/runtime/http_authorization_service.c` and
`connectors/traefik/response_observer/observer.go`) are likewise frozen as lossless
`text_lines`, authenticated against commit
`3a1bafecd0c38ccf20427d580c767ed42addf4aa`. Their original SHA256 identities,
dependent deltas, profile input/result hashes and provenance remain unchanged.
This repairs historical registry verification when those product files advance;
it neither authorizes changed current input bytes nor establishes runtime evidence.

The historical NGINX `connectors/nginx/src/ngx_http_modsecurity_access.c`
anchor is also frozen as lossless `text_lines`, authenticated against commit
`c03352ba160675a94bf63125cceaa25367f52c27`. Its original SHA256 identity,
dependent observation delta and profile hashes remain unchanged. This keeps
complete registry verification valid after the current NGINX product source
advances and grants no current-source or runtime qualification.

The maintained Traefik process controls use `ci/lib/i12_process_observation.py`
instead of importing a historical driver. Controls that inspect or instrument
archived driver text obtain it through `Registry.content`, including its exact
hash check. Apache controls similarly reconstruct their pinned C/H records into
a private disposable test directory before compilation. Neither operation adds
scenarios or promotes historical evidence.
