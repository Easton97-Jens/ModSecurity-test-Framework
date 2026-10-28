# MRTS preparation and handoff

**Language:** English | [Deutsch](mrts-preparation.de.md)

The Framework owns corpus selection, generation, import, schema validation,
rule-load creation and runner handoff. The pinned `tools/MRTS` repository is a
read-only generator of rules and FTW definitions. Connector owners control host
ports, processes, cleanup and runtime evidence.

## Package interface

Use the Framework-owned interpreter with its declared PyYAML dependency. The
generator needs PyYAML; this interface does not run MRTS host orchestration or
install MRTS dependencies. Pass absolute, explicit repository and output roots:

```sh
"$PYTHON" "$FRAMEWORK_ROOT/ci/provisioning/mrts-package.py" prepare \
  --framework-root "$FRAMEWORK_ROOT" --mrts-root "$MRTS_ROOT" \
  --connector-root "$CONNECTOR_ROOT" --build-root "$BUILD_ROOT" \
  --package-root "$BUILD_ROOT/mrts/package" --include-feature-demo 0
```

`BUILD_ROOT` must be a dedicated permitted external runtime directory. Package
destinations must be fresh children of `BUILD_ROOT/mrts`; source checkouts,
traversal and symlinked destinations are rejected. Output is generated in a
private staging directory and published by one directory rename after every
selected corpus succeeds. An existing destination is rejected; choose a fresh
destination for regeneration. A failure preserves an earlier package but does
not select or reuse it. Successful commands print the resulting root on stdout
and preparation diagnostics on stderr.

`--upstream-definitions DIR` and `--feature-demo-definitions DIR` select explicit
definition directories instead of the pinned defaults. Only selected corpora
are accessed. With `--include-feature-demo 0`, demo generation and import do not
run, and the manifest records `feature-demo: disabled`. With value `1`, both
corpora must generate, import and validate; cross-corpus rule-ID collisions are
fatal. The pinned demo currently has overlapping IDs, so enabling it may fail
visibly. Disabled demo cases are not executable reference cases in this path.

The package contains `upstream-config-tests/` and, when selected,
`feature-demo/`, each with `rules/`, `ftw/`, `framework-cases/` and `mrts.load`.
Private definition snapshots live under `definitions/`. The generator wrapper
and definition guard validate these snapshots before invoking MRTS. The existing
importer remains the only FTW-to-Framework conversion implementation. It
preserves string types through YAML, including header name `"2"`, repeated
headers and order, and retains strict header/control-character checks. A direct
import also stages the complete case catalog before replacing an older one.

## Verification and private execution

Run the same command with `verify` to reuse a package. `manifest.json` binds the
Framework, MRTS and Connector revisions, relevant Framework source digests,
Python/PyYAML versions, selected corpora, complete definition selection and
hashes, artifact hashes, unique case IDs and import/validation status. Verification
requires the checked-out MRTS revision to match the Framework gitlink and a clean
MRTS tree. Changed, added or removed definitions, altered artifacts, differing
source identities or a different demo selection require fresh preparation.
`MODSECURITY_MRTS_PREPARED=1` alone is insufficient: shell consumers also require
`MRTS_PACKAGE_ROOT` and verify the manifest.

For every connector execution, create a separate private copy:

```sh
"$PYTHON" "$FRAMEWORK_ROOT/ci/provisioning/mrts-package.py" materialize \
  --framework-root "$FRAMEWORK_ROOT" --mrts-root "$MRTS_ROOT" \
  --connector-root "$CONNECTOR_ROOT" --build-root "$BUILD_ROOT" \
  --package-root "$BUILD_ROOT/mrts/package" --include-feature-demo 0 \
  --output-root "$BUILD_ROOT/run-apache/package" --port 18080
```

When using custom definition directories, pass those same directory options
for `verify` and `materialize`. The destination must be absent and inside
`BUILD_ROOT`, separate from the prepared package. Materialization verifies the
package, copies it, rewrites only private FTW input ports and generated path
references, validates the imported cases and publishes the copy atomically.
`materialization.json` records the source manifest hash, port and private
artifact hashes. The shared package is unchanged. This file describes a prepared
copy, not a host-test result. Same-UID trusted operators can mutate files; this
is integrity checking and private preparation, not process isolation or a signed
artifact system.

`ci/lib/mrts-common.sh` uses this interface for `prepare_mrts_runtime_variant`.
Each shell/connector obtains its own copy and adds its imported case roots and
load files to the runner. Optional existing preambles remain in separately
named combined load files. The `mrts-generate`, `mrts-import`, `mrts-load` and
`mrts-ftw` Make entry points use the same preparation path. The first and third
print the package root and upstream load-file path respectively. Preparation
can produce more cases than a particular test selection executes; it does not
enlarge the active default test inventory.

## Result integrity

`ci/lib/mrts_results.py` is shared by the native job writer and native report
consumer. It matches go-ftw JSON result IDs to the selected private FTW cases and
keeps selection, attempted/executed, PASS, FAIL, SKIP, ignored, forced and missing
results separate. Duplicate/conflicting IDs, forced outcomes, empty mandatory
selections, missing results and writer failures prevent a runtime PASS. Aggregate
attempt counts never supply missing PASS observations. Reports revalidate the
structured source rather than trusting a cached job PASS. Legacy text without
selection-bound observations remains incomplete. A valid prepared manifest is
not host-runtime evidence.

## Integration order and scope

Deliver Framework changes first. Then review the separate Connector caller and
result changes against this interface. After a separately authorized Framework
merge, update the Parent Framework gitlink to the verified merged revision in
an explicit pin-update task, then integrate the dependent Connector change.
Neither preparation nor these source changes update `tools/MRTS` or its pin.
No direct default-branch push or automatic merge is required.

The general transfer of tests into the Framework remains separate. Its only
touchpoints are this Framework-owned MRTS helper/importer/report interface and
the Parent native caller. HTTP/2, HTTP/3, coverage and historical full matrices
are outside this change. A real H1 proof must separately link a selected
definition, generated rule, imported case, actually loaded connector and
observed result to a validated report; generation/schema checks alone do not
provide that proof.
