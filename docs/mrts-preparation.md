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

Package preparation and result handling share the external-root checks in
`ci/lib/mrts_path_safety.py`. Select the runtime root independently of incoming
definition, result and manifest paths. It must be separate from the executing
Framework checkout and configured source checkouts, including their ancestors;
system directories and the general temporary directory are rejected. The
nearest existing directory must belong to the current user and permit no group
or public writes. Ancestors must belong to the current user or root; a writable
shared ancestor requires sticky-directory protection. If `CODEX_TEMP_ROOT` or
`RUNNER_TEMP` is configured, the runtime root must be a proper descendant of at
least one of them. Traversal and symlink components are rejected before path
resolution.

`--framework-root` must match the checkout containing the executing package
script. Preparation invokes only its fixed generator, importer and load-writer
entry points, using validated absolute operands. Shell and Git executables are
selected from system search directories; the importer uses the current Python
interpreter. Executables must be regular, executable files owned by the current
user or root without group or public write permission. Caller-controlled `PATH`
entries do not select those Shell and Git executables.

The definition guard starts the trusted generator in an isolated Python child
with explicit bytecode suppression (`-I -B`). A fixed bootstrap admits only the
resolved generator directory for MRTS adjacent imports, preserves generator
arguments and executes it with `runpy`. Inherited `PYTHONSAFEPATH=1` therefore
works without admitting caller Python paths, changing the parent interpreter,
or writing bytecode into the pinned MRTS checkout.

`--upstream-definitions DIR` and `--feature-demo-definitions DIR` select explicit
definition directories instead of the pinned defaults. Only selected corpora
are accessed. With `--include-feature-demo 0`, demo generation and import do not
run, and the manifest records `feature-demo: disabled`. With value `1`, both
corpora must generate, import and validate; cross-corpus rule-ID collisions are
fatal. The pinned demo currently has overlapping IDs, so enabling it may fail
visibly. Disabled demo cases are not executable reference cases in this path.

Definition directories must be flat. Both package selection and the direct
generator guard reject subdirectories, including `base.yaml` alongside
`extra/additional.yaml`, before generating a partial corpus. Adding a nested
definition after preparation also prevents verification and materialization.
Move definitions into one reviewed flat directory before preparing a package.

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

Source binding includes the path guards (`mrts_path_safety.py` and
`runtime_path_safety.py`), shell provisioning libraries and entry points,
definition guard, importer, classifications and `runner_core.py`. It also binds
the runner's transitive Framework imports: `adapter_interface.py`,
`case_roots.py`, `msconnector_models.py` and `generated_report_utils.py`.
The manifest additionally binds every Python file in the fixed Framework-owned
`modsecurity_test_framework/` public namespace, including its package aliases
and context/result helpers. The full discovered path/digest map is compared on
reuse: added, removed or changed sources invalidate it. Namespace traversal and
reads reject symlinks and enforce file, depth and byte limits; incoming
environment paths cannot extend the source scope. Changing only one bound file
invalidates reuse even when Git HEAD stays unchanged. Packages prepared with the older, smaller source set need regeneration.

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

When invoking the result writer as a standalone CLI, explicitly export the
trusted `BUILD_ROOT` selected for the run (`export BUILD_ROOT`). The result CLI
has no build-root argument and does not derive authority from a supplied
result, FTW directory or output path. All result inputs and destinations must
be children of that approved root, with owned directories that permit no group
or public writes and without traversal or symlink components. Missing
`BUILD_ROOT` or an invalid path fails the writer. The package CLI continues to
take the explicit `--build-root` argument shown above.

The standalone result CLI and shared MRTS path guard load their actual path
functions from fixed adjacent Framework files with `runpy`. They work with
`PYTHONSAFEPATH=1` without depending on script-directory lookup, changing global
module search paths, adding module aliases or consulting a Connector checkout.

## Integration order and scope

Parent PR #432 has already merged. Framework PR #139 continues separately;
the sequence below describes the original dependency plan. A Framework pin
update remains a separate action after the Framework merge.

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
