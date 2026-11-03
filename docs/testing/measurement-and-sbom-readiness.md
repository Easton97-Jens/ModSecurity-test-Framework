# Measurement and component SBOM readiness

**Language:** English | [Deutsch](measurement-and-sbom-readiness.de.md)

This is preparation for an explicitly selected later assessment. It does not run
that assessment or qualify any connector/protocol. The default 100 cases remain
unchanged. Historical targeted coverage retains its original source applicability.

## Final-pair prerequisites

Select clean, committed Parent and Framework checkouts and record their exact
HEADs; verify the intended Parent gitlink separately. Framework may deliberately
be tested before a separately authorized Parent pin update, but report that actual
pair. `CONNECTOR_REVISION` must identify the actual Parent HEAD. Use the configured
Framework-owned interpreter and import roots; do not substitute Parent's venv.
Canonical interpreter versions belong to each repository's current locks. Check
them before preparing environments. `ci/tools/bootstrap-python.sh` is the existing
Framework bootstrap; it installs dependencies and upgrades pip, so use it only
when that preparation is authorized, with an external `VENV_DIR` and an explicit
compatible `PYTHON_BIN`. It is not an offline or hashlocked bootstrap.

Python measurement additionally needs Parent's existing
`ci/requirements/sonar-coverage.txt` hashlock in an approved isolated tool
environment compatible with the selected tests. The exporter itself uses stdlib
only. Go measurement needs each actual module's compiler/cache and admitted test
overlay; native measurement needs matching compiler/gcov and fresh external
instrumented builds. Follow [host execution context](../host-execution-context.md)
before any required host execution. Missing prerequisites are blockers.

From Parent, with `P`, `F`, `PYTHON`, `MEASUREMENT_ROOT` and `TMP_ROOT` explicitly
set to approved absolute paths and `PARENT_SHA` to the selected exact HEAD:

```sh
rtk bypass env CONNECTOR_ROOT="$P" CONNECTOR_REVISION="$PARENT_SHA" \
  TEST_ROOT="$F" FRAMEWORK_ROOT="$F" PYTHONPATH="$F:$F/connector_suite" \
  PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "$PYTHON" -P \
  "$F/connector_suite/modsecurity_connector_ci/checks/analysis/run-sonar-coverage.py" \
  --language python --on-demand --output-root "$MEASUREMENT_ROOT" --temp-root "$TMP_ROOT"
```

This command is prepared for later authorization; repeat only the selected
languages (`python`, `go`, `native`), then `finalize-python` on the same output
root. Each language needs a fresh subdirectory. The runner preserves Parent-only
Python attribution, actual execution witnesses, selected tests and unmeasured
timing partitions. Manifests now record the actual Framework revision and dirty
state as well as Parent's. Finalization rejects missing/mismatched Framework
provenance before combining data. Historical manifests lacking that field remain
historical evidence; do not edit them to claim a new pair. `--allow-dirty` is
development evidence only and cannot establish final-pair qualification.

## Explicit-input partial SBOM

`ci/tools/export-component-sbom.py` emits deterministic
[CycloneDX 1.6 JSON](https://cyclonedx.org/docs/1.6/json/) with composition
`incomplete`. It is an exporter, not a resolver/scanner. Repeat input flags for
multiple files; all JSON/Go input files are bounded to 16 MiB, regular, single-link
files without symlink path components. Input hashes, selected absolute paths,
actual repository revisions/state and exporter SHA-256 bind the output. A new
external output file is required; existing files are preserved. Exit 77 means
invalid/missing input, stale/dirty source state, or invalid output. Error output
does not echo arbitrary input data. Supply reviewed metadata without secrets.
Repeated selection of the same input fails; identical component records shared
by different selected inputs appear once while retaining all input provenance.

Supported inputs:

- `--source`: current runtime lock `profiles`, or an object with `components`.
  Each entry has `component`/`name`, `version`, optional `id`/`profile`, and either
  `download_url` plus `sha256`, or `repository_url` plus exact `commit`.
  HTTPS URLs must be credential-free, without query/fragment. Release hashes
  attach to the distribution reference; a commit is not reported as a file hash.
  The current runtime lock has eight cache-profile records. It omits other native
  build dependencies and does not enumerate ten qualified runtime profiles.
- `--go`: the object stream from `go list -mod=readonly -m -json all`, run in each
  selected module directory using the intended build configuration. For an
  offline cached export use `rtk bypass env GOTOOLCHAIN=local GOWORK=off GOPROXY=off
  GOSUMDB=off go list -mod=readonly -m -json all > "$INPUT_ROOT/module.json"`.
  Missing cache entries fail; prepare them only through an authorized dependency
  workflow. Replacements and unresolved modules fail rather than guessing source
  identities. A module list does not establish a binary/package dependency graph.
- `--python`: JSON array from `rtk bypass "$PYTHON" -m pip list --format=json
  --disable-pip-version-check > "$INPUT_ROOT/packages.json"`. It describes that
  environment's installed distributions, not their linkage into the product.
- `--artifacts`: JSON array with `name`, `version`, `profile`, `path` and a nonempty
  `build` object containing reviewed compiler, flags and source descriptions.
  Relative paths resolve beside this input file. The exporter streams actual
  artifact bytes into SHA-256 and rejects files changing during hashing. Build
  descriptions remain supplied assertions; they are not executed or promoted
  into verified linkage. For example:

```json
[{"name":"connector-module","version":"development","profile":"nginx-h2",
  "path":"build/connector.so","build":{"compiler":"record actual compiler",
  "flags":["record actual flags"],"source_revision":"record actual source"}}]
```

Example with known inputs and exact selected HEADs:

```sh
rtk bypass "$PYTHON" "$F/ci/tools/export-component-sbom.py" \
  --parent-root "$P" --parent-revision "$PARENT_SHA" \
  --framework-root "$F" --framework-revision "$FRAMEWORK_SHA" \
  --source "$F/ci/provisioning/runtime-component-lock.json" \
  --go "$INPUT_ROOT/module.json" --python "$INPUT_ROOT/packages.json" \
  --artifacts "$INPUT_ROOT/artifacts.json" --output "$INPUT_ROOT/components.cdx.json"
```

Omitted classes remain unmeasured. The exporter never claims complete native
transitivity, OS/container packages, resolved binary linkage, security freedom or
runtime success. Supplying all four input classes still yields incomplete scope.
For full native/container SBOM acceptance, first select actual artifacts/images,
their build/OS/linkage evidence and an approved resolver or generator. Validate
the emitted file with the official [1.6 schema](https://github.com/CycloneDX/specification/blob/1.6/schema/bom-1.6.schema.json)
in an approved existing schema-validation environment. The exporter adds no
mandatory scanner or dependency. Version age alone does not justify an update;
reassess concrete affected component/features against primary advisories.

Focused on-demand exporter checks:
`rtk bypass "$PYTHON" -m unittest -v tests.ci_security.test_component_sbom`.
