# MRTS Integration

MRTS is a framework-owned test-generation source for ModSecurity compatibility
probes. It is not connector code, and connector repositories should only
delegate to the framework MRTS targets.

MRTS is included as a required framework submodule at `tools/MRTS`. Initialize it
after cloning the framework:

```sh
git submodule update --init --recursive
```

MRTS targets use `tools/MRTS` by default. You can also use a separate local
checkout:

```sh
MRTS_ROOT=/path/to/MRTS make mrts-generate
```

If `tools/MRTS` is missing or not initialized, MRTS targets exit with status 77.
Run `git submodule update --init --recursive` to restore the default checkout.

MRTS source inputs are read directly from the MRTS submodule:

```text
$MRTS_ROOT/config_tests/
$MRTS_ROOT/feature_demo/config_tests/
```

The default runnable corpus is the upstream MRTS config-test corpus:

```text
$MRTS_ROOT/config_tests/
```

Feature-demo config tests remain visible as optional/demo coverage, but they are
imported as pending/non-runtime by default:

```text
$MRTS_ROOT/feature_demo/config_tests/
```

Golden references live under `$MRTS_ROOT/generated/` and
`$MRTS_ROOT/feature_demo/generated/`. They are drift/reference inputs only: they
are never included in `mrts.load`, never imported as runtime framework cases,
and never appended to `EXTRA_CASE_ROOTS`.

Generated MRTS files live under `$MRTS_BUILD_ROOT`, which defaults to
`$BUILD_ROOT/mrts`. They include generated ModSecurity rules, generated go-ftw
YAML tests, imported framework YAML cases, and `mrts.load`:

```text
$MRTS_BUILD_ROOT/upstream-config-tests/{rules,ftw,framework-cases,mrts.load}
$MRTS_BUILD_ROOT/feature-demo/{rules,ftw,framework-cases,mrts.load}
```

## Commands

```sh
make mrts-generate
make test-no-mrts
make test-with-mrts
make test-with-mrts-feature-demo
make test-mrts-matrix
make mrts-ftw
```

`make test-no-mrts` does not require MRTS and does not append MRTS case roots.
If `EXTRA_CASE_ROOTS` is already set by the caller, it is preserved.

`make test-with-mrts` generates MRTS artifacts once, writes `mrts.load` once,
imports generated framework cases once, appends the build-root upstream MRTS
framework case directory to `EXTRA_CASE_ROOTS`, and runs the existing connector
smokes. By default, `mrts.load` includes only generated rules from
`upstream-config-tests`.

Feature-demo runtime is explicit opt-in only:

```sh
MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO=1 make test-with-mrts-feature-demo
```

The opt-in path checks for rule-id collisions before it allows feature-demo
rules into `mrts.load`.

`make mrts-ftw` runs go-ftw directly when `go-ftw` and
`tests/mrts/ftw.mrts.config.yaml` are available. It is optional and is not part
of `smoke-all`.

## Variants And Results

MRTS combines with the existing CRS variants:

```text
$BUILD_ROOT/results/no-crs/no-mrts
$BUILD_ROOT/results/no-crs/with-mrts
$BUILD_ROOT/results/with-crs/no-mrts
$BUILD_ROOT/results/with-crs/with-mrts
```

If `RESULTS_DIR` is explicitly set, MRTS helpers preserve it.

## Coverage Classification

Imported MRTS cases carry `metadata.source: mrts` and are counted by phase,
topic, variable/collection, connector scope, and MRTS corpus when their case root
is included through `EXTRA_CASE_ROOTS`.

Cases are marked `active` only when request, expectation, phase, and variable
classification are reliable. Otherwise they are marked `pending` with:

```text
MRTS classification incomplete
```

Generated MRTS evidence remains optional and variant-specific. It does not
promote PASS status by itself, and existing RESPONSE_BODY/phase-4 non-promotion
policy remains unchanged.

Report categories distinguish `runnable: upstream-config-tests`,
`optional/demo: feature-demo`, `golden-only: upstream-generated`, and
`legacy/reference: framework-curated`.

## Native Infrastructure Overlay

The framework carries an experimental NGINX PR24 overlay under
`tests/mrts/infra-overlays/nginx-pr24/`. The overlay is staged into
`$MRTS_NATIVE_ROOT` for native MRTS runs, and all runtime path, port, module,
log, and command edits happen only in that staging copy. Replace this overlay
with `$MRTS_ROOT/config_infra/nginx_linux` once MRTS PR 24 is merged upstream.
