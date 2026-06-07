# MRTS Integration

MRTS is an optional framework-owned test-generation source for ModSecurity
compatibility probes. It is not connector code, and connector repositories
should only delegate to the framework MRTS targets.

MRTS is expected at `tools/MRTS` by default, but it is not vendored and is not a
framework submodule.

```sh
mkdir -p tools
git clone https://github.com/owasp-modsecurity/MRTS.git tools/MRTS
```

You can also use a separate local checkout:

```sh
MRTS_ROOT=/path/to/MRTS make mrts-generate
```

MRTS definition files live in:

```text
tests/mrts/definitions/
```

Generated MRTS files live under `tests/mrts/generated/` and are ignored by git.
They include generated ModSecurity rules, generated go-ftw YAML tests, imported
framework YAML cases, and `mrts.load`.

## Commands

```sh
make mrts-generate
make test-no-mrts
make test-with-mrts
make test-mrts-matrix
make mrts-ftw
```

`make test-no-mrts` does not require MRTS and does not append MRTS case roots.
If `EXTRA_CASE_ROOTS` is already set by the caller, it is preserved.

`make test-with-mrts` generates MRTS artifacts once, writes `mrts.load` once,
imports generated framework cases once, appends
`tests/mrts/generated/framework-cases` to `EXTRA_CASE_ROOTS`, and runs the
existing connector smokes.

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
topic, variable/collection, and connector scope when their case root is included
through `EXTRA_CASE_ROOTS`.

Cases are marked `active` only when request, expectation, phase, and variable
classification are reliable. Otherwise they are marked `pending` with:

```text
MRTS classification incomplete
```

Generated MRTS evidence remains optional and variant-specific. It does not
promote PASS status by itself, and existing RESPONSE_BODY/phase-4 non-promotion
policy remains unchanged.
