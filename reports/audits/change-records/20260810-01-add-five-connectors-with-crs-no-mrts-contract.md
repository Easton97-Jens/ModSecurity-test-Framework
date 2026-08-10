# Change record

**Language:** English | [Deutsch](20260810-01-add-five-connectors-with-crs-no-mrts-contract.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260810-01-add-five-connectors-with-crs-no-mrts-contract` |
| UTC date | 2026-08-10 |
| Framework base revision | `03880bf` (observed task-worktree base; delivery facts are recorded below after observation) |
| Issue or pull request | [Draft PR #74](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/74); observed exact head `58e8d410ba15f1a96538362e7ce259dbd5a335cd` passed the listed hosted checks before this record update. The PR was a Draft at observation and no merge was requested. |

## Motivation and problem statement

Add a reusable, fail-closed Framework evidence contract for the distinct
With-CRS/No-MRTS profile without turning static validation into a connector
runtime claim.

## Affected components and security boundaries

The contract validates controlled, host-provided evidence at the
Framework/connector boundary. It has a closed five-connector inventory:
`apache`, `haproxy`, `envoy`, `traefik`, and `lighttpd`. NGINX is excluded only
from this profile, not from the general six-connector boundary. MRTS remains a
read-only external dependency: every accepted normalized record and its typed
raw cleanup record bind the profile's explicit No-MRTS state, but this record
does not claim a host-side MRTS-process observation.

## Acceptance criteria

- The profile is limited to the exact five connectors and rejects NGINX.
- The canonical CRS fixture binds the allow control and rule `942270` deny
  control to the official CRS `v4.28.0` tag, whose peeled object must equal
  commit `55b09f5acfd16413e7b31041100711ceb7adc89c`.
- The validator fails closed for incomplete, mismatched, unsafe, or
  non-No-MRTS evidence, binds strict raw request/block/cleanup records, and
  never overwrites result paths. Each parsed artifact and recorded digest come
  from one no-follow file-descriptor snapshot; a concurrent name swap fails.
- Output artifacts are `CONTRACT_VALIDATED` and `UNATTESTED`; they cannot be
  promoted to a connector-host runtime PASS by this Framework-only change.
- English and German reader documentation state the evidence boundary and the
  canonical CLI interface.

## Alternatives considered

Reusing a general six-connector result or treating NGINX exclusion as a global
capability change was rejected because each profile is an independent claim.

## Implementation decision

Use `ci/checks/catalog/five_connectors_with_crs_no_mrts.py` with separate
`profile`, `verify-fixture`, `validate`, and `aggregate` operations. The tool
validates host-provided evidence; it neither provisions a host nor runs MRTS.
It requires the fresh CRS topology, immutable commit, release-tag peel, rule
file digest, rule fingerprint, fixed adapter identity, typed raw records,
closed schemas, private no-follow evidence paths, descriptor-bound
content/digests, and create-only outputs.

## Changed files and tests

This change adds or updates the following Framework-owned components:

- `ci/checks/catalog/five_connectors_with_crs_no_mrts.py` and the fixed
  Make-to-validator bridge `ci/tools/run-five-connectors-with-crs-no-mrts.py`
- `tests/cases/security/crs/crs_sqli_anomaly_block.yaml` and the four closed
  schema files below `tests/schemas/five-connectors-with-crs-no-mrts/`
- `ci/provisioning/fetch-crs.sh`, `ci/provisioning/crs-provenance.sh`,
  `ci/lib/common.sh`, and `ci/checks/catalog/check-crs-version-pinning.sh`
- `Makefile` and the read-only profile workflow
- `.github/workflows/ci-security-quality.yml`,
  `.github/workflows/update-workflow-tools.yml`,
  `ci/checks/security/check-ci-security-contract.py`,
  `ci/tools/update-workflow-tools.py`, and `pyrightconfig.json`, which keep
  the new verifier/workflow inside the existing quality and workflow-update
  contracts
- `tests/ci_security/test_five_connector_with_crs_no_mrts_contract.py` and
  `tests/security_regression/test_crs_git_ref_provenance.py`
- `docs/testing-and-evidence.{md,de.md}`
- `docs/connector-integration.{md,de.md}`
- `docs/reference/variables.{md,de.md}`
- `docs/github-actions-workflow-security.{md,de.md}`
- this paired Change Record and the Change-Record indexes.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `make BUILD_ROOT=<task-build> test-five-connectors-with-crs-no-mrts-contract` | 0 | 24 focused positive and adversarial contract tests passed, including same-UID evidence and CRS-checkout name-swap rejection, top-level fixture-semantic drift, fixed runner argv/environment rejection, actual Make-target import coverage, and Make-dollar normalization without a shell. | Local external task build/tmp roots; no runtime evidence. |
| `make BUILD_ROOT=<task-build> SOURCE_ROOT=<task-build>/runtime/src check-five-connectors-with-crs-no-mrts-fixture` | 0 | Fresh checkout fetched the reviewed `v4.28.0` tag, verified its peel to `55b09f…c89c`, and found rule `942270`. | Local task-owned `fixture-verify-final` source root. |
| `python -m unittest …test_default_release_tag_is_fetched_and_peeled_to_the_approved_commit …test_rejects_missing_or_moved_reviewed_release_tag -v` | 0 | Both targeted CRS tag-provenance regressions passed. | Local external task build/tmp roots; fake-Git transport fixture. |
| `make BUILD_ROOT=<task-build> TMP_ROOT=<task-build>/tmp test-no-crs-contract` | 0 | 98 No-CRS contract and transport-hardening regressions passed. | Local task-owned build/tmp roots; no host runtime. |
| `make BUILD_ROOT=<task-build> TMP_ROOT=<task-build>/tmp test-crs-provenance-contract` | 0 | 19 CRS provenance regressions passed, including reviewed-tag absence/move rejection. | Local task-owned build/tmp roots; fake-Git transport fixture. |
| `make BUILD_ROOT=<task-build> TMP_ROOT=<task-build>/tmp lint` | 0 | Complete repository-native lint target passed: shell/Python syntax, contract suites, provenance, workflow, data-flow, catalog, documentation, and diff checks. | Local task-owned build/tmp roots; no host runtime. |
| `make BUILD_ROOT=<task-build> check-documentation` | 0 | Links, bilingual variable docs, repository paths, and paired Change Record contract passed. | Local Framework worktree. |
| `make BUILD_ROOT=<task-build> test-ci-security-contract` | 0 | 171 CI-security contract regressions passed. | Local task-owned build/tmp roots. |
| `python -m unittest tests.security_regression.test_mrts_common_sonar -v` | 0 | 6 No-MRTS helper regressions passed without corpus access. | Local task-owned build/tmp roots; no MRTS corpus/runtime. |
| `python -m unittest tests.security_regression.test_generate_case_matrix_sonar -v` | 0 | 17 generator/report-contract regressions passed. | Local task-owned build/tmp roots; no generated report refresh. |
| GitHub Actions push run `31396297465` / `portable-contract` | 1 | Observed initial failure: the standalone workflow had not installed the existing hash-locked PyYAML dependency. The follow-up adds that exact `requirements-ci.lock` step. | Hosted log observed; replacement exact-head profile run `31401586813` passed. |
| GitHub Actions push run `31396297434` / `scaffold-lint` | 2 | Observed initial failure: two new runner tests assumed a local interpreter spelling or a later validation error. The follow-up makes those assertions portable while retaining the closed-runner checks. | Hosted log observed; replacement exact-head lint runs `31401578475` and `31401582775` passed. |
| GitHub Actions pull-request run `31399120871` / `python-ci-security-quality` | 1 | Observed later failure: Pyright rejected 11 direct nested-object mutations in the focused test. This narrow test-only correction uses runtime-checked nested mappings. | Hosted log observed; replacement exact-head quality run `31401582724` passed; no security-control bypass claimed. |
| GitHub exact-head status for `58e8d410ba15f1a96538362e7ce259dbd5a335cd` | 0 | Both lint runs, profile contract, Python quality, Actionlint/Zizmor, Gitleaks, CodeQL, SonarCloud, OSV, Scorecard, action-version, and common-structure checks passed. | Observed PR #74 status checks: profile `31401586813`, quality `31401582724`, workflow lint `31401582893`, CodeQL `31401582980`, Gitleaks `31401583111`, lint `31401578475` / `31401582775`, action versions `31401582705`, OSV `31401582870`, Scorecard `31401582653`, common structure `31401578605` / `31401582669`; SonarCloud status check passed. |

## Security impact

This is Framework contract hardening. It adds fail-closed identity,
release-tag-to-commit provenance, typed raw-evidence correlation, containment,
no-overwrite, No-MRTS, cleanup, and descriptor-bound evidence checks. A
same-UID name swap between an evidence hash and parser read, or during the
fresh CRS checkout/rule check, now fails closed; published JSON digests derive
from the exact bytes written and aggregation parses/hashes each output through
one descriptor snapshot. The Make targets neutralize inherited dollar syntax
before Make expansion and invoke a repository-owned runner that builds only
closed argv vectors; no caller-selectable tool path reaches a shell. No host
exploit reproduction or bypass result is claimed in this record. The validator
checks structural consistency of supplied host records but does not
cryptographically authenticate their producer; every successful Framework
artifact is therefore explicitly non-promoting.

## Documentation and runtime evidence

English and German documentation describe the profile and its limits. No
five-host runtime, production, lifecycle, or MRTS-process evidence was
collected by this documentation change.

## Checks not run

The local interpreter is Python `3.14.4`, while `.python-version` requires
`3.14.6`. The repository's configuration contract passes; exact interpreter
execution is evidenced by the observed hosted exact-version quality run
`31401582724`. Pyright cannot run locally because its repository-managed Node
prerequisite is absent; its checksum-verified hosted gate passed, but is not
claimed as a local pass. Actionlint, Zizmor, Gitleaks, and Ruff are unavailable
locally; the observed hosted Actionlint/Zizmor/Gitleaks gates passed, but are
not claimed as local passes. ShellCheck reports existing diagnostics on
unchanged sourced-script lines; only the repository's `bash -n` lint step
passed. Generated report refresh/checks were not run because they are
generator-owned, can write generated output, and the Framework change
intentionally has no five-host or MRTS runtime input. Parent-owned five-host
composition E2E, runtime matrix, and production evidence are out of Framework
scope.

## Limitations and residual risk

A valid supplied evidence bundle establishes only the validator's bounded
contract. Connector owners still must produce and retain authentic host,
lifecycle, and operational evidence for any runtime or promotion claim.

## Final diff and review status

The initial full local validation completed with the repository-native `make
lint` target. Draft PR #74's first push observed two portability defects; the
narrow follow-up remediated them. A later exact-head Pyright failure received a
narrow test-only correction, and its exact-head hosted quality rerun passed.
The focused security-diff scan found no surviving reportable finding, while its
three operator-input Make-expansion candidates were still remediated with
literal-dollar normalization, a fixed runner, and real-target regression
coverage. The exact head `58e8d410ba15f1a96538362e7ce259dbd5a335cd` has
successful hosted lint, profile, quality, Actionlint/Zizmor, Gitleaks, CodeQL,
SonarCloud, OSV, Scorecard, action-version, and common-structure checks. At
that observation, Draft PR #74 was a Draft with clean merge state; no review
decision, merge, or host-runtime result is claimed. Structural host evidence
remains explicitly non-promoting.
