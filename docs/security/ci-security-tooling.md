# Framework CI security tooling

**Language:** English | [Deutsch](ci-security-tooling.de.md)

This guide describes the Framework-owned CI security controls. It applies only
to this repository. It does not initialize, scan, execute, or alter the
read-only `tools/MRTS` checkout, and it does not establish connector-runtime
security claims.

## Security model

All pull-request workflows use `pull_request`; none uses
`pull_request_target`. Routine jobs receive only `contents: read`, use
immutable Action SHAs with reviewed version comments, and check out with
`persist-credentials: false` and `submodules: false`. They do not restore or
save caches and do not upload arbitrary artifacts.

Every CI-security pull-request checkout explicitly selects the immutable PR
head rather than GitHub's synthetic merge ref. Jobs that serve both PR and
non-PR events use `github.event.pull_request.head.sha || github.sha`; trusted
default-branch jobs use `github.sha`. The Gitleaks PR-range job uses the PR
head directly and proves the checked-out SHA before scanning. The local
semantic evidence contract validates these mappings and the executable scanner
commands after discarding shell comments and excluding control-flow bodies,
unreachable post-`exit` commands, and uncalled helpers.

Every workflow has an explicit timeout and concurrency behavior. PR and normal
CI jobs cancel superseded runs for the same workflow/ref. The two scheduled
maintenance jobs deliberately do not cancel an active run: the common-version
job can create one constrained update PR, and the artifact-cleanup job deletes
only artifacts under its documented retention policy.

`security-events: write` is limited to the trusted, non-PR
`ci-security-codeql.yml` upload job. Its read-only PR companion
`ci-security-codeql-pr.yml` analyzes the exact PR head with `upload: never`
and `upload-database: false`; it never receives `security-events: write`.
OSV and Scorecard use checksum-verified release CLIs outside the checkout,
receive no GitHub token, and do not publish SARIF. Their PR jobs can therefore
analyze fork heads with only `contents: read`. OSV retains only validated,
fixed-path JSON comparison evidence; Scorecard PR jobs remain artifact-free.
No workflow uses `id-token: write`.

## Workflows and scope

| Workflow | Trigger and trust boundary | Control |
| --- | --- | --- |
| `ci-security-workflow-lint.yml` | PR, default-branch push, manual | Checksum-verified actionlint with ShellCheck, offline zizmor, immutable-pin/permission/checkout contracts, parsed semantic evidence validation, and safe/unsafe fixtures. |
| `ci-security-quality.yml` | PR and default-branch changes to the CI-security Python scope | Checksum-verified Ruff lint/format and Pyright using an exact Node.js runtime. The scope is the CI-security and Change Record checkers, downloader, and their tests. |
| `ci-security-secrets.yml` | PR, schedule, manual | Gitleaks checks out and proves the exact PR head, then scans the exact merge-base-to-head range with `--redact=100`; full history is scheduled/manual advisory until findings are triaged. |
| `ci-security-osv.yml` | PR; scheduled and manual default branch | A checksum-verified OSV Scanner binary compares exact PR base and head dependency-contract blobs without remediation and fails only for newly introduced OSV vulnerability groups. Every revision must provide `requirements-dev.txt`; the PR head must provide `requirements-ci.lock`, while a pre-introduction base revision receives a bounded empty optional input. Base, head, and comparison JSON are retained for one day only after regular-file, size, and JSON validation. The named inputs never traverse `tools/MRTS`; scheduled/manual default-branch scans are advisory. |
| `ci-security-codeql-pr.yml` | PR | CodeQL analyzes the exact PR head with only `contents: read`, the pinned Action's `linked` tool bundle, `upload: never`, and `upload-database: false`. It analyzes GitHub Actions, Python, and C/C++ and ignores `tools/MRTS/**`; it never receives a Code Scanning write permission. |
| `ci-security-codeql.yml` | Default-branch push, schedule, manual | Trusted CodeQL analyzes the exact `github.sha` with the same bounded language scope and linked tool bundle. Its one job-scoped `security-events: write` permission is used only to upload Code Scanning SARIF after non-PR execution. No Go or JavaScript/TypeScript scope is claimed, and C/C++ uses `build-mode: none` so the scan does not provision connector or MRTS dependencies. |
| `ci-security-scorecard.yml` | PR; default-branch push, schedule, manual on the default branch | A checksum-verified OpenSSF Scorecard binary assesses the exact local PR checkout without a GitHub token. The PR result is JSON-validated but artifact-free. Trusted default-branch jobs use the exact `github.sha`, retain one validated bounded JSON file for one day, and remain advisory because no score threshold is imposed; scanner and JSON-validation failures are not advisory. No SARIF is uploaded. |
| `ci-security-dependency-review.yml` | Dependency-changing PRs | Dependency Review checks high-severity vulnerabilities and runtime/development scopes without automatic remediation or PR comments. |

The existing `lint.yml`, `test-common.yml`, Action-version check,
common-version maintenance, and artifact cleanup workflows use the same
immutable Action, permission, checkout, timeout, and concurrency contract.
This scope hardens `test-common.yml` workflow execution only; its independently
governed common-case catalog assertion and materialization semantics are not a
CI-security product fix.

## Provenance and dependency controls

`ci/tooling/security-tools.lock.yml` is the authoritative record for every
remote Action and downloaded CLI in this CI scope. It records the name,
version, immutable release commit, upstream release, licence, purpose,
platform, update procedure, and—where a binary/package is downloaded—the
exact release asset and SHA-256.

`ci/tools/fetch-security-tool.py` accepts only named lock records, direct
HTTPS GitHub release assets, and an absolute, non-symlink strict child of the
current-user-owned `RUNNER_TEMP` directory. It checks the SHA-256 before
publishing a raw executable or extracting an archive, rejects unsafe archive
paths, links, and devices, extracts only the locked executable or package tree,
and publishes the result atomically. It never installs a package into the
Framework checkout.

`requirements-ci.lock` pins the CI PyYAML wheel for reviewed CPython 3.12.13 on
Linux x86_64 and requires its official PyPI SHA-256. Workflows select that
exact patch with `check-latest: false`, then install it with `--require-hashes`,
`--only-binary=:all:`, and `pip check`. Dependabot monitors both
`github-actions` and `pip`, but a proposed update remains subject to the
lock/provenance review and immutable-pin contract; no workflow auto-fixes a
dependency.

OSV's current scope is deliberately explicit. Its `.lock` suffix is not a
Python-requirements filename that OSV Scanner accepts directly, so the workflow
materializes the exact Git blob as `requirements-ci.txt` inside private runner
temporary storage before scanning it. This is an input-compatibility adapter,
not a dependency rewrite, source-tree modification, or automatic fix.
`pyproject.toml` currently contains CI-tool configuration rather than project
dependencies, and the Framework has no constraints or Go-module contract. A
future manifest type requires an explicit lock, scanner-scope, and contract
update rather than silent recursive discovery.

To update a record, verify the upstream release-tag-to-commit identity, licence,
asset filename/member, and SHA-256. Update the lock, matching workflow version
comments, the contract tests, and this guide in one reviewed change. Do not
replace a SHA pin with a mutable tag.

## Evidence, retention, and SonarQube Cloud

The security workflows intentionally publish no arbitrary scanner artifacts.
Gitleaks redacts findings. Only trusted, non-PR CodeQL execution uses the
GitHub code-scanning SARIF channel; the PR companion deliberately performs no
SARIF or database upload. OSV validates that its exact-base, exact-head, and
comparison files are regular bounded JSON objects before retaining that
comparison evidence for one day; OSV input reports must additionally satisfy
the expected result/package/group schema. Scorecard validates its PR result
without an artifact and retains its bounded current-revision JSON evidence for
one day. Neither scanner uploads SARIF. GitHub retention and access controls
therefore apply separately to CodeQL platform records, bounded OSV and
Scorecard artifacts, and workflow logs.

The artifact exception is deliberately narrow: OSV uploads only the three
fixed PR JSON paths, and OSV/Scorecard default-branch jobs upload only one
fixed current-revision JSON path. Each file is a non-symlink regular UTF-8 JSON
object capped at 1 MiB. Names use the GitHub run ID, there are no glob uploads
or downstream artifact consumers, and no additional GitHub write permission is
granted. Scorecard is governance evidence, not a cosmetic target: local,
no-token results do not prove branch protection, reviews, Security Policy,
SAST, fuzzing, maintained status, or repository-token permissions. Results
drive review and technically justified remediation; they never authorize an
automatic policy or dependency change.

The Framework currently receives a SonarQube Cloud GitHub App check, but this
repository has no Framework-owned scanner workflow, project key, or token
configuration to alter. This change preserves that external integration by not
weakening its quality gate, exclusions, or findings. Its current failed gate is
tracked separately and must be evaluated on the exact PR head; it is not hidden
or reclassified by these CI controls.

## Local validation

Use a Framework virtual environment and a task-owned cache/output location;
do not create a virtual environment or caches in `tools/MRTS`. Focused commands
include:

```sh
make test-ci-security-contract
make check-documentation
make lint
```

The dedicated semantic workflow-evidence check is also available as:

```sh
python3 ci/checks/security/check-ci-security-evidence-contract.py
```

The CI workflow additionally exercises the pinned actionlint, zizmor, Ruff,
and Pyright tools. If an auxiliary runtime is absent locally, record that
limitation rather than substituting a global or user-site installation.
