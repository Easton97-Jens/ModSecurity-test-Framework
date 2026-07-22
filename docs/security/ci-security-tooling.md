# Framework CI security tooling

**Language:** English | [Deutsch](ci-security-tooling.de.md)

This guide describes the Framework-owned CI security controls. It applies only
to this repository. It does not initialize, scan, execute, or alter the
read-only `tools/MRTS` checkout, and it does not establish connector-runtime
security claims.

## Security model

Ordinary pull-request workflows, including `ci-security-osv.yml`, use
`pull_request`. The OSV job receives only `contents: read`, checks out the
immutable pull-request base SHA with no persisted credential or submodules,
fetches only the numbered GitHub pull-request head reference, verifies the
reported head SHA, and reads the two named dependency manifests plus only the
head `.python-version` blob as bounded data. The latter is materialized once as
a regular non-symlink file below private `runner.temp` after size and stable
CPython-3.13 format validation, solely for `setup-python`. Its checked-out
Framework source and scanner helper are therefore the base revision; it never
checks out or executes PR-head content. All routine jobs receive only `contents: read`, use immutable Action SHAs
with reviewed version comments, and check out with `persist-credentials: false`
and `submodules: false`. They do not restore or save caches and do not upload
arbitrary artifacts.

Every ordinary CI-security pull-request checkout explicitly selects the
immutable PR head rather than GitHub's synthetic merge ref. Jobs that serve
both PR and non-PR events use `github.event.pull_request.head.sha ||
github.sha`; trusted default-branch jobs use `github.sha`. The Gitleaks
PR-range job uses the PR head directly and proves the checked-out SHA before
scanning. The OSV PR job instead runs only the trusted base revision and uses
the verified PR object solely for bounded blob reads and the isolated
`setup-python` version-file bootstrap. The local
semantic evidence contract validates these mappings and the executable scanner
commands after discarding shell comments and excluding control-flow bodies,
unreachable post-`exit` commands, and uncalled helpers.

Every workflow has an explicit timeout and concurrency behavior. PR and normal
CI jobs cancel superseded runs for the same workflow/ref. The three scheduled
maintenance jobs deliberately do not cancel an active run: the common-version
job validates only an ephemeral runner-temporary candidate and has no delivery
path, the workflow/tool updater can create or continue only its matching Draft
maintenance PR, and the artifact-cleanup job deletes only artifacts under its
documented retention policy.

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
| `ci-security-osv.yml` | Constrained non-privileged `pull_request`; scheduled and manual default branch | The PR job executes the trusted PR base SHA, fetches the numbered PR reference without checkout, verifies its exact head SHA, and compares bounded `requirements-dev.txt` and `requirements-ci.lock` blobs without remediation. It materializes only the verified bounded head `.python-version` blob once below private `runner.temp` as a regular non-symlink file solely for `setup-python`; no PR-head source is checked out or executed. It fails only for newly introduced OSV vulnerability groups. Every revision must provide `requirements-dev.txt`; the PR head must provide `requirements-ci.lock`, while a pre-introduction base revision receives a bounded empty optional input. Base, head, and comparison JSON are retained for one day only after regular-file, size, and JSON validation. The named inputs never traverse `tools/MRTS`; scheduled/manual default-branch scans are advisory. |
| `ci-security-codeql-pr.yml` | PR | CodeQL analyzes the exact PR head with only `contents: read`, the pinned Action's `linked` tool bundle, `upload: never`, and `upload-database: false`. It analyzes GitHub Actions, Python, and C/C++ and ignores `tools/MRTS/**`; it never receives a Code Scanning write permission. |
| `ci-security-codeql.yml` | Default-branch push, schedule, manual | Trusted CodeQL analyzes the exact `github.sha` with the same bounded language scope and linked tool bundle. Its one job-scoped `security-events: write` permission is used only to upload Code Scanning SARIF after non-PR execution. No Go or JavaScript/TypeScript scope is claimed, and C/C++ uses `build-mode: none` so the scan does not provision connector or MRTS dependencies. |
| `ci-security-scorecard.yml` | PR; default-branch push, schedule, manual on the default branch | A checksum-verified OpenSSF Scorecard binary assesses the exact local PR checkout without a GitHub token. The PR result is JSON-validated but artifact-free. Trusted default-branch jobs use the exact `github.sha`, retain one validated bounded JSON file for one day, and remain advisory because no score threshold is imposed; scanner and JSON-validation failures are not advisory. No SARIF is uploaded. |
| `ci-security-dependency-review.yml` | Dependency-changing PRs | Dependency Review checks high-severity vulnerabilities and runtime/development scopes without automatic remediation or PR comments. |
| `update-workflow-tools.yml` | Scheduled/manual trusted default revision | A read-only resolver obtains candidates only from lock-derived official GitHub release/Git endpoints. A separate read-only validator checksum-downloads changed tool assets and applies the candidate only in a bounded runner-temporary copy to recheck the resulting pins and contracts. The sole write-capable publisher re-resolves and checksum-validates its fresh candidate, accepts only a base-identity-verified matching Draft PR branch, confines changes to an explicit allowlist, uses a normal push, and creates a Draft PR only. |

The existing `lint.yml`, `test-common.yml`, Action-version check,
common-version maintenance, workflow/tool maintenance, and artifact-cleanup
workflows use the same immutable Action, permission, checkout, timeout, and
concurrency contract.
This scope hardens `test-common.yml` workflow execution only; its independently
governed common-case catalog assertion and materialization semantics are not a
CI-security product fix.

## Provenance and dependency controls

`ci/tooling/security-tools.lock.yml` is the authoritative record for every
remote Action and downloaded CLI in this CI scope. It records the name,
version, immutable release commit, upstream release, licence, purpose,
platform, update procedure, and—where a binary/package is downloaded—the
exact release asset and SHA-256.

The CI-security contract also resolves every parsed non-local workflow `uses`
reference recursively and binds it to that lock's action name and exact
`immutable_commit`, regardless of YAML key spelling. Source-level immutable-pin
and release-comment checks remain defense in depth. Regression fixtures prove
that quoted keys and flow mappings carrying a different full SHA are rejected.

Every Action record also fixes its `release_resolution`. Most Actions use the
official `latest-release` endpoint. `github/codeql-action` instead uses the
reviewed `same-major-release` mode because its `releases/latest` response may
describe a CodeQL bundle rather than the Action. The resolver reads one bounded
official release page, accepts only published non-prerelease numeric Action
tags in the locked `v4` major, then resolves that exact tag through the Git API
to its immutable commit. It never treats a bundle or a new Action major as an
Action update.

`ci/tools/fetch-security-tool.py` accepts only named lock records, direct
HTTPS GitHub release assets, and an absolute, non-symlink strict child of the
current-user-owned `RUNNER_TEMP` directory. A completed redirect is allowed
only to `github.com`, `objects.githubusercontent.com`, or
`release-assets.githubusercontent.com`. It verifies the SHA-256 before
publishing a raw executable or extracting an archive, rejects unsafe archive
paths, links, and devices, extracts only the locked executable or package tree,
and publishes the result atomically. It never installs a package into the
Framework checkout.

`ci/tools/update-workflow-tools.py` is the only native updater for that lock
scope. Its resolver has no GitHub token and accepts only lock-derived official
GitHub API URLs. Its candidate binds to the SHA-256 of the trusted current lock
and can change only release/version, immutable commit, and—in a tool record—the
expected asset tuple and SHA-256. The validator fails closed on a stale lock,
unexpected field, URL, asset naming rule, or digest, applies the candidate
only in a bounded runner-temporary copy, and calls the downloader only for
changed tool assets. The publisher repeats resolution, checksum-validates its
fresh tool candidate, validates its working copy, and accepts changes only to
its explicit lock/workflow/paired-guide allowlist. It does not execute a
downloaded asset, use `pull_request_target`, force-push, or merge. Existing
branches are reused only when the one open PR has the exact branch, title,
base, marker, and Draft state and its changed tuples verify from the current
default-branch lock identity.

`requirements-ci.lock` pins the CI PyYAML CP313 wheel for reviewed CPython
3.13.14 on Linux x86_64 and requires its official PyPI SHA-256. Workflows
select that exact patch with `check-latest: false`, then install it with
`--require-hashes`, `--only-binary=:all:`, and `pip check`. Dependabot monitors both
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
comments, the contract tests, and this guide in one reviewed change. The native
updater applies the same tuple rules and still leaves a Draft PR for review; do
not replace a SHA pin with a mutable tag.

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
