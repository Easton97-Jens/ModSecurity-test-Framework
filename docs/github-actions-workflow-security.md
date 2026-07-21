# GitHub Actions workflow security

**Language:** English | [Deutsch](github-actions-workflow-security.de.md)

This guide defines the Framework-owned contract for GitHub Actions workflows.
It protects the CI supply-chain and pull-request trust boundary without making
claims about connector runtime behavior.

## Scope and inventory

The contract covers every `.yml` and `.yaml` file in `.github/workflows/`,
including nested directories. The validator resolves a requested workflow file
or directory below the current repository root before reading it, and skips a
resolved path that escapes that root (for example through a symlink).
There are no Framework-owned `pull_request_target` workflows or PR submodule
checkouts in this inventory. The separately documented CI-security suite has
bounded OSV/Scorecard artifact exceptions; its only SARIF/CodeQL upload is the
trusted, non-PR `ci-security-codeql.yml` job. Its read-only
`ci-security-codeql-pr.yml` companion analyzes PR heads without an upload or a
write permission. No such behavior was removed by this hardening work.

| Workflow | Triggers | External Actions | Effective permissions | Trust disposition |
| --- | --- | --- | --- | --- |
| `check-action-versions.yml` | `workflow_dispatch`, filtered `pull_request` | `actions/checkout` | `contents: read` | PR source is untrusted; it runs read-only with no persisted checkout credential. |
| `check-common-versions.yml` | `workflow_dispatch`, schedule | `actions/checkout`, `actions/setup-python` | workflow and checker job both `contents: read` | Scheduled/manual trusted-maintainer workflow; it checks and ShellChecks a candidate copied under runner temporary storage, intentionally has no publisher, and cannot create, update, merge, force-push, or delete a PR branch. |
| `update-workflow-tools.yml` | `workflow_dispatch`, schedule | `actions/checkout`, `actions/setup-python`, `actions/github-script` | workflow default `contents: read`; only the publisher job has `contents: write`, `pull-requests: write` | Resolver and validator are token-free/read-only; the publisher creates or reuses only its matching Draft maintenance PR and never force-pushes. |
| `cleanup-artifacts.yml` | `workflow_dispatch`, schedule | `actions/github-script` | workflow default `contents: read`; cleanup job effective `actions: write` | Scheduled/manual trusted-maintainer workflow; its job can delete repository artifacts only. |
| `lint.yml` | `push`, `pull_request` | `actions/checkout` | `contents: read` | PR source and its development dependencies are untrusted; no write permission, secret, persisted credential, or submodule is configured. |
| `test-common.yml` | `push`, `pull_request` | `actions/checkout` | `contents: read` | PR source is untrusted; no write permission, secret, persisted credential, or submodule is configured. |

## Immutable Action provenance

Every remote Action must use a 40-character lowercase commit SHA and an
adjacent validated release-version comment. The current approved upstreams,
releases, and commit identities are:

| Action | Official upstream | Release | Commit SHA | License | Necessary use |
| --- | --- | --- | --- | --- | --- |
| `actions/checkout` | [actions/checkout](https://github.com/actions/checkout) | `v7.0.1` | `3d3c42e5aac5ba805825da76410c181273ba90b1` | MIT | Checks out the Framework source for validation or maintenance. |
| `actions/setup-python` | [actions/setup-python](https://github.com/actions/setup-python) | `v7.0.0` | `5fda3b95a4ea91299a34e894583c3862153e4b97` | MIT | Selects Python for the constrained maintenance updaters. |
| `actions/github-script` | [actions/github-script](https://github.com/actions/github-script) | `v9.0.0` | `3a2844b7e9c422d3c10d287c895573f7108da1b3` | MIT | Inspects or creates the constrained workflow-tool updater Draft PR and calls the GitHub Actions artifact API for retention cleanup. |

The contract rejects tags, branches, shortened or uppercase SHAs, dynamic
references, Docker references, malformed or block-scalar `uses:` values,
YAML-flow collections, explicit mapping keys, YAML tags/anchors/aliases/merge
keys in key or value position, escaped double-quoted mapping keys, YAML
document markers (including after a UTF-8 BOM), and a missing release comment.
Local `./` Actions are not remote dependencies and therefore do not need a
remote pin; none currently exist, and any future local Action in a PR workflow
remains subject to the read-only PR trust boundary below.

## Permissions and pull-request trust boundary

Every workflow starts with exactly:

```yaml
permissions:
  contents: read
```

Only a trusted job may replace that baseline with a smaller purpose-specific
permission map. `check-common-versions` remains read-only: it validates an
ephemeral runner-temporary candidate and deliberately has no publisher. Only
the `update-workflow-tools` publisher needs repository-content and pull-request
writes to create its constrained Draft maintenance PR; `cleanup-artifacts`
needs only `actions: write` to delete artifacts; the trusted non-PR CodeQL
upload job needs `security-events: write`. No PR-triggered job may grant a
write permission.

Each direct `actions/checkout` use sets:

```yaml
with:
  persist-credentials: false
```

The common-version checker receives no GitHub token, copies `common.sh` to
runner-temporary storage before applying its candidate update, and has no
branch or pull-request publisher. The workflow/tool updater splits public
resolution, candidate validation, and publication into three jobs: resolver
and validator retain `contents: read`, receive no publishing token, and do not
modify the checkout. The publisher re-resolves the candidate,
accepts only the fixed branch `automation/update-framework-workflow-tools`,
fails unless an existing matching PR is Draft, and scopes its token to the
small publisher steps. It verifies changed release assets through the existing
checksum-safe downloader without executing them; a completed redirect may end
only on `github.com`, `objects.githubusercontent.com`, or
`release-assets.githubusercontent.com`, and SHA-256 is verified before
extraction. The validator applies each candidate only in a bounded
runner-temporary copy to recheck the resulting contracts. A reusable branch
must byte-match the trusted base tree after the constrained updater produces
its verified candidate. The publisher changes only a fixed file allowlist,
uses a normal push, and creates a Draft PR only. Workflow- and job-level
environments may not expose `github.token` under any variable name, including
`GITHUB_TOKEN`. GitHub permissions are job-scoped rather than step-scoped:
narrowing an environment variable reduces direct shell exposure but does not
turn a write-capable trusted job into a per-step permission boundary. That job
is consequently limited to scheduled or manual trusted-maintainer triggers and
contains no PR event. The repository contract parses that exact trigger set
and publisher step profile and SHA-256-binds every publisher `run` and
`github-script` body; comments, aliases, extra commands, or changes to the
Draft/branch proof therefore fail closed.

For every `pull_request` workflow, the checker rejects `pull_request_target`,
write permissions, `secrets.` and `secrets[...]` references, reusable-workflow
secret forwarding, direct checkout without `persist-credentials: false`, and
enabled or dynamic submodules. This models both same-repository and fork PR
code as untrusted.

## Enforced checks and fixtures

`ci/checks/security/check-github-actions-workflows.py` is the canonical
source-controlled validator. Its pin mode uses only the Python standard
library, so the dedicated action-pin workflow can run before development
dependencies are installed. Its permission mode uses PyYAML, rejects duplicate
keys, aliases, anchors, and merge keys, and is run by the Framework lint
contract.

```sh
make check-github-actions-pins
make check-github-actions-permissions
make check-github-actions-workflows
make test-workflow-security-contract
```

The regression suite first validates the real workflows, then proves that safe
read-only-PR and trusted-writer fixtures pass. Unsafe fixtures prove rejection
of mutable references in both extensions, block mappings, flow mappings, and
flow-sequence mappings, dynamic and alternate key syntax references, missing
release comments, `pull_request_target`, top-level and PR-job write
permissions, persisted credentials, broad job token exposure, submodules,
secret references, and duplicate YAML keys. `make lint` invokes the checker
and this suite, while the filtered `check-action-versions` workflow also runs
when its checker, fixtures, test, or Makefile changes.

## Updating an Action pin

Before changing an Action pin:

1. Verify the action is the official upstream repository, has a necessary
   function, and is not an unexpected fork.
2. Verify the intended upstream release, release-to-commit mapping, and
   license; record the full commit SHA and exact version comment together.
3. Update every relevant workflow reference, preserving the exact
   `# vX.Y.Z` comment next to the SHA.
4. Run the YAML parser, both validator modes, the workflow-contract suite, and
   the available actionlint, ShellCheck, and zizmor checks.
5. Update this English/German guide and the Framework Change Record with the
   observed provenance and validation results.

The scheduled/manual `update-workflow-tools.yml` can prepare a reviewable
candidate, but it is deliberately not an approval or merge mechanism. It uses
only the official GitHub release/Git APIs implied by the existing lock, checks
release-tag-to-commit identity, and requires the official release asset's
published SHA-256 before a downloaded-tool record can change. Release-asset
redirects are confined to the documented official host allowlist, and the
digest is verified before extraction. A failed lookup, digest, branch,
base-derived branch-content, PR-shape, lock-digest, or allowlist check stops
publication.

## Limitations and operational expectations

This contract is a repository control, not a replacement for GitHub branch
protection, workflow review, action provenance review, actionlint, zizmor,
CodeQL, Scorecard, or SonarQube Cloud. Those controls must be evaluated on the
actual pull-request head. Tool availability is recorded truthfully in the
Change Record; an unavailable local tool is not treated as a passed check.

If a future workflow changes the documented artifact/SARIF exception, consumes
artifacts across a trust boundary, uses OIDC, invokes a reusable workflow, or
needs a new write permission, extend the checker, fixtures, inventory, and
Change Record before relying on the new behavior.
