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
| `check-common-versions.yml` | `workflow_dispatch`, schedule | `actions/checkout`, `actions/setup-python`, `peter-evans/create-pull-request` | workflow default `contents: read`; updater job effective `contents: write`, `pull-requests: write` | Scheduled/manual trusted-maintainer workflow; no pull-request trigger. |
| `cleanup-artifacts.yml` | `workflow_dispatch`, schedule | `actions/github-script` | workflow default `contents: read`; cleanup job effective `actions: write` | Scheduled/manual trusted-maintainer workflow; its job can delete repository artifacts only. |
| `lint.yml` | `push`, `pull_request` | `actions/checkout` | `contents: read` | PR source and its development dependencies are untrusted; no write permission, secret, persisted credential, or submodule is configured. |
| `test-common.yml` | `push`, `pull_request` | `actions/checkout` | `contents: read` | PR source is untrusted; no write permission, secret, persisted credential, or submodule is configured. |

## Immutable Action provenance

Every remote Action must use a 40-character lowercase commit SHA and an
adjacent validated release-version comment. The current approved upstreams,
releases, and commit identities are:

| Action | Official upstream | Release | Commit SHA | License | Necessary use |
| --- | --- | --- | --- | --- | --- |
| `actions/checkout` | [actions/checkout](https://github.com/actions/checkout) | `v7.0.0` | `9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0` | MIT | Checks out the Framework source for validation or maintenance. |
| `actions/setup-python` | [actions/setup-python](https://github.com/actions/setup-python) | `v6.3.0` | `ece7cb06caefa5fff74198d8649806c4678c61a1` | MIT | Selects Python for the common-version updater. |
| `actions/github-script` | [actions/github-script](https://github.com/actions/github-script) | `v9.0.0` | `3a2844b7e9c422d3c10d287c895573f7108da1b3` | MIT | Calls the GitHub Actions artifact API for retention cleanup. |
| `peter-evans/create-pull-request` | [peter-evans/create-pull-request](https://github.com/peter-evans/create-pull-request) | `v8.1.1` | `5f6978faf089d4d20b00c7766989d076bb2fc7f1` | MIT | Creates the scheduled/manual common-version update pull request. |

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
permission map. `check-common-versions` needs repository-content and
pull-request writes to create its maintenance PR; `cleanup-artifacts` needs
only `actions: write` to delete artifacts; the trusted non-PR CodeQL upload
job needs `security-events: write`. No PR-triggered job may grant a write
permission.

Each direct `actions/checkout` use sets:

```yaml
with:
  persist-credentials: false
```

The common-version updater exposes `GITHUB_TOKEN` only in the `Validate and
update common.sh` shell step, and the pull-request Action continues to receive
its explicit `token: ${{ github.token }}` input. Workflow- and job-level
environments may not expose `github.token` under any variable name, including
`GITHUB_TOKEN`. GitHub permissions are job-scoped rather than step-scoped:
narrowing an environment variable reduces direct shell exposure but does not
turn a write-capable trusted job into a per-step permission boundary. That job
is consequently limited to scheduled or manual trusted-maintainer triggers and
contains no PR event.

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
of mutable references in both extensions, dynamic and alternate key syntax
references, missing release comments, `pull_request_target`, top-level and
PR-job write permissions, persisted credentials, broad job token exposure,
submodules, secret references, and duplicate YAML keys. `make lint` invokes
the checker and this suite, while the filtered `check-action-versions` workflow
also runs when its checker, fixtures, test, or Makefile changes.

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
