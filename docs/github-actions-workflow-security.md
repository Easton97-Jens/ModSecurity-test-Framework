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
The Framework-owned OSV workflow uses the non-privileged `pull_request` event.
Its narrow job checks out the trusted PR base SHA, fetches and verifies the
numbered PR head object, and reads only named dependency-manifest blobs plus
the PR-head `.python-version` blob. The latter is size- and format-bounded,
written once as a regular non-symlink file below private `runner.temp`, and is
used only by `setup-python`. The checked-out Framework source and scanner helper
are therefore the base revision, not PR-head files: the job never checks out or
executes PR-head content. No PR checkout enables submodules.
The separately documented CI-security suite has bounded OSV/Scorecard artifact
exceptions; its only SARIF/CodeQL upload is the trusted, non-PR
`ci-security-codeql.yml` job. Its read-only
`ci-security-codeql-pr.yml` companion analyzes PR heads without an upload or a
write permission. No such behavior was removed by this hardening work.

| Workflow | Triggers | External Actions | Effective permissions | Trust disposition |
| --- | --- | --- | --- | --- |
| `check-action-versions.yml` | `workflow_dispatch`, filtered `pull_request` | `actions/checkout`, `actions/setup-python` | `contents: read` | PR source is untrusted; it runs read-only with no persisted checkout credential. |
| `check-common-versions.yml` | `workflow_dispatch`, schedule | `actions/checkout`, `actions/setup-python`, `actions/create-github-app-token`, `actions/github-script`, `peter-evans/create-pull-request` | workflow and native publisher token `contents: read`; only the short-lived, repository-limited App token has `contents`, `pull-requests`: write | Resolver and candidate jobs remain read-only; the default-branch publisher independently re-resolves and SHA-256-binds the candidate, fail-closes on unsafe maintenance state, and creates or updates one fixed-branch Draft PR for `ci/lib/common.sh`. |
| `check-python-version.yml` | `workflow_dispatch`, schedule | `actions/checkout`, `actions/setup-python`, `actions/create-github-app-token`, `actions/github-script`, `peter-evans/create-pull-request` | workflow default `permissions: {}`; only resolver, candidate-validator, and publisher receive built-in `contents: read`; the repository-limited App token has only `contents`, `pull-requests`: write | Resolver and candidate jobs are read-only. The default-branch publisher independently re-resolves one stable candidate, verifies exactly one fixed Draft branch/PR and changes only `.python-version`; it never merges. A final read-only outcome job makes only the exact no-update state green. |
| `cleanup-artifacts.yml` | `workflow_dispatch`, schedule | `actions/github-script` | workflow default `contents: read`; cleanup job effective `actions: write` | Scheduled/manual trusted-maintainer workflow; its job can delete repository artifacts only. |
| `lint.yml` | `push`, `pull_request` | `actions/checkout`, `actions/setup-python` | `contents: read` | PR source and its development dependencies are untrusted; no write permission, secret, persisted credential, or submodule is configured. |
| `test-common.yml` | `push`, `pull_request` | `actions/checkout`, `actions/setup-python` | `contents: read` | PR source is untrusted; no write permission, secret, persisted credential, or submodule is configured. |
| `ci-security-osv.yml` | constrained `pull_request`, schedule, manual | `actions/checkout`, `actions/setup-python`, `actions/upload-artifact` | `contents: read` | The non-privileged PR job executes the trusted base revision only, verifies a fetched PR object, and treats dependency-manifest and bounded `.python-version` blobs as data rather than checked-out code. |
| `update-workflow-tools.yml` | schedule, manual | `actions/checkout`, `actions/setup-python`, `actions/create-github-app-token`, `actions/github-script` | reader jobs and the publisher's built-in token `contents: read`; its minted App token has `contents`, `pull-requests`, `workflows`: write | The constrained publisher runs only after independent resolver and validator jobs, scopes its short-lived App token to this repository, and creates a Draft PR only. |
| `update-submodules.yml` | schedule, manual | `actions/checkout`, `actions/setup-python` | reader jobs `contents: read`; only the validated default-branch publisher has `contents: write`, `pull-requests: write` | The resolver follows only `Easton97-Jens/MRTS` `refs/heads/main`; the validator explicitly initializes only `tools/MRTS` before checking the detached candidate; the publisher changes only `tools/MRTS`, uses a normal non-force push, and creates or updates one matching Draft PR. |

## Immutable Action provenance

Every remote Action must use a 40-character lowercase commit SHA and an
adjacent validated release-version comment. The current approved upstreams,
releases, and commit identities are:

| Action | Official upstream | Release | Commit SHA | License | Necessary use |
| --- | --- | --- | --- | --- | --- |
| `actions/checkout` | [actions/checkout](https://github.com/actions/checkout) | `v7.0.1` | `3d3c42e5aac5ba805825da76410c181273ba90b1` | MIT | Checks out the Framework source for validation or maintenance. |
| `actions/setup-python` | [actions/setup-python](https://github.com/actions/setup-python) | `v7.0.0` | `5fda3b95a4ea91299a34e894583c3862153e4b97` | MIT | Selects the exact `.python-version` interpreter for Framework CI and controlled maintenance validation. |
| `actions/setup-node` | [actions/setup-node](https://github.com/actions/setup-node) | `v7.0.0` | `820762786026740c76f36085b0efc47a31fe5020` | MIT | Selects the reviewed Node.js runtime for checksum-verified Pyright. |
| `actions/upload-artifact` | [actions/upload-artifact](https://github.com/actions/upload-artifact) | `v7.0.1` | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` | MIT | Retains only bounded CI-security evidence. |
| `actions/github-script` | [actions/github-script](https://github.com/actions/github-script) | `v9.0.0` | `3a2844b7e9c422d3c10d287c895573f7108da1b3` | MIT | Inspects constrained Draft PRs or performs artifact-retention cleanup. |
| `actions/create-github-app-token` | [actions/create-github-app-token](https://github.com/actions/create-github-app-token) | `v3.2.0` | `bcd2ba49218906704ab6c1aa796996da409d3eb1` | MIT | Mints the Common-version, CPython-version, or workflow-tool publisher's short-lived, repository-limited App token. |
| `peter-evans/create-pull-request` | [peter-evans/create-pull-request](https://github.com/peter-evans/create-pull-request) | `v8.1.1` | `5f6978faf089d4d20b00c7766989d076bb2fc7f1` | MIT | Creates constrained Common-version or CPython-version Draft pull requests. |
| `github/codeql-action` | [github/codeql-action](https://github.com/github/codeql-action) | `v4.37.6` | `5595ccaf912efad79be6eef63a5619ff05969be3` | MIT | Performs the bounded CodeQL analysis and trusted SARIF upload. |
| `actions/dependency-review-action` | [actions/dependency-review-action](https://github.com/actions/dependency-review-action) | `v5.0.0` | `a1d282b36b6f3519aa1f3fc636f609c47dddb294` | MIT | Reviews dependency-changing pull requests without remediation. |

The contract rejects tags, branches, shortened or uppercase SHAs, dynamic
references, Docker references, malformed or block-scalar `uses:` values,
YAML-flow collections, explicit mapping keys, YAML tags/anchors/aliases/merge
keys in key or value position, escaped double-quoted mapping keys, YAML
document markers (including after a UTF-8 BOM), and a missing release comment.
Independently of source spelling, the CI-security contract recursively binds
every parsed non-local `uses` reference to its reviewed lock record and exact
immutable commit; the source-level release-comment check remains defense in
depth. Quoted-key and flow-mapping references with a different full SHA are
therefore rejected rather than relying on a literal `uses:` spelling.
Local `./` Actions are not remote dependencies and therefore do not need a
remote pin; none currently exist, and any future local Action in a PR workflow
remains subject to the read-only PR trust boundary below.

## Permissions and pull-request trust boundary

Every workflow declares an explicit top-level baseline. Most begin with:

```yaml
permissions:
  contents: read
```

`check-python-version` is the narrow explicit exception: it begins with
`permissions: {}` and grants its resolver, candidate-validator, and publisher
jobs their separate built-in `contents: read` token; its outcome job remains
empty. This avoids ambient token access in the final status path. No
workflow-level permission map grants write.
Only a trusted job may replace that baseline with a smaller purpose-specific
permission map. `check-common-versions` keeps its resolver, candidate, and
native publisher token at `contents: read`; only its post-validation,
repository-limited GitHub App token receives `contents` and `pull-requests`:
write. `update-workflow-tools` retains `contents: read` for every built-in job
token and, only after independent resolver and validator jobs, mints a
repository-limited GitHub App token with `contents`, `pull-requests`, and
`workflows` write permission. The CPython and Common-version tokens have only
`contents` and `pull-requests`: write; the workflow-tool token additionally
has `workflows`: write because it may change workflow files.
`cleanup-artifacts` needs only `actions: write` to delete artifacts;
`update-submodules` gives `contents` and `pull-requests` writes only to its
validated default-branch publisher; the trusted non-PR CodeQL upload job needs
`security-events: write`. No PR-triggered job may grant a write permission.

Each direct `actions/checkout` use sets:

```yaml
with:
  persist-credentials: false
```

This prevents the checkout credential from persisting for later Git commands.
GitHub still provides an automatic job token to Actions, and `actions/checkout`
uses that job-scoped default input unless an action explicitly receives another
credential. The Common-version resolver and candidate jobs declare no explicit
token or secret. Its publisher is limited to scheduled/manual execution on the
trusted default branch, independently re-resolves the candidate, compares its
SHA-256 with the read-only validation result, and requires the working-tree
diff and action `add-paths` to contain only `ci/lib/common.sh`. The publisher's
native token stays read-only and no `github.token`, `GITHUB_TOKEN`, PAT, SSH
credential, or runner-driven push may publish. It tests the availability of
`WORKFLOW_UPDATER_APP_CLIENT_ID` and `WORKFLOW_UPDATER_APP_PRIVATE_KEY` without
printing either value; the private-key value is passed only to the immutable
`create-github-app-token` Action. That Action is scoped to the current owner
and repository and requests only `contents` and `pull-requests`: write, never
`workflows`: write. Its output is consumed only by the reviewed read-only
state check and the immutable `create-pull-request` Action. The CPython-version
resolver and candidate jobs also declare no explicit token or secret. The
Common-version and CPython publishers preflight
`WORKFLOW_UPDATER_APP_CLIENT_ID` and
`WORKFLOW_UPDATER_APP_PRIVATE_KEY` without printing either value. They use the
pinned App-token action as the sole publisher credential source, have no
`github.token`, `GITHUB_TOKEN`, PAT, SSH, or runner-driven publishing fallback,
and fail red if configuration or token minting fails. The workflow-tool resolver
and validator likewise remain token-free in source. Its tightly profiled
publisher passes
`vars.WORKFLOW_UPDATER_APP_CLIENT_ID` and
`secrets.WORKFLOW_UPDATER_APP_PRIVATE_KEY` only to the immutable
`create-github-app-token` step, requests a token for the current repository
only, and passes that output only to its constrained Draft-PR API and normal
push steps. It has no `github.token` publishing fallback, and the action's
default post-job token revocation remains enabled. The App must be installed
only for this Framework repository and grant exactly `Contents`, `Pull
requests`, and `Workflows` write authority; missing or insufficient hosted
configuration fails the publisher rather than widening a credential. The
MRTS submodule resolver and validator likewise declare no token or secret. Its
separate publisher uses the native job token only for its reviewed GitHub CLI
and normal Git push steps, verifies an existing Draft branch changes only
`tools/MRTS`, and rejects force pushes, a default-branch target, or a PR event.
The
contract rejects an explicit token/secret reference at workflow level or in any
reader job and binds the write-capable publisher profiles exactly. The Python publisher independently
re-resolves the candidate, allows only `.python-version` in both the checked
diff and `add-paths`, fixes the automation branch, sets `draft: true`, and
rejects merge or auto-merge shell commands in the source contract. GitHub
permissions are job-scoped rather than step-scoped: narrowing an environment
variable reduces direct shell exposure but does not turn a write-capable trusted
job into a per-step permission boundary. Each publisher is consequently limited
to scheduled or manual trusted-maintainer triggers and contains no PR event.

## Maintenance publisher and terminal outcomes

The CPython and workflow-tool maintenance workflows end with a read-only `outcome` job using
`if: ${{ always() }}` and `permissions: {}`. It validates the resolver
status, its machine-readable outputs, and the actual upstream job results
before writing a bilingual summary. Only the exact reviewed no-update states
(`current:false` for CPython and `resolved:false` for workflow tools) are
successful no-op outcomes; their validator/publisher jobs must be skipped or
otherwise expected, and no branch, commit, or pull request is created or
modified. Missing, malformed, or unknown output—and any resolver, validator,
publisher, App-configuration, or App-token failure—causes the terminal job to
fail rather than being represented as no update.

For an update, the workflow-tool resolver emits canonical candidate Base64 and
SHA-256 identity. The validator and publisher independently validate that exact
identity, and the publisher requires a non-empty reviewed change before it can
apply it. CPython independently re-resolves the fixed `3.14.x` candidate
before updating. Each publisher validates a single matching Draft branch and
open PR: fixed branch/title, Draft state, marker, `master` base, and the
approved path scope. CPython permits only `.python-version`; workflow tools
retain their existing allowlist. Neither publisher force-pushes, targets the
default branch directly, enables auto-merge, nor masks cleanup/publishing
errors.

The shared App configuration uses
`vars.WORKFLOW_UPDATER_APP_CLIENT_ID` and
`secrets.WORKFLOW_UPDATER_APP_PRIVATE_KEY` by name only. The CPython publisher
and Common-version publisher request only `Contents` and `Pull requests`
write; the workflow-tool publisher additionally requests `Workflows` write
because it may update workflow files. The generated App Draft PR is an
ordinary PR and must satisfy the repository's normal PR checks and human review
before any merge; none of these workflows merges or enables auto-merge.

### Common-version Draft publisher

The Common-version maintenance identity is fixed to branch
`automation/update-framework-common-versions`, title
`chore(ci): update common.sh versions`, the repository default branch as base,
and `draft: true`. Its body contains the marker
`<!-- framework-common-version-updater -->`, English and German explanations,
the validated old/new variable values, and the validated upstream source or
release reference for each changed component. It states that no auto-merge is
authorized. Before the App-token PR Action can change a branch, a read-only
GitHub API check accepts only state A (no branch and no open matching PR) or
state B (exactly one same-repository Draft PR with the fixed head, base, title,
marker, and `ci/lib/common.sh`-only diff). Any other state fails closed without
deleting or overwriting a branch or PR. A trusted-default-branch drift during
publisher revalidation also fails closed.

The resolver emits `update_available=false` only when every update-eligible
source is current. `unknown`, `blocked`, and `error` results fail the resolver;
intentionally tracked local-policy values without an updater contract are
reported as `not_applicable` and do not disguise an unsafe source result. The
credential-free terminal result job always runs: for `false`, it requires a
successful resolver and skipped candidate/publisher jobs, then writes the
reviewed English/German no-update summary; for `true`, it requires all three
prior jobs to succeed and reports the constrained Draft PR URL or number, with
a clear fallback when the Action does not return either value. Any other state
fails rather than being interpreted as no update. Thus no-update cannot change
a branch, PR, or commit. Missing App configuration after an available update
also fails clearly rather than being treated as no update. A PR created with
the App token is expected to emit normal pull-request events, so required
checks, workflow/action pin checks, Python and ShellCheck quality, Common-
version provenance, documentation contracts, and scope-applicable
SonarQube/branch-protection checks must be observed on its actual head before a
human merge. The workflow itself never approves, merges, or enables auto-merge.

For every `pull_request` workflow, the checker rejects `pull_request_target`,
write permissions, `secrets.` and `secrets[...]` references, reusable-workflow
secret forwarding, direct checkout without `persist-credentials: false`, and
enabled or dynamic submodules. The OSV job is not an exception to this trigger
policy: it runs with `contents: read`, no secrets, no persisted credentials,
and no submodules. It additionally checks out the PR base SHA and is required
to fetch, SHA-verify, and blob-read the PR head, preserving a data-only
dependency comparison for untrusted same-repository and fork PR input.

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
make check-python-version
make test-workflow-security-contract
```

`ci/checks/security/check-python-version.py` separately requires the canonical
regular `.python-version` file, recursive workflow coverage, setup before every
direct or Make-driven Python command, no hard-coded patch or Python matrix, and
no bare `pip`. It allows exactly two runner-temporary version-file exceptions:
the candidate file in the direct `check-python-version.yml` validation job after
canonical setup, and the OSV `pull-request-head` file after its trusted-base,
SHA-verified, bounded, non-symlink PR-head blob materialization. The CI-security
contract additionally enforces the exact maintenance topologies, trusted
publisher gates, publisher revalidation, fixed Draft-PR branches, and the
respective approved path scopes.

The regression suite first validates the real workflows, then proves that safe
read-only-PR and trusted-writer fixtures pass. Unsafe fixtures prove rejection
of mutable references in both extensions, block mappings, flow mappings, and
flow-sequence mappings, dynamic and alternate key syntax references, missing
release comments, any `pull_request_target`, top-level and PR-job write
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

## Limitations and operational expectations

This contract is a repository control, not a replacement for GitHub branch
protection, workflow review, action provenance review, actionlint, zizmor,
CodeQL, Scorecard, or SonarQube Cloud. Those controls must be evaluated on the
actual pull-request head. Tool availability is recorded truthfully in the
Change Record; an unavailable local tool is not treated as a passed check.

For the Python-version publisher, GitHub permissions to dispatch a workflow,
protected-default-branch rules, required checks, SonarQube Cloud, review
freshness, and the token-created Draft PR's exact head are hosted controls.
They must be verified for each published head before any human merges it; the
workflow itself never merges or enables auto-merge.

If a future workflow changes the documented artifact/SARIF exception, consumes
artifacts across a trust boundary, uses OIDC, invokes a reusable workflow, or
needs a new write permission, extend the checker, fixtures, inventory, and
Change Record before relying on the new behavior.
