# 20260718-01 — Enforce immutable full-SHA Framework action pins

**Language:** English | [Deutsch](20260718-01-fix-framework-actions-sha-pins.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260718-01-fix-framework-actions-sha-pins |
| UTC date | 2026-07-18 |
| Framework base revision | cdc91a398d6c156eaff927d742b23018a3817fb6 |
| Finding / root-cause group | FND-FRAMEWORK-0003 / RC-FW-001-action-reference-immutability |
| Issue or pull request | Draft PR collection is pending; this record intentionally contains no future PR number, URL, or delivery SHA. |

## Motivation and security boundary

The previous inline workflow control accepted mutable major action tags such as
actions/checkout@v7. A changed upstream tag could therefore alter the code
executed by a scheduled or manually dispatched Framework workflow without an
immutable action identity. This Framework-only change remediates the external
uses: resolution boundary identified by FND-FRAMEWORK-0003.

Affected Framework paths:

- .github/workflows/check-action-versions.yml
- .github/workflows/check-common-versions.yml
- .github/workflows/cleanup-artifacts.yml
- .github/workflows/lint.yml
- .github/workflows/test-common.yml
- ci/checks/security/check-workflow-action-pins.py
- tests/security_regression/test_workflow_action_pins.py
- Makefile

Parent source and gitlinks are not part of this change; MRTS is untouched.

## Acceptance criteria and implementation decision

The checker recursively covers .yml and .yaml workflow files; permits only a
local ./ reference or an external full 40-character Git commit SHA; and rejects
mutable major tags, branches, abbreviated hashes, Docker forms, and unsupported
YAML encodings fail-closed. Quoted full-SHA references and external reusable
workflows pinned to a full SHA remain legitimate controls.

Retaining the inline regular expression would remain hard to test and would
permit mutable tags. Pinning only observed workflow lines would not prevent a
future regression. Adding a YAML-parser dependency would enlarge the Framework
supply chain. The selected standard-library checker is the smallest
Framework-native control: it centralizes the rule, scans the actual workflow
tree, and exposes a focused regression target. Unsupported ambiguous YAML key
forms are rejected rather than interpreted permissively.

The seven references preserve their existing major-version intent but use these
reviewed commits:

| Prior major tag | Immutable commit SHA |
| --- | --- |
| actions/checkout@v7 | 9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 |
| actions/setup-python@v6 | ece7cb06caefa5fff74198d8649806c4678c61a1 |
| actions/github-script@v9 | 3a2844b7e9c422d3c10d287c895573f7108da1b3 |
| peter-evans/create-pull-request@v8 | 5f6978faf089d4d20b00c7766989d076bb2fc7f1 |

The checker handles quoted scalar encodings, skips only indented literal/folded
block-scalar contents, and fails closed for explicit keys, YAML node
properties, aliases, and multiline flow/quoted forms that could obscure uses.
Docker references are rejected because an image digest is not the required Git
commit SHA. make lint runs the focused regression target and real-workflow
validator.

## Tests and evidence

The initial focused regression failed before enforcement changed while an
unquoted full 40-character SHA control passed. The final focused suite has 21
tests and covers .yml/.yaml, comments, quotes and escapes, literal script
blocks, local/Docker/reusable forms, branches, abbreviated hashes, flow
mappings, explicit keys, YAML node properties, aliases, and full-SHA controls.
The broader tests/security_regression suite has 34 tests.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| rtk env ... python -m unittest tests/security_regression/test_workflow_action_pins.py | 0 | 21 focused action-pin regression tests passed. | 20260718T092013Z-fnd-framework-0003-actions-sha-pins-41e9a058 |
| rtk env ... python ci/checks/security/check-workflow-action-pins.py | 0 | Actual changed workflows contain only full-SHA external references. | 20260718T092013Z-fnd-framework-0003-actions-sha-pins-41e9a058 |
| rtk env ... python -m unittest discover -s tests/security_regression -v | 0 | 34 security-regression tests passed. | 20260718T092013Z-fnd-framework-0003-actions-sha-pins-41e9a058 |
| rtk env ... make lint ... | 0 | Framework lint, workflow syntax, focused pin suite, real checker, and documentation aggregate passed; its hard-coded /tmp CRS subcheck was rerun separately. | 20260718T092013Z-fnd-framework-0003-actions-sha-pins-41e9a058 |
| rtk sh ci/checks/catalog/check-crs-version-pinning.sh | 0 | The CRS pinning subcheck passed outside the sandbox. | 20260718T092013Z-fnd-framework-0003-actions-sha-pins-41e9a058 |
| rtk shellcheck -x ci/lib/common.sh ci/checks/catalog/check-common-helpers.sh | 1 | Same ten existing master diagnostics on unchanged shell files; independent baseline finding. | local feasibility evidence |
| task-local actionlint --version | 0 | Fresh SHA-256-verified release extraction from the versioned Parent lock; reported 1.7.12. | 20260718T110350Z-fnd-framework-0003-delivery-c3a1f003 |
| task-local zizmor --version | 0 | Fresh SHA-256-verified release extraction from the versioned Parent lock; reported 1.27.0. | 20260718T110350Z-fnd-framework-0003-delivery-c3a1f003 |
| rtk gh api repos/Easton97-Jens/ModSecurity-test-Framework/commits/cdc91a398d6c156eaff927d742b23018a3817fb6/check-runs | 0 | Base/master has independent SonarCloud Code Analysis and common-structure failures. | GitHub base check evidence |

For the authorized delivery revalidation, the Parent versioned lock and its
repository-native helper were rechecked before a fresh, task-owned local
installation. The helper requires the exact upstream release URL and asset,
validates SHA-256 before extraction, and does not alter the system or PATH.

| Tool | Exact upstream release identity | Exact asset and SHA-256 |
| --- | --- | --- |
| actionlint | rhysd/actionlint v1.7.12; release commit `914e7df21a07ef503a81201c76d2b11c789d3fca` | `actionlint_1.7.12_linux_amd64.tar.gz`; `8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8` |
| zizmor | zizmorcore/zizmor v1.27.0; release commit `e2627367eb7c917a90503ce05a66872fd91da6fb` | `zizmor-x86_64-unknown-linux-gnu.tar.gz`; `277f2bd8fd37cf60c42ab7afca6faa884e65440fa31e02b44bdaae60f62a358f` |

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| rtk env ... python -m unittest discover -s tests/security_regression -p test_workflow_action_pins.py -v | 0 | 21 focused action-pin regression tests passed. | 20260718T110350Z-fnd-framework-0003-delivery-c3a1f003 |
| rtk env ... python ci/checks/security/check-workflow-action-pins.py | 0 | All five actual Framework workflows contain only full-SHA external references. | 20260718T110350Z-fnd-framework-0003-delivery-c3a1f003 |
| rtk env ... python -m unittest discover -s tests/security_regression -v | 0 | 34 security-regression tests passed. | 20260718T110350Z-fnd-framework-0003-delivery-c3a1f003 |
| rtk env ... make lint | 0 | Framework lint, shell syntax, workflow syntax, focused pin suite, real checker, CRS pinning, and documentation aggregate passed. | 20260718T110350Z-fnd-framework-0003-delivery-c3a1f003 |
| rtk ... check-workflow-action-pins.py --workflow-root safe fixture | 0 | Full SHA, local action, local reusable workflow, external reusable full SHA, and folded block-scalar text were accepted. | 20260718T110350Z-fnd-framework-0003-delivery-c3a1f003 |
| rtk ... check-workflow-action-pins.py --workflow-root unsafe fixture | 1 (expected) | Rejected `@v4` with an inline comment, a short hash, Docker, an explicit key, an alias, and an external reusable `@v1`. | 20260718T110350Z-fnd-framework-0003-delivery-c3a1f003 |
| task-local actionlint against all five workflows | 1 (baseline-only) | Same unchanged SC2046 embedded-shell warning as Framework master; no task-owned actionlint/ShellCheck diagnostic. | master and current-run comparison |
| task-local zizmor --offline against all workflows | 13 (baseline-only) | Seven master `unpinned-uses` high findings were removed; only four pre-existing `artipacked` findings remain. | master and current-run comparison |
| task-local zizmor --offline --min-severity high against all workflows | 0 | No high or critical finding remains on the task branch. | 20260718T110350Z-fnd-framework-0003-delivery-c3a1f003 |
| rtk shellcheck ci/lib/common.sh ci/checks/catalog/check-common-helpers.sh | 1 (baseline-only) | Same ten diagnostics on unchanged shell files on master and the task branch; no task-owned new diagnostic. | master and current-run comparison |
| rtk make check-bilingual-docs, check-doc-links, check-repository-path-references, check-documentation | 0 | Bilingual, links, paths, and documentation checks passed. | 20260718T110350Z-fnd-framework-0003-delivery-c3a1f003 |
| rtk git diff --check | 0 | No whitespace error. | 20260718T110350Z-fnd-framework-0003-delivery-c3a1f003 |

Codex Security revalidation and the executable fixture matrix found no concrete
bypass in the required matrix. They confirmed fail-closed handling of explicit
flow keys, node properties and aliases; quoted/escaped values; comments;
.yml/.yaml; local, Docker, reusable, branch, short-hash, and GitHub-expression
forms; and literal/folded block-scalar boundaries. The raw actionlint and
zizmor invocations were preserved as baseline evidence rather than suppressed:
the remaining diagnostics are present on the unchanged Framework master.

## Documentation, delivery, and residual risk

This English record and its German companion document the Framework change. No
GitHub Actions runtime execution was performed. At this record revision, the
user authorizes the focused Framework commit, normal push, and Draft-PR
collection after the final scope review. It intentionally contains no future
commit SHA, remote SHA, PR number, or PR URL.

No Framework merge, Parent commit, Parent gitlink update, or MRTS modification
is authorized. FND-FRAMEWORK-0001 remains dependent on Framework PR #23, and
FND-SONAR-0002 remains an independent Framework-master Sonar scope; neither is
changed here. They do not block the authorized Draft PR, but they require a
later revalidation against the then-current Framework master before
`verified_pr` can be used.

The scoped Framework diff is ready for PR collection. The post-creation PR
body must record `finding_status: fixed`, `pr_status: collected_draft_pr`,
`verification_status: pending_framework_baseline_revalidation`,
`dependency: Framework-PR #23`, `independent_blocker: FND-SONAR-0002`,
`requires_revalidation: true`, and `merge_authorization: not_granted`, together
with the observed local/remote/PR-head SHA equality. No dynamic upstream tag
rewrite was performed.
