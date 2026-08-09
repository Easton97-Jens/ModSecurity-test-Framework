# Change record: Fix Common-version post-apply test-fixture invariance

**Language:** English | [Deutsch](20260809-01-fix-common-version-post-apply-test-invariance.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260809-01-fix-common-version-post-apply-test-invariance |
| UTC date | 2026-08-09 |
| Framework base revision | c71e15db7b7517b237add9fa09b3493e7bc93627 |
| Issue or pull request | No pull request exists at record authorship. One Framework Draft pull request is user-authorized after final local checks; this record never authorizes a merge. |

## Motivation and problem statement

Common-version publisher run #17 passed its resolver and candidate-validation
jobs, correctly applied HAProxy 3.2.21 to 3.2.22 with the reviewed digest, and
then failed in the publish job's “Independently revalidate and apply the
candidate” step while rerunning regression tests. Several fixtures read mutable
canonical ci/lib/common.sh pins and hard-coded 3.2.22 as a necessarily new
target. The validator starts with an unapplied candidate, whereas the publisher
revalidates the already-mutated candidate; correct idempotent plan_update()
therefore returns None. A valid candidate became a false post-apply failure.

## Affected components and security boundaries

This is a Framework test-fixture and test-helper change under
tests/security_regression/. It does not alter ci/lib/common.sh, the updater,
workflows, publication authority, connector runtime behavior, Parent, MRTS, or
a Gitlink.

## Acceptance criteria

- A fresh fixture applies and revalidates an approved automatic update.
- An already-applied tuple is a semantic no-op.
- The Run #17 HAProxy tuple and a synthetic future tuple both preserve the
  focused publisher suite.
- Manual provenance lines remain byte-exact after the automatic fixture update.
- No production version pin or workflow behavior changes.

## Alternatives considered

Keeping canonical-pin fixtures preserves the false coupling. Relaxing the
post-apply assertions hides a real updater regression. Changing the publisher,
updater, workflow, or approved product pins exceeds the Framework test scope.
The selected approach uses temporary fixtures with synthetic reviewed tuples.

## Implementation decision

A test-only helper structurally replaces exactly one supported common.sh
assignment and rejects missing or ambiguous assignments. Provenance tests build
temporary Framework roots with synthetic reviewed tuples while retaining real
production scripts as code under test. The Common-version suite adds
post-apply idempotence and disposable-child-suite checks for the recorded Run
#17 tuple and a future synthetic tuple. Archive tests use package-qualified
test-helper imports, so fully qualified unittest execution is not dependent on
caller-provided PYTHONPATH.

## Changed files and tests

- tests/security_regression/common_version_fixture_support.py adds the
  test-only single-assignment fixture writer.
- test_common_versions_sonar_provenance.py isolates HAProxy fixtures and adds
  post-apply/no-op invariance coverage.
- test_nginx_release_provenance.py, test_crs_git_ref_provenance.py,
  test_modsecurity_v3_git_ref_provenance.py, test_apr_util_provenance.py,
  test_pcre2_archive_digest.py, and test_nginx_archive_digest.py use
  synthetic reviewed tuples or structural replacement.
- This paired Change Record and its indexes document the Framework-only scope.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| rtk proxy env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.security_regression.test_common_versions_sonar_provenance tests.security_regression.test_nginx_release_provenance tests.security_regression.test_crs_git_ref_provenance tests.security_regression.test_modsecurity_v3_git_ref_provenance tests.security_regression.test_apr_util_provenance -v | 0 | 65 focused publisher and provenance tests passed on the formatted end state, including Run #17 and synthetic-future post-apply cases. | Task-owned external Framework worktree |
| rtk proxy env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.security_regression.test_pcre2_archive_digest tests.security_regression.test_nginx_archive_digest -v | 0 | 22 archive/release provenance tests passed. | Task-owned external Framework worktree |
| rtk proxy python3 -m py_compile tests/security_regression/*.py | 0 | All eight edited test modules compiled. | Task-owned external Framework worktree |
| rtk proxy ruff check and ruff format --check for the eight changed modules | 0 | Ruff lint and formatting accepted the final changed-file scope. | SHA-256-locked task-local tool directory |
| rtk proxy make test-ci-security-contract test-workflow-action-pins test-workflow-security-contract check-github-actions-workflows | 0 | CI-security, action-pin, workflow-security, and workflow pin/permission contracts passed. | Task-owned external Framework worktree |
| rtk proxy make check-documentation test-change-record-contract check-bilingual-docs check-doc-links | 0 | EN/DE documentation, links, and Change Record contracts passed. | Task-owned external Framework worktree |
| rtk proxy make lint | 0 | Full native lint matrix passed, including shell syntax, provenance, CI-security, workflow, documentation, and whitespace checks. | Task-owned external Framework worktree |
| rtk proxy actionlint; rtk proxy zizmor --offline; rtk proxy shellcheck -x ci/lib/common.sh | 0 | Actionlint, zizmor with repository-configured suppressions, and relevant Common-helper ShellCheck passed. | SHA-256-locked task-local tool directory |
| rtk proxy git diff --check | 0 | No whitespace errors in the Framework source diff. | Task-owned external Framework worktree |
| rtk proxy python3 finalize_scan_contract.py --scan-dir security-scan-final-20260809T064127Z --source-root Framework-worktree | 0 | The complete final twelve-path diff-scoped security scan sealed with zero reportable findings. | Task-owned external security-scan evidence directory |

## Security impact

No security remediation was performed; this change strengthens test-fixture
invariance. It preserves the fail-closed provenance, checksum, immutable-Git,
post-write revalidation, and rollback controls that the tests exercise. The
complete diff-scoped security review found no reportable patch-anchored issue.

## Documentation and runtime evidence

This English/German Change Record pair and its indexes are updated. Run
31292884310 is hosted failure evidence: the candidate was valid, but
post-apply fixture coupling made the publisher test step fail. No connector or
production runtime evidence was collected, and no hosted exact-head result
exists at this record stage.

## Checks not run

The native Make/documentation/lint matrix is complete. Pyright is blocked
locally because its hash-locked package requires unavailable node; no global
tool was installed. Full-worktree ShellCheck has existing findings outside this
test-only scope, so the focused production common helper is the relevant
control check. Hosted exact-head checks, Sonar analysis, and review state do
not exist until the user-authorized Draft pull request is opened.

## Limitations and residual risk

The helper is trusted test-only code and writes only temporary fixtures at
current call sites. Promotion into a production input path would require
replacement-value validation and containment review. Hosted validation remains
required before a Draft pull request is considered verified.

## Final diff and review status

At record authorship the Framework work is local and uncommitted. The source
scope is test code and this Change Record; whitespace review, focused Ruff,
two focused regression suites, and a sealed complete security diff review are
recorded above. No Parent, MRTS, Gitlink, workflow, product-pin, push,
pull-request, or merge action has occurred yet.
