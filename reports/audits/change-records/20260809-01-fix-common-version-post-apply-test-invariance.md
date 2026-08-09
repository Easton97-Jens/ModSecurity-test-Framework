# Change record: Fix Common-version post-apply test-fixture invariance

**Language:** English | [Deutsch](20260809-01-fix-common-version-post-apply-test-invariance.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260809-01-fix-common-version-post-apply-test-invariance |
| UTC date | 2026-08-09 |
| Framework base revision | c71e15db7b7517b237add9fa09b3493e7bc93627 |
| Issue or pull request | Framework Draft PR [#70](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/70) on task-owned branch `fix/common-version-post-apply-test-invariance`. This record documents a user-authorized follow-up refactor; it never authorizes a merge. |

## Motivation and problem statement

Common-version publisher run #17 passed its resolver and candidate-validation
jobs, correctly applied HAProxy 3.2.21 to 3.2.22 with the reviewed digest, and
then failed in the publish job's “Independently revalidate and apply the
candidate” step while rerunning regression tests. Several fixtures read mutable
canonical ci/lib/common.sh pins and hard-coded 3.2.22 as a necessarily new
target. The validator starts with an unapplied candidate, whereas the publisher
revalidates the already-mutated candidate; correct idempotent plan_update()
therefore returns None. A valid candidate became a false post-apply failure.

Follow-up SonarQube Cloud PR analysis passed its Quality Gate with zero new
issues and hotspots, but reported 20 new duplicated lines (1.876...%). The
two exact duplicate blocks were in the Common-version provenance test, while
the named workflow-tool updater/test pair also repeated canonical candidate
serialization and official release URL construction. The user authorized a
small behavior-preserving refactor of all three task-owned files rather than a
metric suppression, exclusion, or denominator-only change.

## Affected components and security boundaries

This is a Framework test-fixture/test-helper and CI-updater refactor under
tests/security_regression/, tests/ci_security/, and ci/tools/. It does not
alter ci/lib/common.sh, workflows, publication authority, connector runtime
behavior, Parent, MRTS, or a Gitlink. The CI-updater security boundary remains
the reviewed lock-derived GitHub identity, canonical candidate bytes, and
fail-closed RUNNER_TEMP file controls.

## Acceptance criteria

- A fresh fixture applies and revalidates an approved automatic update.
- An already-applied tuple is a semantic no-op.
- The Run #17 HAProxy tuple and a synthetic future tuple both preserve the
  focused publisher suite.
- Manual provenance lines remain byte-exact after the automatic fixture update.
- No production version pin or workflow behavior changes.
- The actual SonarQube Cloud duplicate blocks are replaced by one private test
  setup helper; no analysis suppression, exclusion, or metric-padding change
  is used.
- Canonical candidate bytes and official release/asset URLs have one source of
  construction while preserving their digest, Base64, lock, and file-output
  contracts.

## Alternatives considered

Keeping canonical-pin fixtures preserves the false coupling. Relaxing the
post-apply assertions hides a real updater regression. Changing the publisher,
updater, workflow, or approved product pins exceeds the Framework test scope.
The selected approach uses temporary fixtures with synthetic reviewed tuples.

Adding a SonarQube suppression, exclusion, or unrelated non-duplicated code
would conceal or merely dilute the observed duplication. Combining action and
tool candidate paths would risk collapsing their distinct provenance controls.
The selected helpers centralize only exact common representations and retain
the separate action/tool and sink-time validation paths.

## Implementation decision

A test-only helper structurally replaces exactly one supported common.sh
assignment and rejects missing or ambiguous assignments. Provenance tests build
temporary Framework roots with synthetic reviewed tuples while retaining real
production scripts as code under test. The Common-version suite adds
post-apply idempotence and disposable-child-suite checks for the recorded Run
#17 tuple and a future synthetic tuple. Archive tests use package-qualified
test-helper imports, so fully qualified unittest execution is not dependent on
caller-provided PYTHONPATH.

The follow-up uses pure `release_url`/`release_asset_url` helpers and one
canonical UTF-8 candidate-byte helper in the updater; Base64, SHA-256, and the
exclusive `0600` candidate file now consume the same bytes. Its paired tests
use the existing candidate builder for both groups and assert those byte-level
contracts. The Common-version test now owns the repeated safe/manual setup in
one temporary context helper while each consumer retains its distinct
provenance, idempotence, and source-preservation assertions.

## Changed files and tests

- tests/security_regression/common_version_fixture_support.py adds the
  test-only single-assignment fixture writer.
- test_common_versions_sonar_provenance.py isolates HAProxy fixtures and adds
  post-apply/no-op invariance coverage.
- test_nginx_release_provenance.py, test_crs_git_ref_provenance.py,
  test_modsecurity_v3_git_ref_provenance.py, test_apr_util_provenance.py,
  test_pcre2_archive_digest.py, and test_nginx_archive_digest.py use
  synthetic reviewed tuples or structural replacement.
- ci/tools/update-workflow-tools.py centralizes trusted release/asset URL and
  canonical candidate-byte construction without changing updater authority.
- tests/ci_security/test_update_workflow_tools.py centralizes candidate
  scaffolding and adds exact byte, Base64, digest, and candidate-file tests.
- test_common_versions_sonar_provenance.py replaces the two SonarQube Cloud
  duplicate blocks with a private safe/manual application context helper.
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
| rtk proxy make lint | 0 | Final native lint matrix passed after the follow-up, including shell syntax, provenance, CI-security, workflow, documentation, and whitespace checks. | Task-owned external Framework worktree |
| rtk proxy actionlint; rtk proxy zizmor --offline; rtk proxy shellcheck -x ci/lib/common.sh | 0 | Actionlint, zizmor with repository-configured suppressions, and relevant Common-helper ShellCheck passed. | SHA-256-locked task-local tool directory |
| rtk proxy git diff --check | 0 | No whitespace errors in the Framework source diff. | Task-owned external Framework worktree |
| rtk proxy python3 finalize_scan_contract.py --scan-dir security-scan-final-20260809T064127Z --source-root Framework-worktree | 0 | The complete final twelve-path diff-scoped security scan sealed with zero reportable findings. | Task-owned external security-scan evidence directory |
| rtk proxy env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.ci_security.test_update_workflow_tools -v | 0 | 26 updater regression tests passed after the canonical URL/byte refactor. | Task-owned external Framework worktree |
| rtk proxy env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.security_regression.test_common_versions_sonar_provenance.CommonVersionProvenanceTests.test_safe_partial_update_preserves_all_manual_provenance_lines_and_revalidates tests.security_regression.test_common_versions_sonar_provenance.CommonVersionProvenanceTests.test_common_version_regressions_are_invariant_after_candidate_application -v | 0 | Both consumers of the extracted safe/manual setup passed. | Task-owned external Framework worktree |
| rtk proxy env COMMON_VERSION_POST_APPLY_META_CHILD=1 PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.security_regression.test_common_versions_sonar_provenance -v | 0 | 29 Common-version tests passed; the recursive publisher-state test was intentionally skipped under its documented child guard. | Task-owned external Framework worktree |
| rtk proxy env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.security_regression.test_common_versions_sonar_provenance.CommonVersionProvenanceTests.test_publisher_focused_suite_accepts_real_and_synthetic_applied_tuples -v | 0 | The isolated recursive publisher-state test passed in 447.165s for the Run #17 and future synthetic tuples. | Task-owned external Framework worktree |
| rtk proxy python3 -m py_compile ci/tools/update-workflow-tools.py tests/ci_security/test_update_workflow_tools.py tests/security_regression/test_common_versions_sonar_provenance.py | 0 | All follow-up changed Python files compiled. | Task-owned external validation root |

## Security impact

No security remediation was performed; this change strengthens test-fixture
invariance. It preserves the fail-closed provenance, checksum, immutable-Git,
post-write revalidation, and rollback controls that the tests exercise. The
complete diff-scoped security review found no reportable patch-anchored issue.
The follow-up focused security reviews found no regression: URL helpers remain
fed by lock-derived identities, and the shared Common-version context retains
the HAProxy-only, manual-provenance, temporary-containment, revalidation,
idempotence, and source-preservation contracts.

## Documentation and runtime evidence

This English/German Change Record pair and its indexes are updated. Run
31292884310 is hosted failure evidence: the candidate was valid, but
post-apply fixture coupling made the publisher test step fail. PR #70's prior
head passed SonarQube Cloud with zero issues/hotspots but 20 duplicate new
lines; the current follow-up head still requires a fresh hosted exact-head
analysis. No connector or production runtime evidence was collected.

## Checks not run

The final native Make/documentation/lint matrix passed for the follow-up.
Pyright is blocked locally because its hash-locked package requires unavailable
node; no global tool was installed. Full-worktree ShellCheck has existing
findings outside this scope, so the focused controls are relevant. Hosted
exact-head checks, Sonar analysis, and review state remain required for the
updated PR head.

## Limitations and residual risk

The helper is trusted test-only code and writes only temporary fixtures at
current call sites. Promotion into a production input path would require
replacement-value validation and containment review. Hosted validation remains
required before a Draft pull request is considered verified.

## Final diff and review status

The Framework PR exists but the user-authorized de-duplication follow-up is
still local at this record update. The final native lint matrix and focused
security review passed. The final source scope is the original post-apply
fixture repair plus three focused refactor files and this paired record; no
Parent, MRTS, Gitlink, workflow, or product-pin change is present. Fresh
commit, push, exact-head CI/Sonar/review evidence, and the separately
authorized PR merge remain pending.
