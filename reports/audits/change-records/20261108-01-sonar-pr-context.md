# Sonar pull-request context contract

**Language:** English | [Deutsch](20261108-01-sonar-pr-context.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261108-01-sonar-pr-context |
| UTC date | 2026-11-08 |
| Framework base revision | `d14937ce8fe7a534bb755cffa6597e62eadbb126` |
| Issue or pull request | [Framework Draft PR #169](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/169) |

## Motivation and problem statement

The Framework workflow contract required Parent C++20/C++23 scans to override
the branch as `master`, including during pull requests. This prevented those
analyses from providing the intended pull-request contexts. Parent owns the
workflow correction; Framework owns its validation contract.

## Affected components and security boundaries

The validator in `connector_suite/modsecurity_connector_tests/test_ci_security_workflows.py`,
its on-demand registration in `connector_suite/config/testing/active-cases.json`
and this English/German record change. The exact project keys, standards,
advisory behavior, source scope, scanner secret restrictions and Quality Gates
remain covered. MRTS remains read-only.

## Acceptance criteria

The corrected workflow passes the contract. Reinserting a `branch_args` matrix
field into any of the three variants fails. Direct scanner overrides of
`branch.name`, `branch.target`, `pullrequest.key`, `pullrequest.branch` and
`pullrequest.base` fail. Every negative mutation must change its input.

## Alternatives considered

Keeping the `master` override would retain the wrong analysis context. Explicit
pull-request arguments would duplicate GitHub event detection and create an
additional route for contradictory identities.

## Implementation decision

Remove `branch_args` from the exact expected matrix and reject direct scanner
branch or pull-request properties. The existing scanner selects context from
the actual GitHub event. Preserve the existing full-scope and advisory tests.
The new offline mutation test reads the admitted Parent YAML directly because
it tests scanner/matrix fields, without expanding unrelated composite actions.
Offline process and network guards remain unchanged.

## Changed files and tests

The validator gains one routing check. One regression test covers the corrected
workflow and eight negative mutations. The paired Change Record documents the
Framework contract and external Parent dependency.
The new on-demand execution is
`offline.sonar-merged-contract.sonar-standard-matrix-rejects-context-overrides`,
with eight expected subtests and explicit cases. The 80 default selectors and
100 default cases are unchanged. Native binding/archive generators are run by
the coordinating task after registration.

## Commands and results

Explicit file-before-read and post-change Secrets checks passed. Focused test
results and the exact selected roots are retained in the external task report.
A first invocation lacked `CONNECTOR_REVISION`; a second lacked `TEST_ROOT`.
Both failed during import and do not count as executed tests. With both explicit
bindings, the legacy class ran 48 tests with 26 failures and two errors in
existing broader workflow contracts; those failures remain visible separately.
The six focused Sonar methods passed (1.612 seconds), including the new eight
negative mutations. An in-memory baseline using the original Framework module
and original Parent Sonar workflow ran 47 tests with the same 26 failures and
two errors. Every failing/error method body is unchanged. A separate untrusted
PR method repeats its existing native-workflow digest failure. Logs are under
`$RUN_ROOT/contract-fix/`, where `RUN_ROOT` denotes the external task run
`20261108-sonar-free-zero` recorded in the private execution report.
The qualified Framework Python
3.15.2 environment is reused under the existing compatibility/lock contract.

With explicit Parent/Framework roots and revisions, `TEST_ROOT`, profile and
existing private output root, run the native `run-active-tests.py --on-demand
--execution offline.sonar-merged-contract.sonar-standard-matrix-rejects-context-overrides
--strict-skips --output-root <external-output-root>` through RTK. The final
native run exited 0: one method, eight observed subcases, zero skips and zero
expected failures. Its receipt is `contract-fix/native-context-direct.stdout`
under `RUN_ROOT`. Preserve earlier failures: missing output directory,
then composite expansion attempting Git after the offline guard was installed.
The direct YAML read removes that unrelated expansion from this new test; no
guard or provenance admission is relaxed.

## Security impact

This corrects analysis identity validation; it does not remediate a runtime
security vulnerability. No scanner exception, source exclusion, gate change or
credential change is introduced.

## Documentation and runtime evidence

This record has an English/German companion. No host-runtime evidence is
collected by this focused contract change. Fresh hosted analyses must establish
the delivered-head PR contexts and gate results independently.

## Checks not run

The complete acceptance campaign remains **NOT_RUN**. Full paired regression,
generated inventory/archive checks and hosted CI belong to the coordinating
task and are not certified by this record.

## Limitations and residual risk

A local contract pass cannot prove that SonarCloud created a PR context or
stored an issue decision. Existing master-branch findings remain separate from
the corrected PR contexts until independently reconciled.

## Final diff and review status

Maintenance reconciliation on 2026-11-14 preserves the current master tool
updates, including the reviewed Sonar v8.4.1 action identity. The private
diagnostic executable remains pinned to its unchanged reviewed commit. A Git
fixture regression covers atomic publication from the exact previous private
v8.4.0 base, stale working callers and mutated prior inputs. The 100 default
cases and 80 default selectors remain the required inventory contract. Native
regeneration and focused validation results are recorded by the coordinating
task; this note alone claims no test or hosted analysis result.

Changes are handed to the coordinating task for scoped diff review, native
documentation/generator checks and normal delivery on the existing Draft PR.
This record does not declare the overall task complete.
