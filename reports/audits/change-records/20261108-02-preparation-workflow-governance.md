# Preparation workflow and governance contracts

**Language:** English | [Deutsch](20261108-02-preparation-workflow-governance.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261108-02-preparation-workflow-governance |
| UTC | 2026-11-08 |
Framework base: `c34343c65311b78d3de87059a4a20bcfe8e9919d`.
Scope: PRECOMMIT working-source preparation for [Draft PR #169](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/169).

## Motivation and problem statement

The earlier complete workflow-contract replay reported 26 failure records across 23 unique methods and two error methods in 48 tests. Four failed module subtests account for the repeated failure records. The 47-method baseline had the same failures/errors; the untrusted-PR failure overlaps both runs. Import-aborted invocations are separate. These failures required current-contract diagnosis rather than a baseline exemption. The separate 84-record legacy governance audit is not this workflow test block.

## Affected components and security boundaries

Framework changes are `connector_suite/modsecurity_connector_tests/test_ci_security_workflows.py`, `ci/lib/common.sh`, and `.codex/inheritance-manifest.toml`, plus native inventory/archive postimages and this paired record. Parent owns workflow orchestration, its publisher mode guard and governance updater; those are external dependencies. MRTS governance PR #7 and its reviewed revision are external dependencies, not Framework delivery facts. The Framework MRTS Gitlink is not advanced by this record.

## Acceptance criteria

Replay all original 48 methods with zero failures, errors or skips; preserve meaningful mutation rejection and the selected 100-case default. Validate the shell permission replacement against the original mask and native shells. Update only reviewed inheritance digests through the native producer. Require later published-chain and hosted checks before delivery closure.

## Alternatives considered

Dropping tests, skipping historical failures, replacing assertions with unconditional acceptance, weakening offline guards, broadening workflow permissions, suppressing scanner warnings or increasing the default case cap would invalidate the contract. Parent-owned test archive paths are obsolete after the Framework ownership migration.

## Implementation decision

Bind tests to current immutable Framework bootstrap and native dispatch contracts, fixed product allowlists, explicit fixture ownership and native inventory selectors. Review expanded Sonar and publisher contracts before updating their closed digests. Preserve the original 20 native Sonar mutations and eight context mutations; six extra pin mutations reject missing, wrong and literal-placeholder pins before normalization. All extra diagnostic variants belong to existing on-demand methods.

The actual broker chain is Parent wrapper → locked Framework historical wrapper → fixed Parent broker at `8ae707d72f1a8acb25d239e55e28a73cbc7522b1`. The current expansion validates exact grants, remote/path/revision, six required string inputs and passthroughs; the terminal immutable body retains its deep trust assertions. The explicit full-module diagnostic requires that Git object locally and fails if absent, without fetch or skip. Ordinary CI uses the compact native supply-chain group.

The shell change replaces the equivalent octal write-bit arithmetic with exact mode-character validation, preserving failure behavior. The inherited architecture, command-execution and Sonar policy hashes were individually reviewed and updated by the native Parent producer under coordinated exclusive ownership, optimistic checks and atomic replacement; this is not a kernel compare-and-swap guarantee.

## Changed files and tests

The workflow source has SHA256 `2c2d21681353a350088858aad9ed0e989159968e0c325dbcd09b6b8587c50bab`. Its 48 method identities are unchanged. The expanded Sonar closed digest is `8346bcb3261d71210ff28687c15bd1e9b69e848ec0316dec966878f524fc56ff`; the independently reviewed publisher digest is `ca21fd86d12ba5bd7fc489073a3e26fdfdcab702e24ba4c4ea918c49a575e38f`.

The shell postimage SHA256 is `850f9d9bc198391a2a74be17a22f79dd96ef3305c9199a1b8ba85413d3bda2ab`. The inheritance manifest SHA256 is `2703f1015c20cb89eecb8b75e492947a353836e3baa78d8d9d0d2472d11d1fd1` (architecture `a62b475a…`, command execution `1b30804d…`, Sonar `3ec379f7…`). Native metadata checks distinguish explicit worktree diagnostics from final canonical nested validation.

## Commands and results

Through RTK, the qualified interpreter `$FRAMEWORK_VENV/bin/python` ran `-m unittest -v modsecurity_connector_tests.test_ci_security_workflows.CiSecurityWorkflowTest` with explicit Parent/Framework roots and revisions, `TEST_ROOT`, Framework-only `PYTHONPATH`, `PYTHONSAFEPATH=1`, `PYTHONNOUSERSITE=1`, bytecode disabled and private external temporary output. The full class passed twice; the instrumented replay observed 48 methods, 222 subtest executions in 14 methods, zero failures/errors/skips. Subtests and retries do not create new unique cases.

The inventory still selects 80 execution selectors and 100 cases. Only one method from this class is selected by default, and its AST is identical to the base commit. No method was added, removed or skipped. The 222 observed subtests are explicit diagnostic executions, not additions to the default selection.

Native dash/bash syntax, the real host-Git boundary and 4,690 valid/invalid mode cases per shell passed; 14 existing focused regression methods passed. Parent's native metadata producer passed 22 tests; the Parent catalog and explicit Parent/Framework/MRTS worktree diagnostic passed. These are qualified local results, not final-chain or hosted results.

The native inventory producer refreshed exactly two existing source digests; every nonbinding field, selector, case and exception identity is unchanged. The native archive producer preserved every Python/Go definition identity. Subsequent `update-inventory-bindings.py --check`, `update-test-archive.py --check`, `check-doc-links.py`, `check-variable-documentation.py`, `check-repository-path-references.py` and `check-change-records.py` each exited 0. Two earlier oversized aggregate Secrets attempts timed out at 30,000 ms; the full same input union was recovered with 32 complete-file PATH batches, all exit 0, covering 2,430 distinct files without omission. No source reads or changes continued during the observed global pause; native checks ran only after explicit clearance.

## Security impact

A real external Parent publisher defect admitted a regular-file executable-bit flip. Its narrow same-mode modification guard was corrected and exercised with the existing raw-mode/status negatives. Framework tests preserve this boundary. No scanner exception, source exclusion, credential mutation, gate weakening, merge or root-boundary expansion is introduced.

## Documentation and runtime evidence

The English/German records describe the same scope. Private run artifacts are under `$RUN_ROOT/workflow-tests/`. Evidence is under `$EVIDENCE_ROOT/`: `workflow-tests/full-class-result.json`, `workflow-tests/final-default100-scope.json`, `workflow-tests/publisher-mode-repro.json`, `warnings/semantic-remediation/applied-validation.json`, `warnings/semantic-remediation/focused-regression.json`, `inheritance/native-metadata-applied.json` and `inheritance/native-inheritance-checks.json`. These external files are not portable repository documentation links. A corrected Secrets-protocol incident is recorded separately; the premature read is not represented as compliant. No new service or runtime acceptance campaign was started.

## Checks not run

The full acceptance campaign remains **NOT_RUN**. Fresh hosted analysis of these source changes, hosted FIFO/JSON reproductions, final published-pair regression and canonical nested inheritance `--all` remain coordinating delivery checks. Existing hosted results cannot certify this PRECOMMIT source. Local Python 3.14.4 is not evidence for the required MRTS Python 3.14.6 hosted lane.

## Limitations and residual risk

Native shell/JSON validity cannot prove complete analyzer coverage. The FIFO parser warning, oversized JSON parse omission and internal publication diagnostics require independently qualified hosted disposition. Local tests do not prove an issue transition, hosted Quality Gate or final Gitlink chain. The 84-record governance classification is separate and was not rerun as a fresh audit here.

## Final diff and review status

The coordinator owns final diff review, native documentation/inventory receipts, normal commits/pushes and existing Draft-PR updates. Independent semantic review approved the publisher boundary before its closed digest changed; final verification is recorded externally. This record reports local preparation and does not declare overall acceptance or delivered-head readiness.
