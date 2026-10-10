# NGINX First-Byte: associate two original observations

**Language:** English | [Deutsch](20261010-04-nginx-first-byte-event-pair.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261010-04-nginx-first-byte-event-pair |
| UTC date | 2026-10-10 |
| Framework base revision | 1bfc4f8e8e4aa9d618c4cfb2205badd5008d8f75 |
| Issue or pull request | Framework PR #137; Parent PR #396 |

## Motivation and problem statement

The two existing Required First-Byte/no-full-buffer records need a causal barrier observation and genuine Rule1100301 evidence from the same native NGINX invocation. Filtering by rule first discarded the real pre-EOS append17/17; the later EOS intervention44/44 carried the rule but no barrier flags. An existing combined-event unit fixture masked this shape.

## Affected components and security boundaries

Framework catalog normalization and independent PASS revalidation; identity, causal-event and evidence-authority boundaries remain strict. No connector product change or security remediation is claimed.

## Acceptance criteria

Both real separated-event records validate without inventing event fields. Missing, ambiguous, mismatched or tampered evidence fails closed. Existing single-event controls remain valid; Required IDs and schemas remain unchanged.

## Alternatives considered

Relaxing First-Byte validation or injecting the later rule into the append was rejected. Selecting only the later rule witness cannot establish the causal barrier.

## Implementation decision

Associate the original append and later rule witness by one supplied transaction, connector/profile, phase and run-local sealed event authority. Explicit run mismatches, ambiguous/missing/reordered members, incompatible profiles and decreasing/invalid counters fail closed. Only the two catalog-bound records on native-nginx-http-module use this paired contract; legacy single-event validation remains unchanged.

A foreign-transaction append in the same sealed run does not activate pairing against a legitimate combined-event proof for the supplied transaction. That fallback still passes the unchanged strict single-event validator; absent, ambiguous or reversed same-transaction pairs do not gain an exception.

Only existing First-Byte fields are projected from the barrier. Decision/status/action and lifecycle EOS stay with the later witness. Body counters remain on their original events; raw counter claims must match the barrier. No rule is injected into append, no17 counters copied onto intervention, no merged event serialized, no new record fields or schema relaxation. Observation fields are the explicit union of validated original members. Standalone PASS validation rederives the pair and enforces catalog metadata rather than trusting mutable record labels.

## Changed files and tests

`ci/checks/catalog/no_crs_baseline.py`, `tests/no_crs/test_no_crs_baseline.py` and this EN/DE record pair. Six native test methods cover both records, original-pair mutations, standalone metadata/field/rule tampering, malformed counters, prior EOS and legacy controls.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Offline genuine AB proposed-regression.py | 1 | Prior collector: two genuine positive failures (RED) | nginx-full97-followup-20261010T084822Z/first-byte-two-event |
| Offline proposed-regression.py --proposed | 0 | Five tests; genuine separated records and mismatch controls | Same task-owned analysis directory |
| Offline proposed-regression.py --proposed --native | 0 | Nine tests: six proposed native methods and three existing controls | Same task-owned analysis directory |
| Native test_no_crs_baseline.py SeparatedNginxFirstByteTest, tests-only | 1 | Six methods, 22 RED assertion failures, 0.854s | versioned-red.log in the same directory |
| Native test_no_crs_baseline.py SeparatedNginxFirstByteTest, after implementation | 0 | Six methods, 7.019s | versioned-green.log |
| Native mixed-transaction legacy regression, before correction | 1 | One genuine matching-barrier failure | versioned-mixed-tx-red.log |
| Native SeparatedNginxFirstByteTest, final correction | 0 | Six methods, 7.445s, no skips | versioned-final-green.log |
| make test-no-crs-contract, initial integration | 0 | 421 tests, 181.889s, no skips | versioned-suite.log |
| make test-no-crs-contract, final mixed-transaction correction | 0 | 421 tests, 179.669s, no skips | versioned-suite-final.log |
| make check-documentation test-change-record-contract, initial | 2 | Change ID lacked filename suffix; both IDs corrected | versioned-docs.log |
| make check-documentation test-change-record-contract, corrected | 0 | All documentation checks and four CR contract tests | versioned-docs-final.log |
| AST parse of both changed Python files; git diff --check | 0 | Syntax and whitespace valid after final source correction | RTK command receipts |
| Offline genuine AB proposed-regression.py, installed source | 0 | Both real records and schemas valid; three tests run, two proposal-only controls skipped | Same immutable inputs; native controls executed separately |
| RTK-wrapped native make lint, frozen implementation on base1bfc | 0 | 604 executions in19 suites, no skips, 1246.181s; unchanged Python source/test hashes | checks/firstbyte_framework_lint_workingtree.* in the task analysis directory |

## Security impact

No security remediation is claimed. Association remains closed to the two catalog-bound native NGINX cases and rechecks original event identity, chronology, counters and standalone authority; no validation suppression is introduced.

## Documentation and runtime evidence

Genuine retained AB input reproduces two failures on the prior collector; offline validation with the integrated source validates both records and case schemas without modifying input bytes. Native regression additions cover identity/profile/run/phase/rule, missing/ambiguous/reordered members, counter and decision mismatches, standalone record tampering and legacy single-event controls. This EN/DE pair documents the Framework repair. A replay is not a new invocation or Full97; no new runtime evidence was collected by this change.

Required scope and IDs unchanged. Parent integration/Gitlink and real runtime proof are separate connector-owned work. MRTS unchanged. No overall Exact-Head or Protected PASS follows from this Framework repair.

## Checks not run

Current-head PR Sonar and a fresh bounded runtime remain pending coordinator delivery and new artifacts. Precommit single-file Vortex analysis was unavailable on the connection (403); this is not a zero-finding analysis. Full native lint passed on the frozen implementation before commit, not on a relabeled future revision. No Full97 or protected workflow was run for this repair.

## Limitations and residual risk

Offline validation reuses immutable genuine evidence; it does not prove a fresh invocation or overall Required coverage. Release/protected infrastructure remains separate.

## Final diff and review status

Integrated from clean Framework 1bfc4f8e8e4aa9d618c4cfb2205badd5008d8f75 after versioned tests-only RED. Exactly four permitted paths are modified/untracked; no catalog/schema/Required or MRTS change. Whitespace and scope checks pass. Independent coordinator review identified and verified the corrected mixed-transaction legacy regression; no further material deviation remains. Commit, remote publication and new runtime proof are subsequent independent steps.
