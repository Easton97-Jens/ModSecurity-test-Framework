# Change record

**Language:** English | [Deutsch](20261103-06-canonical-language-switches.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261103-06-canonical-language-switches |
| UTC date | 2026-11-03 |
| Framework base revision | 189c42d0b4362fccc732d2480935348220c287da |
| Issue or pull request | Follow-up to Framework #167 and Parent #443 |

## Motivation and problem statement

The strict Parent documentation consumer rejected four language-switch lines in three newly delivered Framework guide pairs. The Framework standalone documentation target had checked other invariants successfully; it did not prove this Parent consumer contract.

## Affected components and security boundaries

Language-switch markup in the protocol, measurement/SBOM and protected-caller guide pairs, two illustrative JSON lines and this record pair. No executable source, pin, schema, case or validation rule changes.

## Acceptance criteria

Use the exact established English/German language-switch syntax and preserve all other guide bytes. Require native strict pair/link checks and full Framework documentation, unchanged native metadata and100-case inventory, then fresh hosted checks and a regular exact-head follow-up merge.

## Alternatives considered

Changing the strict checker or ignoring module documents would weaken the contract. Normalize the four incorrect switch lines and retain a byte-identical technical JSON example in both languages.

## Implementation decision

English uses **Language:** English | Deutsch link; German places the English link before | Deutsch. Existing correct switches stay byte-identical. Three German illustrative placeholder strings on two JSON lines use the shared English values; field names, schema identifier and exporter semantics stay unchanged. Parent selects the actual follow-up merge after independent checks.

## Changed files and tests

Four one-line switch fixes and two JSON example lines, this paired record. Existing strict ordinary_pair_errors/local_link_errors APIs validate all three affected pairs; no new test or checker exception.

## Commands and results

RTK and existing Framework CPython3.15.2; exact commands/results retained in integration run20261103T175654Z-integration, framework-doc-followup/. Checks include strict three-pair consumer validation, unchanged remaining-content proof, native metadata write/check, inventory and full documentation. Publication and current-head CI receipts follow in the PR.

## Security impact

No executable/security behavior, gate, source/path guard or protected identity changes. Canonical markup restores the existing cross-repository consumer contract.

## Documentation and runtime evidence

Only EN/DE language switches and illustrative JSON placeholders change; no host runtime is claimed. Thirteen real final-pair invocations remain required after final Parent integration.

## Checks not run

No local Sonar preflight/install/auth repair, comprehensive campaign, publisher or protected dispatch. Fresh hosted analysis is still required; prior-head success is not reused.

## Limitations and residual risk

This fixes the concrete Parent consumer failure only. Independent historical migration-map/Apache/advisory findings and comprehensive acceptance goals remain separate.

## Final diff and review status

Review the exact six-line source diff and unchanged remaining bytes; native checks and current-head CI must pass. Existing task worktrees/evidence are retained.
