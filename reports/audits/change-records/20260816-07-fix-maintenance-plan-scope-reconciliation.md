# Change record: 20260816-07-fix-maintenance-plan-scope-reconciliation

**Language:** English | [Deutsch](20260816-07-fix-maintenance-plan-scope-reconciliation.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260816-07-fix-maintenance-plan-scope-reconciliation` |
| UTC date | `2026-08-16` |
| Framework base revision | `79e2757c4cc99372ce140458a986edc2553f2bd9` |
| Issue or pull request | Resulting-master workflow run `31979182626`; no pull-request or merge result is established by this record. |

## Motivation and problem statement

After the CodeQL release-resolution correction was merged, resulting-master
run `31979182626` resolved the mandatory global and selected runtime scopes but
failed the read-only review-plan reconciliation step with exit code 2. The
failure reported that the scope must include every mandatory global component.
The plan represented concrete checked component IDs separately from aggregate
result scopes, so checking aggregate names against the component-ID list
rejected a valid normalized result shape.

## Affected components and security boundaries

The affected Framework component is review-plan validation in
`ci/tools/reconcile-common-version-review-issues.py`, with regression coverage
in its CI-security tests. The relevant boundary is trusted CI maintenance
plan integrity: mandatory global coverage must remain present even when a
runtime/source component filter is used. Parent, connector runtime, and the
read-only `tools/MRTS` checkout are outside scope.

## Acceptance criteria

1. Reconciliation accepts a normalized plan whose concrete checked component
   IDs cover all mandatory global result scopes.
2. Aggregate scopes are evaluated from normalized results associated with
   checked component IDs, not as if they were component IDs.
3. Missing mandatory global result scopes remain fail-closed.
4. A component filter continues to restrict only additional runtime/source
   components; Go-FTW, Albedo, and canonical CI pins remain covered.
5. Duplicate normalized component IDs and mismatched fixed global
   scope/component pairs are rejected, while reviewed dynamic Action/tool
   component families remain accepted.

## Alternatives considered

- Removing mandatory-global validation was rejected because every maintenance
  run must retain global coverage.
- Treating aggregate scope names as component IDs was rejected because the
  resolver's normalized result model uses concrete component IDs plus a
  separate aggregate scope.
- Allowing component-filtered plans to omit global results was rejected because
  it would violate the shared maintenance contract.

## Implementation decision

The reconciler keeps the concrete `checked_components` contract and validates
mandatory global coverage from the `scope` values of normalized
`component_results` whose `component_id` is checked. This preserves the
fail-closed requirement while matching the resolver's result model. The
validator additionally rejects duplicate normalized component IDs and enforces
the fixed global scope/component mappings, with explicit dynamic prefixes for
Action and security-tool component families. The English and German security
guides document the global-scope and filter semantics.

## Changed files and tests

The implementation and regression tests cover normalized global result scopes,
missing aggregate scopes, duplicate result IDs, mismatched fixed mappings,
accepted dynamic Action/tool component families, unlisted global components,
lifecycle reconciliation, and the validate-only CLI plan shape. This record
and the paired security guides document the observed failure and the
correction.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `gh run view 31979182626 --repo Easton97-Jens/ModSecurity-test-Framework --json headSha,jobs,conclusion` | `0` | The resulting-master run at `79e2757c4cc99372ce140458a986edc2553f2bd9` completed scope resolution, then failed read-only review-plan reconciliation with exit code 2. | [Run 31979182626](https://github.com/Easton97-Jens/ModSecurity-test-Framework/actions/runs/31979182626) |
| `gh run view 31979182626 --repo Easton97-Jens/ModSecurity-test-Framework --log-failed` | `0` | The failed step reported that the scope must include every mandatory global component. | [Run 31979182626](https://github.com/Easton97-Jens/ModSecurity-test-Framework/actions/runs/31979182626) |
| `git diff --check -- docs/security/ci-security-tooling.md docs/security/ci-security-tooling.de.md reports/audits/change-records/20260816-07-fix-maintenance-plan-scope-reconciliation.md reports/audits/change-records/20260816-07-fix-maintenance-plan-scope-reconciliation.de.md` | `0` | No whitespace errors in the documentation and Change Record files. | Framework task worktree |

## Security impact

The correction preserves fail-closed mandatory-global coverage and does not
weaken the runtime/source component filter boundary. No new permission,
credential, network authority, or artifact path is introduced.
Duplicate result identifiers and unexpected fixed global mappings are rejected;
only the reviewed dynamic component families remain extensible.

## Documentation and runtime evidence

The English and German security guides document that Go-FTW, Albedo, canonical
language pins, and canonical CI pins participate in every shared maintenance
run, while filters apply only to additional runtime/source components. Run
`31979182626` is observed runtime failure evidence only. It does not prove a
successful corrective hosted run, a pull-request result, a merge, or any
SonarQube Cloud result.

## Checks not run

- The complete focused and full Framework validation suite is owned by the
  implementation work and is not represented as passed by this documentation
  change.
- No successful post-correction hosted run, pull request, SonarQube Cloud
  result, or master merge is established by this record.

## Limitations and residual risk

The correction remains unverified in hosted CI until a later run demonstrates
that resolver and reconciliation both complete successfully. The user-specified
SonarQube Cloud conditions remain required before any future merge.

## Final diff and review status

This documentation subtask changes only the paired security guides and paired
Change Record. The files are unstaged and uncommitted for the implementation
agent's handoff. No push, pull request, merge, Parent gitlink update, or MRTS
action was performed by this subtask.
