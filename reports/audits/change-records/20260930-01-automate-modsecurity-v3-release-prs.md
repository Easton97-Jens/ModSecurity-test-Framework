# Prepare automatic ModSecurity v3 release update PRs

**Language:** English | [Deutsch](20260930-01-automate-modsecurity-v3-release-prs.de.md)

## Change identity and status

- Change ID: `20260930-01-automate-modsecurity-v3-release-prs`
- Related issue: #129
- Status: draft implementation; not verified for integration or runtime use.
- Base revision: `5cd7a7f96811b6d3021ce3c1e36bbc5d308806fb`.
- Core implementation commit: `6b8f698cf1a8e83767b3cfd45b53da3c9b18e289`.

## Motivation and problem statement

Issue #129 reports a ModSecurity v3 release transition from `v3.0.16` to
`v3.0.17` as a manual provenance review. The existing maintenance workflow
already resolves dependency candidates and publishes update PRs. The
ModSecurity-v3 descriptor and specialized resolver still select the manual
path. This draft publishes the previously prepared core change for review.

## Framework-owned implementation

`ci/tools/check-common-versions.py` changes four lines: the ModSecurity-v3
update policy, its compatibility description, the resolver docstring, and
the call from `check_manual_git_provenance` to
`check_automatic_git_provenance`. No release pin is bumped by this change.

The allowed release shape remains `v3.x.y`, including stable minor releases
within v3, rather than patch releases in v3.0 only. Other major versions are
not selected for automatic application. The fixed upstream repository hash,
current tag/commit validation, peeled-commit resolver, alias checks, and
atomic tag/commit group are unchanged. These provenance controls do not
prove connector compatibility or upstream release safety.

## Validation and evidence

The published core commit was read back through GitHub. Its diff contains
exactly the four intended line replacements in the one implementation file.
No successful full-file compilation, unit-test, integration-test, or runtime
result is claimed for this draft.

A local repository fetch could not proceed because `github.com` did not
resolve in the execution environment. The repository-selected environment
and RTK were unavailable. The GitHub connector was used for publication;
remote file inspection is not execution evidence.

## Acceptance criteria still outstanding

- Adapt existing ModSecurity manual-only fixtures and expectations, and
  review the remaining `MANUAL_REVIEW_VARIABLES` classification.
- Verify automatic candidate creation and settlement, atomic tag/commit
  updates, annotated/lightweight tags, moved tags, invalid repositories,
  alias mismatches, prereleases, and releases outside v3.
- Verify canonical-plan application, generated-view consistency, and
  review-issue reconciliation without premature issue closure.
- Update the paired variable-reference and workflow-security documentation.
- Run the affected regression suites and collect required runtime/smoke
  evidence before treating the implementation as integration-ready.

## Documentation, delivery, and boundaries

This paired change record is added. Existing reader-facing policy documents
and generator-owned outputs are deliberately not rewritten as though the
remaining work were complete. Tests and workflows are unchanged.

Delivery is limited to the task branch and a draft PR. No merge, direct
`master` update, auto-merge enablement, or branch-protection change is made.
Issue #129 is referenced, not closed. Parent impact: none. Parent gitlink
disposition: `unchanged`. MRTS impact: `default_read_only`; no MRTS changes.
No connector promotion or runtime-support claim is made.

## Security and residual risk

Automated provenance checks replace a manual-only candidate classification;
they do not constitute human review of migration notes. Existing security
checks are retained, but the behavior change remains unverified until the
outstanding tests and documentation work are completed. No secrets, tokens,
private payloads, or runtime logs are included in this change.
