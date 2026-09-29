# Framework MRTS definition intake boundary

**Language:** English | [Deutsch](CR-20260929-mrts-definition-intake.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `CR-20260929-mrts-definition-intake` |
| UTC date | 2026-09-29 |
| Framework base revision | `f9e48b0774b5bdf7aaa8e38ce98eb6c50bf293c8` |
| Source finding | `B03` / `csf_24b4dcf793c63c691309c9af` |
| Unchanged MRTS gitlink | `8a6bb546c4c81d8ffc7be801dceac60c6925685f` |
| Delivery target | Framework-only Draft PR; no merge |

## Motivation and problem statement

The supplied B03 finding identifies unrestricted global attribute assignment
inside the separately owned MRTS generator. The user selected Parent and
Framework for changes, not MRTS. This draft therefore adds a bounded mitigation
at the existing Framework generation entrypoint, without copying or modifying
the generator and without claiming that its root cause is fixed.

The [intake record](../findings/20260929-mrts-intake.json) retains the original
finding ID, reported severity, affected repository boundary and pending
verification. The companion Parent draft preserves the full 72-source to
59-work-item mapping. Other findings are not silently treated as completed.

## Affected components and security boundaries

The Framework wrapper delegates to a new Framework-owned Python launcher.
The launcher constrains definition data before it reaches the trusted,
operator-selected MRTS program. It does not sandbox generator code, authenticate
a hostile same-UID process, or replace the existing output-path checks.

The schema comes from the README global keywords and RuleGenerator in the
pinned MRTS tree. Both the documented historical
`default_tests_phase_methods` spelling and the implemented
`default_test_phase_methods` spelling remain accepted without translation.
`default_constants` is retained from the implementation. Attribute names
outside this explicit set are rejected; object introspection is not a schema.

## Acceptance criteria

- Reject undocumented global keys and non-mapping global configuration before
  invoking the generator, including whole-global scalar substitution.
- Validate all selected definitions before the generator is invoked.
- Hand the generator private snapshots of the parsed, validated documents;
  never validate a source pathname and then ask the generator to reopen it.
- Preserve lexical definition ordering, supported data, output arguments and
  unsuccessful child exit status.
- Preserve the caller's existing runtime-root and output-root controls.
- Verify the entire pinned default and feature-demo corpus before promotion.
- Keep direct MRTS invocation and the unresolved MRTS root fix explicit.

## Alternatives considered

Changing the MRTS submodule from this Framework task would cross the selected
repository boundary. A validate-then-reopen design would leave a data
replacement window. A private parsed-data snapshot avoids that window without
claiming a process sandbox or importing the generator into Framework.

## Implementation decision

The existing shell wrapper calls `mrts_definition_guard.py` with the selected
generator, roots and definition files. The new launcher uses the already
required PyYAML safe loader and an explicit global-key allowlist, then writes
numbered snapshots to a private temporary directory below the existing
external MRTS build root. Snapshots use mode 0600 and the directory mode 0700;
cleanup occurs on normal completion and exceptions. MRTS receives these files
in the same lexical order as before.

Existing shell output cleanup remains before the launcher call. This draft
therefore does not promise preservation of previous generated outputs when
a later input is rejected. It also does not change rulefile/testfile
containment inside MRTS or permit arbitrary new global attributes.

A dedicated read-only exact-head workflow installs only the repository's
existing hash-locked CI dependencies and runs the added regression module.
No action pin, dependency lock, quality gate or existing test is relaxed.

## Security and compatibility impact

Definitions that used undocumented object attributes through `global` are
now rejected at this entrypoint. This is intentional, but full corpus
compatibility has not been executed in the editing environment.
The original generator remains unmodified and direct invocation remains
outside the mitigation. B03 cannot be closed on the basis of this wrapper.

## Changed files and tests

- `ci/provisioning/generate-mrts.sh`
- `ci/provisioning/mrts_definition_guard.py`
- `tests/security_regression/test_mrts_definition_guard.py`
- `.github/workflows/ci-findings-regressions.yml`
- `reports/audits/findings/20260929-mrts-intake.json`
- This English/German Change Record pair.

## Commands and results

| Check | Actual result at preparation |
| --- | --- |
| Original shell transfer | Complete content matched Git blob SHA-1 before editing |
| Python syntax / intake JSON | Parsed as data, not behavioral test execution |
| New launcher tests | Added; NOT RUN locally because required RTK is unavailable |
| Generator test double | Defined for argument, snapshot, permission, rejection and cleanup tests; not claimed executed |
| Full pinned MRTS corpus | NOT RUN; direct generator behavior remains a separate validation gate |
| Shell syntax / native git diff --check | NOT RUN; source diff and added-line whitespace inspected separately |
| New exact-head CI | Configured; result pending in the Draft PR |
| Full CI / SonarQube / security scan | No successful result claimed here |

The available code-work skill was read. The repository-referenced global
execution skill was not accessible. No local project command bypasses the
mandatory RTK path and no successful test output is invented.

## Remaining work and delivery

This is `candidate_entrypoint_mitigation`, not complete remediation or verified
closure of B03. The direct MRTS fix requires a separately authorized task in
the MRTS repository. Legitimate corpus generation, existing containment
regressions and final current-head quality checks remain required.

Parent impact: a separately delivered Framework commit does not change the
Parent's selected dependency. Parent gitlink disposition: `unchanged`.
MRTS impact: `default_read_only`; MRTS gitlink: `unchanged`.
No other repository branch, default branch, dependency pin or existing PR is
modified. No merge, force-push, automatic risk acceptance or release claim.
