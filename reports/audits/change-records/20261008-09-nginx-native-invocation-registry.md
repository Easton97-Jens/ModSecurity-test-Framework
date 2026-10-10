# Change record

**Language:** English | [Deutsch](20261008-09-nginx-native-invocation-registry.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261008-09-nginx-native-invocation-registry |
| UTC date | 2026-10-08 |
| Framework base revision | `5d19a0ef91f50c57c05cc1c40873f8d9ca4ab873` |

## Motivation and problem statement

Forty-two non-config Required NGX cases need explicit native dispatch identities. A generic request fixture or a source alias is not proof of native execution.

## Affected components and security boundaries

Framework catalog, case-catalog schema and new catalog controls only. Root separately owns selection, canonical normalization and retained-evidence validation. Parent native producers and MRTS are unchanged by this slice.

## Acceptance criteria

Register exactly 42 existing case IDs, preserve generic expectations and capabilities, bind each NGX contract to its own ID, allow only the two explicit Phase-4 source aliases, and reject missing, foreign or extended descriptors.

## Alternatives considered

Changing generic expectations would affect other connectors. Arbitrary operation names or source aliases would permit case substitution. A closed connector-local descriptor avoids both.

## Implementation decision

`native_invocations.nginx` declares operation and contract_case_id; source_record_id appears only for EOS-to-split and bounded-metadata-to-over-limit reuse. The five closed operation groups contain raw parser 4, Common mapper 2, Phase-4/MIME 12, request sequence 22 and event boundary 2 cases. Event child variants remain owned by the closed helper.

Nine exact NGX-only expected_overrides preserve generic contracts: mapper faults use visible400; obsolete minimal ID explicitly uses existing SAFE/visible200; immediate Engine Reject has visible200, native403, no rule and body_limit; post-response finish failure retains visible200; timeout before/after commit uses visible504/200, native504, no rule and engine_timeout; out-of-scope/missing MIME explicitly has visible200/no rule. Native status and Engine error class are separate from visible HTTP.

The schema closes connector, descriptor and override fields and binds every complete descriptor to its existing case. Registrations are required for the 42 closed IDs. No synthetic events or inspected-byte derivations are produced here.

## Changed files and tests

Catalog and case-catalog schema; new test_nginx_native_invocation_catalog.py; this paired record. All generic case fields, Required IDs, capabilities and protocol cases remain unchanged.

## Commands and results

RTK-wrapped Framework-owned Python controls initially demonstrated 11 registration/schema failures. Final focused discovery passed seven tests; existing prerequisite controls passed two tests. The closed-helper registry control also passed against the coordinator's actual six helper modules read-only. JSONschema package was absent; tests use the repository's existing JSON Schema validator without installing dependencies.

## Security impact

Unknown operations, wrong contract IDs, foreign aliases, altered overrides, missing registrations and additional fields fail closed. A registration never constitutes native evidence or PASS.

## Documentation and runtime evidence

This paired record documents dispatch input only. Actual retained native events, wire bytes, process identities, source authentication and cleanup remain mandatory central evidence boundaries.

## Checks not run

Integrated 97-case H1 selection, central normalization, native runtime/build and final CI remain coordinator-owned.

## Limitations and residual risk

The standalone worktree contains only the C helper; integrated helper compatibility was checked separately against the coordinator worktree. The native Engine budget remains a selected-process post-return contract, not hard interruption.

## Final diff and review status

Focused Framework slice only; no Root worktree changes, publication, Parent Gitlink updates or MRTS mutation.
