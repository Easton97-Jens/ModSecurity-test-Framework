# Change Record: real empty-header runner

**Language:** English | [Deutsch](20261001-01-empty-header-runner.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20261001-01-empty-header-runner` |
| UTC date | `2026-10-01` |
| Framework base revision | `62e4fa8901f80114234f6cafa38a0a8364ace35d` |
| Issue or pull request | Local Framework slice; external Parent PR #396 remains Draft |

## Motivation and problem statement

The selected required `empty_header_value` scenario had no concrete runner.
HTTP 200 alone could not distinguish an absent header from a present empty
one. The external Parent Curl driver also suppressed materialized empty
headers; that separately tested Parent correction is not included here.

## Affected components and security boundaries

Framework owns the YAML, catalog, generated public resource and its tests.
Actual host drivers, native event producers and runtime promotion are outside
this Framework change. No validator or event producer is modified.

## Acceptance criteria

The runner reaches the catalog path with a present empty header. A chained
phase-1 rule requires both exactly one header and an empty value. The audit
and native-event expectation bind rule `1100503`. Missing native evidence
keeps a claimed source PASS at FAIL. Selection capabilities remain unchanged.

## Alternatives considered

An unconditional rule or HTTP-status-only assertion would not prove header
mapping. Excluding the obligation or borrowing unrelated evidence would hide
the gap. A dedicated two-condition rule is the smallest genuine fixture.

## Implementation decision

Add `empty_header_value.yaml`, connect its catalog runner, and require the
rule and phase event fields. Keep `request_headers`/`phase1` prerequisites and
allow/HTTP-200 semantics. Regenerate the public contract resource with its
generator and update the YAML inventory from 185 to 186, retaining 166 No-CRS
records and 339 unique public tests.

## Changed files and tests

- `tests/cases/no-crs-baseline/catalog.json` and `empty_header_value.yaml`
- `tests/no_crs/test_empty_header_runner.py`
- `tests/no_crs/test_no_crs_baseline.py` (exact implemented-runner inventory)
- `tests/contract_api/test_public_contract_api.py`
- `modsecurity_test_framework/data/framework-contract-catalog.json`
- `docs/testing-and-evidence.md` / `.de.md` and this paired record

## Commands and results

All shell commands used RTK. The two focused fixture/evidence tests failed
before the fix and pass afterward. The generated-resource API regression
observed 186 YAML entries against the old expectation of 185. Full `make lint`
then completed with exit0, including Contract API20, catalog166, security and
documentation checks. The first No-CRS suite passed131/132 and failed only
because its exact runner inventory omitted the new fixture. Adding that one
implemented ID, without removing any expectation, yielded132/132 (exit0).
No production or validator code changed after the full lint; only this test
inventory and final documentation facts. Final documentation/diff checks
are rerun before commit. The initial full lint rejected the German record
headings; correcting them to the template preserved that check unchanged.

## Security impact

Evidence integrity is strengthened: an absent header or missing native event
cannot fulfill the case. No payload, secret, new event type, Common semantics,
protocol selection, required downgrade or status-validator change is added.

## Documentation and runtime evidence

The testing guide and this record are English/German pairs. An external
Parent-owned isolated diagnostic, `nginx-empty_header_value-MKUpI7qd`, reused
the retained C build with the task harness/fixture. It observed HTTP 200,
master UID 0, worker UID 65534, and real native rule 1100503. The unchanged
Parent collector saw that event; Framework normalization accepted the
individual source case and the individual PASS-completeness check. A real
nonempty-header control, `nginx-empty_header_value-pvB0el3W`, returnedHTTP200
but caseFAIL with no native target-rule event. The unchanged required-path
diagnostic remainsRED: 53 missing after54, selection97 unchanged. Its aggregate
remains FAIL. This is diagnostic
evidence, not new exact-head/full-lifecycle canonical PASS.

## Checks not run

No full E2E, Parent gitlink update, remote CI, push, PR mutation or merge.
Required coverage remains red. MRTS and master are unchanged.

## Limitations and residual risk

One of the original 54 missing execution paths is now implemented and locally
observed; other scenarios require separate real drivers. Runtime results from
the retained C build are not relabeled as a new exact-head run. A later
exact-head lifecycle must produce complete canonical evidence and checksums.

## Final diff and review status

The focused independent read-only review found no blocking issue. Source and
scoped diff/whitespace review found no secrets or unrelated source changes.
The independent Framework commit is local only; no remote delivery or Parent
gitlink update is claimed.
