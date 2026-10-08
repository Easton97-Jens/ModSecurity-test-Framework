# Change record

**Language:** English | [Deutsch](CR-20261008-nginx-required-config-migration.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | CR-20261008-nginx-required-config-migration |
| UTC date | 2026-10-08 |
| Framework base revision | `385046a` |

## Motivation and problem statement

Three existing Required case IDs retain their required status and receive an
explicit native configuration invocation. `invalid_status` checks the existing
Engine parser's rejection of `status:not-a-number`. The two scope-file cases
check rejection of the removed `modsecurity_phase4_content_types_file` API,
using their actual, owned source fixtures. They do not claim Engine MIME parsing
rejects an accepted type or that an HTTP request was executed.

## Affected components and security boundaries

Closed catalog/schema, owned config-fixture projection and strict canonical config-bundle reader. Parent driver and MRTS are not changed by this Framework slice.

## Acceptance criteria

The canonical reader requires exact fixture bytes, single-link private regular
files, exact configuration and diagnostic paths, observed exit 1, retained
binary/module/config/stdout/stderr hashes and matching run/source identities.
Missing, replaced, foreign, rehashed wrong-fixture and HTTP-case receipt reuse
controls remain failures.

## Alternatives considered

Removing Required IDs or claiming accepted MIME configuration is a rejection would change scope or invent evidence.

## Implementation decision

Keep all three IDs Required with the explicitly approved native config contracts and exact owned fixture bytes.

## Changed files and tests

Catalog/schema, config-bundle reader, migration/wiring and existing receipt controls; paired record.

## Commands and results

Validation: 14 migration/wiring/existing config-receipt unit tests passed in the
integration worktree. Three earlier real configtests passed their individual
strict canonical checks with explicitly older build provenance. These results
are not a fresh integrated Exact-Head E2E result. All 97 selected Required IDs
remain required; final runtime, complete suites and current remote quality
checks are pending.

## Security impact

Strict bytes, ownership, identity, digest and negative mismatch controls are retained. No request/event is synthesized.

## Documentation and runtime evidence

The earlier three actual configtests have old build provenance; they are diagnostic individual records only.

## Checks not run

Fresh integrated build, complete framework/parent suites, full lifecycle and remote CI/Sonar.

## Limitations and residual risk

Source declarations and focused tests do not close final Required coverage.

## Final diff and review status

Focused configuration migration. Gitlinks and Required selection unchanged.
