# Required NGINX configuration migrations

Three existing Required case IDs retain their required status and receive an
explicit native configuration invocation. `invalid_status` checks the existing
Engine parser's rejection of `status:not-a-number`. The two scope-file cases
check rejection of the removed `modsecurity_phase4_content_types_file` API,
using their actual, owned source fixtures. They do not claim Engine MIME parsing
rejects an accepted type or that an HTTP request was executed.

The canonical reader requires exact fixture bytes, single-link private regular
files, exact configuration and diagnostic paths, observed exit 1, retained
binary/module/config/stdout/stderr hashes and matching run/source identities.
Missing, replaced, foreign, rehashed wrong-fixture and HTTP-case receipt reuse
controls remain failures.

Validation: 14 migration/wiring/existing config-receipt unit tests passed in the
integration worktree. Three earlier real configtests passed their individual
strict canonical checks with explicitly older build provenance. These results
are not a fresh integrated Exact-Head E2E result. All 97 selected Required IDs
remain required; final runtime, complete suites and current remote quality
checks are pending.
