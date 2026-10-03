# Change Record: bounded NGINX configuration-test evidence

**Language:** English | [Deutsch](20261001-02-nginx-configtest-evidence.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20261001-02-nginx-configtest-evidence` |
| UTC date | `2026-10-01` |
| Framework base revision | `896e4bd71fa3b1a07dd0109e2e8c7b7991d40d19` |
| Issue or pull request | Local Framework slice; external Parent PR #396 remains Draft |

## Motivation and problem statement

The selected required phase-0 `invalid_boolean` record had no concrete NGINX
configuration operation. Its public expectation represented `config_rejected`
as an event. Parser acceptance/rejection is not HTTP or a rule/event alias;
asserted exits alone cannot prove execution.

## Affected components and security boundaries

Framework owns catalog, public API, canonical normalization and validation.
The actual Parent host invocation/collector are separate external dependencies.
MRTS, connector source, Common event production and Parent gitlinks are unchanged.

## Acceptance criteria

Only the explicit NGINX `configtest` for `modsecurity maybe;` may use this
contract. PASS requires exact exit `1`, `invalid_boolean`, both diagnostics,
case/run/source/component identity and the authorized five-file bundle.
Missing, foreign, symlinked or changed artifacts fail. Signed execution
failures remain failure evidence, never PASS; HTTP cases remain strict.

## Alternatives considered

Synthetic events, borrowed HTTP 200, blanket nonzero-exit PASS, excluding
required records or trusting receipt assertions alone would conceal the gap.

## Implementation decision

Declare only the concrete NGINX realization. Preserve selection/applicability
and other expectations. Finalization derives authority from the explicit
source file's parent and securely retains `nginx-binary`, `nginx-module.so`,
`nginx.conf`, `stdout.log`, `stderr.log` under
`inventory/configtests/invalid_boolean`. Rehash the files and validate the
closed nonsecret template and exact captured diagnostic. Config-only evidence
needs no HTTP/native event and cannot claim daemon start, listener, workers,
reload or request. The public `configuration` type matches bounded observations,
not actual execution proof. The global full-lifecycle PASS gate is unchanged.

## Changed files and tests

- `ci/checks/catalog/no_crs_baseline.py`, catalog, case-result and configtest-receipt schemas.
- Four `tests/no_crs/test_configtest_*` modules covering receipts, artifacts, signed exits and runtime facts.
- `modsecurity_test_framework/contracts.py`, public catalog generator/resource and API tests.
- Paired testing guide, this record and archive indexes.

## Commands and results

All shell commands used RTK and external temporary/cache/log roots. Public
tests reproduced the unknown tagged kind and event-only generation; artifact
and signed-exit regressions were red before their respective corrections.
FIFO and explicit manifest-host regressions were also red before correction.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk proxy` wrapping `make test-contract-api` | `0` | 23 tests and catalog check passed | External analysis log `config-public-api-suite.log` |
| `rtk proxy` wrapping focused configtest unittest discovery | `0` | 27 tests passed in 3.144 s, including FIFO/manifest-host/bounded-copy controls | External analysis log `config-all-focus.log` |
| `rtk proxy` wrapping signed-exit unittest module | `0` | 3 tests passed with valid artifact authority; exact exit mismatch, not missing proof | External analysis log `config-exit-authority-focus.log` |
| `rtk proxy` wrapping `make test-no-crs-contract` | `0` | 159 tests passed in 112.402 s | External analysis log `framework-configtest-frozen-no-crs-20261001.log` and `.exit` |
| `rtk proxy` wrapping `make lint` | `0` | Full Framework lint completed successfully | External analysis log `framework-configtest-final-lint-20261001.log` and `.exit` |
| `rtk proxy` wrapping `make check-documentation` | `0` | Links, bilingual variables, repository paths and Change Records passed | External analysis log `framework-configtest-docs.log` |
| `rtk proxy` wrapping `git diff --check` | `0` | Whitespace check passed before documentation handoff | Local Framework worktree |

## Security impact

No validator weakening, synthetic runtime evidence, native event, payload,
secret or global path authority. Negative controls cover wrong exits,
directives/diagnostics, foreign identity, altered files and symlinks.

## Documentation and runtime evidence

Testing guide and record have matching EN/DE companions. Unit/public-contract
checks are distinct from the separately observed retained-build diagnostic
`nginx-configtest-retained-jaYdBrvH`. Its real NGINX binary/module invocations
passed through the actual Parent collector and Framework canonical finalizer.
The positive `invalid_boolean` canonical record is PASS; the wrong-module
control is FAIL, despite both actual process exits being `1`. All five
retained files rehashed, managed layout validation had zero errors, and the
external diagnostic checker exited `0` (`nginx-configtest-retained-check-20261001.json`).
No events or HTTP requests were produced; daemon-start/listener facts remain
false. Both source and canonical aggregates remain FAIL because required
requests were not executed. This proves only a retained-build diagnostic
configuration invocation, not a new Exact-Head full-lifecycle PASS.

## Checks not run

No full E2E, remote CI, push, PR mutation, merge or Parent gitlink update.
Optional Ruff was unavailable; no package was installed.

## Limitations and residual risk

The other nine configuration-related required records remain unimplemented.
Selection/required scope is not reduced. Protocol, fault, startup and reload
obligations are not fulfilled by this configtest. Global promotion still
requires all selected required cases and genuine lifecycle evidence.

## Final diff and review status

At the original handoff checkpoint, the Framework changes were uncommitted
and the final scoped diff review and local commit were pending. That local
handoff was subsequently committed as
`c4f53e1` (`fix(no-crs): require retained nginx configtest receipts`).
The commands, nine remaining configuration records and runtime observations
above describe that historical checkpoint; the later
[size configtest record](20261003-01-nginx-size-configtest.md) records its own
subsequent change. Focused, No-CRS, full lint and documentation checks passed
at the original checkpoint; an independent review found no mandatory blocker.
This record does not attest remote delivery, a Parent pointer change or global
lifecycle success. Sensitive runtime artifacts remain outside versioned
documentation.
