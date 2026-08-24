# Change record

**Language:** English | [Deutsch](20260824-01-pin-expat-haproxy-provenance.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260824-01-pin-expat-haproxy-provenance` |
| UTC date | 2026-08-24 |
| Framework base revision | `c40e924ec5c341032908e0082feba1d37ed1dfda` |
| Issue or pull request | Parent finding `FND-PARENT-0216`; Framework pull request pending |

## Motivation and problem statement

The connector-isolated HAProxy runtime reached Expat through a moving
`master` reference and then a GitHub `releases/latest` lookup. That public API
lookup was rate-limited in a fresh GitHub runner. The dependency identity must
therefore be an already reviewed immutable commit rather than a retry, cache,
token, or mutable branch workaround.

## Affected components and security boundaries

- `ci/lib/common.sh` supplies the Parent's Framework-derived Expat provenance
  tuple.
- `ci/tools/check-common-versions.py` and the English/German variable
  reference describe the cross-repository ownership accurately.
- The Parent remains responsible for the connector-scoped acquisition and
  full-commit verification; no Framework acquisition process is introduced.

No Connector implementation, MRTS content, NGINX path, GitHub Actions
permission, cache-sharing policy, or default branch is changed.

## Acceptance criteria

1. `EXPAT_GIT_REF` is a lower-case, full 40-character immutable commit.
2. The chosen commit is the peeled commit of upstream Expat `R_2_8_2`.
3. Framework metadata and EN/DE documentation no longer call the value unused
   legacy acquisition metadata.
4. A focused regression test rejects restoration of a moving reference.
5. Parent Gitlink movement occurs only after this Framework change is committed,
   pushed, and available on its separate pull request.

## Alternatives considered

- A newer Expat release was not selected: that would be an unrequested
  dependency upgrade.
- More retries, a PR token, or a mutable cache would not establish immutable
  provenance and were rejected.
- Changing the Parent to acquire a branch directly was rejected because a
  branch can move after review.

## Implementation decision

The Framework records the reviewed peeled commit
`c61098da494eea1cbd091118118dcee417faacea` for the existing `R_2_8_2` source.
The `not_applicable` Framework resolver remains correct because Framework does
not fetch Expat; its description now names the Parent as the strict runtime
consumer. The Parent-side change enables strict verification only in the
HAProxy route, so no other connector's workflow path is broadened.

## Changed files and tests

- `ci/lib/common.sh`
- `ci/tools/check-common-versions.py`
- `docs/reference/variables.md`
- `docs/reference/variables.de.md`
- `tests/security_regression/test_checker_series_and_ci_inventory.py`
- this paired English/German Change Record

The focused test asserts the exact commit shape and value and verifies that the
registry describes the Parent consumer and immutable provenance.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- |
| `rtk proxy git ls-remote https://github.com/libexpat/libexpat.git …` | 0 | Upstream `R_2_8_2^{}` peeled to the recorded commit. | Task transcript, 2026-08-24 |
| `rtk proxy … python3 -m py_compile …` | 0 | Modified checker and focused test compile. | Isolated Framework worktree |
| `rtk proxy sh -n ci/lib/common.sh` | 0 | The canonical shell source parses. | Isolated Framework worktree |
| `rtk proxy python3 ci/tools/check-common-versions.py --validate-canonical` | 0 | Canonical local pin contract passes. | Isolated Framework worktree |
| Focused Expat regression function | 0 | The immutable pin and Parent-consumer contract pass. | Isolated Framework worktree |

## Security impact

This is a supply-chain and availability hardening change. The formerly moving
reference is replaced by a reviewed immutable commit. The alternate paths
(token authentication, retry-only behavior, and mutable cache reuse) remain
absent. The actual Git checkout is still verified by Parent's strict
connector-scoped provisioner before use.

## Documentation and runtime evidence

The English/German variable reference and this paired Change Record document
the same Framework boundary. No Connector or MRTS runtime was run in this
Framework worktree; Parent must perform that exact-head validation after the
Framework PR is available and its gitlink is deliberately updated.

## Checks not run

Framework hosted checks, SonarCloud, and the Framework pull request are pending
at record creation. Full Framework lint and Parent HAProxy hosted runtime are
pending the Parent change and controlled gitlink update.

## Limitations and residual risk

The pin proves a fixed upstream source identity but cannot by itself provision
or validate a Parent runner. The dependent Parent work must remain restricted
to HAProxy and verify the exact Framework gitlink before a runtime result is
claimed.

## Final diff and review status

All changes reside in an external, task-owned Framework worktree. The diff is
limited to provenance metadata, documentation, one focused regression test,
and this record pair. No Parent gitlink, MRTS content, or workflow credential
was staged at record creation.
