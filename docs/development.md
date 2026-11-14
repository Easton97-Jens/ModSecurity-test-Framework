# Development

**Language:** English | [Deutsch](development.de.md)

This guide is the maintained entry point for Framework contribution, CI layout,
and local validation. It intentionally separates reproducible repository work
from connector-owned builds and runtime evidence.

## Local setup

Use explicit, writable locations outside the Git worktree for source copies,
build products, logs, temporary files, and evidence. The central
[variables and placeholders](reference/variables.md) define the accepted
values and path boundaries.

```sh
make setup-dev
make quick-check
make lint
```

Fetching upstream dependencies and running host smokes are explicit operations.
They must not silently write into a checkout, replace an existing source tree,
or turn an unavailable dependency into a PASS.

### Pinned Apache source recovery

The Apache preparer retains the canonical HTTPD version, source URL and digest
from `ci/lib/common.sh`. A regular HTTPD archive already in the approved download
root may be reused only after its required literal SHA-256 is checked again.
Reviewed checksum metadata is verified before extraction; a validated private
metadata cache may be reused. Cache reuse is not a network-download or host-runtime claim.
After both digest checks, the archive is copied into the private Apache build
root and rehashed there; extraction uses only that verified copy.

For an absent HTTPD archive, only a direct HTTP 404 from the canonical release
endpoint permits recovery from the same filename at the official
`https://archive.apache.org/dist/httpd/` endpoint. Other HTTP errors, redirects,
timeouts, TLS failures, invalid provenance, unsafe paths and checksum failures
remain blocking. The actual transfer endpoint or verified-cache reuse is
recorded separately from the canonical source identity. APR and APR-util
acquisition, including APR-util's direct/no-redirect boundary, are unchanged.

Use `make test-httpd-source-recovery` for the focused offline regression suite.
It validates source-acquisition behavior, not a connector's runtime readiness.

The HTTPD 2.4.69 checksum is fetched directly, without redirects, from the
immutable official distribution revision
`https://dist.apache.org/repos/dist/!svn/bc/89000/release/httpd/httpd-2.4.69.tar.bz2.sha256`.
The retired release's canonical metadata URL redirects to `archive.apache.org`;
a reproduced TCP-connect timeout at that host motivated this reviewed source
selection, without changing TLS checks, retry limits or timeouts. The exact
release URL, metadata bytes SHA-256, filename and independent `common.sh`
archive pin must all match before extraction. A new version requires a reviewed
revision/object update. The actual direct HTTP 200/TLS transfer and both hashes
are retained separately from canonical source identity; a valid existing private
metadata cache proves verified bytes, not a fresh network transfer.

For the independently reviewed HTTPD 2.4.69 tuple, the same direct primary 404
instead selects the proven immutable source archive at distribution revision
89000, paired with the checksum object above. Both the Python native cache
producer and standalone Apache preparer require direct HTTP 200, no redirect,
and the unchanged independent archive pin. The native producer creates its own
cache marker before acquisition; copied files cannot be adopted by inventing
markers. Other release tuples retain the existing archive recovery policy.
The reviewed filename comes from the immutable metadata object; consumers read
the current canonical tuple from `common.sh` and check its exact HTTPS origin,
path and absence of query or fragment, without copying its version or URL pin.

### Configured NGINX headers for C checks

The shared `nginx_include_flags_or_blocked` helper supports installed headers
and configured NGINX source trees. The configured-source include list covers
`src/event/quic` as well as the HTTP v2/v3 directories, so a real QUIC-enabled
`objs/ngx_auto_config.h` can include `ngx_event_quic.h`. Installed-header
priority, configured-source prerequisites and missing-header failures remain
unchanged; the QUIC directory is not an additional mandatory prerequisite for
older or non-QUIC source trees. C compilation through these flags proves only
compilation, not TLS linkage, H2/H3 traffic or connector-runtime qualification.

## Repository layout

| Path | Responsibility |
|---|---|
| `ci/lib/` | Shared shell and Python helpers |
| `ci/provisioning/` | Explicit source, build, and runtime preparation |
| `ci/runtime/` | Runtime-smoke entrypoints |
| `ci/checks/` | Catalog, documentation, evidence, protocol, and security checks |
| `ci/reporting/` | Generators for bounded reports and snapshots |
| `tests/runners/` | YAML validation, materialization, selection, and assertions |
| `tests/normalizers/` | Bounded artifact normalization |
| `tests/cases/` | Framework-owned YAML case corpus |

Keep connector implementation code, host configuration, and connector-specific
runtime evidence in the connector repository. Framework helper code must not
grow a hidden workspace or parent-directory fallback.

## Documentation policy

The maintained manual documentation is the canonical paired content in `docs/`,
including change traceability, plus the variables and glossary references.
English and German partners must retain the same paths, commands, identifiers,
defaults, tables, and safety boundary.

Non-trivial Framework changes also require the paired record described in
[change traceability](change-traceability.md). The record belongs to this
repository and must not combine Framework facts with connector findings or
parent-repository changes.

Workflow provenance, scanner boundaries, and the local CI-security validation
contract are maintained in [CI security tooling](security/ci-security-tooling.md).

Generated reports are changed only through their generator. The root
`TEST-COVERAGE-SUMMARY.md` is a deliberate public/generated exception because
Framework and connector checks consume it. It is not a second manual status
document.

Use `make check-documentation` after a documentation change. It runs link,
variable/reference, and repository-path checks. Avoid local developer paths,
temporary absolute examples, redirect-only Markdown files, and copied report
snapshots.

## Validation and review

| Change area | Minimum validation |
|---|---|
| Markdown navigation or references | `make check-documentation` and `git diff --check` |
| Bilingual documentation, records, or templates | `make check-bilingual-docs` and `make check-doc-links` |
| Framework CI-security workflows or tooling | `make test-ci-security-contract` and `make check-change-records` |
| Variables or placeholders | `make check-variable-documentation` |
| Makefile local script paths | `make test-makefile-contract` (also part of `make lint`) |
| YAML catalog or runner behavior | `make check-no-crs-catalog` and focused tests |
| Generated reports | `make refresh-framework-reports` and `make check-test-matrix` |
| Runtime or evidence helpers | Relevant focused checks plus the connector-owned harness |

Run the smallest relevant check first, then the repository-level checks before
handoff. Do not weaken a test, rename a case or rule identifier, or edit a
generated artifact merely to satisfy a path move.

## Quality and maintenance

Formatting, shell syntax, Python compilation, documentation checks, security
data-flow checks, catalog validation, and evidence checks are aggregated by
`make lint`. Quality findings should be resolved in the owning code or
documentation instead of preserved as a parallel planning document.

Keep secrets, credentials, raw request bodies, raw response bodies, and
unreviewed runtime logs out of versioned files. Prefer bounded metadata and
the privacy rules in [testing and evidence](testing-and-evidence.md).

## Historical context

Former CI audits, SonarCloud remediation lists, roadmap snapshots, and TODO
inventories were consolidated into the active maintenance rules above. Git
history remains the place for completed planning detail.
