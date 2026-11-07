# Acceptance profile and checksum follow-up

**Language:** English | [Deutsch](20261107-01-acceptance-profile-checksum-followup.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261107-01-acceptance-profile-checksum-followup |
| UTC date | 2026-11-07 |
| Framework base revision | `d0c7e1036e57bdb980603f68e4e3e64e51de9049` |
| Issue or pull request | [Framework Draft PR #169](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/169) |

## Motivation and problem statement

The retired HTTPD release checksum redirects to an archive host whose TCP
connection times out. Existing companion executors cover H1; separate H2
paths and native Traefik Strict qualification are required. Preserve the
previous NGINX, Apache, HTX, SPOP and ext_proc regressions.

## Affected components and security boundaries

Framework owns the Apache metadata admission/download path, opt-in H2
executors, evidence readers, fixtures, tests, native compiler inventory and
configuration-reference generator. Parent product fixes are an external
dependency. MRTS remains read-only. Standard selection stays at 100 cases.

## Acceptance criteria

Require official metadata provenance, independent archive and metadata hashes,
direct verified HTTPS, and rejection of download errors or malformed objects.
Retain the original 32 non-NGINX IDs and add 24 separate profile IDs; require
real TLS/H2, rule/transaction/response correlation, live parallel stream
isolation, actual Strict reset, successful follow-up and native cleanup.
Final committed-pair runs and required hosted checks are separate evidence.

## Alternatives considered

A longer timeout cannot repair an unreachable archive TCP endpoint. Deriving
an expected digest from the downloaded archive, accepting an unproven metadata
snapshot, suppressing scanner findings or reusing another integration model's
PASS would violate the trust or evidence contract.

## Implementation decision

Use the exact official immutable HTTPD distribution object at revision
`89000`, version `2.4.69`, with independently reviewed metadata SHA-256
`7351aea97f61589f9803d432dc59e1002ba06e3b344fdba9ca281c2e82cf0b08`.
The current archive literal pin and exact filename remain required. Cache reuse
also requires those exact object bytes; it does not claim a historical fetch.
Global TLS, redirect and timeout policy is unchanged.

For this exact release tuple, a direct canonical archive 404 selects the
independently verified source archive from the same immutable revision. Both
native producers require direct HTTP 200, zero redirects and the independent
archive pin. Only native acquisition creates cache provenance markers.

Each new profile has its own real host execution. Companion records retain
opaque-handle lifecycle ownership without exporting the handle. Logical
host/handoff identity is kept distinct from the shared Common engine backend.
Native Traefik uses an explicit Safe(default)/Strict middleware policy supplied
by the external product. A test-only link wrapper enables native cleanup
metadata; independent host/wire records prove the physical connection.
The new C observer is included in the closed native compile inventory.

## Changed files and tests

- Apache provisioning helper, checksum reader and focused source-recovery tests.
- Separate companion and native Traefik H2 adapters, rules, observers and reader
  corruption controls; tracked Go regressions selected by native overlays.
- Opt-in registry: 56 IDs across seven profiles; 25 NGINX IDs and eight existing
  H2/H3 neighbours yield 89 requested host executions / 85 distinct bare case IDs,
  plus three Apache H1 cases. Four shared NGINX names require explicit driver
  and traffic-variant identity; repetition never increases unique counts.
- Source-backed configuration-reference entries and paired documentation.

## Commands and results

All shell commands use RTK and explicit selected roots/revisions. Preliminary
real host diagnostics exercised all 24 new H2 IDs. The metadata helper's eight
units, seven actual-shell negative controls and native 18-case HTTPD recovery
target passed. Final clean-pair results, unique test IDs, source/build admission,
native compiler capture, hosted CI and exact full SHAs are retained in the
external task report; these preliminary diagnostics do not qualify another pair.

## Security impact

Keep TLS/host verification, private UDS ownership, bounded metadata-only
evidence, source/artifact admission and fail-closed writer behavior.
Strict action requests are separate from observed wire resets. Typed observed
transport termination never fabricates response EOS or endpoint attribution.
No scanner exception, NOSONAR, gate relaxation or credential discovery occurs.

## Documentation and runtime evidence

The paired protocol preparation guide, development guide and native Traefik H2
guide describe selection and boundaries. Runtime records preserve failed
diagnostics and independently observed protocol, phase/rule, peer/follow-up
and cleanup facts. Evidence remains outside Git.

## Checks not run

Comprehensive acceptance remains **NOT_RUN**. No MRTS execution or mutation,
local Sonar scanner, merge or administrative change is performed.

## Limitations and residual risk

The existing Sonar connection permits GET but rejects issue POST transitions.
All 23 existing occurrences were independently reassessed; local proposals do
not close server findings or pass a hosted Gate. Current delivered-head Sonar
and Apache CRS/aggregate readbacks remain mandatory. Existing advisory and
legacy inventory findings are reported separately.

## Final diff and review status

Follow-up commits preserve the existing Draft PR branch history. Final scoped
diff, generated inventory/archive, docs, pins and current-head checks are
reconciled in the external report. Readiness requires every mandatory criterion;
this source record does not declare readiness.
