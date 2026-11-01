# Configured NGINX QUIC include integrity

**Language:** English | [Deutsch](20261030-03-nginx-quic-include-integrity.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261030-03-nginx-quic-include-integrity |
| UTC date | 2026-10-30 |
| Framework base revision | `f5a0940c56edbb94d55d309636ce3d6f501e31a2` |
| Issue or pull request | No Framework PR assigned at local preparation |

### Test-migration follow-up — 2026-11-01

The user resumed work and permitted new tests. Draft #144 incorporates
Framework master `d503ddbea1a3b6df7766edc247b0a9886ff10668` through an ordinary
branch merge, not a PR merge. It remains independent of Draft #143; Parent
pin/source and MRTS remain unchanged. Original no-new-tests statements below
refer to the October30 preparation only.

Four new individually selected on-demand methods in
`tests/security_regression/test_common_shell_sonar_contracts.py` exercise real
shell functions with header-only directory fixtures: exact configured-QUIC
include ordering, configured non-QUIC acceptance, unconfigured-tree rejection
and explicit installed-header precedence. No function under test is mocked.
No standard selector, inventory binding or generated migration map changes;
the standard inventory remains100 expanded cases.

All four exact `CommonShellSonarContractsTest.test_nginx_*` selectors passed
with Framework Python through RTK and external temporary/cache roots. The
primary ordered-include regression against the unchanged `d503ddbe` helper
failed as expected (one assertion failure, exit1: missing `src/event/quic`);
the same regression passes with this fix. The run root is
`quic-helper-regressions-20261101.qfNWdw`. These tests establish flag selection,
not actual compilation or H3 traffic. The October30 real-tree compiler results
remain historical, separate evidence and were not rerun in this follow-up.

`make check-documentation check-canonical-common-pins` passed (links,
340 bilingual pairs, path references, Change Record and pins); shell syntax
and whitespace passed. A first documentation run rejected an extra level-two
record heading; making it a subsection restored the template contract.
Independent final test/EN-DE review found no blocker.

## Motivation and problem statement

The configured-source NGINX include producer omitted `src/event/quic`.
With real `NGX_OPENSSL` / `NGX_QUIC` configuration, `ngx_core.h` includes
`ngx_event_quic.h`; the existing consuming C17 check failed before compiling
the connector. The generated native NGINX include list already contains this
directory. This is shared compile-input integrity, not a connector defect.

## Affected components and security boundaries

Framework-owned `ci/lib/common.sh`, specifically `ci_nginx_source_dir_flags`.
Trusted configured-source paths become compiler include arguments. No path
selection, provisioning, canonical pin, compiler or permission policy changes.

## Acceptance criteria

- The already failing V3-enabled C17 check passes with the corrected helper.
- The existing non-V3 configuration still compiles.
- Source prerequisites, installed-header priority, return statuses and required
  compiler warnings remain unchanged.
- Add only the authorized focused self-tests after the completed migration;
  no default selector or runtime campaign is added.
- Paired documentation and the independent Framework delivery remain truthful.

## Alternatives considered

Do not disable QUIC, fake generated macros, weaken `-Werror`, copy headers into
another directory, or patch a consumer-specific include workaround. Adding the
missing source include centrally fixes every caller without changing discovery.
Requiring the QUIC directory would unnecessarily reject older source trees.

## Implementation decision

Add only `-I$ci_nginx_dir/src/event/quic` after the existing event include.
Keep the previous prerequisites and relative order of all existing directories.
No QUIC header/directory existence requirement is introduced.

## Changed files and tests

`ci/lib/common.sh`; paired `docs/development.md` / `.de.md`; this paired record.
No test source, fixture, case or assertion was changed on October30. Two existing
shell status/helper contract tests were reused; they mock the include selector
and do not themselves prove QUIC include correctness. The actual consuming
C17 compilation supplied that evidence. The November1 follow-up adds the four
methods and their fixture factory in the self-test file named above.

## Commands and results

Exact external-consumer invocations, selected source roots, configuration
digests and command results are retained in `validation.md` under approved run
`framework-nginx-quic-includes-20261030.yubq4W`. Consumer source was explicitly
Parent `db431efaa62e5dd408846c0feec4fd9751421247`; this is an external validation
dependency, not a Parent code, pin or delivery change.

| Command / retained procedure | Exit code | Concise result | Evidence |
| --- | --- | --- | --- |
| `v3-on-before`: existing `rtk bypass make check-nginx-c17` | 2 | Reproduced missing `ngx_event_quic.h` with unmodified base helper | External `validation.md` |
| `v3-on-after`: same existing C17 target, corrected helper | 0 | All listed translation units compiled with `-std=c17 -Wall -Wextra -Werror` | External `validation.md` |
| `v3-off-after`: same target, existing non-V3 configuration | 0 | Non-V3 compatibility control passed | External `validation.md` |
| `rtk bypass sh -n ci/lib/common.sh` | 0 | POSIX shell syntax passed | External command record |
| `rtk bypass bash -n ci/lib/common.sh` | 0 | Bash syntax passed | External command record |
| Existing two-method Framework unittest invocation | 0 | Status/helper contracts passed; no new tests | External `validation.md` |
| Existing consuming `check-nginx-c-standard-wiring` | 0 | C17, source coverage, blockers and warning contract passed | External `validation.md` |
| Existing Framework `check-canonical-common-pins` | 0 | Canonical pin contract unchanged and passed | External `validation.md` |
| Existing Framework `check-documentation` | 0 | Links, 334 bilingual pairs, path references and Change Record structure passed | External command record |

## Security impact

No security remediation or vulnerability claim. The same trusted source-root
boundary, missing-prerequisite failures, warnings and canonical pins remain.
The change does not turn missing headers or disabled QUIC into runtime success.

## Documentation and runtime evidence

The development EN/DE pair documents the complete configured-source include
list and compilation-only evidence boundary. No host was started, network
traffic generated or TLS/H2/H3 runtime qualification collected. No Parent
gitlink or MRTS change; separate existing Framework work is not integrated.

## Checks not run

No archived suites, host smokes, full protocol/TLS matrix or new
qualification campaign. They are outside the user's integrity-only scope.
Hosted checks and Sonar require the future exact PR head; no previous head's
results are reused. Full local `lint` was not invoked because it includes
unrelated suites; relevant syntax, contracts and documentation checks ran.

## Limitations and residual risk

The local compiler check used retained NGINX 1.31.6 configurations, not all
supported versions or the originally requested pinned TLS/runtime profiles.
Installed-header behavior and older-tree prerequisites now also have focused
directory/flag regression checks, not cross-version compile proof. This fix is
not yet integrated into Parent's pinned Framework revision.

## Final diff and review status

The source change is one include-list addition. Root reviewed the scoped diff;
independent final caller, compatibility and EN/DE review found no blocker.
No secrets, raw HTTP material or full environment values are recorded. Ready
for normal separate Framework Draft delivery; hosted checks remain unverified
until that exact head is published. No PR merge, Parent pointer update or MRTS
change is claimed here.
