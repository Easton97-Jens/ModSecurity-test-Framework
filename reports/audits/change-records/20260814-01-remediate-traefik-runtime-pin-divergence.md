# Remediate Traefik runtime pin divergence

**Language:** English | [Deutsch](20260814-01-remediate-traefik-runtime-pin-divergence.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260814-01-remediate-traefik-runtime-pin-divergence` |
| UTC date | 2026-08-14 |
| Framework base revision | `1260aaae411ecf88cf50dc480b80e2e20ac47901` |
| Finding | `FND-FRAMEWORK-0069` (`fixed`) |
| Issue or pull request | [Framework PR #78](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/78) from `fix/fnd-framework-0069-traefik-runtime-pin` to `master` is the task-owned delivery unit. The initial implementation commit `741dd30287d9d5fd38946ee317da4d1f91494b19` was pushed normally; every later PR head requires a fresh exact-head check. Merge facts are retained only when observed in PR and task lifecycle evidence. |

## Motivation and problem statement

The retained `F-GS-001` analysis showed that active Framework Traefik resolution used the reviewed `3.7.10` Linux-amd64 release archive and SHA-256 while the adjacent runtime-components manifest described an old `3.7.5` archive and digest. The manifest was not an active runtime reader, but it was an unchecked competing source of artifact provenance. The Framework resolver also accepted a matching local/PATH binary without proving the canonical archive digest.

## Affected components and security boundaries

Framework-owned changes cover the canonical tuple in `ci/lib/common.sh`, archive preparation, generic smoke resolution, the Traefik manifest slice and synchronizer, catalog guard, lint wiring, and focused regression tests. The boundary is caller environment/cache/archive/manifest to archive extraction, binary staging, and connector execution. The sibling Parent resolver bridge is a consumer integration: it delegates to the Framework boundary and introduces no second version or digest authority.

## Acceptance criteria

- Only Framework `common.sh` manually defines the Traefik version and release-archive SHA-256; all other tuple fields are derived.
- Manifest output is deterministic and fails on a version/hash/URL/archive/platform/missing/malformed/duplicate-source divergence.
- A local or caller-supplied binary cannot reach Framework/Parent direct entry paths unless canonical archive verification has succeeded.
- A correct synthetic archive remains a legitimate offline control, focused regressions pass, and the check is CI-visible.

## Alternatives considered

Keeping the manifest hand-maintained would leave a second source of truth; removing it would lose an existing catalog artifact; adding a duplicate Parent pin would split ownership. The selected deterministic Traefik-slice generator and thin Parent bridge preserve Framework authority while leaving unrelated manifest components untouched.

## Implementation decision

`ci_traefik_set_canonical_tuple` owns the reviewed tuple and derives the official HTTPS URLs, archive name, and `linux_amd64` platform. The provenance guard rejects inherited/live alternate or incomplete state before a download, archive, extraction, or process sink. The preparer re-verifies an existing or downloaded canonical archive before staging. The manifest synchronizer validates one source assignment and rewrites/checks only Traefik deterministically.

The catalog guard runs in Framework lint; Parent lint and the existing PR-visible workflow run the same guard. Direct Parent smoke/native callers use the returned Framework cache path only. Documentation now directs preparation through the Framework rather than copying a stale pin.

The resolver preserves a blocked (`77`) preparation result instead of flattening it to a generic failure. The Parent lifecycle only inventories the canonical cache binary after a successful staging result, so an inherited `TRAEFIK_BIN` cannot become a post-failure process sink.

### SonarQube Cloud follow-up

SonarQube Cloud analysis for PR #78 head
`18da86f34827f34a5a99877796e21532fd31f824` reported two task-owned
`python:S6353` maintainability findings on the version expression in the new
manifest synchronizer. The concise `\d` expression now uses `re.ASCII`: it
removes both findings without broadening the prior ASCII-only release-version
boundary. The focused regression proves that the canonical ASCII version is
accepted while a self-consistent version written with Arabic-Indic Unicode
digits is rejected before archive-name or URL derivation.

## Changed files and tests

- Framework runtime and catalog: `ci/lib/common.sh`, `ci/provisioning/prepare-traefik-runtime.sh`, `ci/lib/connector-smoke-common.sh`, `ci/provisioning/runtime-components.manifest.json`, `ci/tools/sync-traefik-runtime-manifest.py`, `ci/checks/catalog/check-open-runtime-provisioning-contract.sh`, `ci/tools/check-common-versions.py`, and `Makefile`.
- Framework regression: `tests/security_regression/test_traefik_runtime_pin_contract.py`.
- The SonarQube Cloud follow-up changes only the synchronizer's version
  expression, that focused regression, and this English/German Change Record
  pair.
- The Parent consumer bridge, direct-entry tests, workflow wiring, and bilingual guidance are coordinated changes, not separate Framework pin authorities.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | ---: | --- | --- |
| `PYTHON=/usr/bin/python3 make test-traefik-runtime-pin-contract` | 0 | Ten focused positive/negative pin-contract tests passed, including blocked-status propagation plus ASCII acceptance and Unicode-digit rejection. | Isolated Framework worktree with task-owned external build/tmp roots, 2026-08-14 |
| `python3 ci/tools/sync-traefik-runtime-manifest.py --write` twice, then `--check` | 0 | Both writes produced `7ea22e43269c85566ad86564171bb74fcbbd86800a3d861cbaf93b473ec12e1b`; the check passed. | Isolated Framework worktree, 2026-08-14 |
| `sh ci/checks/catalog/check-open-runtime-provisioning-contract.sh` | 0 | Canonical tuple, archive path/export, and manifest contract passed. | Isolated Framework worktree, 2026-08-14 |
| `PYTHON=/usr/bin/python3 make lint` | 0 | Full Framework lint passed after the source/test follow-up, including security, documentation, Change Record, Traefik contract, and whitespace contracts. | Isolated Framework build root, 2026-08-14 |
| Parent compiler-guide and runtime-environment contract suites | 0 | Each focused suite passed 21 tests; the runtime snapshot test covers the post-stage canonical-cache assignment. | Separate isolated Parent worktree, 2026-08-14 |

## Security impact

The original static mismatch is no longer reproducible through the generated manifest check. Negative controls reject stale/malformed/partial/alternate tuples, wrong platform, a caller `TRAEFIK_BIN`, and a same-version bare binary before archive extraction or runtime setup. A synthetic exact archive stages as the legitimate control. This is dependency-provenance hardening; it does not claim that a malicious artifact executed or that an external source was compromised.

The SonarQube Cloud follow-up retains the manifest parser's ASCII-only version
invariant. `re.ASCII` prevents Python's default Unicode `\d` behavior from
accepting confusable release digits in the archive and URL derivation path.

## Documentation and runtime evidence

English/German connector and compiler guidance no longer copy the stale pin and instead describe Framework preparation. No external archive download or live Traefik smoke/native run was performed. Hosted checks for Framework PR #78 must be read against its exact current head and are not treated as evidence of a live release acquisition.

## Checks not run

- Official pinned archive download and digest check: no retained archive and no separate network acquisition authorization.
- Live smoke/native connector control: depends on the actual archive and local runtime prerequisites.
- Exact-head hosted-check revalidation after each PR update and resulting-master revalidation: these are distinct delivery checks, and their results are retained only when observed in PR and task lifecycle evidence.
- Parent Gitlink update: not authorized here. Cross-repository policy requires a merged, verified Framework-master SHA before a separate Parent pointer change.

## Limitations and residual risk

The guard cannot protect against code execution already able to change Framework source or invoke arbitrary shell in the same trust boundary. The real upstream artifact remains unverified; resulting-master evidence is retained only when observed in PR and task lifecycle evidence. MRTS was not touched.

## Final diff and review status

Task-owned Framework and Parent diffs received scoped whitespace checks with no errors. `FND-FRAMEWORK-0069` remains `fixed`, not `verified` or `closed`. The Framework implementation was committed and normally pushed through Framework PR #78. The current user wording `bringe ihn in den master` selects only this task-owned Framework PR for controlled Framework-master integration; this record does not authorize a Parent Gitlink update, production delivery, or MRTS action.

The documented SonarQube Cloud source/test follow-up is part of Framework PR
#78. Its exact-head delivery status is retained in PR and task evidence rather
than this Change Record; any later PR head still requires fresh exact-head
verification.
