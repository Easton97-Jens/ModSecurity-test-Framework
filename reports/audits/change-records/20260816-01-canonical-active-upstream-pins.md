# Change record: 20260816-01-canonical-active-upstream-pins

**Language:** English | [Deutsch](20260816-01-canonical-active-upstream-pins.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260816-01-canonical-active-upstream-pins` |
| UTC date | 2026-08-16 |
| Framework base revision | `3cb33609626ff689c54b6dc0f31fb7e9401fe75e` |
| Issue or pull request | Draft PR pending at record creation; no issue is closed. |

## Motivation and problem statement

Active upstream pins had accumulated across shell provisioners, runtime
manifest/lock views, CI workflows, Python/tool locks, CRS contract views, and
documentation. That made a reviewed tuple capable of drifting without one
generic checker detecting every active consumer. The concrete observed example
was a Lighttpd runtime manifest still recording `1.4.84` while the reviewed
shell tuple was `1.4.85`.

The Framework needs one manually maintained active-pin source and deterministic
derived views. The delivery also preserves the preceding security remediation:
untrusted Make controls, mutable runtime-cache handoff, and runtime provenance
must remain fail-closed rather than being relaxed to make generation easier.

## Affected components and security boundaries

The Framework-only scope covers `ci/lib/common.sh`, generic pin parsing and
generation tools, runtime provisioning and lock/manifest contracts, CI and
workflow pin views, CRS views, Make entrypoints, tests, and paired technical
documentation. The security boundary begins with reviewed version/ref/asset/
platform/digest tuples and ends at the consumer that provisions, validates, or
publishes the derived view. Parent product source, Parent gitlink, connector
host-runtime claims, MRTS, global installation, and deployment are excluded.

## Acceptance criteria

1. `ci/lib/common.sh` is the only manually maintained active-pin authority.
2. Runtime manifest and lock, Python/tool/workflow pins, and CRS views are
   deterministically generated or validated from that authority.
3. Missing, unknown, duplicate, stale, platform-mismatched, URL-mismatched,
   or malformed runtime entries fail closed.
4. Active provisioning preserves digest/provenance binding, private verified
   archive materialization, and safe Make caller-input handling.
5. Focused regression, generic checker, idempotence, lint, and full native
   unit-test evidence pass without network pin discovery or dependency install.
6. Parent gitlink and MRTS remain unchanged.
7. CRS view tooling accepts only non-symlink contained fixture roots and uses
   the validated resolved path at every filesystem sink.

## Alternatives considered

- Retaining independent literals in each consumer was rejected because it
  recreates undetectable drift.
- Sourcing `common.sh` from Python generators was rejected because it grants
  shell execution authority to generated-view input; the final parser is
  non-executing and allowlisted.
- Continuing to extract runtime artifacts from shared cache locations after a
  first hash check was rejected because a replacement race can cross the
  review boundary.

## Implementation decision

`common.sh` defines canonical descriptor-style tuples and derives asset/URL
values safely. `sync-runtime-components.py` parses only the reviewed
assignment/expansion subset, produces atomic deterministic runtime views, and
has a compatibility wrapper for the prior Traefik-only interface. Dedicated
generators/checkers cover Python, workflow, and CRS views. The generic lock
checker validates descriptor-declared manifest membership, exact URLs, and
canonical platform values.

Runtime artifacts are verified, copied, rehashed, extracted, built, staged,
and recorded in task-private `BUILD_ROOT` locations. `safe-make.sh` removes and
rejects GNU Make pre-parser controls while supported CI/helper entrypoints use
that boundary. Existing EN/DE documents now identify canonical versus derived
views rather than independently declaring active pins.

CRS view tooling validates a caller-provided fixture root and every fixed view
path for lexical and resolved containment, non-symlink components, and regular
file type. The validator returns only the checked resolved path, which is then
used for all CRS reads, comparisons, and atomic writes; no raw CLI-derived
path reaches those filesystem sinks.

## Changed files and tests

- Canonical source and runtime contracts: `ci/lib/common.sh`,
  `ci/lib/runtime-component-common.sh`, runtime provisioners, runtime
  manifest/lock, and smoke/provenance helpers.
- New generator/security tools: `ci/tools/common_canonical_pins.py`,
  `crs_contract_pins.py`, `safe-make.sh`,
  `sync-runtime-components.py`, `sync-canonical-python-pins.py`,
  `sync-canonical-workflow-pins.py`, and `sync-crs-contract-views.py`.
- Consumer contracts: `Makefile`, V3 smoke Make/runtime scripts, CI workflows,
  runtime/CI security checkers, Python/tool lock views, and catalog checks.
- Documentation: paired connector, workflow-security, variable,
  CI-tooling, and testing/evidence references.
- Tests: new generator/runtime synchronization regressions plus expanded
  provenance, private-materialization, safe-Make, lock, download, bootstrap,
  CRS, and CI contract coverage, including CRS root-traversal and symlink-root
  rejection with a legitimate temporary-fixture control.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | ---: | --- | --- |
| `python -m unittest -v` for runtime lock/sync/download/smoke/bootstrap modules | 0 | 86 focused security/runtime tests passed. | Local canonical-pin validation receipt |
| `python -m unittest -v` for provenance and generator modules | 0 | 46 generator/atomic-provenance tests passed. | Local canonical-pin validation receipt |
| `python -m unittest -q` for NGINX/APR/CRS/V3/PCRE2 provenance modules | 0 | 78 broad provenance tests passed. | Local canonical-pin validation receipt |
| `make lint` with task-owned external roots | 0 | Existing lint/contract chain passed. | Local canonical-pin validation receipt |
| `python -m unittest discover -q` | 0 | 98 native full-suite tests passed. | Local canonical-pin validation receipt |
| Generic canonical, synchronizer, lock, catalog, shell-syntax, and `git diff --check` checks | 0 | Generated views and source contracts were clean and idempotent. | Local canonical-pin validation receipt |
| Focused CRS root-containment, canonical Python, and workflow synchronizer tests | 0 | 26 tests passed, including traversal and symlink-root negatives. | Draft-PR remediation validation |

## Security impact

This is a security hardening and supply-chain provenance change. Regression
controls cover malicious shell input in the parser, malicious GNU Make control
assignments/options, stale or tampered provenance, incorrect runtime URLs and
manifest membership, fake checksum tools, and shared-cache handoff attempts.
They also cover CRS root traversal and symlink-root substitution before a view
can be read or written. Legitimate controlled inputs continue to pass. The
final review found no confirmed high- or critical-impact issue in supported
active entrypoints.

## Documentation and runtime evidence

Paired English/German Framework documentation describes the canonical source
and derived views. The tests are local source, generator, and contract
evidence. No connector host was started and no host-runtime `PASS` is claimed.
The Parent can consume this Framework revision only through a separately
authorized Parent gitlink lifecycle.

## Checks not run

- `pytest -q` was attempted but the supplied Framework environment has no
  `pytest` module; no dependency was installed. The native full `unittest`
  discovery run is the available fallback.
- No network-based latest-version discovery or real upstream artifact download
  was run; deterministic fixtures protect the reviewed pin contract.

## Limitations and residual risk

Direct raw `/usr/bin/make` invocation remains caller authority outside the
supported `safe-make.sh`/CI/helper boundary. The task-private build root must
remain non-writable to an attacker after final hashing. A new platform or
runtime profile requires a reviewed canonical tuple and regression coverage.
The `--root` fixture directory remains caller authority; the containment
guarantee assumes no concurrent hostile writer can replace its checked files
between validation and the filesystem operation.

## Final diff and review status

The original canonical diff and the CRS root-containment remediation passed
their task-owned whitespace, generated-view idempotence, focused security
review, and local validation. Draft PR #82 is open; the next commit and normal
push will be verified against the remote and PR heads after delivery. The
SonarQube Cloud security-gate failure on the preceding PR head is the reason
for this remediation; no current-head hosted result is claimed here. This
record does not claim a merge, Parent, MRTS, or gitlink outcome.
