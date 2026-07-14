# Change record: 20260714-01-fix-framework-protocol-target-paths

**Language:** English | [Deutsch](20260714-01-fix-framework-protocol-target-paths.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260714-01-fix-framework-protocol-target-paths` |
| UTC date | 2026-07-14 |
| Framework base revision | `ef6b6d516d63c05beb8bb4e872a8568c9fded75d` |
| Issue or pull request | None; targeted Framework repair |

## Motivation and problem statement

The public Make targets `protocol-client`, `check-protocol-evidence`, and
`check-transport-hardening-evidence` defaulted to absent hyphenated Python
filenames. The maintained files use underscores. Historical commit
`428dfb2741785adabad7a6280882ea5251e00324` moved the three implementations
into their current `ci/checks/` directories and introduced the incorrect
hyphenated basenames in the Makefile defaults.

## Affected components and security boundaries

This changes Framework Makefile path resolution, a static Makefile contract,
and paired Framework documentation. It does not change a connector, host
adapter, capability manifest, evidence schema, transport assertion, or
promotion decision. Existing protocol and transport evidence validators remain
unchanged; the relevant boundary is preventing a missing local tool from
silently breaking their established invocation contract.

## Acceptance criteria

1. All three retained public targets resolve to their existing maintained
   local runner or checker.
2. No replacement runner, product file, Parent file, or Parent Gitlink is
   changed.
3. Missing target prerequisites retain clear non-success status and exit code.
4. A static test rejects missing Makefile-referenced local Python or shell
   scripts, including the original hyphenated regression.
5. English and German documentation and Change Records describe the same
   target contract and runtime-evidence boundary.

## Alternatives considered

- Adding hyphenated wrapper scripts was rejected because it would duplicate or
  invent a runner instead of repairing the stale paths.
- Renaming the public targets was rejected because Parent Makefile forwarders
  and the Parent protocol CI workflow call those exact names.
- Changing the Parent was rejected because the defect and maintained runners
  are wholly Framework-owned.

## Implementation decision

The three Makefile defaults now point to the existing underscore-named files:
`protocol_client.py`, `check_protocol_evidence.py`, and
`check_transport_hardening_evidence.py`. The public target names, recipes,
arguments, and prerequisite guards are unchanged.

`test-makefile-contract` scans direct local Python and shell script references
and `$(CI_ROOT)` defaults in the top-level Makefile. It rejects absent,
escaping, or non-regular files, asserts the three intended mappings, and has a
synthetic negative case for `protocol-client.py`. `make lint` invokes that
static target.

## Changed files and tests

Versioned Framework changes:

- `Makefile`.
- `tests/makefile_contract/test_makefile_local_scripts.py`.
- `docs/reference/variables.md` and `docs/reference/variables.de.md`.
- `docs/testing-and-evidence.md` and `docs/testing-and-evidence.de.md`.
- `docs/development.md` and `docs/development.de.md`.
- This paired Change Record.

The focused static suite covers all current Makefile local script references,
the three corrected protocol defaults, and the original missing hyphenated
path. Existing protocol-client and transport-hardening tests retain their
positive and negative runner semantics.

## Commands and results

All write-capable commands used a task-specific descendant of the Framework
temporary root; paths are intentionally omitted from this record.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | ---: | --- | --- |
| `rtk make test-makefile-contract` | 0 | 3 static contract tests passed | Task-local temporary output only |
| `rtk make test-protocol-client` | 0 | 16 protocol client/evidence tests passed | Task-local temporary output only |
| `rtk make test-no-crs-contract` | 0 | 81 No-CRS and transport-hardening contract tests passed | Task-local temporary output only |
| `rtk make protocol-client` | 2 | Clear `PROTOCOL_URL` prerequisite error | Not applicable |
| `rtk make check-protocol-evidence` | 2 | Clear `PROTOCOL_ARTIFACT_DIR` prerequisite error | Not applicable |
| `rtk make check-transport-hardening-evidence` | 2 | Clear `CONNECTOR` prerequisite error | Not applicable |
| `rtk make -n` for the three repaired targets | 0 | All printed the maintained underscore-named local tool paths | Not applicable |
| `rtk make check-bilingual-docs` | 0 | 38 bilingual pairs checked | Not applicable |
| `rtk make check-doc-links` | 0 | Tracked documentation links passed | Not applicable |
| `rtk make check-repository-path-references` | 0 | 382 maintained files scanned; no stale paths | Not applicable |
| `rtk make lint` | 0 | Static checks, the new contract, catalog, documentation, and diff checks passed | Task-local temporary output only |
| `rtk git diff --check` | 0 | No whitespace errors | Not applicable |

## Security impact

No security remediation, product behavior, authorization, validation rule,
or evidence policy changed. The correction preserves the existing bounded
protocol and transport checkers instead of bypassing them. No security
attack-path or alternate-bypass retest was required because no security control
changed.

## Documentation and runtime evidence

Paired English/German reference, testing, and development documentation now
state the stable public target names, the underscore-named runners, the
prerequisite exit-2 behavior, and the static-versus-runtime boundary. This
record is paired in English and German.

No connector runtime or lifecycle evidence was collected. A deliberately
unserved loopback invocation and empty isolated artifact directories exercised
target dispatch only and returned non-success as expected; they are not H1,
H2, H3, connector, or production evidence.

## Checks not run

- H1, H2, and H3 connector-runtime checks are blocked: no connector-owned host
  endpoint, harness, certificate, ALPN, or QUIC environment was supplied.
- CRS/MRTS connector matrices are not run because this static path repair
  changes no catalog, matrix selection, or connector behavior and needs
  Parent-owned runtime prerequisites.
- Generated report refresh and matrix checks are not run because no generator
  source changed and those targets can rewrite generated files.
- C/C++ and hardened diagnostic builds are not applicable: no C/C++ source or
  build contract changed.

## Limitations and residual risk

The new contract verifies default, statically referenced local script paths;
caller-supplied tool overrides remain caller-owned. It cannot prove that a
connector host, client feature set, TLS/ALPN, or QUIC environment is available.
Those conditions remain separate runtime evidence requirements.

## Final diff and review status

The unstaged Framework diff was reviewed for scope, whitespace, generated
files, and sensitive content. `git diff --check` passed. No commit is created
by this task. The Parent repository and its Gitlink remain outside the change
scope.
