# Change record

**Language:** English | [Deutsch](20260910-03-derive-envoy-fixture-pins.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260910-03-derive-envoy-fixture-pins` |
| UTC date | 2026-09-10 |
| Framework base revision | `ea2a157984c7e3b754c1a2d6e9837039895fcafe` |
| Issue or pull request | Framework PR [#118](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/118) carries this same-branch correction; protected integration remains pending fresh exact-head evidence. |

## Motivation and problem statement

The trusted canonical update in PR #118 advances reviewed component tuples.
Several regression fixtures still searched for or asserted prior literals.
They therefore rejected a legitimate reviewed update, or could silently skip
their intended mutation, before covering the provenance and generated-runtime
controls.

This Framework-only correction addresses validated finding
`FND-FRAMEWORK-0122`. It changes test fixtures and their test-only parser; it
does not change a canonical pin, runtime downloader, lock checker, workflow,
permission, token, or provisioning path.

## Affected components and security boundaries

- `tests/security_regression/common_version_fixture_support.py`
- `tests/security_regression/test_modsecurity_v3_git_ref_provenance.py`
- `tests/security_regression/test_runtime_component_sync.py`
- `tests/security_regression/test_common_version_atomic_provenance.py`
- `tests/security_regression/test_pcre2_archive_digest.py`
- `tests/fixtures/pcre2-digest/`

The relevant boundary is the trusted canonical-update validation path. Active
Envoy tuple values must stay source-derived, and altered or duplicate active
values must remain fail-closed before a provenance-sensitive Git or runtime
sink is reached.

## Acceptance criteria

- Positive snapshot/reentry controls obtain the current Envoy value from the
  synthetic fixture source without evaluating shell source.
- The duplicate active-pin control still returns `77` before Git activity.
- Runtime-component mutation controls derive current version, URL, and digest,
  then apply an independently altered value that the checker rejects.
- HAProxy coincidence and series-mismatch fixtures structurally rewrite their
  disposable source copy, so reviewed releases cannot make a test mutation
  silently disappear.
- The copied APR-util update fixture structurally replaces current assignments
  before applying its deliberately synthetic initial tuple.
- The PCRE2 archive fixture derives its archive name and archived root from the
  reviewed current version, while its local source payload stays version-free.
- Existing current-lock and current-canonical controls continue to pass.
- No production pin, checker, downloader, workflow permission, or publisher
  scope is relaxed.

## Alternatives considered

Hard-coding the currently observed Envoy release would recreate the defect on
the next reviewed update. Sourcing `common.sh` from the Python helper would
unnecessarily execute fixture shell source. Weakening the fail-closed checker
would remove a valid control. These alternatives were rejected.

## Implementation decision

The shared test-only helper now structurally reads or replaces exactly one
supported shell assignment using its non-executing assignment grammar. The
provenance tests derive their expected/duplicated Envoy value from source text.
Runtime synchronization controls derive current Envoy and HAProxy values
before changing an independently altered value or a disposable fixture. The
atomic APR-util fixture structurally prepares its fixed synthetic starting
tuple. The PCRE2 archive test derives its generated archive identity from the
reviewed current version instead of a prior release directory. Deliberately
hostile foreign-host and shell-expression test data remain unchanged.

The existing PR branch first received a normal merge of current Framework
`master`; the one `common.sh` conflict retained master's OpenSSL-derived NGINX
TLS aliases, preserving the established invariant from the already integrated
change.

## Changed files and tests

- `tests/security_regression/common_version_fixture_support.py`
- `tests/security_regression/test_modsecurity_v3_git_ref_provenance.py`
- `tests/security_regression/test_runtime_component_sync.py`
- `tests/security_regression/test_common_version_atomic_provenance.py`
- `tests/security_regression/test_pcre2_archive_digest.py`
- `tests/fixtures/pcre2-digest/`
- this paired Change Record

The correction covers positive snapshot propagation, duplicate active-pin
rejection, altered runtime-profile rejection, HAProxy release-series controls,
APR-util atomic update setup, PCRE2 archive verification, and the fresh
initialization control. It does not add runtime artifacts or alter connector
behavior.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Focused pre-patch snapshot/reentry test | 1 | Expected stale `1.39.0` assertion reproduced against current `1.39.1` fixture output. | Task-owned corrective worktree |
| Focused pre-patch runtime-sync mutation test | 1 | Expected old version and digest source needles were absent after the canonical update. | Task-owned corrective worktree |
| `bash -n ci/lib/common.sh` | 0 | Resolved same-branch merge shell source is syntactically valid. | Task-owned corrective worktree |
| `python -m py_compile` for changed test sources | 0 | Changed Python sources compiled using the selected Framework environment. | Task-owned corrective worktree |
| Focused provenance positive and negative controls | 0 | Four selected snapshot, duplicate, fresh-init, and altered-pin controls passed. | Task-owned corrective worktree |
| Runtime-sync mutation control and runtime-lock suite | 0 | One changed mutation control and 13 lock controls passed. | Task-owned corrective worktree |
| Initial `make lint` after the first repair | 2 | Revealed the remaining stale HAProxy HTX mutation needle; the observed failure was repaired before delivery. | Task-owned corrective worktree |
| `python -m unittest tests.security_regression.test_runtime_component_sync -v` | 0 | All 19 runtime synchronization controls, including the repaired HAProxy cases, passed. | Task-owned corrective worktree |
| `python -m unittest tests.security_regression.test_common_version_atomic_provenance -v` | 0 | 30 canonical update/provenance controls passed. | Task-owned corrective worktree |
| `python -m unittest tests.security_regression.test_pcre2_archive_digest -v` | 0 | All 3 PCRE2 digest controls passed with the current version-derived archive fixture. | Task-owned corrective worktree |
| Final correctly bound `make lint` | 0 | Full local lint passed, including documentation, workflow security, canonical pins, runtime lock/sync, provenance, and archive controls. | Task-owned corrective worktree |

## Security impact

The original Envoy stale-fixture path was reproduced before the patch and
passes after source-derived repair. The same-class HAProxy and APR-util
source-coupled fixture paths are structurally prepared before their intended
controls run, and the PCRE2 positive archive control now reaches the current
reviewed archive identity. The alternate duplicate-pin and independently
altered runtime tuple controls remain failing closed. No attacker-controlled
input reaches the former assertions, and no security control is weakened.

## Documentation and runtime evidence

This English/German pair documents the Framework-only validation-contract
correction. The normal master merge is recorded as lifecycle context; no
runtime service, download, or connector execution evidence was collected.

## Checks not run

The complete exact-head hosted workflow/CodeQL/SonarQube cycle remains pending
after the final PR-branch commit and push. No new canonical maintenance
dispatch, Parent change, MRTS change, or runtime matrix was run.

## Limitations and residual risk

The repair is intentionally limited to test source coupling. It does not prove
runtime behavior. Protected merge remains conditional on the current PR head
being non-Draft, conflict-free, and fully green under the active ruleset.

## Final diff and review status

The normal master merge conflict was reviewed with shell syntax and whitespace
checks. The corrective diff passed full local lint and an independent security
review; it awaits exact-head CI and protected-merge evidence. No force push,
direct master write, check rerun/cancellation, or branch-protection bypass is
used.
