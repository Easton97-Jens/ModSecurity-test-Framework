# Framework MRTS definition intake boundary

**Language:** English | [Deutsch](CR-20260929-mrts-definition-intake.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `CR-20260929-mrts-definition-intake` |
| Date (UTC) | 2026-09-29 |
| Base revision | `f9e48b0774b5bdf7aaa8e38ce98eb6c50bf293c8` |
| Source finding | `B03` / `csf_24b4dcf793c63c691309c9af` |
| Unchanged MRTS gitlink | `8a6bb546c4c81d8ffc7be801dceac60c6925685f` |
| Delivery target | Framework Draft PR #128; no merge |

## Motivation and problem statement

B03 identifies unrestricted global attribute assignment inside the separately
owned MRTS generator. The user selected Parent and Framework, not MRTS. This
draft adds a bounded mitigation at the existing Framework generation entrypoint,
without modifying the generator or claiming its root cause is fixed.

The [intake record](../findings/20260929-mrts-intake.json) retains the original
finding ID, reported severity, ownership boundary and pending verification.
The companion Parent draft preserves the 72-source to 59-work-item mapping.
Other findings are not silently treated as completed.

The initial workflow used unsupported job-level runner context and flow YAML.
Subsequent checks also required concurrency, a default bash shell and the
repository Python contract. These are fixed without changing those checkers.
The old observation test serialized YAML documents through JSON and changed
integer mapping keys to strings; the test double now uses lossless YAML,
retaining the original exact document comparison.

Sonar issue AaDsHe5ZOryZpzLd_yHy, rule pythonsecurity:S8705, identifies argument
injection at run_guarded's subprocess call, including the tests_out flow.
An argv list prevents shell splitting, but does not stop an existing relative
path beginning with '-' from being interpreted as an option. Two harmless
real-subprocess regressions demonstrated this before the source correction.

## Acceptance criteria

- Reject undocumented global keys and non-mapping global configuration before
  generator execution, including whole-global scalar substitution.
- Validate every selected definition before invoking the generator.
- Pass private snapshots of parsed and validated data, not reopened originals.
- Preserve lexical order, supported data including integer keys, output arguments,
  unsuccessful child exit status, cleanup and caller-owned path controls.
- Keep generator, snapshot and output paths as path operands, not CLI options.
- Execute the selected script even when its relative filename resembles an option.
- Verify the full pinned default and feature-demo corpus before promotion.
- Keep direct MRTS invocation and its unresolved root fix separate.
- Require current-head regression, CI and Sonar results; no inferred PASS.

## Implementation decision and rationale

The shell entrypoint delegates to the Framework-owned Python launcher. The
launcher is not a sandbox for trusted operator-selected generator code or
hostile same-UID processes and does not replace existing output-path checks.

The global-key schema comes from the pinned MRTS README and RuleGenerator.
Both default_tests_phase_methods and default_test_phase_methods remain
accepted without translation; default_constants remains supported. Other
attribute names are rejected instead of using object introspection as a schema.

The existing safe PyYAML loader is used. Numbered snapshots under the external
build root have file mode 0600 and directory mode 0700, preserve lexical order
and are removed on normal completion and exceptions. This prevents the generator
from reopening replaced original definitions. Shell output cleanup still occurs
before launcher validation, so earlier generated output is not retained after
later input rejection.

The Sonar correction resolves the existing generator, output and snapshot paths
to absolute paths before constructing argv, and terminates Python option parsing
with -- before the script. Numbered snapshot operands are consequently absolute
too. Relative paths still work as data, including names beginning with '-'.
The operator still selects the trusted program and output roots; this is not
new arbitrary-program isolation. No shell quoting or shell execution is added.

The exact-head regression workflow uses existing immutable action pins and
hash-locked dependencies. TMPDIR and PIP_CACHE_DIR are step-scoped, directories
use private umask, and the existing concurrency/bash contracts are implemented.
The temporary unauthenticated Sonar diagnostic has completed and is removed.
No required test or Sonar check is removed, suppressed or downgraded.

## Changed files

- `ci/provisioning/generate-mrts.sh`
- `ci/provisioning/mrts_definition_guard.py`
- `tests/security_regression/test_mrts_definition_guard.py`
- `.github/workflows/ci-findings-regressions.yml`
- `reports/audits/findings/20260929-mrts-intake.json`
- This English/German Change Record pair.

## Commands executed

| Check | Actual evidence and limitation |
| --- | --- |
| Initial source intake | Complete shell source matched its Git blob before editing; Python/JSON parsed as data |
| Initial action-version and actionlint jobs | 109307180219 and 109307181277 failed on flow YAML and invalid runner context |
| Intermediate security-contract job | 109347213959 exposed missing concurrency and default bash; corrected |
| Initial dedicated tests at 60a75c90500f765675059e341bf8e73f6008a023 | Job 109347213122: 9 passed, 1 failed due to lossy JSON observation |
| Test-first run at d1a6aeef864ad851f1f9f6b924c29719006c8c64 | Job 109350381183: all original 10 tests passed; the 2 new argument-boundary tests failed with child exit 2 |
| Sonar evidence retrieval | Jobs 109347213481 and 109350381226 read the original public annotation and exact S8705 issue/flow without credentials |
| Local project tests / builds / git diff --check | NOT RUN: required RTK and provisioned local repository tools are absent |
| Source-fix head regression / full CI / Sonar | Pending fresh results after this correction; not certified in advance |

The test-first command was python3 -m unittest discover -s
tests/security_regression -p 'test_mrts_definition_guard.py' -v on GitHub's
exact PR-head checkout with repository Python and hash-locked dependencies.
The existing integer-key assertion was not weakened. The option-like generator
failed in Python's option parser; relative output roots failed in the fixture
parser. No destructive payload or external target was used.

## Security impact

Undocumented global attributes are rejected at the Framework entrypoint.
Path operands can no longer reinterpret the selected child invocation as
interpreter/generator options through a leading hyphen. The original MRTS
code is unchanged and direct invocation is outside this mitigation. B03 cannot
be closed merely because these launcher tests or Sonar later pass.

No permission expansion, dependency-pin change, scanner exclusion, severity
edit, test disablement or quality-gate relaxation is part of the correction.

## Runtime evidence

The failed argument-boundary regressions and successful ten original controls
are real subprocess tests at the recorded test-first head, using a harmless
fixture generator. They are not a full MRTS corpus or connector host-runtime
run. Fresh results at the source-fix head must be evaluated independently.

## Known limitations

This remains candidate_entrypoint_mitigation, not complete remediation or
verified closure of B03. A direct MRTS fix requires a separately authorized
task. Existing shell cleanup precedes validation. The launcher does not
provide process isolation or authenticate an operator-selected program.

## Remaining risks

The pinned default/feature-demo corpus and existing containment regressions
still require execution. Same-UID and trusted-generator assumptions are
unchanged. Sonar's reported CLI flow is repaired as a path/option boundary;
the annotation's generic HTTP-source wording is not evidence of an HTTP
listener in this launcher. The new scan must evaluate the actual correction.

## Checks not run and rationale

Local project commands and full generator/host runs were not executed because
the editing environment lacks required RTK and provisioned repository tools.
The code-work and Sonar skills were read; the referenced global execution
skill was not available. No unwrapped local project command substituted for
RTK. No omitted, skipped or pending check is a PASS.

## Final diff and review status

The CI-remediation commits repair workflow and documentation contracts, correct
the test observation format, add two negative regressions, then fix the source
argument boundary. All original guard assertions and source-intake restrictions
remain. The temporary diagnostic job is removed after its evidence was read.

Parent impact: unchanged selected dependency. Parent gitlink: unchanged.
MRTS scope: default_read_only. MRTS gitlink: unchanged. The PR remains a draft
pending current-head checks and review. No merge, force-push, risk acceptance,
new claimed host support or automated finding closure.
