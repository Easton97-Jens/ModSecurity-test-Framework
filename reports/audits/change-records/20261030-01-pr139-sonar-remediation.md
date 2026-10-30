# MRTS path and process boundary remediation

**Language:** English | [Deutsch](20261030-01-pr139-sonar-remediation.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261030-01-pr139-sonar-remediation |
| UTC date | 2026-10-30 |
| Framework base revision | `7488bbcd8dcbeea94744d0b46f46bc4143335c87` |
| Issue or pull request | [Framework PR #139](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/139) |

## Motivation and problem statement

PR #139's Cloud analysis reported 24 issues in the new package/result helpers.
The Quality Gate failed on the new security rating. Local fixtures confirmed
that the result reader and writer accepted paths outside the selected runtime
root and that a malformed failed-ID list could exceed a three-second timeout.
Package commands also needed an explicit trust boundary for the Framework
scripts they execute. Rule descriptions and complete issue/hotspot pagination
were checked before remediation; scanner findings were traced to their actual
source and sink rather than treated as automatic exploit proof.

## Affected components and security boundaries

Framework package provisioning, private artifact rewrites, result reads/writes
and native report consumption. The shared `ci/lib/mrts_path_safety.py` validates
dedicated external roots independently of incoming artifact paths. No Parent
source or gitlink, MRTS source/fixture/gitlink, scanner exclusions, rule settings
or Quality Gate settings change. Parent PR #432 is already merged; this change
continues the existing Framework PR without authorizing a merge or pin update.

## Acceptance criteria

Legitimate package preparation, verification, private port adaptation and
explicit-ID PASS remain valid. Traversal, outside siblings, symlink components,
system/source roots, public write access and foreign Framework execution roots
are rejected. Non-regular/oversized result inputs fail without blocking.
Malformed failed lists finish promptly and IDs retain ASCII semantics. Fresh
Cloud results and required checks must be verified against the pushed PR head.

## Alternatives considered

Suppressing findings, accepting issues or changing analysis/gate configuration
would not repair the boundaries. Trusting each input's parent would authorize
the very path being checked. Requiring a new result-CLI root argument would
break the merged Parent caller; the existing trusted exported `BUILD_ROOT`
provides the authorization root instead. Same-UID process isolation is outside
this file-integrity contract.

## Implementation decision

Use one shared owned, non-writable, symlink-free external-root policy with
configured runtime anchors when present. Validate input/output containment,
lexical traversal, directory ownership and file types before access. Result
reads use a no-follow, nonblocking descriptor and a byte limit; job publication
remains atomic. The native report passes its trusted runtime root explicitly.

Bind package scripts to the executing Framework checkout, select closed Git
operations and provisioning steps, use trusted executable paths and a system
child PATH, and preserve the Framework virtual-environment launcher. Check
manifest leaves and complete artifact trees before reads or provenance/port
rewrites. Keep the helper in the manifest source identity. Split complex
operations and replace the failed-list regex search with token validation;
retain ASCII `\d` matching. Existing CLI flags and manifest integrity checks
remain in use; changed source identity requires fresh packages.

## Changed files and tests

`ci/lib/mrts_path_safety.py`, `ci/lib/mrts_results.py`,
`ci/provisioning/mrts-package.py`, `ci/reporting/generate-mrts-native-report.py`,
the two package/result integrity regression modules, paired preparation docs
and this paired record. Eighteen new tests cover the boundaries above, including
unchanged foreign-file sentinels and successful standalone CLI/venv controls.
No default inventory or historical matrix is enlarged.

## Commands and results

Commands used RTK and the Framework-owned Python environment. Portable command
spellings below normalize local prefixes as `<task-root>`, `<Framework-python>`
and `<pinned-checkout>`; exact invocations and logs remain in external task
evidence. No credentials are recorded.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk bypass <Framework-python> -m unittest` with the seven focused MRTS modules | 0 | 85 tests passed, including 18 new regressions | `<task-root>/evidence/integrated-regressions.log` |
| `rtk bypass <Framework-python> ci/checks/catalog/check-mrts-importer.py` | 0 | Four fixture cases passed | `<task-root>/evidence/importer-fixtures.log` |
| `rtk bypass <Framework-python> -m py_compile` on six changed Python files | 0 | Compilation passed | External command record |
| `rtk bypass sh -n ci/lib/mrts-common.sh ci/provisioning/generate-mrts.sh ci/provisioning/write-mrts-load.sh` | 0 | Shell syntax passed | External command record |
| `rtk bypass gitleaks dir --redact=100` | 0 | No leaks before inspection or after source changes | `<task-root>/evidence/final-source-secrets.json` |
| `rtk bypass /usr/local/bin/sonar-with-env analyze` on the three changed helpers | 1 | Local agentic analysis unavailable: service returned 403; all three files skipped | `<task-root>/evidence/local-sonar.json` |

## Security impact

Original-path fixtures confirm the baseline result read/write escapes and
failed-list timeout. Current positive and alternate-bypass tests reject outside
siblings, lexical traversal, symlink ancestors/leaves, FIFO/oversized inputs,
unsafe runtime roots and foreign Framework roots while preserving valid
packages and observed results. Independent review caught venv-prefix loss and
a manifest read before leaf validation; both were corrected and regression
tested. No validation, auth, isolation, scanner rule or gate is weakened.

## Documentation and runtime evidence

Updated `docs/mrts-preparation.md` and its German companion explain root
authorization, fixed process entry points and the standalone writer's trusted
`BUILD_ROOT` export. Existing H1 evidence remains historical; this remediation
adds deterministic package/result fixtures and does not claim new host-runtime
qualification.

## Checks not run

No historical protocol/MRTS matrix, new host run, coverage campaign or dependency
audit: these are outside the scoped helper fixes. Local Sonar agentic analysis
is unavailable on this connection; hosted PR analysis is the required source
for the final Quality Gate. Required hosted checks are pending after push.

## Limitations and residual risk

Trusted same-UID mutation remains outside process isolation. Preparation and
manifest validation do not prove connector runtime behavior. Existing optional
demo collisions and pending upstream classifications remain visible. Changing
the Framework pin or merging this PR requires a separate authorized action.

## Final diff and review status

Package/result changes received independent boundary review. Focused local
checks passed as recorded above. Final documentation, staged-diff, whitespace,
commit-range secret checks and current-head hosted delivery evidence will be
completed in the delivery cycle; no hosted pass or merge is claimed here.
