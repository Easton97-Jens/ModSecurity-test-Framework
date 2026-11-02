# Change record: CodeQL recognition of existing boundary guards

**Language:** English | [Deutsch](20261102-01-codeql-guard-recognition.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261102-01-codeql-guard-recognition |
| UTC date | 2026-11-02 |
| Framework base revision | `bc08ee7ca413012da189902b8b9c61c98151e76b` |
| Issue or pull request | Follow-up to [#151](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/151); follow-up PR not yet created at this record's draft stage |

## Motivation and problem statement

The user selected native recognition of confirmed corrections, without dismissing findings. After #151, CodeQL still reports #16, #25 and #26 despite the tested complete-target and bounded-header admission guards. This change adds explicit sink-side defenses recognized by the active models. It does not establish a new runtime vulnerability in the already guarded implementation.

## Affected components and security boundaries

Framework-owned Traefik backend request/response artifacts and the Lighttpd supervisor test HTTP header. Parent product code and Parent gitlink remain unchanged; MRTS remains `default_read_only`. The other 23 findings retain their individual assessments in the [previous record](20261101-04-codeql-boundaries.md).

## Acceptance criteria

Retain both complete-target guards before standard-library normalization, 100-continue and body reads. Check both actual artifact destinations against the separator-terminated backend root before reading the body. Preserve all existing 16 cases, additional canonical names, special responses and receipt hashes. Continue rejecting invalid transaction identifiers with 400 while preserving every admitted/generated identifier. Obtain candidate-specific CodeQL evidence that the three affected results disappear while the other 23 remain. Preserve rules, categories, permissions, exclusions, real private-namespace tests and default selection. Automatic master alert closure requires a separately authorized merge and subsequent master analysis.

## Alternatives considered

Mass dismissal, suppression, query changes and scanner exclusions do not demonstrate native recognition and are outside the selected option. Removing the early guards or normalizing malformed targets into accepted names changes the established admission contract. A finite 16-name allowlist rejects legitimate canonical names. Neither approach is used.

## Implementation decision

After strict target admission, compute absolute request and response artifact paths with `os.path.abspath`. Require each full path to start with `os.path.abspath(root) + os.sep`; the trailing separator excludes sibling-prefix paths. Perform the actual writes through `Path` constructed from those checked paths. Both checks precede the body read. This is lexical containment, not a symlink-confinement guarantee.

Keep `[A-Za-z0-9._:-]{1,128}` admission and its 400 response. At `send_header`, remove CR and LF with two explicit `replace` calls as a second serialization defense. Every identifier reaching that sink through the existing admission/generated-value paths is unchanged. Invalid inputs are still rejected rather than sanitized into acceptance.

The baseline analysis `2073372882` used CodeQL CLI `2.27.1`, `python-queries` `1.8.11` and `python-all` `7.2.6`: 26 results from 43 rules. Model source revision: `6e9f9e38390175c41b99070a423c875f450759ca`. Relevant primary sources are [header sanitizers](https://github.com/github/codeql/blob/6e9f9e38390175c41b99070a423c875f450759ca/python/ql/lib/semmle/python/security/dataflow/HttpHeaderInjectionCustomizations.qll#L62), [standard-library models](https://github.com/github/codeql/blob/6e9f9e38390175c41b99070a423c875f450759ca/python/ql/lib/semmle/python/frameworks/Stdlib.qll#L1118) and [path-injection query logic](https://github.com/github/codeql/blob/6e9f9e38390175c41b99070a423c875f450759ca/python/ql/lib/semmle/python/security/dataflow/PathInjectionQuery.qll). Model inspection alone is not candidate scan evidence.

## Changed files and tests

- `connector_suite/adapters/traefik/harness/i12_auth/backend.py`: two explicit checked destinations and writes using those destinations.
- `tests/security_regression/test_traefik_auth_backend.py`: sixth method verifies four non-catalog canonical names, including one-character and 23-character boundaries, actual artifact bytes and receipt identity/hash.
- `connector_suite/modsecurity_connector_tests/test_trusted_lighttpd_runtime_supervisor.py`: header serialization defense and expanded raw HTTP regression. Invalid values cover empty, 129-byte, folded, SOH, DEL and Latin-1 identifiers; valid unchanged values cover lengths 1, 8 and 128. Existing generated-probe and valid-reflection rejection controls remain.
- Native generators refresh one backend binding, archive source identities/new method and migration views. Parsed inventory comparison shows exactly one source SHA change; every selector, case and Product-source choice is preserved.
- This paired Change Record is the documentation change. Existing CI discovers six backend methods plus the unchanged seven strict selectors: 13 methods/114 expanded scenarios. Native generation preserves 100 default cases/80 executions, 2,586 optional cases/1,140 executions, 528 fixed/235 dynamic sources and all 1,993 original IDs.

## Commands and results

All local commands use RTK. `FRAMEWORK_ROOT` is the task worktree, `CONNECTOR_ROOT` the unchanged Parent, `PYTHON` the Framework-owned interpreter and `RUN_ROOT` the external evidence root for run ID `framework-codeql-recognition-20261102`. No raw bodies or complete logs are recorded here.

| Command or observed procedure | Exit code | Result | Evidence |
| --- | --- | --- | --- |
| `rtk bypass env PYTHONPATH=${FRAMEWORK_ROOT}:${FRAMEWORK_ROOT}/connector_suite TMPDIR=${RUN_ROOT} PYTHONDONTWRITEBYTECODE=1 ${PYTHON} -m unittest discover -s tests/security_regression -p test_traefik_auth_backend.py -v` | 0 | Six backend methods pass, including the four non-catalog names | Task coordinator's current local run |
| Focused execution of `test_probe_handler_rejects_folded_and_control_transaction_headers`, `test_fixed_probe_rejects_reflected_or_reused_transaction_identifier` and `test_fixed_probes_cover_control_detection_and_alternate_negative` in `modsecurity_connector_tests.test_trusted_lighttpd_runtime_supervisor.TrustedLighttpdRuntimeSupervisorTest` through RTK and the Framework interpreter | 0 | Three methods pass; six malformed and three valid boundary values covered by the expanded method | Task coordinator's current local run |
| Same explicit Framework/Parent context, `-m unittest -v` for the three full supervisor/NGINX/Lighttpd modules | 0 | 84 methods: 81 pass, three explicit BLOCKED namespace skips in ordinary sandbox | Current local run |
| Exact seven-selector runner from existing CI, through the owner-mapped outer user namespace in approved host execution | 0 | Seven methods pass without skips, including all three real private-network wildcard cases | RUN_ROOT/ci-selected-regressions.py |
| Native `update-inventory-bindings.py --apply`, `update-test-archive.py`, `build-migration-map.py`; all three `--check`; parsed inventory comparison | 0 | Generation/freshness pass; one binding hash only; default/optional choices and counts above preserved | Current local run |
| Syntax compilation of three changed Python sources; both native CI security contract scripts | 0 | All pass; existing workflow bytes unchanged | Current local run |
| `rtk make check-documentation check-canonical-common-pins check-canonical-python-pins check-canonical-workflow-pins check-canonical-crs-contract-pins PYTHON=${PYTHON} FRAMEWORK_ROOT=${FRAMEWORK_ROOT} BUILD_ROOT=${RUN_ROOT}/build` | 0 | Documentation/link/path/Change Record checks and all four canonical pin checks pass | Current local run |
| Existing CodeQL workflow dispatched on the task branch, without workflow changes | Not yet observed | Candidate-specific 3-result delta still pending | Current task |

## Security impact

The strict admission controls from #151 stay intact. Additional explicit sink defenses improve analyzer recognition and provide a second boundary at the actual write/header output. Absolute-path normalization happens only after complete-target admission; it does not admit traversal or encoded malformed targets. The header defense does not weaken the existing rejection of folding, control characters, non-ASCII or overlong values. No scanner status, rule, exclusion, category or permission is changed.

## Documentation and runtime evidence

This complete EN/DE pair records the Framework-only follow-up. Current evidence is bounded backend/parser/loopback unit execution, real isolated kernel checks and baseline model inspection. The ordinary sandbox explicitly blocks three namespace cases; approved host execution passes the same cases within the exact seven-selector runner, without skips. No connector host/profile qualification or promotion evidence is produced. Parent pin unchanged; MRTS treated read-only. No alert dismissal, master integration or automatic merge is performed.

## Checks not run

At local commit, candidate-specific hosted CI/CodeQL/Sonar remain pending; exact-head results belong in the PR description and external lifecycle evidence. Earlier #151 checks are not evidence for this candidate. No full connector suite or historical Traefik campaign is executed for this bounded follow-up.

## Limitations and residual risk

`abspath` and separator-prefix checks are lexical and do not resolve symlinks; this record makes no broader filesystem-isolation claim. A model-compatible pattern is insufficient to claim closure before actual candidate analysis. The 15 documented flow counterexamples, five qualified TLS findings and three deliberate wildcard findings remain outside this targeted three-alert change. Their continued presence is expected. Branch scan evidence and actual master alert state are distinct: master can mark absent results `Fixed` only after separately authorized integration and successful subsequent analysis. No claim of closing all 26 findings.

## Final diff and review status

Fresh independent review found no concrete bypass or legitimate-behavior regression in the three source/test files. It separately records the lexical-only containment assumption and claims no scanner pass. The coordinator reviewed native generated changes, confirmed inventory equality except one backend hash, observed passing local checks and clean whitespace; exact-head hosted results remain pending until the actual branch scan and PR are checked. No secrets, matched secret values, credentials, raw request/response bodies or complete logs are included.
