# NGINX mapper status fixture dependency repair

**Language:** English | [Deutsch](20261102-01-nginx-mapper-status-fixture.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261102-01-nginx-mapper-status-fixture |
| UTC date | 2026-11-02 |
| Framework base revision | `bc08ee7ca413012da189902b8b9c61c98151e76b` |
| Issue or pull request | Framework PR #153; external Connector PR #348; see the separately authorized integration checkpoint below |

## Motivation and problem statement

The real request mapper now calls `ngx_http_modsecurity_http3_authority`.
The standalone fixture extracted the mapper but omitted this header-defined
dependency. Before this repair, C17 compilation failed with an implicit
declaration and `incompatible types when assigning to type ‘ngx_str_t’ from type ‘int’`;
setUpClass failed and zero methods ran. Reproduction uses the current Framework
base above and external Connector input `97dfcaddb698d5b95c3f78531eb81803699ffbe1`.

## Affected components and security boundaries

Only Framework test construction and native generated descriptions change.
No Connector product code, runtime decision, dependency version or MRTS file
changes. Preserve genuine allocation/internal-error failures and strict warnings;
a compiler setup failure must not masquerade as executed passing tests.

## Acceptance criteria

The existing five methods compile with `-std=c17 -Wall -Wextra -Werror`,
execute without skips, and retain all assertions. Actual valid mapping remains
accepted, both pointer faults and eight pool failures remain HTTP500, header
overflow remains HTTP400, and the zero-limit behavior remains accepted.
Preserve default selection and independently review actual-helper extraction.

## Alternatives considered

Do not stub authority, duplicate its implementation, remove `-Werror`, change
product code, remove negative cases or select away the failing fixture.
Extract the actual header bodies through the existing source extractor.

## Implementation decision

Extract the real `ngx_http_modsecurity_next_header` before its real authority
caller, preserving the `static ngx_inline ngx_table_elt_t *` and
`static ngx_inline ngx_str_t` signatures omitted by the line-based extractor.
Supply host fields, null-string/inline/version macros and the host
case-insensitive comparison primitive. The unchanged HTTP/1.1 fixture request
initializes the added host fields to NULL. HTTP/3 defaults enabled for compilation;
explicit `CC='cc -DNGX_HTTP_V3=0'` verifies the existing disabled branch too.
This is conditional fixture compilation, not a new protocol qualification test.

## Changed files and tests

Change only `connector_suite/modsecurity_connector_tests/test_nginx_request_mapper_status.py`,
the native selection archive, migration baseline and test map, plus this paired
record. No new methods/selectors/cases. All five method ASTs and `probe` are
byte-for-byte AST-equivalent to the base. Fourteen probes and ten named subtests
remain: 1 valid, 2 pointer faults, 8 allocation failures, 2 header boundaries,
1 zero-limit probe. Existing inventory bytes are unchanged: 100/80 default
cases/executions, 2586/1140 on-demand, 528 fixed Framework source bindings,
235 revision-bound Product paths and 1993 preserved baseline IDs.
The native migration generator also refreshes existing external Envoy Makefile
caller line locations for the explicitly selected Connector revision; no selector
or product source is changed.

## Commands and results

Run ID: `nginx-mapper-fixture-20261102`. Use RTK and Framework-owned
`$FRAMEWORK_PYTHON` (observed Python3.14.4;
hosted Python is separately pinned by the repository). Compiler: Ubuntu cc15.2.0.
Each Python invocation uses `rtk bypass env`, the explicit context below, then
that interpreter and the command tail in the table. Before reproduction used
RUNNER_TEMP ending `/before`; after checks use `/after`.

```text
ON_DEMAND_TESTS=1
TEST_ROOT=$FRAMEWORK_ROOT
FRAMEWORK_ROOT=<explicit selected Framework checkout>
FRAMEWORK_REVISION=bc08ee7ca413012da189902b8b9c61c98151e76b
CONNECTOR_ROOT=<explicit selected Connector checkout>
CONNECTOR_REVISION=97dfcaddb698d5b95c3f78531eb81803699ffbe1
CONNECTOR_TEST_PROFILE=protocol-integrity
CONNECTOR_TEST_OUTPUT_ROOT=$EXTERNAL_RUN
RUNNER_TEMP=$EXTERNAL_RUN/after
TMPDIR=$EXTERNAL_TMP
PYTHONPATH=$FRAMEWORK_ROOT:$FRAMEWORK_ROOT/connector_suite
PYTHONDONTWRITEBYTECODE=1
PYTHONNOUSERSITE=1
```

| Command tail / procedure | Exit code | Observed result |
| --- | --- | --- |
| `-m unittest -v modsecurity_connector_tests.test_nginx_request_mapper_status` before repair | 1 | Original authority declaration/type compile errors; Ran0tests |
| Same module after repair | 0 | All5methods PASS |
| Native `python_child` for each of the five exact method selectors, with `CC='cc -DNGX_HTTP_V3=1'` and then `=0` | 0 each | Each configuration:5methods,10subtests,0skips,0expected failures;14probes |
| `-m unittest -v` with extraction, header iteration and four focused mapper-adoption selectors | 0 | All11methods PASS;28.336s |
| `connector_suite/modsecurity_connector_ci/tools/update-inventory-bindings.py --apply`, then `--check` | 0 each | Existing bindings VERIFIED; no inventory digest slots changed |
| `connector_suite/modsecurity_connector_ci/tools/update-test-archive.py`, then `--check` | 0 each | Archive regenerated and verified |
| `connector_suite/modsecurity_connector_ci/tools/build-migration-map.py` | 0 | Native baseline/map regenerated; counts and1993IDs preserved |
| `-m modsecurity_test_framework.connector --check` | 0 | Admission only:100active,2586on-demand,limit100; not suite execution |
| AST comparison of all5methods and probe; inventory bytes versus base | 0 | Unchanged |
| `rtk bypass git diff --check` | 0 | No whitespace errors |

Exact expanded per-method commands/results are retained in
`nginx-mapper-fixture-20261102/after/five-method-results.json`.
The native observer invocation is `-c 'import sys; from modsecurity_connector_ci.lib.active_test_inventory import python_child; raise SystemExit(python_child(sys.argv[1]))'`
followed by `modsecurity_connector_tests.test_nginx_request_mapper_status.NginxRequestMapperStatusTests.`
and each of the five existing method names. Its observed subcase counts in the
requested order are0/2/8/0/0. Adjacent selectors:
`test_c_source_contract.CSourceContractTests`,
`test_nginx_header_iteration_contract.NginxHeaderIterationContractTest` and
`test_nginx_common_adoption.NginxCommonAdoptionCheckerTests` methods
`test_current_helper_aware_contract_is_accepted`,
`test_mapper_typed_error_status_cannot_be_success_or_client_default`,
`test_mapper_client_header_limit_cannot_be_removed_or_unbounded`,
`test_mapper_client_limit_counts_the_synthetic_authority_host`;
all use module prefix `modsecurity_connector_tests.`.

## Security impact

Test-integrity repair, not remediation of a validated product vulnerability.
No success stub, warning suppression, selection exemption, collector exception,
gate weakening or manual digest editing. Existing error controls remain.

## Documentation and runtime evidence

This English/German Change Record is the only maintained prose change.
These results establish standalone C compilation and existing focused contracts,
not hosted NGINX/TLS/H2/H3 behavior. No live host campaign or MRTS execution.

## Checks not run

Full default/historical suites and H2/H3 qualification are outside this bounded
task. Fresh documentation/secrets checks, final committed-pair validation and
new-head hosted CI/CodeQL/Sonar remain delivery steps at this preparation point;
old-head greens are not evidence for the new commits.

## Limitations and residual risk

The Framework fix still needs its own published exact commit and independent
hosted checks. Connector #348 may provisionally pin that published PR SHA under
its dependent-PR contract; Framework must be integrated before eventual Connector
merge. No merge is authorized here. External Connector and MRTS ownership remain
separate; local uninitialized MRTS must not be reported as verified provenance.

## Final diff and review status

Independent read-only fixture review found correct real bodies/signatures/order
and no assertion/probe changes. Final scoped staged/generated/doc/secrets review
and delivery evidence are recorded separately when observed. No credentials,
full inherited environment, request bodies or unrestricted raw logs are included.

### Final local preparation checks

Native migration-map `--check` passed (exit0), preserving the same counts/IDs.
`make check-documentation check-canonical-common-pins check-canonical-python-pins check-canonical-workflow-pins check-canonical-crs-contract-pins`
passed with explicit Framework root/interpreter and external BUILD_ROOT/OUTPUT_ROOT:
358bilingual pairs,2165scanned paths,0old paths, record/link checks and all four
canonical pin checks. The initial documentation attempt rejected local absolute
developer paths in this new pair (exit2); portable examples corrected those
records without changing the checker. Exact expanded local paths remain only
in the approved external receipts.
The staged diff Secret scan through existing Gitleaks `stdin --redact=100`
passed (exit0,no leaks); whitespace and syntax checks passed.
Independent EN/DE review confirmed parity. The initially retained running-session
receipt for one completed method was supplemented with its observed terminal
exit0; no rerun or fabricated status. Hosted checks and the final Parent pin
remain separate delivery evidence.

### Separately authorized integration checkpoint

The preceding preparation results and no-merge restriction belong to the
original repair task. The current user separately authorizes regular integration
of Framework #153, then repinning and integrating Connector #348, only after
fresh exact-head checks. Squash is the only enabled repository merge method.
No direct master push, force push, administrative bypass, weakened check, MRTS
modification or separate Connector #436 integration is authorized.

Framework master advanced to `2a723ef05c85f8eaa85299826a9ec8f41c373736`
(#152). Its independent Traefik/Lighttpd CodeQL corrections and Lighttpd source
binding are preserved through a normal additive base merge. The only content
conflict was the generated migration baseline; the archive was regenerated too.
Native `update-inventory-bindings.py --check` passed without an inventory edit.
Native archive/map generators completed: 100/80 standard cases/executions,
2586/1140 on-demand and 1993 preserved IDs. No manual digest or selector change.
The fixture and all five method/probe bodies remain unchanged from the fix.

Integration run ID: `nginx-mapper-integration-20261102`. Use the Framework-owned
interpreter and explicit external context above, selecting external Connector
source `b93f2fb2113824e200b41a87ad90918e1eb98e8f` and freshly resolved revisions.
Fresh committed-head methods in both V3 configurations, adjacent contracts,
generators/archive/bindings, documentation/secrets, CI/CodeQL/Sonar including
issues/hotspots, repository rules and post-merge tree/master checks remain
mandatory. Observed receipts and exact final/merge SHAs are retained externally
and in PR metadata. No old PASS is transferred to a new revision or live protocol
qualification. MRTS is unchanged; no branch/worktree/evidence deletion requested.

Fresh preparation checks after base resolution passed: all five methods in both
V3 modes (14 observed probe returns and ten named subcases per mode; no skips),
eleven adjacent methods (28.133s), generator check modes, 100-case admission,
documentation (360 language pairs, 2167 paths), four canonical pin checks and
redacted Gitleaks on the six-path final diff. An initial record check rejected
the new level-two checkpoint heading; changing only its heading level to the
existing subheading convention restored the unchanged checker. Exact committed
heads and post-merge gates still require their separate fresh delivery receipts.
