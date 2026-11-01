# Change record: Framework CodeQL boundaries

**Language:** English | [Deutsch](20261101-04-codeql-boundaries.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261101-04-codeql-boundaries |
| UTC date | 2026-11-01 |
| Framework base revision | `5ef57603a4933f18c988f1f9f32b93f478182440` |
| Integration base (normal merge into task branch) | `b85280278310f4034af78149ac13671438965c7b` (#150 independently merged; source changes preserved) |
| Issue or pull request | New remediation PR from `codex/framework-codeql-remediation-20261101` pending; #147 already merged, independent #150 untouched |

## Motivation and problem statement

26 open GitHub CodeQL alerts (#3–#28) require individual flow assessment. Backend path traversal and unchecked header reflection are confirmed; real wildcard negative tests require demonstrated isolation. Scanner configuration, suppressions and alert status remain unchanged.

## Affected components and security boundaries

Framework-owned Traefik test-backend artifacts, Lighttpd probe headers, and NGINX/Lighttpd kernel negative tests. Parent gitlink remains unchanged; MRTS remains `default_read_only`. No connector product qualification.

## Acceptance criteria

Validate the complete request target before body/file/receipt access; preserve all 16 existing cases. Reproduce the original attack on base and recheck the fix and alternative bypasses. Reject header controls; preserve supervisor rejection of valid reflection. Execute wildcard binds only in a demonstrated private network namespace. Reconcile all 26 IDs separately, regular CI registration, native generators, EN/DE records and final checks.

## Alternatives considered

A 16-character limit breaks existing cases (maximum 23). Checking only self.path loses normalized leading slashes or whitespace. Decoding, truncation or sanitization is ambiguous. Wildcard mocks remove kernel counterevidence; global scanner exceptions are unjustified.

## Implementation decision

The raw request line and do_POST independently full-match the entire target against `/[a-z0-9-]{1,23}`; rejection is 400, including before 100-continue. The bounded grammar is not a finite case allowlist. Header reflection accepts only `[A-Za-z0-9._:-]{1,128}`. A shared namespace helper requires different namespace identity and exactly `lo`; missing prerequisites produce an explicit BLOCKED skip before any wildcard bind.

### Individual alert assessment

Lines refer to base or the named functions; edits may shift lines. Each row identifies source, transformation, sink, guard/reachability and verdict/counterevidence. A local verdict does not close a GitHub alert.

| ID | Source → transformation → sink | Guard, verdict and evidence |
| --- | --- | --- |
| #3 | `ci/checks/security/check-security-data-flow-cases.py:30–35` → boolean match `:72` → label diagnostic `:70,:122` | Only fixed pattern labels reach stderr; matched values are not interpolated. |
| #4 | `connector_suite/adapters/traefik/scripts/runtime_smoke.py:635–645` → fixed socket name `:686` → YAML `socketPath:448` → write `:738` | Private directory/socket location is serialized, not credential contents. |
| #5 | `connector_suite/modsecurity_connector_tests/test_go_version_contract.py:32–56` → static workflow text → temporary write `:60–63` | No GitHub-expression evaluation or credential lookup; fixture only. |
| #6 | `connector_suite/modsecurity_connector_tests/test_python_version_contract.py:182–190` → checked-in workflow text → temporary write `:187` → `parse_jobs:188` | Public interpreter-verification program, no secret resolution. |
| #7 | `connector_suite/modsecurity_connector_ci/runtime/lifecycle/i12/envoy/test_review_runs.py:137` → inert receipt fixture `:140–143` → `review_runs.client_summary:206`, `event_summary:399` | Closed output fields and enum filtering exclude synthetic marker; assertions :147–150. |
| #8 | `connector_suite/modsecurity_connector_tests/test_update_go_components.py:64–90` → `baseline_go_sum()` → fixture write `:207` | Fixed net/sys/text/grpc tokens or public Go integrity sums; no credential. |
| #9 | `connector_suite/modsecurity_connector_tests/test_update_go_components.py:64–90` → `baseline_go_sum()` → fixture write `:479` | Same public integrity-fixture provenance; no credential. |
| #10 | `connector_suite/modsecurity_connector_tests/test_update_go_components.py:64–90` → `baseline_go_sum()` → fixture write `:489` | Same public integrity-fixture provenance; no credential. |
| #11 | `connector_suite/modsecurity_connector_tests/test_update_go_components.py:64–90` → `baseline_go_sum()` → fixture write `:516` | Same public integrity-fixture provenance; no credential. |
| #12 | `connector_suite/modsecurity_connector_ci/checks/common/check-python-version-contract.py:2093` → `test_trusted_lighttpd_namespace_dispatch_workflow.py:82–105` forbidden-marker tuple → diagnostic `:110` → checker output | Literal secrets. marker is inspected, not resolved; fixed diagnostic. |
| #13 | `connector_suite/modsecurity_connector_ci/checks/common/check-python-version-contract.py:2093` → same fixed marker diagnostic → checker stderr `:2248` | No secret value enters stderr; source is the literal forbidden-marker tuple. |
| #14 | `connector_suite/modsecurity_connector_ci/runtime/common/hostruntime_preflight.py:103–122` → distinct `(Path, reason)` → unpack `:532` → reason-only `_check:534` → bounded JSON `:828` | Reported flow conflates tuple elements; output contains fixed reason/status codes. |
| #15 | `connector_suite/modsecurity_connector_ci/runtime/broker/nginx_root_broker.py:1884` → validated build root → bundle `:2315` → manifest check `:2371` → directory `:2376` → print `:5046` | Sink prints a directory Path, not credentials or file contents. |
| #16 | `connector_suite/modsecurity_connector_tests/test_trusted_lighttpd_runtime_supervisor.py` request header → parsed transaction ID → `send_header` | Confirmed folded/SOH/DEL output before fix. Full ASCII token [A-Za-z0-9._:-]{1,128} now rejects with 400 before reflection; real-loopback red/green. |
| #17 | `connector_suite/adapters/haproxy/harness/i12_companion_host.py:176` default verified client → fixed loopback → `wrap_socket:182`, localhost | No later weakening; CERT_REQUIRED and hostname check. Current-host legacy TLS rejected; qualified counterevidence only (TLS evidence below). |
| #18 | `connector_suite/adapters/haproxy/harness/i12_native_sequences.py:129` default verified client → loopback `connect:80–82` with fixed hostname | No later weakening; CERT_REQUIRED and hostname check. Current-host legacy TLS rejected; qualified counterevidence only. |
| #19 | `connector_suite/modsecurity_connector_tests/test_envoy_transport_hardening_contract.py:54` default server context → certificate → TLS socket `:56` | No later weakening; current-host legacy TLS rejected. Server CERT_NONE is not a client verification claim; qualified counterevidence. |
| #20 | `connector_suite/modsecurity_connector_tests/test_haproxy_htx_transaction_id.py:120` default server context → certificate `:121` → TLS socket `:122` | No later weakening; current-host legacy TLS rejected; qualified counterevidence only. |
| #21 | `connector_suite/modsecurity_connector_tests/test_haproxy_i12_companion_host.py:36` default server context → certificate `:37` → accepted-socket wrap `:41` | No later weakening; current-host legacy TLS rejected; qualified counterevidence only. |
| #22 | `connector_suite/adapters/lighttpd/tests/test_backend_close_harness_contract.py` IPv6-wildcard negative test → real :: bind → Linux no-listener guard | Same namespace/interface guard; both IPV6_V6ONLY settings and post-close absence assertions retained; isolated test passes. |
| #23 | `connector_suite/modsecurity_connector_tests/test_nginx_port_cleanup_probe.py` wildcard-listener negative test → real 0.0.0.0 bind → cleanup probe | Real wildcard behavior retained; verified different private network namespace with exactly lo now gates body. Isolated kernel test passes. |
| #24 | `connector_suite/modsecurity_connector_tests/test_nginx_port_cleanup_probe.py` dual-stack negative test → real :: bind → reuseaddr/cleanup probe | Same fail-closed namespace/interface guard; EADDRINUSE and post-close release assertions retained; isolated test passes. |
| #25 | `connector_suite/adapters/traefik/harness/i12_auth/backend.py` raw request target → self.path.lstrip('/') → request-body artifact write | Confirmed outside sentinel overwrite on base. Raw-target and do_POST full-match guards now precede body/file/receipt operations; original and alternative bypasses rejected. |
| #26 | `connector_suite/adapters/traefik/harness/i12_auth/backend.py` raw request target → same name → response-body artifact write | Same confirmed path boundary and common fix; separate request/response sentinels remain unchanged after fix. |
| #27 | `connector_suite/adapters/traefik/harness/i12_auth/auth_proxy.py:35` prefix/nonempty alphanumeric-hyphen validation → name `:37` → .sample.raw `:38` | No separators, dots or percent encoding admitted; no later decoding. Traversal unreachable through validated identity; nine bad suffix controls pass. |
| #28 | `connector_suite/adapters/traefik/harness/i12_auth/auth_proxy.py:35–37` validated unchanged name → .receipt.json `:55` | Same path confinement; validation follows bounded body read, so no pre-body guarantee is claimed. |


## Changed files and tests

- `connector_suite/adapters/traefik/harness/i12_auth/backend.py`: two target-boundary guards.
- `tests/security_regression/test_traefik_auth_backend.py`: five methods cover 57 invalid direct-handler targets, one real outside-sentinel scenario, 16 raw-parser targets, all 16 legitimate catalog cases, and four actual loopback requests. Assertions preserve request/response artifacts, receipt hashes, status/headers, p3-deny, p4-safe, 40,019-byte large response and observer-abort length behavior.
- `connector_suite/modsecurity_connector_tests/test_trusted_lighttpd_runtime_supervisor.py`: bounded reflected token and real malformed-header regression; existing valid-reflection rejection retained.
- `modsecurity_test_framework/private_network_test.py`, `connector_suite/modsecurity_connector_tests/test_nginx_port_cleanup_probe.py`, `connector_suite/adapters/lighttpd/tests/test_backend_close_harness_contract.py`: isolation helper, real wildcard regressions and same-namespace/foreign-interface fail-closed controls.
- `.github/workflows/ci-findings-regressions.yml` registers five backend methods plus seven explicit selectors in the existing workflow: twelve methods/104 expanded scenarios for these regressions, including eight new methods. Any skip fails; default selection remains 100 cases/80 executions. The CI launcher maps an outer user namespace's UID/GID 0 to the checkout owner's host UID/GID. Nested private network namespaces retain that filesystem identity and can read private runner directories; namespace and interface guards remain required before wildcard binds.
- Native bindings refresh one backend source. Archive regeneration adds eight new task methods. Ten host-preflight definitions and one sequence method from #147 are now present in the integration base through independently merged #150 and remain preserved. Optional migration map: 2,586 cases/1,140 executions, 528 fixed/235 dynamic; 1,993 IDs preserved.

## Commands and results

All local commands use RTK. `FRAMEWORK_ROOT` denotes the Framework worktree, `CONNECTOR_ROOT` the unchanged Parent, `PYTHON` the Framework-owned interpreter, and `RUN_ROOT` the external evidence root for run ID `framework-codeql-20261101`. Logs and temporary artifacts remain external.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk bypass env TMPDIR=${RUN_ROOT} PYTHONPATH=${FRAMEWORK_ROOT} PYTHONDONTWRITEBYTECODE=1 ${PYTHON} -m unittest discover -s tests/security_regression -p test_traefik_auth_backend.py -k literal_traversal -v` against unpatched backend | 1 | Expected red: controlled outside sentinel overwritten | framework-codeql-20261101; scoped reproduction, no host files targeted |
| Same backend discovery, without `-k literal_traversal`, patched source | 0 | Five methods pass; vector counts above | framework-codeql-20261101 |
| `rtk bypass env PYTHONPATH=.:connector_suite ON_DEMAND_TESTS=1 CONNECTOR_ROOT=${CONNECTOR_ROOT} CONNECTOR_REVISION=2abad408cae7e5a103d12a9a9e432129bfe0468f TEST_ROOT=${FRAMEWORK_ROOT} TMPDIR=${RUN_ROOT}/header-listeners PYTHONDONTWRITEBYTECODE=1 ${PYTHON} -m unittest -v modsecurity_connector_tests.test_trusted_lighttpd_runtime_supervisor modsecurity_connector_tests.test_nginx_port_cleanup_probe connector_suite.adapters.lighttpd.tests.test_backend_close_harness_contract` | 0 | 84 tests: 81 pass, three explicit BLOCKED skips in ordinary context | framework-codeql-20261101/header-listeners/focused-modules.log |
| Same environment, three wildcard selectors listed in `framework-codeql-20261101/header-listeners/result.md`, approved host execution | 0 | Three real isolated wildcard tests pass; no skips | framework-codeql-20261101/header-listeners/isolated-wildcards.log |
| Focused existing relay, Go-symlink, Envoy/HAProxy verified-TLS and normalized-output redaction controls | 0 for corrected scoped invocations | Eight existing controls pass; nine invalid auth suffixes and label-only diagnostic controls also pass | framework-codeql-20261101/counterevidence/focused-control-summary.json |
| Five exact SSL constructor probes; six bounded MemoryBIO handshake controls | 0 for completed probes | Actual settings recorded; TLS 1.0/1.1 rejected, TLS 1.2 controls succeed | framework-codeql-20261101/counterevidence/tls-context-probe.json; tls-legacy-handshake-probe.json |
| `rtk bypass git diff --check` after header/listener implementation | 0 | No whitespace errors | framework-codeql-20261101/header-listeners/result.md |
| `rtk make check-documentation check-canonical-common-pins check-canonical-python-pins check-canonical-workflow-pins check-canonical-crs-contract-pins PYTHON=${PYTHON} FRAMEWORK_ROOT=${FRAMEWORK_ROOT} BUILD_ROOT=${RUN_ROOT}/build` | 0 | Documentation, links, paths and records pass; 356 bilingual pairs | framework-codeql-20261101 |
| `rtk bypass actionlint .github/workflows/ci-findings-regressions.yml`; `rtk bypass ${PYTHON} ci/checks/security/check-ci-security-contract.py` | 0 | Existing workflow and CI security contract pass | framework-codeql-20261101 |
| `rtk bypass env TEST_ROOT=${FRAMEWORK_ROOT} CONNECTOR_ROOT=${CONNECTOR_ROOT} CONNECTOR_REVISION=2abad408cae7e5a103d12a9a9e432129bfe0468f PYTHONPATH=${FRAMEWORK_ROOT}:${FRAMEWORK_ROOT}/connector_suite PYTHONDONTWRITEBYTECODE=1 ${PYTHON} connector_suite/modsecurity_connector_ci/tools/update-inventory-bindings.py --apply`, then `--check`; `update-test-archive.py`, then `--check`; `build-migration-map.py`, then `--check` from the same tools directory with the same environment prefix | 0 | One source binding refreshed; native archive/map generation and freshness checks pass | framework-codeql-20261101 |
| `rtk bypass env PYTHONPATH=${FRAMEWORK_ROOT}:${FRAMEWORK_ROOT}/connector_suite TMPDIR=${RUN_ROOT} PYTHONDONTWRITEBYTECODE=1 ${PYTHON} -P -m modsecurity_test_framework.connector --connector-root ${CONNECTOR_ROOT} --connector-revision 2abad408cae7e5a103d12a9a9e432129bfe0468f --test-root ${FRAMEWORK_ROOT} --profile codeql-boundaries --output-root ${RUN_ROOT}/admission --check` | 0 | Admission only: 100 default/2,586 optional cases; no tests executed | framework-codeql-20261101 |
| Syntax compilation of six changed/new Python sources; exact seven-selector CI runner in approved host context | 0 | Syntax passes; seven methods pass without skips | framework-codeql-20261101 |
| Controlled private-directory import probe; exact seven-selector runner through the owner-mapped outer user namespace | 0 | Old root mapping fails the private-owner import; owner mapping passes both outer and nested imports. All seven actual methods pass without skips through the revised launcher | framework-codeql-20261101/namespace-import-probe.py; ci-selected-regressions.py |

The malformed-header test failed in all three subtests before the fix, then passed. Initial counterevidence attempts with missing connector context, an incorrect test-class selector, a pre-body assertion inappropriate to auth_proxy, and a minimum-version attribute assumption failed; corrected scoped checks above distinguish actual protection from assumptions. No failed attempt is counted as a pass.

## Security impact

Backend traversal could overwrite request and response artifacts outside the backend root. Common early target admission closes both sinks before body reads, including alternate normalized/raw targets and suffix/encoding variants. Header reflection previously leaked obsolete folding, SOH and DEL into the response; the observed folded case demonstrates continued header output, not arbitrary new-header injection. Invalid values now return 400 without reflection. Real wildcard tests preserve kernel behavior while restricting execution to verified isolated namespaces; unsupported contexts explicitly skip as BLOCKED.

The remaining alerts have the individually stated counterevidence; they are not blanket dismissals. For TLS #17–#21, actual Python **3.14.4** differs from pinned **3.14.8**. All five contexts report `minimum_version=MINIMUM_SUPPORTED`, `maximum_version=MAXIMUM_SUPPORTED`, OpenSSL **3.5.5**, security level **2**, and no explicit OP_NO_TLSv1/OP_NO_TLSv1_1 bits. Actual default client/server MemoryBIO handshakes reject TLS 1.0/1.1 with UNSUPPORTED_PROTOCOL and accept TLS 1.2 controls. This is current-host effective-policy evidence, not an observed TLSv1_2 minimum attribute or universal platform guarantee. [Official Python SSL documentation](https://docs.python.org/3.14/library/ssl.html#ssl.SSLContext) describes defaults and their platform dependence. No speculative TLS changes were made.

## Documentation and runtime evidence

This complete English/German Change Record pair records Framework scope. Evidence is bounded unit/parser/loopback/kernel/TLS counterevidence under the external run root. No connector host/profile qualification or promotion evidence was collected. Parent pin unchanged; MRTS read-only. No GitHub alert-status writes, merge, or PR #150 changes.

## Checks not run

At local commit, current-head hosted CI/CodeQL/Sonar remain pending; results belong in the PR description and external lifecycle evidence. PR #151's previous head 2615ebb failed the new isolation job because three nested namespace processes could not import modules from runner-owned private directories (job 124970023439). The owner-mapped launcher fixes the reproduced permission boundary; its exact seven selectors pass locally without skips and received independent review. Local Sonar scan-before-read was explicitly waived by the user after scanner CPU incompatibility; hosted scanning and Quality Gates remain required. Ordinary namespace execution was blocked by sandbox policy; approved host execution supplies the separate runtime evidence.

## Limitations and residual risk

Adjacent auth validation: 23 of 24 methods pass; a pre-existing migration error resolves the central manifest beneath Parent instead of Framework. `prepare.py` was restored unchanged. A broader path correction encounters the sealed Traefik profile and remains outside this fix; no sealed hashes were refreshed and no guards weakened.

Real wildcard literals remain visible to CodeQL; isolation evidence does not prove automatic alert closure. TLS evidence depends on the actual interpreter/OpenSSL policy and does not validate the pinned interpreter. CI execution must retain explicit BLOCKED semantics when namespaces are unavailable. The bounded backend grammar admits safe names beyond the current finite catalog. No raw bodies, credentials, matched secrets or full logs are copied into this record.

## Final diff and review status

Coordinated source review and independent review found no concrete remaining bypass of the changed boundaries. The EN/DE pair, all 26 ID rows, generated artifacts and whitespace were reconciled; documentation validation passes with 356 bilingual pairs. Nine independently reviewed methods pass with three explicit isolation-related skips; the seven required CI selectors separately pass in approved host context without skips. Hosted results remain pending until the actual PR head is checked. No alert-status writeback or merge.
