# Change Record: 20261114-01-cross-connector-review-regressions

**Language:** English | [Deutsch](20261114-01-cross-connector-review-regressions.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261114-01-cross-connector-review-regressions |
| UTC date | 2026-11-14 |
| Framework base revision | `6e2c433a9c4e63df0634442b2bb63f151917dac5` |
| Issue or pull request | [Framework PR 171](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/171) |

## Motivation and problem statement

Framework regressions must distinguish the corrected connector behaviors from source-only assertions and preserve honest source/host evidence boundaries.

## Affected components and security boundaries

Framework owns reusable tests/checker/runner; Parent owns product behavior. MRTS remains unchanged. The ten logical profiles are Apache native; NGINX native; HAProxy HTX; HAProxy SPOE/SPOP with native response companion; Envoy ext_proc; Envoy ext_authz with response companion; Traefik native middleware; Traefik forwardAuth with response companion; Lighttpd Stock sidecar; and Lighttpd patched native.

## Acceptance criteria

Response observation cannot impose a duplicate body limit; append Reject and EOS rule outcomes remain distinct; optional event failure cannot relax native enforcement or Strict abort. Runner rejection precedes execution, admitted argv remains literal, path grammar is tested, and failures clean up child processes. Tests and documentation must preserve the Parent/Framework ownership boundary and describe outstanding evidence explicitly.

## Alternatives considered

Source-pattern-only checks cannot prove causal append/EOS behavior or executable runner boundaries. Existing compiled product seams, native Engine fixtures and actual helper/process tests were extended instead of weakening admission or substituting a fixed system binary.

## Implementation decision

Common response observation uses saturating `uint64_t` counters at `UINT64_MAX`, without a second response inspection/delivery limit at `SIZE_MAX` or 4 GiB. Native API chunk lengths remain `size_t`; request overflow guards and separate memory, storage, chunk, frame and timeout controls remain. Runtime body-progress ABI consumers must rebuild against matching headers. Go response-summary byte fields remain `int64` and saturate at `MaxInt64`; `uint64` chunk counters saturate at `MaxUint64`. Both continue to the actual Engine/EOS path after saturation and preserve request and transport guards.

A native response-body Reject requires a valid accepted append before EOS plus actual intervention metadata: RESPONSE_BODY, disruptive 1, status 403, raw redirect URL NULL and no rule ID. Exact English log prose and the SDK logged-ID list are not causal authority. A genuine EOS rule intervention stays distinct; malformed/API/technical errors remain errors. Apache post-commit native Reject seals/aborts in every mode and preserves native status/first cause without a second response.

The optional Safe event exception is restricted to healthy, completed, committed phase 4 with an actual causally correlated rule intervention. It never covers native body-limit Reject, API/processing/native-audit errors or an earlier mandatory event failure. Event-only sink/short-write/serialization/allocation failure warns without changing response or required native audit/cleanup. Strict abort remains effective even if event emission fails. Lighttpd patched-native Reject is terminal in every mode; Common rejects body-limit LOG_ONLY host actions in phase 4 as well as phase 2. Traefik preserves physical Wire-DENY 403 before commit and reports a typed native-Reject error after commit; Envoy preserves the typed error before generic Deny/Continue can discard its cause.

Runner admission now returns typed validated binary/module/output values consumed at execution sinks. Literal argv handling preserves legitimate admitted binary names; NGINX and SecAuditLog paths have separate grammar-aware representations and explicit rejection of unsupported syntax. PID handling accepts positive integers before process-file access. Cohesive helpers reduce the main function complexity while preserving source/manifest admission, credentials, worker, audit and cleanup assertions. NGINX constness, callback address, redundant cast/semicolon and cohesive context-member changes address the reported local Sonar rule causes without suppressions or gate changes.

## Changed files and tests

Changed reusable fixtures and selections under `connector_suite/modsecurity_connector_tests`: native intervention normalization and Engine limit C fixtures; companion transport/runtime fixtures; Apache lifecycle, native-limit and event-sink tests; HAProxy native/host/physical-event/Engine-limit tests; NGINX logging/error-page tests; runtime event/observation, companion-counter and rule-ID tests; runner and its new behavioral regression file. The NGINX adoption checker and its complete mutation suite preserve evidence checks after context grouping. Runner tests exercise real path admission, symlink/ownership/manifest rejection before execution, literal process argv, malformed PID rejection, configuration grammar boundaries, scenario orchestration and child cleanup. Final Envoy/Traefik response-observation and Lighttpd/Traefik/Envoy native-Reject regressions exercise actual Engine/EOS paths and physical bridge fixtures, preserving request overflow guards and distinguishing precommit denial from postcommit errors.

The CI compatibility follow-up changes `connector_suite/modsecurity_connector_tests/test_haproxy_binding_refactor.py`: its C stub accepts the five intervention arguments and rejects nonzero response append/EOS context in the one-shot request evaluator. Positive rule-ID cases use complete Engine metadata; bare bracket IDs and `id:42` remain negative provenance controls, alongside malformed and out-of-range metadata. Product, Parent pin, CI and gates are unchanged.

## Commands and results

The following coordinator-observed runs exited 0. They are separate selections and must not be added as unique end-to-end cases. Define `P=<parent-root>`, `F=<framework-root>`, `E=<evidence-root>`, `PY=<framework-python>` and `SDK` as the actual cached ModSecurity 3.0.17 prefix used by the coordinator. Path aliases represent the actual external checkout, evidence and interpreter locations used; machine-specific prefixes are not versioned here. The prefix below is `rtk bypass env CONNECTOR_ROOT=$P CONNECTOR_REVISION=b50b3d4c0e051c63df649fd15d4a2442c8df14b3 TEST_ROOT=$F PYTHONPATH=$F:$F/connector_suite ON_DEMAND_TESTS=1 PYTHONDONTWRITEBYTECODE=1 RUNNER_TEMP=$E/sonar-followup`.

| Command after prefix | Observed result |
| --- | --- |
| `$PY -m unittest -v modsecurity_connector_tests.test_runtime_response_observation_policy modsecurity_connector_tests.test_runtime_event_sink_failures modsecurity_connector_tests.test_nginx_fzipi_runner modsecurity_connector_tests.test_response_companion_counters modsecurity_connector_tests.test_rule_id_metadata` | 48 methods passed; coordinator terminal run 4961, exit 0. |
| `MODSECURITY_PREFIX=$SDK $PY -m unittest -v modsecurity_connector_tests.test_engine_response_limits.EngineResponseLimits.test_boundaries_actions_chunking_and_modes modsecurity_connector_tests.test_engine_response_limits.EngineResponseLimits.test_native_transaction_companion_serialization_and_phase_contracts modsecurity_connector_tests.test_engine_response_limits.EngineResponseLimits.test_engine_partial_prefix_excludes_marker_after_limit modsecurity_connector_tests.test_engine_response_limits.EngineResponseLimits.test_marker_after_old_one_megabyte_connector_default` | 4 methods passed against Engine 3.0.17: 72 variants, native companion, 3 partial-prefix and 6 old-1-MiB cases; terminal run 6298, exit 0. |
| `$PY -m unittest -v modsecurity_connector_tests.test_nginx_common_adoption` | 120 checker/mutation tests passed; terminal run 8192, exit 0. |

The Engine row uses the same environment with the additional `MODSECURITY_PREFIX` assignment before the interpreter. From `P`: `rtk make check-common-helpers ON_DEMAND_TESTS=1 FRAMEWORK_ROOT=$F PYTHON=$PY BUILD_ROOT=$E/sonar-followup/common-helpers` passed (terminal run 32751, exit 0); `rtk make check-nginx-common-adoption FRAMEWORK_ROOT=$F PYTHON=$PY` passed (terminal run 98654, exit 0). `rtk make check-bilingual-docs check-doc-links FRAMEWORK_ROOT=$F PYTHON=$PY` passed before these new records: bilingual checks, path references and links.

Selected worker evidence under `E/sonar-followup`: `nginx/verification.json` records 66 NGINX methods and `check-nginx-c17` passing; `apache-haproxy/review-validation.json` records 80 Apache/HAProxy methods plus C17 checks passing. The coordinator also reports the later 31-method HTX selection passing. The older receipts identify their own source bytes and do not certify changes made afterward. The unchanged-base classifier negative control compiled with C17 strict warnings and exited 1 on four assertions for changed/empty/missing prose; the corrected path passes the fresh regression selection. Exact-source Secrets checks passed for the selected files read by this record author; they do not certify code quality.

Final Go observation regressions passed using `rtk bypass make -C connectors/envoy test-envoy-ext-proc FRAMEWORK_ROOT=$F PYTHON=$PY` (8 package results) and `rtk bypass make -C connectors/traefik test-native-middleware FRAMEWORK_ROOT=$F PYTHON=$PY` (1 package). Both used `ON_DEMAND_TESTS=1 GOWORK=off GOTOOLCHAIN=local GOPROXY=off`, external `GOMODCACHE`/`GOCACHE` and task-owned temporary paths. New actual Engine/EOS-path boundary cases fail with the original counters, including physical original-source Go overlays, and pass with response saturation. These default targets exclude libmodsecurity-tag integration. Lighttpd/Common host-action tests passed 19 methods, including OFF/SAFE/STRICT across no/header/body commit and guard-removal negative controls. The final combined bridge/runtime selection is recorded separately below.

The coordinator freshly reran the complete combined selection on the final local sources: `$PY -m unittest -v modsecurity_connector_tests.test_runtime_host_action_validation modsecurity_connector_tests.test_lighttpd_i10_adapter_errors modsecurity_connector_tests.test_traefik_i10_dispatcher modsecurity_connector_tests.test_envoy_bridge_failures modsecurity_connector_tests.test_runtime_event_sink_failures modsecurity_connector_tests.test_runtime_response_observation_policy`. Same prefix as the 48-method run except `RUNNER_TEMP=$E/sonar-followup/runtime`, working directory `P`, without additional `FRAMEWORK_ROOT` (helpers resolve `TEST_ROOT`). All 63 methods passed in 48.897 s; terminal run 31658, observed exit 0. This supersedes the earlier 62/63 run after correcting its single Traefik precommit test oracle; the separate 2-method retest also passed.

Historically, nine NGINX H1 native scenarios passed at Parent `4b87783a62b13bbb5f4c60809c779379e487345c` with Framework `6e2c433a9c4e63df0634442b2bb63f151917dac5`. This dated earlier scope is not current-followup qualification. The prior record also describes its own separate earlier source identity; its receipt is not reassigned to this followup.

The follow-up command `rtk bypass env CONNECTOR_ROOT=$P CONNECTOR_REVISION=d0bc8b51c8a07582b4554574c2fb55aa30ca88e1 TEST_ROOT=$F PYTHONPATH=$F:$F/connector_suite ON_DEMAND_TESTS=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR=$E/sonar-followup/apache-haproxy RUNNER_TEMP=$E/sonar-followup/apache-haproxy $PY -m unittest -v modsecurity_connector_tests.test_haproxy_binding_refactor modsecurity_connector_tests.test_haproxy_native_results modsecurity_connector_tests.test_runtime_event_sink_failures` passed all 25 methods: 8 binding-refactor, 8 native-result and 9 Runtime-event-sink methods (exit 0). The local pre-fix binding-refactor fixture reproduced the CI three-versus-five-argument compilation failure; the corrected fixture compiles with strict C17 warnings. The native-result selection retains actual append/EOS and terminal-error checks; the Runtime selection confirms the updated helper extraction resolves the pinned fixture failure. These are compiled-seam results, not a fresh host-runtime or current-head CI pass. Evidence: `E/sonar-followup/apache-haproxy/ci-followup-before.log` and `E/sonar-followup/apache-haproxy/ci-followup-after.log`.

## Security impact

These changes preserve enforcement and distinguish native limits, genuine rule decisions and technical failures. The runner review did not demonstrate four command/path-injection vulnerabilities in the pre-existing admitted argv flow; the fixes make admission-to-sink authority explicit and correct a reproduced configuration-path serialization defect. Source/binary admission, canonical-path, symlink, ownership, single-link, manifest, worker, audit and cleanup controls remain. No suppression, gate weakening, dependency installation or MRTS change is part of this followup.

## Documentation and runtime evidence

Parent EN/DE phase, ABI and profile documentation is coordinated in `CR-20261114-cross-connector-review-followup`. This Framework pair records reusable regression evidence. Fresh rebuilt native host execution and remote current-head Sonar analysis were not run at this record commit: native artifact admission requires the clean product commit, and CI/Sonar delivery analysis requires push. Subsequent receipts are tracked on [Parent PR 448](https://github.com/Easton97-Jens/ModSecurity-conector/pull/448) and [Framework PR 171](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/171). Earlier native results belong to their original source identities. Compiled seams and real Engine fixtures do not establish all-host runtime behavior. No native 32-bit execution, all-profile host matrix, all-Go validation or new Sonar-zero claim is made. These omitted delivery checks remain required; this record does not exempt them.

## Checks not run

Fresh native execution and post-commit/push CI/Sonar analysis remain required; reasons and tracking PRs are documented under “Documentation and runtime evidence”.

## Limitations and residual risk

The source/host evidence boundaries documented above remain. Selected regressions replace neither a host matrix nor native 32-bit execution; final delivery checks are still required.

## Final diff and review status

Record pair prepared for coordinator review; no commit, push or merge by this author. The native Parent scaffold succeeded; Framework uses its documented paired-template alternative because no Framework scaffold generator was found. Both new pairs passed their repository-specific scoped structural contracts, EN/DE inline technical-token parity, reciprocal companion-link and whitespace checks, and exact-file Secrets scans. Final source review, exact-head evidence reconciliation and PR delivery remain with the coordinator.

### Second-wave review and verification

The second wave addresses six Parent maintenance findings in private Common/Apache/HAProxy helpers and callback-address spelling, and thirteen Framework maintenance findings through cohesive fixture helpers, flat case matrices and exception checks scoped to one call. All 97 C-fixture assertions and existing Go Fatal assertions are preserved. Stale HAProxy five-argument/request/bare-ID controls and five Runtime extractor lists were updated for the six-argument contract and const mock boundaries. Independent review of the four changed Parent source files reported no findings; the phase-2/phase-4 host-action guard remains byte-identical to `d0bc8b51c8a07582b4554574c2fb55aa30ca88e1`.

Coordinator-observed fresh checks passed: 75 methods in 51.012 s (terminal run 65440), using the eight-module command below; runner 16 methods in 1.099 s (terminal run 21810, `$PY -m unittest -v modsecurity_connector_tests.test_nginx_fzipi_runner`); parser/Apache/HAProxy selection 89 methods in 27.748 s, Apache/HAProxy C17 and HTX contract checks; repeated native Go targets `make -C connectors/envoy test-envoy-ext-proc` (8 packages) and `make -C connectors/traefik test-native-middleware` (1 package), with explicit Framework/interpreter selection as above. These selections overlap and are not summed. The 75-method command uses the admitted explicit checkout environment with `CONNECTOR_REVISION=d0bc8b51c8a07582b4554574c2fb55aa30ca88e1` and `RUNNER_TEMP=$E/sonar-followup/runtime`:

`$PY -m unittest -v modsecurity_connector_tests.test_runtime_host_action_validation modsecurity_connector_tests.test_lighttpd_i10_adapter_errors modsecurity_connector_tests.test_traefik_i10_dispatcher modsecurity_connector_tests.test_envoy_bridge_failures modsecurity_connector_tests.test_runtime_event_sink_failures modsecurity_connector_tests.test_runtime_response_observation_policy modsecurity_connector_tests.test_native_result_event_protocol modsecurity_connector_tests.test_i09_native_decision`

Dated first-wave evidence: nine native NGINX scenarios passed at Parent `d0bc8b51c8a07582b4554574c2fb55aa30ca88e1` with Framework `12678a1b464241a92b720cfba847df6c9d675770`. For that prior Parent head, [main Sonar workflow](https://github.com/Easton97-Jens/ModSecurity-conector/actions/runs/43597336656) succeeded (required quality-gate log at 13:02:07 UTC on 2026-11-14); [native Sonar workflow](https://github.com/Easton97-Jens/ModSecurity-conector/actions/runs/43597336733) succeeded for all 12 target jobs and SDK. The first Cloud analyses reported passing Parent/Framework gates with respectively 6/13 maintenance findings, zero security findings and zero hotspots; Framework had seven green CI workflows. Those dated results do not qualify the forthcoming refactor head or establish zero findings overall. Fresh clean-head native execution and CI/Sonar results remain required and tracked on Parent PR 448 / Framework PR 171; no delivery check is waived.

### Final native-audit completion check

Final review found that the runner parsed the audit after shutdown but discarded that snapshot, so a late duplicate could escape the earlier per-request ownership check. The new `verify_final_audit` reads the final audit once, revalidates every scenario through `validate_audit_result`, and refreshes receipt counts/rule IDs from those final records. A rejected case records its observed count and failed status. Admission, artifact/source identity, credentials, managed shutdown and listener checks remain intact.

Before the runner change, three new tests against the unchanged `cf5bb83ab23634ba2b1712cfd8bcf58bb5d5f45a` runner failed with eight assertions: six late duplicate scenarios, a late original-status change and stale receipt metadata (exit 1, 0.056 s). After the fix, `rtk bypass env ... $PY -m unittest -v modsecurity_connector_tests.test_nginx_fzipi_runner` passed all 19 methods in 1.342 s (terminal run 48284, exit 0), using the explicit `P`/`F`/`PY` checkout environment with `CONNECTOR_REVISION=43baefa2d3a6ce66876aca1a2cd0d7b50e2a412a`. These are real parser/validator tests with controlled HTTP/storage/socket I/O; each exception assertion contains one invocation. The native fixture module and artifact admission contract are unchanged. Fresh execution of all nine native scenarios with the newly committed Framework identity and subsequent CI remain required before delivery; this unit result does not claim them.
