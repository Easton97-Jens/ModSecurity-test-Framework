# Protocol acceptance preparation change record

**Language:** English | [Deutsch](20261106-01-protocol-acceptance-preparation.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261106-01-protocol-acceptance-preparation |
| UTC date | 2026-11-06 |
| Framework base revision | `62b411e073551ef0fef22ab3d372e2489f2ae168` |
| Issue or pull request | [Framework PR #169](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/169); exact delivery SHAs and CI receipts retained externally |

## Motivation and problem statement

The existing native NGINX executor deliberately excludes reset/cancellation,
active multiplex isolation, modern streaming, h2c and Strict stream termination.
This change adds a separate executable preparation surface without altering
existing assertions or the 100-case default inventory. Full acceptance is NOT_RUN.

## Affected components and security boundaries

Framework owns the driver, libcurl client, rules, independent evidence reader,
unit controls and paired documentation. Native connector implementation,
capabilities and promotion remain Parent-owned. Parent gitlink is unchanged by
this Framework change; MRTS remains read-only. Retained evidence is private,
bounded, hash-bound and external to the checkout.

## Acceptance criteria

The separate 25-ID registry must execute real NGINX/client scenarios; require
independent request/connection/stream/transaction/rule witnesses, actual active
multiplexing, bytes before EOS and isolated resets; reject incomplete/mutated
bundles and writer errors; preserve the old executor/default inventory; and
retain truthful targeted host/cleanup evidence and bilingual documentation.
All 25 targeted host cases were evaluated; four failed mandatory H2 reset
expectations remain open. The preparation outcome is NOT_READY and does not
establish READY_FOR_FULL_ACCEPTANCE.

## Alternatives considered

Expanding the standard suite would violate the fixed inventory. Relabeling
missing required paths unsupported would conceal a preparation gap. Mock-only
checks cannot prove host semantics. The selected opt-in runner retains the
existing executor and adds independent host evidence with negative unit controls.

## Implementation decision

Use a source-built libcurl multi client and the existing same-context preflight
and owned-process cleanup. Start the peer before the target, observe distinct
active streams on one connection and retain native transaction cleanup. Keep
client debug/ALPN, server access and QUIC sources distinct. A paused upstream
barrier requires observed bytes before EOS. Strict native `abort_connection`
remains distinct from client-observed H2 `0x2`/H3 `0x102` stream resets with a
healthy peer/follow-up. Reopen the complete hashed bundle before PASS.

## Changed files and tests

- `connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-protocol-acceptance.py`
- `tests/runners/protocol_acceptance_contract.py`
- `tests/runners/protocol_acceptance_client.py` and `protocol_acceptance_client.c`
- `tests/rules/protocol-acceptance.conf`
- `tests/no_crs/test_protocol_acceptance_contract.py`
- `docs/protocol-acceptance-preparation.md` / `.de.md`, the existing native
  execution documentation pair's crosslinks, and this Change Record pair.

Contract tests cover all scenario expectations and corrupt independent
witnesses, source/hash/revision binding, h2c ALPN, bidirectional QUIC,
Strict stream reset identity, concurrent native transactions and upstream abort.

## Commands and results

Command context: `F` = Framework task worktree, `P` = selected Parent checkout,
`PYTHON` = selected existing Framework-owned interpreter.
Absolute host paths are retained in external task evidence, as required by the
repository documentation path contract.
The selected existing Framework environment uses Python 3.15.2; the configured
3.14.4 environment mismatch is recorded, with no dependency installation.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk bypass env ON_DEMAND_TESTS=1 PYTHONPATH="$F:$F/connector_suite" TEST_ROOT="$F" CONNECTOR_ROOT="$P" CONNECTOR_REVISION=a5f697c35acb5386d2037f91dfed10ad4b469cd9 "$PYTHON" -m unittest tests.no_crs.test_nginx_protocol_executor modsecurity_connector_tests.test_nginx_full_lifecycle_protocol_wiring -q` | 0 | 29 adjacent regression tests passed | Task execution evidence |
| `rtk make check-documentation PYTHON="$PYTHON"` | 0 | Links, bilingual parity, repository paths and Change Record contract passed; initial exit 2 for local paths corrected by keeping absolute paths external | Task documentation validation |
| `rtk bypass git diff --check` | 0 | No whitespace errors | Task documentation validation |

Fresh focused verification also passed 15 contract unit methods, 21 negative
mutations of copied real observations (all rejected), strict C17 client build,
CLI/cache/writer negative controls and a bounded cleanup probe after an accepted
partial HTTP request (2-second bound). Exact executed commands, tool versions,
source/artifact identities and raw results remain in external task evidence.

The targeted `trial4` procedure invoked every registered ID against the real
host and source-built client: 21 PASS / 4 FAIL, with 25/25 cleanup verified.
Failures: `h2_phase4_strict`, `h2_server_rst_stream`, `h2_upstream_reset`,
`phase4_strict_http2_stream_reset`. Separate H2-only/no-QUIC build reproduction
also failed Strict and upstream-reset expectations. These are retained failing
product-path regressions; no expectation or product code was changed.

The eight adjacent existing real-host cases also passed:
`protocol_h2_negotiated`, `h2_phase2_deny`, `h2_phase3_deny`, `h2_phase4_safe`,
`protocol_h3_negotiated`, `h3_phase2_deny`, `h3_phase3_deny`, `h3_phase4_safe`.
The completed execution receipt is retained externally as
`host/adjacent/executions.json`, with Framework base
`62b411e073551ef0fef22ab3d372e2489f2ae168` and Parent source
`a5f697c35acb5386d2037f91dfed10ad4b469cd9`. These successful adjacent paths do
not close the four failed new H2 cases.

## Security impact

No product security remediation is performed. The new validation surface rejects
missing or contradictory protocol/transaction witnesses and incomplete writes.
Raw native event fields are preserved. No global permissions, authentication,
capability declarations or test gates are weakened; no credentials are retained.

## Documentation and runtime evidence

The new preparation documentation and this record have full EN/DE companions;
the existing native executor documentation links to the separate runner.
The paired guide records the real `trial4` outcomes and H2 failure mechanism.
H3 Strict independently observed target reset with the peer held after headers
until reset, then healthy peer/follow-up on the same connection. H2 reset was
only observed after an approximately 12-second peer barrier timeout, followed
by peer failure despite an immediate native abort event. The source hypothesis
is NGINX HTTP/2 queuing RST in `close_stream` while another peer is processing;
root-cause proof and remediation remain separate work. Original `host/trial4`
bundles and all absolute paths remain in external task evidence. Comprehensive
acceptance is NOT_RUN; preparation is NOT_READY.

## Checks not run

Comprehensive acceptance: NOT_RUN, explicitly deferred by the user. Local Sonar:
not run, explicitly suspended; no local install/start/authentication. GitHub
Sonar, CodeQL and PR checks: running or under investigation; exact-head outcomes external. All-profile host qualification:
not performed by this NGINX-specific runner. No product fix was performed;
failed H2 expectations remain required.

## Limitations and residual risk

The new runner serves only `native-nginx-http-module`; all ten logical profiles
remain separate claims. Required Apache H2, HAProxy HTX H2/SPOE companion H2 stream-shutdown and
Envoy ext_proc H2 paths remain open. Selected stock/patched lighttpd profiles
retain their current H1-only contract, without new unsupported declarations. A matching build alone is not runtime proof. Unit controls do not
replace actual host evidence. Failed harness trials must remain recorded and
must not change product expectations. Global preparation readiness is unclaimed.

## Final diff and review status

The explicitly approved Framework [PR #169](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/169)
and Parent [PR #445](https://github.com/Easton97-Jens/ModSecurity-conector/pull/445)
exist. The earlier push rejection was superseded by fresh user authorization;
both original commits were pushed. GitHub CI remains under evaluation, with
final exact-head outcomes retained externally. No merge was performed.

All 33 targeted host reruns were completed at Parent
`5093a7aa349372279fb2c76974da6423de511332` / Framework
`fa444236fa3b00c91ba94de49f69f52101087087` / MRTS
`ee2174431c4edf97e66afe32558ce8454deb2397`: new cases 21 PASS / 4 FAIL,
adjacent cases 8 PASS; all 33 cleanups verified. Those results qualify that exact
pair and its admitted artifacts. Four H2 requirements and other modern profile
paths remain open; NOT_READY and full acceptance NOT_RUN remain unchanged.

Parent CI exposed an omitted generated test-archive projection: the native
`update-test-archive --check` failed in lint, quick, NGINX and Common checks.
Running the native generator in Framework adds only the new 15-method test
source to the archive, changing 8096 to 8111. This follow-up changes the archive
projection and documentation, with no runtime-code or expectation change.
Verification of a later commit pair is separate and is not claimed from the
5093/fa host runs. Exact follow-up SHAs and CI receipts remain external.

Framework PR CI then rejected the newly tracked C client before scanner startup:
its closed native compile inventory omitted the source. Add only
`tests/runners/protocol_acceptance_client.c` to the reviewed recipes and update
the exact offline inventory assertion from 81 to 82 units. Preserve complete
set equality, warning flags, credential boundaries and every analysis gate.
Refresh the generated specialist archive for the changed offline test source.
No local scanner, Sonar installation or authentication is run. Final follow-up
SHAs, targeted host repetitions and current-head CI results remain external.
