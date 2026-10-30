# HAProxy Harness

**Language:** English | [Deutsch](README.de.md)

Status: framework live-YAML runtime entrypoint
Runtime status: live request-side YAML execution through HAProxy, SPOA/SPOP,
and libmodsecurity. Current evidence:
No-CRS `46 PASS / 0 FAIL / 8 BLOCKED`; With-CRS
`48 PASS / 0 FAIL / 7 BLOCKED`.

`run_haproxy_smoke.sh` exists as the connector-side entrypoint for the framework
runtime-smoke runner. It lists shared YAML cases with `case_cli.py`,
materializes each selected case, live-starts local HAProxy, the SPOP runtime,
and a local backend, sends the case curl request through HAProxy, asserts the
observed status, writes per-case `result.json`, appends
`haproxy-results.jsonl`, and emits the standard
`{ "haproxy": { "summary": ..., "cases": ... } }` summary JSON.

The full-lifecycle dispatcher deliberately does not reuse this SPOA/SPOP
compatibility entrypoint. It invokes `runtime-smoke-haproxy-htx` through
`full-lifecycle-haproxy-htx`, which builds a disposable patched Framework-synchronized HAProxy
worktree and selects only `filter modsecurity-htx`. It loads the Framework's
canonical No-CRS rules and uses real host socket requests: P1 rule `1100001`
returns 403, P1 rule `1100002` returns 429, and P3 rule `1100201` returns 403
after one upstream response is observed. P2/P4 remain payload-free host
observations only. The harness writes raw bounded host evidence separately
from metadata events and keeps `capability_promotion=not_permitted`; it is not
safe/strict late-action, first-byte, Common-runtime-bridge, or capability-
promotion evidence.

The framework can prepare a local HAProxy binary without global installation
through `modules/ModSecurity-test-Framework/ci/provisioning/prepare-haproxy-runtime.sh`.
The generic SPOA/SPOP compatibility harness uses the Framework-synchronized
HAProxy release, pinned only in framework `ci/lib/common.sh`; its official
checksum file and source Makefile were verified before adding the pin. The
prepared binary path is:

```text
/src/ModSecurity-conector-build/haproxy-runtime/haproxy/sbin/haproxy
```

A local SPOA agent starter exists and can run a local self-test through:

```sh
make -C connectors/haproxy self-test-spoa
```

That self-test does not start HAProxy, does not parse SPOP frames, does not load
libmodsecurity, and must not be reported as a HAProxy runtime smoke.

A separate SPOP runtime binary can be built through:

```sh
make -C connectors/haproxy build-spoa-runtime
make -C connectors/haproxy self-test-spoa-runtime
```

This binary verifies local HELLO/AGENT-HELLO, NOTIFY request argument parsing,
verified `set-var txn.modsecdiag.blocked true` ACK encoding, and DISCONNECT
handling. During `make smoke-haproxy`, HAProxy sends `method`, `uri`,
`req.hdrs_bin` with a safe `req.hdrs` fallback, and `req.body` to this runtime.
The runtime feeds those bytes to libmodsecurity. This is request-side live
evidence, not a complete production SPOA implementation.

Framework runtime-smoke entrypoint:

```sh
make smoke-haproxy
```

Framework HAProxy matrix entrypoints:

```sh
make runtime-matrix-haproxy
make test-haproxy-no-crs
make test-haproxy-with-crs
```

`make runtime-matrix-haproxy` runs the live No-CRS and With-CRS HAProxy smokes
and then updates the runtime snapshot from those summary JSON files. Split
targets write their own directories:

- `/src/ModSecurity-conector-build/results/no-crs/haproxy-summary.json`
- `/src/ModSecurity-conector-build/results/with-crs/haproxy-summary.json`

The combined root summary is copied from the selected live variant, currently
With-CRS.

The current `run_haproxy_smoke.sh` entrypoint writes PASS evidence under
`/src/ModSecurity-conector-build/results/` only when live HAProxy sends NOTIFY
to the runtime, libmodsecurity evaluates the materialized rules file, HAProxy
enforces disruptive 403 decisions through the set-var/deny path, and the
observed status matches the YAML expectation.

The entrypoint checks HAProxy runtime prerequisites before writing evidence. If
the local HAProxy binary is missing, it attempts the framework prepare helper.
When that helper succeeds, the HAProxy binary/source-acquisition blockers are
removed from `blocked_reasons`. When all live enforcement checks pass:

- `make smoke-haproxy` live-starts HAProxy and the SPOP runtime, sends local
  HTTP requests through HAProxy, and records fresh per-case evidence;
- `spoe_runtime_status` is `live-request-side-verified`;
- `modsecurity_binding_status` is `live-enforcement-verified`;
- `runtime_verified` is `true` for live-executed PASS/FAIL case rows;
- `crs_verified` is evidenced by the With-CRS `crs_sqli_anomaly_block` PASS.

The ModSecurity binding self-test can be run directly:

```sh
make -C connectors/haproxy build-modsecurity-binding
make -C connectors/haproxy self-test-modsecurity-binding
make -C connectors/haproxy self-test-modsecurity-binding-crs
```

That self-test verifies in-process phase-1 header blocking, request-body
processing, and CRS SQLi decisions when the CRS target is used. Only
`make smoke-haproxy` may promote live enforcement status.

Current live request-side evidence covers:

- `REQUEST_URI`
- `REQUEST_HEADERS` and `REQUEST_HEADERS_NAMES`
- `ARGS` and `ARGS_NAMES`
- `REQUEST_COOKIES` and `REQUEST_COOKIES_NAMES`
- `REQUEST_BODY` for URL-encoded, JSON, XML, and multipart requests
- `FILES`
- CRS SQLi anomaly blocking with the prepared CRS preamble

The request-body path uses HAProxy request buffering, `tune.bufsize 65536`,
SPOE `max-frame-size 65532`, and one `req.body` argument. Larger, streamed, or
multi-frame bodies remain outside the proven surface.

Future HAProxy promotion beyond current partial status still requires:

- full production SPOA/SPOP implementation evidence or a selected alternative
  integration path
- response header/body phase evidence
- audit/log assertion evidence
- redirect and non-403 disruptive status mapping
- broader performance and failure-mode evidence

Executable cases and runners are framework-owned, for example:

- `modules/ModSecurity-test-Framework/tests/cases/`
- `modules/ModSecurity-test-Framework/tests/runners/case_cli.py`

An advertised `body_len` that differs from the received `req.body` sample is rejected as an unsupported incomplete transport sample (admission status 503), without a BODY_LIMIT classification. The complete one-frame sample is handed to libModSecurity; this route does not implement full-body incremental transport.
