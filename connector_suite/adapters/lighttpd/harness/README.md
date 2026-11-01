# lighttpd Harness

**Language:** English | [Deutsch](README.de.md)

Status: native config-load, start, and minimal runtime-smoke paths

The connector owns four native harness scripts:

- `prepare_native_smoke.sh` writes temporary Common and lighttpd configs below
  `BUILD_ROOT` with both body modes disabled;
- `check_lighttpd_config.sh` loads the real module through real `lighttpd -tt`;
- `start_lighttpd_smoke.sh` starts, checks, and stops lighttpd without requests;
- `runtime_lighttpd_smoke.sh` separately sends an allowed and a blocked request.

The corresponding targets are:

```sh
make -C connectors/lighttpd check-lighttpd-config
make -C connectors/lighttpd start-smoke-lighttpd
make -C connectors/lighttpd runtime-smoke-lighttpd
```

The runtime smoke uses `OPTIONS *` so lighttpd core can return the allowed 200
without loading unrelated stock modules from the temporary connector module
directory. Adding `X-Modsec-Smoke: block` must return 403 from rule `1000001`.
The script also verifies the narrow Common JSONL decision metadata.

`start-smoke-lighttpd` deliberately sends zero requests and reports that count.
The bridge self-test is separate and is never used as host evidence.

`run_lighttpd_smoke.sh` remains the entrypoint for the older framework-owned
`sidecar_proxy` path. It is an alternative path and its evidence must not be
mixed with the native-module evidence.

The full-lifecycle dispatcher does not reuse the generic stock No-CRS runner.
It invokes `runtime-smoke-lighttpd-patched` through
`full-lifecycle-lighttpd-patched`, which builds and loads only a matched patched
Framework-synchronized lighttpd core/module pair. The isolated target sends the same narrow
Phase-1 200/403 requests with both body modes disabled; it is not request-body,
response-body, Phase-4, or capability-promotion evidence.

Request/response body evidence, CRS, production hardening, security
verification, and full-matrix evidence are not provided by this harness.

## HTTP/1.1 pre-upstream Phase-2 gate runner

`run_phase2_pre_upstream_gate.py` is a separate repository-owned runner for
the selected patched HTTP/1.1 `mod_proxy` request-body profile. It takes a
fresh task-owned root, staged matching lighttpd binary/module, rules file, and
the libmodsecurity directory; it allocates three distinct private IPv4-loopback
ports itself. It starts only foreground task-owned processes and records
bounded framing/counter metadata, never request payloads.

The runner proves that delayed chunked Phase-2 deny bytes do not connect to or
reach the upstream before terminal EOS, that a delayed benign chunked allow
is forwarded only after EOS/allow, and that the host re-frames that allowed
request as one unchunked `Content-Length` delivery equal to the retained body
size. It also requires `501` with no new upstream
connection for `Incremental`, configured `server.stream-request-body`, and
explicitly enabled body-bearing `Upgrade` plus `gw.upgrade-with-request-body`.
A terminal host-side `501` uses logging finalization only: it records
the audit phase exactly once without synthesizing request-body EOS or a
Phase-2 decision. It is request-body P2 evidence only; it does not promote
response-body P4, CRS, HTTP/2/HTTP/3, unrestricted streaming, or
production-readiness claims.

The module passes bounded memory/file ranges to native P2 without its own
cumulative limit. This runner does not configure or prove the independent
`server.max-request-size` host setting.

## Response-body backend-close profile

`run_lighttpd_backend_close.sh` is only for patched lighttpd. It deliberately
sets `response_body_mode=streaming` so the current upstream-EOF/response-body
abort path can be evidenced. A stock host has no version-contractual streaming
hook and therefore fails closed before it creates a runtime root, host, or
listener; its body mode is never silently changed. Use
`run_lighttpd_stock_lifecycle.sh` for the stock transport/lifecycle profile
instead. Its V7/V11 result is host/transport evidence, not a typed stock
response-body connector event.

## Stock lifecycle profile

`run_lighttpd_stock_lifecycle.sh` runs the bounded stock-host profile and
stores evidence outside the checkout. The current run root is
`lighttpd-stock-lifecycle-v6-v10-20260825T100000Z`.

The profile records V6 as a bounded two-second gateway/proxy backend-read
timeout fallback: it does not claim direct client-cancel propagation or a
typed stock connector event; it requires the `read timeout on socket` host
marker and a same-host 200 follow-up. Raw truncated upstream-response fixtures
for V7/V11, eight bounded parallel HTTP/1.1 200 responses, and client EOF
after host termination are retained as host/transport evidence. Restart
controls must produce `200 -> 403 -> 200`. PIDFD/session/port/UDS cleanup
receipts are required for both the first and replacement host.

V12--V15 and the complete 17-vector acceptance remain `NOT_EXECUTED`; these
bounded receipts neither elevate them nor prove a complete leak audit.

## No-CRS fixture isolation and cleanup

The No-CRS baseline uses the trusted namespace runner
`run_no_crs_fixture_trusted_namespace.py`. The runner rejects a host-root or
set-id caller and starts the trusted setup chain through root-owned
`/usr/bin/unshare`, fixed `/usr/bin/dash` and `/usr/bin/mount`, and then
`/usr/bin/bwrap`. The shell setup makes mount propagation private and mounts a
private `nosuid,nodev,noexec` tmpfs at `/tmp` before entering bwrap. Bwrap
exposes only the minimal read-only system and runtime binds needed by the
harness plus the exact task-owned smoke root as the sole writable bind. The
fixture root itself is mode-0700.

The setup component is the only component that may require namespace and
mount capabilities. It attests the capability state after setup; the harness
continues only when all effective, permitted, inheritable, ambient, and
bounding capabilities are zero and `no_new_privs` is enabled. The test
process does not retain setup capabilities. Missing namespace support,
unexpected capability state, or an unavailable execution-isolation control
fails closed; there is no fallback to the former path-check-then-`rmdir`
cleanup.

Fixture lifetime is tied to the private namespace. Normal completion,
fixture creation failure, test failure, timeout, signal termination, helper
failure, and partial initialization all tear down the child process group and
private namespace. The final namespace-state verifier checks only the
capability sets, `no_new_privs`, mount state, and fixed fixture-root
device/inode (`dev:ino`) identity. The descriptor-I/O cleanup command separately
verifies the allowlisted fixture-leaf inventory, retains every leaf, and does
not unlink or re-resolve the fixture pathname. All leaves and the directory
disappear when the private tmpfs namespace is torn down. Mount propagation is
explicitly private, so fixture mounts are not propagated to the host mount
namespace.

Threat model: a same-UID process may rename, replace, or recreate the old
fixture pathname while a test is running. The security boundary therefore
does not rely on an inode check followed by a pathname deletion. The fixture
is created and used in a private mount namespace, the writable root is
controlled by the runner, and namespace release removes the private mounts.
This prevents a replaced host pathname from becoming the cleanup target.

The local nested container has only a one-entry UID/GID map, so it cannot
exercise the complete non-root production entry path. That limitation blocks
the local production integration claim; it does not authorize a less secure
fallback.

The pull-request `test-lighttpd` workflow sets
`LIGHTTPD_REQUIRE_NAMESPACE_INTEGRATION=1` when it runs the namespace suite.
An unavailable unprivileged user/mount/PID namespace is therefore a failed
hosted security check, never a skipped-success substitute for the lifecycle,
race, signal, crash, and teardown evidence.
