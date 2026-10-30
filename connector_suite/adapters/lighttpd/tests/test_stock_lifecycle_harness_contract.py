"""Contract tests for the bounded Stock lighttpd lifecycle entrypoint."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import os
from pathlib import Path
import shutil
import select
import subprocess
import tempfile
import time
import unittest
from importlib.util import module_from_spec, spec_from_file_location


REPO_ROOT = connector_root()
HARNESS = source_path('connectors/lighttpd/harness/run_lighttpd_stock_lifecycle.sh', root=REPO_ROOT)
PROBE = source_path('connectors/lighttpd/harness/lighttpd_stock_lifecycle_probe.py', root=REPO_ROOT)
SPEC = spec_from_file_location("lighttpd_stock_lifecycle_probe", PROBE)
PROBE_MODULE = module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(PROBE_MODULE)


class StockLifecycleHarnessContractTest(unittest.TestCase):
    def test_receipt_write_is_confined_to_private_root_and_rejects_symlinks(self):
        previous_root = PROBE_MODULE.TRUSTED_RUNTIME_ROOT
        with tempfile.TemporaryDirectory() as temporary:
            try:
                root = Path(temporary)
                PROBE_MODULE.TRUSTED_RUNTIME_ROOT = root
                receipt = root / "receipt.json"
                PROBE_MODULE._safe_write(receipt, {"status": "pass"})
                self.assertEqual(receipt.read_text(encoding="utf-8").count("status"), 1)
                with self.assertRaises(PROBE_MODULE.ProbeFailure):
                    PROBE_MODULE._safe_write(root / "nested" / "receipt.json", {"status": "fail"})
                outside_root = root.parent / "outside-root-receipt.json"
                with self.assertRaises(PROBE_MODULE.ProbeFailure):
                    PROBE_MODULE._safe_write(outside_root, {"status": "fail"})
                outside = root / "outside"
                outside.mkdir()
                link = root / "linked"
                link.symlink_to(outside, target_is_directory=True)
                with self.assertRaises(PROBE_MODULE.ProbeFailure):
                    PROBE_MODULE._safe_write(link / "receipt.json", {"status": "fail"})
            finally:
                PROBE_MODULE.TRUSTED_RUNTIME_ROOT = previous_root

    def test_entrypoint_is_executable_and_shell_clean(self) -> None:
        self.assertTrue(os.access(HARNESS, os.X_OK))
        text = HARNESS.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("#!/bin/sh\nset -euC\n"))
        self.assertIn("lighttpd_backend_close_probe.py", text)
        self.assertIn("lighttpd_stock_lifecycle_probe.py", text)
        self.assertIn("LIGHTTPD_BIN", text)
        self.assertIn("LIGHTTPD_CONNECTOR_MODULE", text)
        self.assertIn("LIGHTTPD_STOCK_LIFECYCLE_RULES_FILE", text)
        self.assertIn("LIGHTTPD_STOCK_LIFECYCLE_FRONTEND_PORT", text)
        self.assertIn("LIGHTTPD_STOCK_LIFECYCLE_UPSTREAM_PORT", text)
        self.assertIn("exec-session", text)
        self.assertIn("cleanup-session", text)
        self.assertIn("integration_mode=native-lighttpd-plugin", text)

    def test_entrypoint_records_scope_without_promoting_missing_vectors(self) -> None:
        text = HARNESS.read_text(encoding="utf-8")
        for required in (
            "backend_close_vectors=V7,V11-incomplete-response",
            "follow_up=allow-200,block-403,allow-200",
            "cleanup=pidfd-session,process,port,uds",
            "lifecycle_vectors=V6-client-abort,V9-bounded-parallel,V10-verified-host-termination",
            "not_executed=V12,V13,V14,V15",
            "stock-provenance.txt",
            "raw-receipt.json",
            "HOST_SHA256",
            "MODULE_SHA256",
            "RULES_SHA256",
            "readlink -f --",
            "RUNTIME_ROOT must be fresh and non-symlink",
            "sha256sum",
            "assert-listener-absent",
        ):
            self.assertIn(required, text)
        self.assertNotIn("LIGHTTPD_BACKEND_CLOSE_MODE=patched", text)
        self.assertNotIn("patched-native-lighttpd", text)
        probe = (source_path('connectors/lighttpd/harness/lighttpd_stock_lifecycle_probe.py', root=REPO_ROOT)).read_text(encoding="utf-8")
        self.assertIn('"event_promotion": "not_claimed"', probe)
        self.assertIn('"upstream_observed_client_close": True', probe)
        self.assertIn('"client_observed_host_close": True', probe)
        self.assertIn('"active_request_started": True', probe)
        self.assertIn('"status": "blocked"', probe)
        self.assertIn('return 77', probe)
        self.assertIn('Stock backend remained open after active client close within bounded timeout', probe)
        self.assertIn('"timeout_seconds": timeout', probe)
        self.assertIn('"backend_read_timeout_seconds": backend_read_timeout', probe)
        self.assertIn('client close completed only after configured backend read timeout', probe)
        self.assertIn('host_timeout_fallback": True', probe)
        self.assertIn('"upstream_observed_client_close": False', probe)
        self.assertIn('"client_direct_propagation": "not_observed"', probe)
        self.assertIn('"elapsed_seconds": round(time.monotonic() - started, 3)', probe)
        self.assertIn("MAX_PARALLEL = 8", (source_path('connectors/lighttpd/harness/lighttpd_stock_lifecycle_probe.py', root=REPO_ROOT)).read_text(encoding="utf-8"))
        self.assertIn("signal-session", text)
        self.assertIn('cleanup_process "$SERVER_SESSION_RECORD" "$SERVER_CLEANUP_RECEIPT"', text)
        self.assertIn('terminated Stock host cleanup receipt is missing', text)
        self.assertIn('SERVER_CLEANUP_RECEIPT=$RUNTIME_ROOT/server-cleanup.json', text)
        self.assertIn('SERVER_CLEANUP_RECEIPT=$RUNTIME_ROOT/server-cleanup-restart.json', text)
        self.assertIn("server-session-restart.json", text)
        self.assertIn('--upstream-port "$UPSTREAM_PORT" --timeout "$TIMEOUT"', text)
        self.assertIn('--backend-read-timeout "$BACKEND_READ_TIMEOUT" --runtime-root "$RUNTIME_ROOT"', text)
        self.assertIn('--receipt "$V6_RECEIPT"', text)
        self.assertIn('Stock V10 client-close evidence did not arrive', text)
        self.assertIn('V6_RESULT=direct-close', text)
        self.assertIn('V6_RESULT=bounded-timeout-fallback', text)
        self.assertIn('v6_result=%s', text)
        self.assertIn('PYTHON_BINARY=$(readlink -f -- "$(command -v python3)")', text)
        self.assertIn('MSCONNECTOR_LIGHTTPD_SESSION_PROFILE=stock-lifecycle-hold', text)
        self.assertIn('MSCONNECTOR_LIGHTTPD_SESSION_EXECUTABLE="$PYTHON_BINARY"', text)
        self.assertIn('MSCONNECTOR_LIGHTTPD_SESSION_RUNTIME_ROOT="$RUNTIME_ROOT"', text)
        self.assertNotIn('"$PYTHON_BINARY" "$LIFECYCLE_PROBE" hold', text)
        self.assertIn('--backend-read-timeout "$BACKEND_READ_TIMEOUT"', text)
        self.assertIn('backend read timeout must be below the overall probe timeout', text)
        self.assertIn('read timeout on socket:', text)
        self.assertIn('stock-v6-control', text)
        self.assertIn('V6_TIMEOUT_RECEIPT=$RUNTIME_ROOT/v6-host-timeout.json', text)
        self.assertIn('V6_CONTROL_RECEIPT=$RUNTIME_ROOT/v6-follow-up.json', text)
        self.assertIn('host_event=proxy_backend_read_timeout', text)
        self.assertIn('source_log_marker=read timeout on socket', text)
        self.assertIn('evidence_type=stock_v6_follow_up_control', text)
        self.assertIn('http_status=200', text)
        self.assertIn('V6 follow-up receipt is missing', text)
        self.assertIn('assert-file-marker', text)
        self.assertIn('--marker "read timeout on socket:"', text)
        self.assertNotIn('with path.open("rb") as stream:', text)
        self.assertNotIn('path.read_bytes()', text)
        self.assertLess(text.index('Stock V10 client-close evidence did not arrive'), text.index('cleanup-session --session-record "$V10_PROBE_SESSION_RECORD"'))
        self.assertNotIn("V9-parallel=pass", text)
        self.assertNotIn("V10-host-termination-during-active-request=pass", text)

    def test_lifecycle_probe_rejects_receipt_overwrite_and_unbounded_parallelism(self) -> None:
        probe = (source_path('connectors/lighttpd/harness/lighttpd_stock_lifecycle_probe.py', root=REPO_ROOT)).read_text(encoding="utf-8")
        self.assertIn("O_EXCL", probe)
        self.assertIn("O_NOFOLLOW", probe)
        self.assertIn("--runtime-root", probe)
        self.assertIn("trusted runtime root", probe)
        self.assertIn("MAX_RECEIPT_BYTES = 65536", probe)
        self.assertIn("ThreadPoolExecutor(max_workers=MAX_PARALLEL)", probe)
        self.assertIn('choices=("client-abort", "parallel", "hold", "release")', probe)

    def test_host_termination_cleanup_is_identity_bound_and_followed_by_control(self) -> None:
        text = HARNESS.read_text(encoding="utf-8")
        terminate = text.index('signal-session --pid "$SERVER_PID"')
        restart = text.index("server-session-restart.json")
        controls = text.index("control_status 200 0")
        self.assertLess(terminate, restart)
        first_cleanup = text.index('terminated Stock host cleanup receipt is missing')
        self.assertLess(terminate, first_cleanup)
        self.assertLess(first_cleanup, restart)
        self.assertLess(restart, controls)
        self.assertIn('assert-session-absent --session "$SERVER_SESSION"', text)
        self.assertIn('assert-session-absent --session "$V10_PROBE_PID"', text)

    def test_missing_provenance_blocks_before_runtime_creation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lighttpd-stock-contract-") as temporary:
            runtime_root = Path(temporary) / "runtime"
            environment = os.environ.copy()
            for name in (
                "LIGHTTPD_BIN",
                "LIGHTTPD_CONNECTOR_MODULE",
                "LIGHTTPD_STOCK_LIFECYCLE_RULES_FILE",
                "LIGHTTPD_STOCK_LIFECYCLE_FRONTEND_PORT",
                "LIGHTTPD_STOCK_LIFECYCLE_UPSTREAM_PORT",
            ):
                environment.pop(name, None)
            environment.update(
                {
                    "RUNTIME_ROOT": str(runtime_root),
                    "BUILD_ROOT": str(Path(temporary) / "build"),
                }
            )
            result = subprocess.run(
                ["sh", str(HARNESS)],
                cwd=REPO_ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 77)
            self.assertIn("LIGHTTPD_BIN is required", result.stderr)
            self.assertFalse(runtime_root.exists())

    def test_host_start_is_invoked_only_after_stock_provenance_is_bound(self) -> None:
        text = HARNESS.read_text(encoding="utf-8")
        binding = text.index("PROVENANCE=")
        execution = text.index('exec-session --file-limit-blocks 128', binding)
        self.assertLess(text.index("HOST_SHA256="), binding)
        self.assertLess(text.index("MODULE_SHA256="), binding)
        self.assertLess(text.index("RULES_SHA256="), binding)
        self.assertLess(binding, execution)
        self.assertIn('control_status 200 0', text)

    def test_cleanup_distinguishes_unattempted_and_unregistered_server_start(self) -> None:
        text = HARNESS.read_text(encoding="utf-8")
        self.assertIn("SERVER_START_ATTEMPTED=0", text)
        cleanup_start = text.index("cleanup() {")
        server_exec = text.index(
            "MSCONNECTOR_LIGHTTPD_SESSION_PROFILE=lighttpd-server",
            cleanup_start,
        )
        attempted = text.index("SERVER_START_ATTEMPTED=1", cleanup_start)
        self.assertLess(attempted, server_exec)
        self.assertGreater(attempted, cleanup_start)
        cleanup_body = text[cleanup_start:server_exec]
        self.assertIn('if [ "$SERVER_START_ATTEMPTED" -eq 1 ]; then', cleanup_body)
        self.assertIn('if [ -f "$SERVER_SESSION_RECORD" ]; then', cleanup_body)
        self.assertIn("cleanup_status=1", cleanup_body)
        self.assertNotIn(
            '[ -f "$SERVER_SESSION_RECORD" ] && cleanup_process',
            cleanup_body,
        )

    def test_unregistered_cleanup_handlers_cover_config_server_and_v10(self) -> None:
        text = HARNESS.read_text(encoding="utf-8")
        guard = (source_path('connectors/lighttpd/harness/lighttpd_backend_close_linux_guard.py', root=REPO_ROOT)).read_text(encoding="utf-8")
        trap_offset = text.index("trap cleanup EXIT")
        for variable in ("CONFIG_PID", "CONFIG_START_TIME", "CONFIG_SESSION"):
            self.assertLess(
                text.index(f"{variable}=\n"),
                trap_offset,
                f"{variable} must be initialized before set -u cleanup traps",
            )
        self.assertIn("cleanup_unregistered_process", text)
        self.assertIn("terminate-unregistered", text)
        self.assertIn('SERVER_START_TIME', text)
        self.assertIn("_pidfd_for_identity", guard)
        self.assertIn("unique session leader", guard)
        self.assertNotIn('kill "$SERVER_PID"', text)

        sleep = shutil.which("sleep")
        if sleep is None or not hasattr(os, "pidfd_open"):
            self.skipTest("Linux sleep/pidfd prerequisites unavailable")
        children = [subprocess.Popen(["setsid", sleep, "30"]) for _ in range(3)]
        try:
            starts = []
            for child in children:
                deadline = time.monotonic() + 2
                start_time = None
                while time.monotonic() < deadline:
                    try:
                        fields = Path(f"/proc/{child.pid}/stat").read_text(encoding="ascii").rsplit(")", 1)[1].split()
                        start_time = fields[19]
                        break
                    except (FileNotFoundError, IndexError):
                        time.sleep(0.01)
                self.assertIsNotNone(start_time)
                starts.append(start_time)
            shell = """
cleanup_unregistered_process() {
    status=0
    python3 "$GUARD" terminate-unregistered --pid "$1" --start-time "$2" --exe "$3" \
        --timeout-seconds 2 >/dev/null || status=$?
    [ "$status" -eq 0 ] || [ "$status" -eq 75 ]
}
cleanup_unregistered_process "$CONFIG_PID" "$CONFIG_START" "$SLEEP"
cleanup_unregistered_process "$SERVER_PID" "$SERVER_START" "$SLEEP"
cleanup_unregistered_process "$V10_PID" "$V10_START" "$SLEEP"
"""
            result = subprocess.run(
                ["sh", "-c", shell],
                env={
                    **os.environ,
                    "GUARD": str(source_path('connectors/lighttpd/harness/lighttpd_backend_close_linux_guard.py', root=REPO_ROOT)),
                    "SLEEP": str(Path(sleep).resolve()),
                    "CONFIG_PID": str(children[0].pid), "CONFIG_START": starts[0],
                    "SERVER_PID": str(children[1].pid), "SERVER_START": starts[1],
                    "V10_PID": str(children[2].pid), "V10_START": starts[2],
                },
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            for child in children:
                self.assertIsNotNone(child.poll())
        finally:
            for child in children:
                child.kill() if child.poll() is None else None
                child.wait()

    def test_parent_death_during_python_registration_phase_terminates_guard(self) -> None:
        if not hasattr(os, "pidfd_open"):
            self.skipTest("Linux pidfd prerequisite unavailable")
        sleep = shutil.which("sleep")
        if sleep is None:
            self.skipTest("sleep prerequisite unavailable")
        script = """
import importlib.util, os, sys, time
spec = importlib.util.spec_from_file_location('guard', sys.argv[1])
guard = importlib.util.module_from_spec(spec); sys.modules['guard'] = guard; spec.loader.exec_module(guard)
ready = int(sys.argv[2])
record = sys.argv[3]
ready_read = int(sys.argv[5])
child_pid = os.fork()
if child_pid == 0:
    os.close(ready_read)
    def delayed_registration(path):
        os.write(ready, b'R')
        while True: time.sleep(1)
    guard._register_session = delayed_registration
    guard.os.environ['MSCONNECTOR_LIGHTTPD_SESSION_PROFILE'] = 'sleep-duration'
    guard.os.environ['MSCONNECTOR_LIGHTTPD_SESSION_EXECUTABLE'] = sys.argv[4]
    guard.os.environ['MSCONNECTOR_LIGHTTPD_SESSION_DURATION'] = '30'
    guard.exec_session(16, record)
else:
    print(child_pid, flush=True)
    os.read(ready_read, 1)
    os._exit(0)
"""
        with tempfile.TemporaryDirectory(prefix="lighttpd-registration-race-") as temporary:
            record = Path(temporary) / "session-record.json"
            read_fd, write_fd = os.pipe()
            process = subprocess.Popen(
                ["python3", "-c", script, str(source_path('connectors/lighttpd/harness/lighttpd_backend_close_linux_guard.py', root=REPO_ROOT)), str(write_fd), str(record), str(Path(sleep).resolve()), str(read_fd)],
                pass_fds=(read_fd, write_fd), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            os.close(write_fd)
            try:
                ready_stream, _, _ = select.select([process.stdout], [], [], 2) if process.stdout is not None else ([], [], [])
                output = process.stdout.readline().strip() if ready_stream else b""
                self.assertTrue(output)
                guard_pid = int(output)
                self.assertNotEqual(os.path.realpath(f"/proc/{guard_pid}/exe"), str(Path(sleep).resolve()))
                deadline = time.monotonic() + 2
                while Path(f"/proc/{guard_pid}").exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertFalse(Path(f"/proc/{guard_pid}").exists())
                self.assertEqual(process.wait(timeout=2), 0)
                self.assertEqual(process.stderr.read(), b"")
                self.assertFalse(record.exists())
            finally:
                os.close(read_fd)
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
                process.kill() if process.poll() is None else None
                process.wait()

    def test_parent_death_after_registration_ends_exec_target_and_session(self) -> None:
        if not hasattr(os, "pidfd_open"):
            self.skipTest("Linux pidfd prerequisite unavailable")
        sleep = shutil.which("sleep")
        if sleep is None:
            self.skipTest("sleep prerequisite unavailable")
        script = """
import importlib.util, json, os, sys, time
from pathlib import Path
spec = importlib.util.spec_from_file_location('guard', sys.argv[1])
guard = importlib.util.module_from_spec(spec); sys.modules['guard'] = guard; spec.loader.exec_module(guard)
record = Path(sys.argv[2])
guard.os.environ['MSCONNECTOR_LIGHTTPD_SESSION_PROFILE'] = 'sleep-duration'
guard.os.environ['MSCONNECTOR_LIGHTTPD_SESSION_EXECUTABLE'] = sys.argv[3]
guard.os.environ['MSCONNECTOR_LIGHTTPD_SESSION_DURATION'] = '30'
if os.fork() == 0:
    guard.exec_session(16, record)
else:
    deadline = time.monotonic() + 2
    while not record.exists() and time.monotonic() < deadline: time.sleep(0.01)
    if not record.exists(): os._exit(2)
    value = json.loads(record.read_text())
    pid = value['leader_pid']
    print(pid, os.path.realpath('/proc/%d/exe' % pid), flush=True)
    os._exit(0)
"""
        with tempfile.TemporaryDirectory(prefix="lighttpd-registration-success-") as temporary:
            runtime_root = Path(temporary) / "runtime"
            runtime_root.mkdir(mode=0o700)
            record = runtime_root / "session-record.json"
            process = subprocess.Popen(
                ["python3", "-c", script, str(source_path('connectors/lighttpd/harness/lighttpd_backend_close_linux_guard.py', root=REPO_ROOT)), str(record), str(Path(sleep).resolve())],
                env={**os.environ, "MSCONNECTOR_TRUSTED_RUNTIME_ROOT": str(runtime_root)},
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                ready_stream, _, _ = select.select([process.stdout], [], [], 2) if process.stdout is not None else ([], [], [])
                line = process.stdout.readline() if ready_stream else ""
                self.assertTrue(line.strip(), process.stderr.read() if process.stderr is not None else "")
                pid_text, executable = line.strip().split(" ", 1)
                target_pid = int(pid_text)
                self.assertEqual(executable, str(Path(sleep).resolve()))
                self.assertEqual(process.wait(timeout=2), 0)
                deadline = time.monotonic() + 2
                while Path(f"/proc/{target_pid}").exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertFalse(Path(f"/proc/{target_pid}").exists())
                self.assertEqual(process.stderr.read(), "")
                self.assertTrue(record.is_file())
            finally:
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
                process.kill() if process.poll() is None else None
                process.wait()



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
