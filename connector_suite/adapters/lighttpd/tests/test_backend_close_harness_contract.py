from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import errno
import io
import json
import pathlib
import os
import select
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from importlib.util import module_from_spec, spec_from_file_location
from unittest.mock import patch


REPO_ROOT = connector_root()
HARNESS = source_path('connectors/lighttpd/harness', root=REPO_ROOT)
PROBE = HARNESS / "lighttpd_backend_close_probe.py"
RUNNER = HARNESS / "run_lighttpd_backend_close.sh"
GUARD = HARNESS / "lighttpd_backend_close_linux_guard.py"
SPEC = spec_from_file_location("lighttpd_backend_close_probe", PROBE)
PROBE_MODULE = module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(PROBE_MODULE)
GUARD_SPEC = spec_from_file_location("lighttpd_backend_close_linux_guard", GUARD)
GUARD_MODULE = module_from_spec(GUARD_SPEC)
assert GUARD_SPEC.loader is not None
assert GUARD_SPEC.name is not None
sys.modules[GUARD_SPEC.name] = GUARD_MODULE
GUARD_SPEC.loader.exec_module(GUARD_MODULE)
NONCE = "f" * 48
HOST_TRANSACTION_ID = "lighttpd-60-3"
PROC_TCP_HEADER = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"


def _sleep_session_environment(duration: str = "30") -> dict[str, str]:
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(GUARD_MODULE.SESSION_ENV_PREFIX)
    }
    environment.update(
        {
            GUARD_MODULE.SESSION_PROFILE_ENV: "sleep-duration",
            GUARD_MODULE.SESSION_EXECUTABLE_ENV: os.path.realpath("/usr/bin/sleep"),
            GUARD_MODULE.SESSION_DURATION_ENV: duration,
        }
    )
    return environment


class BackendCloseHarnessContractTest(unittest.TestCase):
    def test_receipt_write_is_confined_to_private_root_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            receipt = root / "receipt.json"
            PROBE_MODULE._write_receipt(root, receipt, b"{}\n")
            self.assertEqual(receipt.read_bytes(), b"{}\n")
            with self.assertRaises(PROBE_MODULE.ProbeFailure):
                PROBE_MODULE._write_receipt(root, root / "nested" / "receipt.json", b"{}\n")
            outside_root = root.parent / "outside-root-receipt.json"
            with self.assertRaises(PROBE_MODULE.ProbeFailure):
                PROBE_MODULE._write_receipt(root, outside_root, b"{}\n")
            outside = root / "outside"
            outside.mkdir()
            link = root / "linked"
            link.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(PROBE_MODULE.ProbeFailure):
                PROBE_MODULE._write_receipt(root, link / "receipt.json", b"{}\n")

    def test_probe_is_raw_bounded_and_requires_eof_or_read_error(self):
        text = PROBE.read_text(encoding="utf-8")
        self.assertIn('b"Content-Length: 64\\r\\n"', text)
        self.assertIn("SENT_BODY: Final = b\"short\"", text)
        self.assertIn("connection.shutdown(socket.SHUT_WR)", text)
        self.assertIn("connection.close()", text)
        self.assertIn("O_EXCL", text)
        self.assertIn("O_NOFOLLOW", text)
        self.assertIn("--runtime-root", text)
        self.assertIn("trusted runtime root", text)
        self.assertIn("expected_path", text)
        self.assertIn("except (socket.timeout, TimeoutError) as exc", text)
        self.assertIn("(socket.timeout, TimeoutError)", text)
        self.assertIn("upstream send deadline expired", text)
        self.assertIn("frontend_status", text)
        self.assertIn("frontend_content_length", text)
        self.assertIn("frontend_body_bytes", text)
        self.assertIn("frontend_body_sha256", text)
        self.assertIn("frontend_body_matches_fixture", text)
        self.assertIn("frontend_nonce_matches_upstream", text)
        self.assertIn("host_transaction_id", text)
        self.assertIn("x-msconnector-host-transaction-id", text)
        self.assertIn("secrets.token_hex(24)", text)
        self.assertIn("or body != SENT_BODY", text)
        self.assertIn('receipt["upstream_listener_closed"] = True', text)
        self.assertIn("raise ProbeFailure(\"frontend read timed out; truncation is not promoted\")", text)
        self.assertIn('"frontend_observed_before_host_stop": True', text)
        self.assertIn("upstream server thread did not terminate by deadline", text)
        self.assertIn("upstream listener did not become ready by deadline", text)
        self.assertIn("unapproved socket error", text)

    def test_runner_requires_explicit_provenance_and_exact_ports(self):
        text = RUNNER.read_text(encoding="utf-8")
        for required in (
            "LIGHTTPD_BIN",
            "LIGHTTPD_CONNECTOR_MODULE",
            "LIGHTTPD_BACKEND_CLOSE_RULES_FILE",
            "LIGHTTPD_BACKEND_CLOSE_MODE",
            "LIGHTTPD_EXPECTED_INTEGRATION_MODE",
            "lighttpd_backend_close_linux_guard.py",
            "check-pidfd",
            "exec-session",
            "assert-session",
            "assert-session-absent",
            "assert-no-uds",
            "assert-abort-event",
            "write-config",
            "write-json",
            "assert-listener",
            "assert-listener-absent",
            "cleanup-session",
            "--reject-unexpected-members",
            "snapshot_configcheck_session",
            "session-configcheck.json",
            "session-configcheck-registration.json",
            "session-host-registration.json",
            "session-configcheck-cleanup.json",
            "session-host-cleanup.json",
            "assert_static_provenance",
            "unexpected_members_fail_closed_after_containment",
            "LIGHTTPD_BACKEND_CLOSE_LOG_FILE_BLOCKS",
            "--file-limit-blocks \"$LOG_FILE_BLOCKS\"",
            "--wait-seconds \"$TIMEOUT\"",
            "set -euC",
            "sha256sum",
            "CONFIG_SHA256",
            "config_sha256",
            "atomic_staging",
            "LIGHTTPD_CONFIG=$RUNTIME_ROOT/lighttpd.conf",
            "basename \"$MODULE_PATH\")\" = mod_msconnector.so",
            "runtime root must be fresh and non-symlink",
            "provenance-before-configcheck.json",
            "provenance-after-configcheck.json",
            "provenance-after-start.json",
            "CONFIG_PID",
            "CONFIG_START_TIME",
            "proc_start_time",
            "proc_state",
            "SERVER_START_TIME",
            "CLEANUP_ACTIVE",
            "CLEANUP_STATUS",
            "RUNTIME_ROOT",
            "sock.bind((\"127.0.0.1\", port))",
            "readlink -f -- \"/proc/$process_pid/exe\"",
            "readlink -f -- \"$HOST_BINARY\"",
            "wait_for_exit",
            "wait_for_host_listener",
            "config-check process did not retain the expected host identity",
            "CLEANUP_TIMEOUT",
            "raw-receipt.json",
            "control_status 200",
            "control_status 403",
        ):
            self.assertIn(required, text)
        self.assertNotIn("curl", text)
        self.assertNotIn("kill -TERM", text)
        self.assertNotIn("kill -KILL", text)
        self.assertNotIn("/root/", text)
        self.assertNotIn("LIGHTTPD_BACKEND_CLOSE_CONFIG", text)
        self.assertNotIn("--backend-read-timeout", text)
        self.assertNotIn("killpg", text)
        cleanup_assertion = text[text.index('python3 "$LINUX_GUARD" assert-no-uds'):]
        self.assertIn('assert-listener-absent --host 127.0.0.1 --port "$FRONTEND_PORT"', cleanup_assertion)
        self.assertIn('assert-listener-absent --host 127.0.0.1 --port "$UPSTREAM_PORT"', cleanup_assertion)
        self.assertNotIn('sock.bind(("127.0.0.1", int(raw)))', cleanup_assertion)
        self.assertGreaterEqual(text.count("assert_host_identity"), 5)
        self.assertTrue(os.access(RUNNER, os.X_OK))
        self.assertTrue(os.access(GUARD, os.X_OK))
        guard_text = GUARD.read_text(encoding="utf-8")
        self.assertIn("expected exactly one frontend LISTEN inode", guard_text)
        self.assertIn("os.pidfd_open(self_pid, 0)", guard_text)
        self.assertIn("signal.pidfd_send_signal(pidfd, 0)", guard_text)
        self.assertIn("Linux pidfd capability is unavailable or unusable", guard_text)
        self.assertIn("PIDFD_TARGET_EXIT_STATUS = 75", guard_text)
        self.assertIn("cannot open pidfd for a live target", guard_text)
        self.assertIn("PidfdTargetExited", guard_text)
        self.assertIn("_owned_listener_inodes(pid, before_inodes)", guard_text)
        self.assertIn("frontend listener changed during task-FD attribution", guard_text)
        self.assertIn("frontend listener inode is no longer held by the task host", guard_text)
        self.assertIn("MAX_PROC_SCAN_ENTRIES", guard_text)
        self.assertIn("MAX_KILL_RESCANS", guard_text)
        self.assertIn("MAX_SESSION_WAIT_RESCANS", guard_text)
        self.assertIn("MAX_ABORT_EVENT_RESCANS", guard_text)
        self.assertIn("MAX_TCP_LISTENER_LINES", guard_text)
        self.assertIn("TERM_EMPTY_CONFIRMATION_RESCANS = 6", guard_text)
        self.assertIn("minimum_empty_rescans", guard_text)
        self.assertIn("def _listen_inodes_snapshot", guard_text)
        self.assertIn("contains a malformed nonblank row", guard_text)
        self.assertIn("contains an invalid local endpoint", guard_text)
        self.assertIn("contains an invalid remote endpoint", guard_text)
        self.assertIn("contains an invalid state field", guard_text)
        self.assertIn("contains an invalid inode field", guard_text)
        self.assertIn('table_path.name == "tcp"', guard_text)
        self.assertIn('table_path.name == "tcp6"', guard_text)
        self.assertIn("def assert_listener_absent", guard_text)
        self.assertIn("frontend listener remains after cleanup", guard_text)
        self.assertIn("len(event_lines) == 1", guard_text)
        self.assertIn("task-owned host error log is not valid UTF-8", guard_text)
        self.assertIn("def terminate_registered_session", guard_text)
        self.assertIn("pidfd_registered_sid_pgid_term_kill", text)
        self.assertIn("signal.pidfd_send_signal(member.pidfd, signal_number)", guard_text)
        self.assertIn("signal.pidfd_send_signal(pidfd, signal_number)", guard_text)
        self.assertIn("registered task leader SID/PGID changed", guard_text)
        self.assertIn("Membership is read only after the pidfd is open", guard_text)
        self.assertIn("cannot fully inspect task session membership", guard_text)
        self.assertIn("task session contained unexpected members during cleanup", guard_text)
        raw_receipt_index = text.index("raw-socket receipt missing before host stop")
        post_raw_identity_index = text.index("assert_host_identity", raw_receipt_index)
        abort_event_index = text.index("assert-abort-event", raw_receipt_index)
        self.assertLess(post_raw_identity_index, abort_event_index)
        controls_index = text.index("control_status()")
        controls_end = text.index("control_status 200 0", controls_index)
        self.assertIn("assert_host_identity", text[controls_index:controls_end])
        self.assertLess(
            text.rindex("control_status 200 0"),
            text.index('assert_host_identity "$SESSION_PRE_CLEANUP"'),
        )
        self.assertEqual(text.count("exec-session --file-limit-blocks"), 2)
        self.assertIn("MSCONNECTOR_LIGHTTPD_SESSION_PROFILE=lighttpd-config-check", text)
        self.assertIn("MSCONNECTOR_LIGHTTPD_SESSION_PROFILE=lighttpd-server", text)
        self.assertNotIn("exec_argv", guard_text)
        self.assertNotIn("argparse.REMAINDER", guard_text)
        pidfd_preflight_index = text.index('python3 "$LINUX_GUARD" check-pidfd')
        first_exec_session_index = text.index('python3 "$LINUX_GUARD" exec-session')
        self.assertLess(pidfd_preflight_index, first_exec_session_index)
        self.assertIn(
            'blocked "usable Linux pidfd capability is required for safe process cleanup"',
            text,
        )
        self.assertIn("exit 77", text)
        self.assertIn("PIDFD_TARGET_EXIT_STATUS=75", text)
        self.assertIn("config-check session inventory changed or pidfd target remained live", text)
        self.assertIn("config-check process did not retain the expected host identity", text)

    def test_runner_fails_closed_on_unknown_process(self):
        text = RUNNER.read_text(encoding="utf-8")
        self.assertIn("task session pidfd containment failed", text)
        self.assertIn("trap cleanup EXIT", text)
        self.assertIn("trap 'cleanup_on_signal HUP' HUP", text)
        self.assertIn("trap 'cleanup_on_signal INT' INT", text)
        self.assertIn("trap 'cleanup_on_signal TERM' TERM", text)
        self.assertIn("exit 128", text)
        self.assertIn("cleanup failed while handling signal", text)
        self.assertIn('exit "$cleanup_status"', text)
        self.assertIn('return "$CLEANUP_STATUS"', text)
        self.assertIn("trap - EXIT HUP INT TERM", text)
        self.assertIn("task host remains active after bounded session containment", text)
        self.assertIn("refusing to cleanup a process without registered task SID/PGID", text)
        self.assertIn('proc_state "$pid")" != Z', text)
        self.assertNotIn('proc_state "$1")" != Z', text)
        self.assertIn('wait "$cleanup_pid" 2>/dev/null || true', text)
        self.assertIn('if [ -n "$cleanup_pid" ]; then', text)
        self.assertIn('cleanup_process "$CONFIG_PID" "$CONFIG_SESSION" "$CONFIG_SESSION_RECORD"', text)
        self.assertIn('cleanup_process "$SERVER_PID" "$SERVER_SESSION" "$SERVER_SESSION_RECORD"', text)
        self.assertIn('--wait-seconds "$CLEANUP_TIMEOUT"', text)
        self.assertIn("cleanup timeout must be between 1 and 30 seconds", text)
        self.assertNotIn("wait \"$SERVER_PID\"", text)
        self.assertNotIn("cleanup || true", text)

    def test_runner_rejects_executable_fifo_before_any_runtime_setup(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            fifo = pathlib.Path(temporary_directory) / "lighttpd-host"
            os.mkfifo(fifo, 0o700)
            environment = os.environ.copy()
            environment.update(
                {
                    "LIGHTTPD_BIN": str(fifo),
                    "LIGHTTPD_CONNECTOR_MODULE": str(GUARD),
                    "LIGHTTPD_BACKEND_CLOSE_RULES_FILE": str(GUARD),
                    "LIGHTTPD_BACKEND_CLOSE_MODE": "patched",
                    "LIGHTTPD_EXPECTED_INTEGRATION_MODE": "patched-native-lighttpd",
                    "RUNTIME_ROOT": str(pathlib.Path(temporary_directory) / "runtime"),
                    "LIGHTTPD_BACKEND_CLOSE_FRONTEND_PORT": "29851",
                    "LIGHTTPD_BACKEND_CLOSE_UPSTREAM_PORT": "29852",
                }
            )
            result = subprocess.run(
                ["/bin/sh", str(RUNNER)],
                env=environment,
                capture_output=True,
                text=True,
                timeout=5,
            )
            self.assertEqual(result.returncode, 77)
            self.assertIn("host binary must be an executable regular file", result.stdout)
            self.assertFalse((pathlib.Path(environment["RUNTIME_ROOT"])).exists())

    def test_runner_accepts_patched_provenance_before_runtime_setup(self):
        environment = os.environ.copy()
        environment.update(
            {
                "LIGHTTPD_BIN": str(RUNNER),
                "LIGHTTPD_CONNECTOR_MODULE": str(GUARD),
                "LIGHTTPD_BACKEND_CLOSE_RULES_FILE": str(GUARD),
                "LIGHTTPD_BACKEND_CLOSE_MODE": "patched",
                "LIGHTTPD_EXPECTED_INTEGRATION_MODE": "patched-native-lighttpd",
                "RUNTIME_ROOT": "not-an-absolute-runtime-root",
            }
        )
        result = subprocess.run(
            ["/bin/sh", str(RUNNER)],
            env=environment,
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 77)
        self.assertIn("RUNTIME_ROOT must be absolute", result.stdout)
        self.assertNotIn("mode and expected integration provenance disagree", result.stdout)

    def test_runner_rejects_stock_response_body_profile_before_runtime_setup(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            runtime_root = pathlib.Path(temporary_directory) / "runtime"
            environment = os.environ.copy()
            environment.update(
                {
                    "LIGHTTPD_BIN": str(RUNNER),
                    "LIGHTTPD_CONNECTOR_MODULE": str(GUARD),
                    "LIGHTTPD_BACKEND_CLOSE_RULES_FILE": str(GUARD),
                    "LIGHTTPD_BACKEND_CLOSE_MODE": "stock",
                    "LIGHTTPD_EXPECTED_INTEGRATION_MODE": "native-lighttpd-plugin",
                    "RUNTIME_ROOT": str(runtime_root),
                }
            )
            result = subprocess.run(
                ["/bin/sh", str(RUNNER)],
                env=environment,
                capture_output=True,
                text=True,
                timeout=5,
            )
            self.assertEqual(result.returncode, 77)
            self.assertIn("Stock response-body backend-close coverage requires the patched streaming-hook host", result.stdout)
            self.assertIn("run_lighttpd_stock_lifecycle.sh", result.stdout)
            self.assertFalse(runtime_root.exists())

    def test_runner_rejects_mismatched_provenance_before_host_validation(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            environment = os.environ.copy()
            environment.update(
                {
                    "LIGHTTPD_BIN": str(RUNNER),
                    "LIGHTTPD_CONNECTOR_MODULE": str(GUARD),
                    "LIGHTTPD_BACKEND_CLOSE_RULES_FILE": str(GUARD),
                    "LIGHTTPD_BACKEND_CLOSE_MODE": "stock",
                    "LIGHTTPD_EXPECTED_INTEGRATION_MODE": "patched-native-lighttpd",
                    "RUNTIME_ROOT": str(pathlib.Path(temporary_directory) / "runtime"),
                    "LIGHTTPD_BACKEND_CLOSE_FRONTEND_PORT": "29851",
                    "LIGHTTPD_BACKEND_CLOSE_UPSTREAM_PORT": "29852",
                }
            )
            result = subprocess.run(
                ["/bin/sh", str(RUNNER)],
                env=environment,
                capture_output=True,
                text=True,
                timeout=5,
            )
            self.assertEqual(result.returncode, 77)
            self.assertIn("mode and expected integration provenance disagree", result.stdout)
            self.assertFalse((pathlib.Path(environment["RUNTIME_ROOT"])).exists())

    def test_runner_signal_trap_preserves_cleanup_failure_status(self):
        text = RUNNER.read_text(encoding="utf-8")
        function_start = text.index("cleanup_on_signal() {")
        function_end = text.index("\n}\ntrap cleanup EXIT", function_start) + 2
        cleanup_on_signal = text[function_start:function_end]

        def invoke(cleanup_status: int) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    "cleanup() { return %d; }\n%s\n"
                    "trap 'cleanup_on_signal TERM' TERM\n"
                    "kill -TERM $$\n" % (cleanup_status, cleanup_on_signal),
                ],
                capture_output=True,
                text=True,
                timeout=2,
            )

        failed_cleanup = invoke(37)
        self.assertEqual(failed_cleanup.returncode, 37)
        self.assertIn("cleanup failed while handling signal TERM (status=37)", failed_cleanup.stderr)
        normal_cleanup = invoke(0)
        self.assertEqual(normal_cleanup.returncode, 128)
        self.assertNotIn("cleanup failed while handling signal", normal_cleanup.stderr)

    def test_runner_repeated_cleanup_preserves_first_failure_for_signal_trap(self):
        text = RUNNER.read_text(encoding="utf-8")
        cleanup_start = text.index("cleanup() {")
        cleanup_end = text.index("\n}\ncleanup_on_signal()", cleanup_start) + 2
        cleanup_function = text[cleanup_start:cleanup_end]
        trap_start = text.index("cleanup_on_signal() {")
        trap_end = text.index("\n}\ntrap cleanup EXIT", trap_start) + 2
        cleanup_on_signal = text[trap_start:trap_end]
        setup = (
            "CLEANUP_ACTIVE=0\n"
            "CLEANUP_STATUS=1\n"
            "calls=0\n"
            "cleanup_process() { calls=$((calls + 1)); return 1; }\n"
            + cleanup_function
            + "\n"
        )
        repeated = subprocess.run(
            [
                "/bin/sh",
                "-c",
                setup
                + "cleanup; first=$?\n"
                + "cleanup; second=$?\n"
                + "printf '%s:%s:%s\\n' \"$first\" \"$second\" \"$calls\"\n",
            ],
            capture_output=True,
            text=True,
            timeout=2,
        )
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertEqual(repeated.stdout, "1:1:2\n")

        signaled = subprocess.run(
            [
                "/bin/sh",
                "-c",
                setup
                + cleanup_on_signal
                + "\ncleanup\n"
                + "trap 'cleanup_on_signal TERM' TERM\n"
                + "kill -TERM $$\n",
            ],
            capture_output=True,
            text=True,
            timeout=2,
        )
        self.assertEqual(signaled.returncode, 1)
        self.assertIn("cleanup failed while handling signal TERM (status=1)", signaled.stderr)

    def _frontend_server(self, payload):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve():
            with listener:
                connection, _ = listener.accept()
                with connection:
                    connection.sendall(payload)
                    connection.shutdown(socket.SHUT_WR)

        thread = threading.Thread(target=serve)
        thread.start()
        return port, thread

    def test_probe_accepts_only_correlated_truncated_response(self):
        payload = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n"
            + b"X-Msconnector-Backend-Close-Nonce: " + NONCE.encode("ascii")
            + b"\r\nX-Msconnector-Host-Transaction-Id: " + HOST_TRANSACTION_ID.encode("ascii")
            + b"\r\nConnection: close\r\n\r\nshort"
        )
        port, thread = self._frontend_server(payload)
        receipt = {}
        try:
            PROBE_MODULE._read_frontend("127.0.0.1", port, "/p4/close/", NONCE, time.monotonic() + 2, receipt)
        finally:
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(receipt["frontend_status"], 200)
        self.assertEqual(receipt["frontend_content_length"], 64)
        self.assertEqual(receipt["frontend_body_bytes"], 5)
        self.assertTrue(receipt["frontend_body_matches_fixture"])
        self.assertTrue(receipt["frontend_nonce_matches_upstream"])
        self.assertEqual(receipt["host_transaction_id"], HOST_TRANSACTION_ID)

    def test_probe_rejects_frontend_timeout_after_partial_response(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve():
            with listener:
                connection, _ = listener.accept()
                with connection:
                    connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\nX-Msconnector-Backend-Close-Nonce: " + NONCE.encode("ascii") + b"\r\nX-Msconnector-Host-Transaction-Id: " + HOST_TRANSACTION_ID.encode("ascii") + b"\r\n\r\nshort")
                    time.sleep(0.3)

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            deadline = time.monotonic() + 0.05
            with self.assertRaises(PROBE_MODULE.ProbeFailure):
                PROBE_MODULE._read_frontend("127.0.0.1", port, "/p4/close/", NONCE, deadline, {})
        finally:
            thread.join(2)
        self.assertFalse(thread.is_alive())

    def test_probe_rejects_wrong_status_or_length(self):
        payload = b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\nX-Msconnector-Backend-Close-Nonce: " + NONCE.encode("ascii") + b"\r\nX-Msconnector-Host-Transaction-Id: " + HOST_TRANSACTION_ID.encode("ascii") + b"\r\n\r\nshort"
        port, thread = self._frontend_server(payload)
        try:
            deadline = time.monotonic() + 2
            with self.assertRaises(PROBE_MODULE.ProbeFailure):
                PROBE_MODULE._read_frontend("127.0.0.1", port, "/p4/close/", NONCE, deadline, {})
        finally:
            thread.join(2)
        self.assertFalse(thread.is_alive())

    def test_probe_rejects_static_response_with_wrong_nonce(self):
        payload = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n"
            b"X-Msconnector-Backend-Close-Nonce: static\r\n"
            b"X-Msconnector-Host-Transaction-Id: lighttpd-60-3\r\n\r\nshort"
        )
        port, thread = self._frontend_server(payload)
        try:
            deadline = time.monotonic() + 2
            with self.assertRaises(PROBE_MODULE.ProbeFailure):
                PROBE_MODULE._read_frontend("127.0.0.1", port, "/p4/close/", NONCE, deadline, {})
        finally:
            thread.join(2)
        self.assertFalse(thread.is_alive())

    def test_probe_rejects_missing_host_transaction_id(self):
        payload = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n"
            + b"X-Msconnector-Backend-Close-Nonce: " + NONCE.encode("ascii")
            + b"\r\nConnection: close\r\n\r\nshort"
        )
        port, thread = self._frontend_server(payload)
        try:
            deadline = time.monotonic() + 2
            with self.assertRaises(PROBE_MODULE.ProbeFailure):
                PROBE_MODULE._read_frontend("127.0.0.1", port, "/p4/close/", NONCE, deadline, {})
        finally:
            thread.join(2)
        self.assertFalse(thread.is_alive())

    def test_probe_rejects_unapproved_socket_error(self):
        payload = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n"
            + b"X-Msconnector-Backend-Close-Nonce: " + NONCE.encode("ascii")
            + b"\r\nX-Msconnector-Host-Transaction-Id: " + HOST_TRANSACTION_ID.encode("ascii")
            + b"\r\n\r\nshort"
        )

        class UnexpectedErrorConnection:
            def __init__(self):
                self.reads = 0

            def __enter__(self):
                return self

            def __exit__(self, _exception_type, _exception, _traceback):
                return False

            def settimeout(self, _timeout):
                return None

            def sendall(self, _payload):
                return None

            def recv(self, _size):
                self.reads += 1
                if self.reads == 1:
                    return payload
                raise OSError(errno.EIO, "synthetic unexpected read failure")

        with patch.object(PROBE_MODULE.socket, "create_connection", return_value=UnexpectedErrorConnection()):
            deadline = time.monotonic() + 2
            with self.assertRaises(PROBE_MODULE.ProbeFailure):
                PROBE_MODULE._read_frontend("127.0.0.1", 1, "/p4/close/", NONCE, deadline, {})

    def test_linux_guard_attributes_listener_to_exact_process(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        pid = os.getpid()
        start_time = GUARD_MODULE._start_time(pid)
        executable = os.path.realpath(f"/proc/{pid}/exe")
        port = listener.getsockname()[1]
        try:
            GUARD_MODULE.assert_listener_owned(pid, start_time, executable, "127.0.0.1", port)
            with self.assertRaises(GUARD_MODULE.GuardFailure):
                GUARD_MODULE.assert_listener_owned(pid, "different-start-time", executable, "127.0.0.1", port)
        finally:
            listener.close()

    def test_linux_guard_rejects_listener_changed_during_fd_attribution(self):
        """A second listener snapshot catches a contender injected after FD lookup."""

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        pid = os.getpid()
        start_time = GUARD_MODULE._start_time(pid)
        executable = os.path.realpath(f"/proc/{pid}/exe")
        try:
            listener_port = listener.getsockname()[1]
            before = GUARD_MODULE._listen_inodes("127.0.0.1", listener_port)
            injected = set(before)
            injected.add("999999")
            with patch.object(
                GUARD_MODULE,
                "_listen_inodes",
                side_effect=[before, injected],
            ) as snapshots:
                with self.assertRaisesRegex(
                    GUARD_MODULE.GuardFailure,
                    "frontend listener changed during task-FD attribution",
                ):
                    GUARD_MODULE.assert_listener_owned(
                        pid,
                        start_time,
                        executable,
                        "127.0.0.1",
                        listener_port,
                    )
            self.assertEqual(snapshots.call_count, 2)
        finally:
            listener.close()

    def test_linux_guard_rejects_same_inode_handoff_after_tcp_snapshot(self):
        """An inherited listener inode must still be held by the verified host."""

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        release_read, release_write = os.pipe()
        handoff_child = os.fork()
        if handoff_child == 0:
            os.close(release_write)
            try:
                os.read(release_read, 1)
            finally:
                os._exit(0)
        os.close(release_read)
        pid = os.getpid()
        start_time = GUARD_MODULE._start_time(pid)
        executable = os.path.realpath(f"/proc/{pid}/exe")
        original_owned_listener_inodes = GUARD_MODULE._owned_listener_inodes
        attribution_calls = 0

        def hand_off_after_first_attribution(process_pid: int, inodes: set[str]) -> set[str]:
            nonlocal attribution_calls
            owned = original_owned_listener_inodes(process_pid, inodes)
            attribution_calls += 1
            if attribution_calls == 1:
                listener.close()
            return owned

        try:
            with patch.object(
                GUARD_MODULE,
                "_owned_listener_inodes",
                side_effect=hand_off_after_first_attribution,
            ):
                with self.assertRaisesRegex(
                    GUARD_MODULE.GuardFailure,
                    "frontend listener inode is no longer held by the task host",
                ):
                    GUARD_MODULE.assert_listener_owned(
                        pid,
                        start_time,
                        executable,
                        "127.0.0.1",
                        port,
                    )
            self.assertEqual(attribution_calls, 2)
        finally:
            listener.close()
            try:
                os.write(release_write, b"x")
            except OSError:
                pass
            os.close(release_write)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                waited_pid, _status = os.waitpid(handoff_child, os.WNOHANG)
                if waited_pid == handoff_child:
                    break
                time.sleep(0.01)
            else:
                os.kill(handoff_child, signal.SIGKILL)
                os.waitpid(handoff_child, 0)

    def test_linux_guard_rejects_foreign_reuseport_listener(self):
        if not hasattr(socket, "SO_REUSEPORT"):
            self.skipTest("SO_REUSEPORT is unavailable")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        try:
            listener.bind(("127.0.0.1", 0))
        except OSError as exc:
            listener.close()
            self.skipTest(f"SO_REUSEPORT bind is unavailable: {exc}")
        listener.listen(1)
        port = listener.getsockname()[1]
        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                (
                    "import socket, sys, time; "
                    "s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); "
                    "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); "
                    "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1); "
                    "s.bind(('127.0.0.1', int(sys.argv[1]))); s.listen(1); "
                    "print('ready', flush=True); time.sleep(30)"
                ),
                str(port),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            ready = child.stdout.readline().strip()
            if ready != "ready":
                self.skipTest("SO_REUSEPORT contender could not start")
            pid = os.getpid()
            start_time = GUARD_MODULE._start_time(pid)
            executable = os.path.realpath(f"/proc/{pid}/exe")
            with self.assertRaises(GUARD_MODULE.GuardFailure):
                GUARD_MODULE.assert_listener_owned(
                    pid,
                    start_time,
                    executable,
                    "127.0.0.1",
                    port,
                )
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=2)
            if child.stdout is not None:
                child.stdout.close()
            if child.stderr is not None:
                child.stderr.close()
            listener.close()

    def test_linux_guard_no_listener_probe_ignores_time_wait(self):
        """Absence is decided from LISTEN state, never from a replacement bind."""

        with patch.object(GUARD_MODULE, "_listen_inodes_snapshot", return_value=set()) as snapshot:
            GUARD_MODULE.assert_listener_absent("127.0.0.1", 29851)
        snapshot.assert_called_once_with("127.0.0.1", 29851, include_ipv6=True)

    def test_linux_guard_no_listener_probe_rejects_foreign_listener(self):
        with patch.object(GUARD_MODULE, "_listen_inodes_snapshot", return_value={"12345"}):
            with self.assertRaisesRegex(
                GUARD_MODULE.GuardFailure,
                "frontend listener remains after cleanup",
            ):
                GUARD_MODULE.assert_listener_absent("127.0.0.1", 29851)

    def test_linux_guard_proc_listener_parser_rejects_empty_or_malformed_header(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            table = pathlib.Path(temporary_directory) / "tcp"
            table.write_text("", encoding="ascii")
            with self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "invalid or incomplete header"):
                GUARD_MODULE._listen_table_inodes(table, "753B", None, "synthetic /proc/net/tcp")
            table.write_text("sl local_address rem_address st\n", encoding="ascii")
            with self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "invalid or incomplete header"):
                GUARD_MODULE._listen_table_inodes(table, "753B", None, "synthetic /proc/net/tcp")
            table.write_text("x" * (GUARD_MODULE.MAX_TCP_LISTENER_LINE_BYTES + 1) + "\n", encoding="ascii")
            with self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "header exceeds the bounded inspection limit"):
                GUARD_MODULE._listen_table_inodes(table, "753B", None, "synthetic /proc/net/tcp")

    def test_linux_guard_proc_listener_parser_rejects_oversized_row(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            table = pathlib.Path(temporary_directory) / "tcp"
            table.write_text(
                PROC_TCP_HEADER + "x" * (GUARD_MODULE.MAX_TCP_LISTENER_LINE_BYTES + 1) + "\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "entry exceeds the bounded inspection limit"):
                GUARD_MODULE._listen_table_inodes(table, "753B", None, "synthetic /proc/net/tcp")

    def test_linux_guard_active_attribution_rejects_foreign_ipv6_listener(self):
        pid = os.getpid()
        expected_start = GUARD_MODULE._start_time(pid)
        expected_exe = os.path.realpath(f"/proc/{pid}/exe")
        with (
            patch.object(GUARD_MODULE, "_listen_inodes", return_value={"ipv4", "ipv6"}),
            patch.object(GUARD_MODULE, "_owned_listener_inodes", return_value={"ipv4"}),
        ):
            with self.assertRaisesRegex(
                GUARD_MODULE.GuardFailure,
                "not exclusively owned by the task host",
            ):
                GUARD_MODULE.assert_listener_owned(
                    pid,
                    expected_start,
                    expected_exe,
                    "127.0.0.1",
                    29851,
                )

    def test_linux_guard_no_listener_probe_rejects_ipv6_wildcard_listener(self):
        if not socket.has_ipv6:
            self.skipTest("IPv6 is unavailable")
        for v6only in (0, 1):
            listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            try:
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, v6only)
                listener.bind(("::", 0))
                listener.listen(1)
                port = listener.getsockname()[1]
                with self.assertRaisesRegex(
                    GUARD_MODULE.GuardFailure,
                    "frontend listener remains after cleanup",
                ):
                    GUARD_MODULE.assert_listener_absent("127.0.0.1", port)
            except OSError as exc:
                self.skipTest(f"IPv6 wildcard listener unavailable for v6only={v6only}: {exc}")
            finally:
                listener.close()

    def test_linux_guard_tcp6_absence_rejects_ipv4_mapped_listener(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            table = pathlib.Path(temporary_directory) / "tcp6"
            table.write_text(
                PROC_TCP_HEADER +
                "0: 0000000000000000FFFF00000100007F:753B 00000000000000000000000000000000:0000 "
                "0A 0 0 0 0 0 54321 0\n",
                encoding="ascii",
            )
            self.assertEqual(
                GUARD_MODULE._listen_table_inodes(table, "753B", None, "synthetic /proc/net/tcp6"),
                {"54321"},
            )

    def test_linux_guard_proc_listener_parser_rejects_malformed_rows(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            table = pathlib.Path(temporary_directory) / "tcp6"
            table.write_text(PROC_TCP_HEADER + "0: malformed\n", encoding="ascii")
            with self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "malformed nonblank row"):
                GUARD_MODULE._listen_table_inodes(table, "753B", None, "synthetic /proc/net/tcp6")
            table.write_text(
                PROC_TCP_HEADER + "0: not-an-endpoint 0000:0000 0A 0 0 0 0 54321 0\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "invalid local endpoint"):
                GUARD_MODULE._listen_table_inodes(table, "753B", None, "synthetic /proc/net/tcp6")

            valid_prefix = (
                "0: 00000000000000000000000000000000:753B "
                "00000000000000000000000000000000:0000 "
            )
            table.write_text(PROC_TCP_HEADER + valid_prefix + "0A 0 0 0 0 0 not-decimal 0\n", encoding="ascii")
            with self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "invalid inode field"):
                GUARD_MODULE._listen_table_inodes(table, "753B", None, "synthetic /proc/net/tcp6")
            table.write_text(PROC_TCP_HEADER + valid_prefix + "GG 0 0 0 0 0 54321 0\n", encoding="ascii")
            with self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "invalid state field"):
                GUARD_MODULE._listen_table_inodes(table, "753B", None, "synthetic /proc/net/tcp6")
            table.write_text(PROC_TCP_HEADER + valid_prefix + "0A0 0 0 0 0 0 54321 0\n", encoding="ascii")
            with self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "invalid state field"):
                GUARD_MODULE._listen_table_inodes(table, "753B", None, "synthetic /proc/net/tcp6")
            table.write_text(
                PROC_TCP_HEADER + "0: 00000000000000000000000000000000:753B invalid-remote 0A 0 0 0 0 0 54321 0\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "invalid remote endpoint"):
                GUARD_MODULE._listen_table_inodes(table, "753B", None, "synthetic /proc/net/tcp6")

    def test_linux_guard_proc_listener_parser_enforces_table_family_width(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            tcp6_table = pathlib.Path(temporary_directory) / "tcp6"
            tcp6_table.write_text(
                PROC_TCP_HEADER + "0: 0100007F:753B 0000:0000 0A 0 0 0 0 0 54321 0\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "invalid local endpoint"):
                GUARD_MODULE._listen_table_inodes(tcp6_table, "753B", None, "synthetic /proc/net/tcp6")
            tcp_table = pathlib.Path(temporary_directory) / "tcp"
            tcp_table.write_text(
                PROC_TCP_HEADER + "0: 00000000000000000000000000000000:753B "
                "00000000000000000000000000000000:0000 0A 0 0 0 0 0 54321 0\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "invalid local endpoint"):
                GUARD_MODULE._listen_table_inodes(tcp_table, "753B", None, "synthetic /proc/net/tcp")

    def test_linux_guard_process_state_classifies_only_disappearance_as_benign(self):
        for disappearance_errno in (errno.ENOENT, errno.ESRCH):
            with self.subTest(disappearance_errno=disappearance_errno), patch.object(
                GUARD_MODULE.Path,
                "read_text",
                side_effect=OSError(disappearance_errno, "synthetic disappeared"),
            ):
                self.assertIsNone(GUARD_MODULE._process_state(42))
        with patch.object(
            GUARD_MODULE.Path,
            "read_text",
            side_effect=OSError(errno.EACCES, "synthetic permission failure"),
        ):
            with self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "errno=13"):
                GUARD_MODULE._process_state(42)

    def test_linux_guard_pidfd_signals_exact_child(self):
        child = subprocess.Popen(["sleep", "30"])
        start_time = GUARD_MODULE._start_time(child.pid)
        executable = os.path.realpath(f"/proc/{child.pid}/exe")
        try:
            GUARD_MODULE.signal_owned(child.pid, start_time, executable, signal.SIGTERM)
            self.assertEqual(child.wait(timeout=2), -signal.SIGTERM)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=2)

    def test_linux_guard_check_pidfd_requires_actual_usable_capability(self):
        self_pid = os.getpid()
        with (
            patch.object(GUARD_MODULE.os, "pidfd_open", return_value=91) as pidfd_open,
            patch.object(GUARD_MODULE, "_pidfd_matches_pid") as matches_pid,
            patch.object(GUARD_MODULE.signal, "pidfd_send_signal") as send_signal,
            patch.object(GUARD_MODULE.os, "close") as close_pidfd,
        ):
            GUARD_MODULE._require_pidfd()
        pidfd_open.assert_called_once_with(self_pid, 0)
        matches_pid.assert_called_once_with(91, self_pid)
        send_signal.assert_called_once_with(91, 0)
        close_pidfd.assert_called_once_with(91)

        with patch.object(
            GUARD_MODULE.os,
            "pidfd_open",
            side_effect=OSError(errno.ENOSYS, "synthetic pidfd unavailable"),
        ):
            with self.assertRaisesRegex(
                GUARD_MODULE.GuardFailure,
                "Linux pidfd capability is unavailable or unusable",
            ):
                GUARD_MODULE._require_pidfd()

        with (
            patch.object(GUARD_MODULE.os, "pidfd_open", return_value=92),
            patch.object(GUARD_MODULE, "_pidfd_matches_pid"),
            patch.object(
                GUARD_MODULE.signal,
                "pidfd_send_signal",
                side_effect=OSError(errno.EPERM, "synthetic pidfd signal unavailable"),
            ),
            patch.object(GUARD_MODULE.os, "close") as close_pidfd,
        ):
            with self.assertRaisesRegex(
                GUARD_MODULE.GuardFailure,
                "Linux pidfd capability is unavailable or unusable",
            ):
                GUARD_MODULE._require_pidfd()
        close_pidfd.assert_called_once_with(92)

    def test_linux_guard_distinguishes_dead_target_from_live_pidfd_denial(self):
        with (
            patch.object(GUARD_MODULE, "_require_pidfd"),
            patch.object(
                GUARD_MODULE.os,
                "pidfd_open",
                side_effect=OSError(errno.ESRCH, "synthetic vanished target"),
            ),
            patch.object(GUARD_MODULE, "_process_state", return_value=None),
        ):
            with self.assertRaisesRegex(
                GUARD_MODULE.PidfdTargetExited,
                "pidfd target exited before it could be opened",
            ):
                GUARD_MODULE._open_pidfd(42)

        with (
            patch.object(GUARD_MODULE, "_require_pidfd"),
            patch.object(
                GUARD_MODULE.os,
                "pidfd_open",
                side_effect=OSError(errno.EPERM, "synthetic live target denial"),
            ),
            patch.object(GUARD_MODULE, "_process_state", return_value="R"),
        ):
            with self.assertRaisesRegex(
                GUARD_MODULE.GuardFailure,
                "cannot open pidfd for a live target",
            ):
                GUARD_MODULE._open_pidfd(42)

        with (
            patch.object(sys, "argv", [str(GUARD), "assert-session", "--pid", "42", "--start-time", "1", "--exe", "/bin/true"]),
            patch.object(
                GUARD_MODULE,
                "assert_singleton_session",
                side_effect=GUARD_MODULE.PidfdTargetExited("synthetic exited target"),
            ),
            patch("sys.stderr", new_callable=io.StringIO) as stderr,
        ):
            self.assertEqual(GUARD_MODULE.main(), GUARD_MODULE.PIDFD_TARGET_EXIT_STATUS)
        self.assertIn("EXITED synthetic exited target", stderr.getvalue())

    def test_runner_configcheck_pidfd_exit_race_is_narrowly_tolerated(self):
        text = RUNNER.read_text(encoding="utf-8")
        identity_start = text.index("wait_for_process_identity() {")
        identity_end = text.index("\n}\nsnapshot_configcheck_session()", identity_start) + 2
        snapshot_start = text.index("snapshot_configcheck_session() {")
        snapshot_end = text.index("\n}\nwait_for_host_listener()", snapshot_start) + 2
        identity_function = text[identity_start:identity_end]
        snapshot_function = text[snapshot_start:snapshot_end]

        def invoke(script: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["/bin/sh", "-c", script],
                capture_output=True,
                text=True,
                timeout=2,
            )

        identity_exited = invoke(
            "PIDFD_TARGET_EXIT_STATUS=75\nCLEANUP_TIMEOUT=0\n"
            "pid_alive() { return 1; }\nprocess_owned() { return 1; }\n"
            + identity_function
            + "\nwait_for_process_identity 42 1\n"
        )
        self.assertEqual(identity_exited.returncode, 75, identity_exited.stderr)

        identity_changed_while_live = invoke(
            "PIDFD_TARGET_EXIT_STATUS=75\nCLEANUP_TIMEOUT=0\n"
            "date() { printf '0\\n'; }\npid_alive() { return 0; }\n"
            "process_owned() { return 1; }\n"
            + identity_function
            + "\nwait_for_process_identity 42 1\n"
        )
        self.assertEqual(identity_changed_while_live.returncode, 1, identity_changed_while_live.stderr)

        identity_changed_then_exited = invoke(
            "PIDFD_TARGET_EXIT_STATUS=75\nCLEANUP_TIMEOUT=1\npid_alive_calls=0\n"
            "date() { printf '0\\n'; }\nsleep() { :; }\n"
            "pid_alive() { pid_alive_calls=$((pid_alive_calls + 1)); [ \"$pid_alive_calls\" -le 2 ]; }\n"
            "process_owned() { return 1; }\n"
            + identity_function
            + "\nwait_for_process_identity 42 1\n"
        )
        self.assertEqual(identity_changed_then_exited.returncode, 1, identity_changed_then_exited.stderr)

        exited_during_guard = invoke(
            "PIDFD_TARGET_EXIT_STATUS=75\n"
            "CONFIG_PID=42\nCONFIG_START_TIME=1\nHOST_BINARY=/bin/true\nCONFIG_SESSION_SNAPSHOT=/tmp/receipt\n"
            "CLEANUP_TIMEOUT=1\npid_alive_calls=0\n"
            "pid_alive() { pid_alive_calls=$((pid_alive_calls + 1)); [ \"$pid_alive_calls\" -le 2 ]; }\n"
            "process_owned() { return 0; }\n"
            "python3() { return 75; }\n"
            "fail() { exit 91; }\n"
            + identity_function
            + "\n"
            + snapshot_function
            + "\nsnapshot_configcheck_session\n"
        )
        self.assertEqual(exited_during_guard.returncode, 0, exited_during_guard.stderr)

        live_after_guard = invoke(
            "PIDFD_TARGET_EXIT_STATUS=75\n"
            "CONFIG_PID=42\nCONFIG_START_TIME=1\nHOST_BINARY=/bin/true\nCONFIG_SESSION_SNAPSHOT=/tmp/receipt\n"
            "CLEANUP_TIMEOUT=1\npid_alive() { return 0; }\n"
            "process_owned() { return 0; }\n"
            "python3() { return 75; }\n"
            "fail() { exit 91; }\n"
            + identity_function
            + "\n"
            + snapshot_function
            + "\nsnapshot_configcheck_session\n"
        )
        self.assertEqual(live_after_guard.returncode, 91, live_after_guard.stderr)

        generic_guard_failure_after_exit = invoke(
            "PIDFD_TARGET_EXIT_STATUS=75\n"
            "CONFIG_PID=42\nCONFIG_START_TIME=1\nHOST_BINARY=/bin/true\nCONFIG_SESSION_SNAPSHOT=/tmp/receipt\n"
            "CLEANUP_TIMEOUT=1\npid_alive_calls=0\n"
            "pid_alive() { pid_alive_calls=$((pid_alive_calls + 1)); [ \"$pid_alive_calls\" -le 2 ]; }\n"
            "process_owned() { return 0; }\n"
            "python3() { return 1; }\n"
            "fail() { exit 91; }\n"
            + identity_function
            + "\n"
            + snapshot_function
            + "\nsnapshot_configcheck_session\n"
        )
        self.assertEqual(generic_guard_failure_after_exit.returncode, 91, generic_guard_failure_after_exit.stderr)

    def test_linux_guard_does_not_swallow_live_proc_membership_errors(self):
        session_id = os.getsid(0)
        with patch.object(
            GUARD_MODULE,
            "_session_fields",
            side_effect=GUARD_MODULE.GuardFailure("synthetic live /proc parse failure"),
        ):
            with self.assertRaises(GUARD_MODULE.GuardFailure):
                GUARD_MODULE._session_members(session_id, strict=True)

    def test_linux_guard_treats_uninspectable_member_as_active(self):
        member_pid = os.getpid()
        with (
            patch.object(GUARD_MODULE, "_scan_session_members", return_value=([member_pid], [])),
            patch.object(
                GUARD_MODULE,
                "_process_state",
                side_effect=GUARD_MODULE.GuardFailure("synthetic live /proc state failure"),
            ),
        ):
            active, errors = GUARD_MODULE._active_session_members(1)
        self.assertEqual(active, [member_pid])
        self.assertEqual(errors, ["synthetic live /proc state failure"])

    def test_linux_guard_bounds_proc_scan_error_member_and_rescan_receipts(self):
        class ProcEntry:
            def __init__(self, name: str):
                self.name = name

            def __fspath__(self):
                return f"/proc/{os.getpid()}"

        with (
            patch.object(
                GUARD_MODULE.Path,
                "iterdir",
                return_value=iter([ProcEntry("1"), ProcEntry("2"), ProcEntry("3")]),
            ),
            patch.object(GUARD_MODULE, "_session_fields", return_value=(1, 77)),
            patch.object(GUARD_MODULE, "MAX_PROC_SCAN_ENTRIES", 2),
        ):
            members, errors = GUARD_MODULE._scan_session_members(77)
        self.assertEqual(members, [1, 2])
        self.assertEqual(errors, ["bounded /proc task-session scan limit exceeded"])

        with (
            patch.object(
                GUARD_MODULE.Path,
                "iterdir",
                return_value=iter([ProcEntry("not-a-pid"), ProcEntry("also-not-a-pid"), ProcEntry("1")]),
            ),
            patch.object(GUARD_MODULE, "_session_fields", return_value=(1, 77)) as session_fields,
            patch.object(GUARD_MODULE, "MAX_PROC_SCAN_ENTRIES", 2),
        ):
            members, errors = GUARD_MODULE._scan_session_members(77)
        self.assertEqual(members, [])
        self.assertEqual(errors, ["bounded /proc task-session scan limit exceeded"])
        session_fields.assert_not_called()

        class ErrorAfterMember:
            def __init__(self):
                self.yielded_member = False

            def __iter__(self):
                return self

            def __next__(self):
                if not self.yielded_member:
                    self.yielded_member = True
                    return ProcEntry(str(os.getpid()))
                raise OSError(errno.EIO, "synthetic iterator failure")

        with (
            patch.object(GUARD_MODULE.Path, "iterdir", return_value=ErrorAfterMember()),
            patch.object(GUARD_MODULE, "_session_fields", return_value=(1, 77)),
        ):
            members, errors = GUARD_MODULE._scan_session_members(77)
        self.assertEqual(members, [os.getpid()])
        self.assertEqual(errors, ["cannot continue /proc task-session enumeration"])

        with patch.object(
            GUARD_MODULE.Path,
            "iterdir",
            side_effect=OSError(errno.EIO, "synthetic initial iterator failure"),
        ):
            members, errors = GUARD_MODULE._scan_session_members(77)
        self.assertEqual(members, [])
        self.assertEqual(errors, ["cannot enumerate /proc for task session containment"])

        def broken_session_fields(member_pid: int):
            raise GUARD_MODULE.GuardFailure(f"synthetic-{member_pid}-" + "x" * 128)

        with (
            patch.object(
                GUARD_MODULE.Path,
                "iterdir",
                return_value=iter([ProcEntry(str(index)) for index in range(1, 9)]),
            ),
            patch.object(GUARD_MODULE, "_session_fields", side_effect=broken_session_fields),
            patch.object(GUARD_MODULE, "MAX_GUARD_ERRORS", 3),
            patch.object(GUARD_MODULE, "MAX_GUARD_ERROR_TEXT", 24),
        ):
            members, errors = GUARD_MODULE._scan_session_members(77)
        self.assertEqual(members, [])
        self.assertLessEqual(len(errors), 3)
        self.assertTrue(all(len(error) <= 24 for error in errors))
        self.assertTrue(errors[-1].endswith("..."))

        recorded_members = []
        aggregation_errors = []
        with patch.object(GUARD_MODULE, "MAX_RECORDED_MEMBER_IDS", 2):
            GUARD_MODULE._append_member_ids(
                recorded_members,
                [1, 2, 3],
                aggregation_errors,
                "bounded synthetic member receipt",
            )
        self.assertEqual(recorded_members, [1, 2])
        self.assertEqual(aggregation_errors, ["bounded synthetic member receipt"])

        session = GUARD_MODULE.RegisteredSession(leader_pid=1, leader_start_time="1", session_id=1, process_group=1)
        with (
            patch.object(GUARD_MODULE, "MAX_KILL_RESCANS", 2),
            patch.object(GUARD_MODULE, "_signal_current_session_members", return_value=([], [])) as signal_members,
            patch.object(GUARD_MODULE, "_wait_for_no_active_session_members", return_value=(False, [])),
        ):
            _signaled, stopped, kill_errors = GUARD_MODULE._kill_until_no_active_session_members(
                session,
                time.monotonic() + 1,
            )
        self.assertFalse(stopped)
        self.assertEqual(signal_members.call_count, 2)
        self.assertIn("bounded task-session KILL rescan limit exceeded", kill_errors)

        with (
            patch.object(GUARD_MODULE, "MAX_SESSION_WAIT_RESCANS", 2),
            patch.object(GUARD_MODULE, "_active_session_members", return_value=([1], [])),
            patch.object(GUARD_MODULE.time, "sleep", return_value=None),
        ):
            stopped, wait_errors = GUARD_MODULE._wait_for_no_active_session_members(1, time.monotonic() + 1)
        self.assertFalse(stopped)
        self.assertIn("bounded task-session wait rescan limit exceeded", wait_errors)

        with (
            patch.object(GUARD_MODULE, "MAX_SESSION_ABSENCE_RESCANS", 2),
            patch.object(GUARD_MODULE, "_active_session_members", return_value=([1], [])),
            patch.object(GUARD_MODULE.time, "sleep", return_value=None),
        ):
            with self.assertRaisesRegex(
                GUARD_MODULE.GuardFailure,
                "bounded task-session absence rescan limit exceeded",
            ):
                GUARD_MODULE.assert_session_absent(1, 1)

    def test_session_absence_ignores_zombie_members_but_not_inspection_errors(self):
        with patch.object(GUARD_MODULE, "_active_session_members", return_value=([], [])):
            GUARD_MODULE.assert_session_absent(123)
        with patch.object(GUARD_MODULE, "_active_session_members", return_value=([], ["cannot inspect"])):
            with self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "cannot fully inspect"):
                GUARD_MODULE.assert_session_absent(123)

    def test_probe_rejects_non_loopback_or_privileged_network_targets(self):
        with self.assertRaises(PROBE_MODULE.ProbeFailure):
            PROBE_MODULE._loopback_host("198.51.100.1")
        with self.assertRaises(PROBE_MODULE.ProbeFailure):
            PROBE_MODULE._loopback_port(80)
        self.assertEqual(PROBE_MODULE._loopback_host("127.0.0.1"), "127.0.0.1")
        self.assertEqual(PROBE_MODULE._loopback_port(29852), 29852)

    def test_linux_guard_bounds_abort_event_rescans(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory) / "runtime"
            root.mkdir(mode=0o700)
            os.environ[GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV] = str(root)
            self.addCleanup(os.environ.pop, GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV, None)
            receipt = root / "raw-receipt.json"
            receipt.write_text(
                '{"host_transaction_id":"lighttpd-60-3","frontend_status":200,'
                '"frontend_content_length":64,"frontend_body_bytes":5}\n',
                encoding="utf-8",
            )
            receipt.chmod(0o600)
            error_log = root / "lighttpd-error.log"
            error_log.write_text("unrelated event\n", encoding="utf-8")
            error_log.chmod(0o600)
            with (
                patch.object(GUARD_MODULE, "MAX_ABORT_EVENT_RESCANS", 2),
                patch.object(GUARD_MODULE.time, "sleep", return_value=None),
            ):
                with self.assertRaisesRegex(
                    GUARD_MODULE.GuardFailure,
                    "bounded upstream_eof abort-event rescan limit exceeded",
                ):
                    GUARD_MODULE.assert_abort_event(receipt, error_log, 4096, 1)

    def test_linux_guard_reads_artifacts_nonblocking_and_preserves_missing_log_polling(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory) / "runtime"
            root.mkdir(mode=0o700)
            os.environ[GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV] = str(root)
            self.addCleanup(os.environ.pop, GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV, None)
            fifo = root / "artifact.fifo"
            os.mkfifo(fifo, 0o600)
            with self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "not a private regular"):
                GUARD_MODULE._read_private_artifact(fifo, 4096, "fixture")
            receipt = root / "raw-receipt.json"
            receipt.write_text(
                '{"host_transaction_id":"lighttpd-60-3","frontend_status":200,'
                '"frontend_content_length":64,"frontend_body_bytes":5}\n',
                encoding="utf-8",
            )
            receipt.chmod(0o600)
            with self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "error log is missing"):
                GUARD_MODULE.assert_abort_event(receipt, root / "missing.log", 4096)

    def test_linux_guard_shared_marker_reader_is_bounded(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory) / "runtime"
            root.mkdir(mode=0o700)
            os.environ[GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV] = str(root)
            self.addCleanup(os.environ.pop, GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV, None)
            log = root / "lighttpd-error.log"
            log.write_text("read timeout on socket: fixture\n", encoding="utf-8")
            log.chmod(0o600)
            GUARD_MODULE.assert_private_artifact_contains(log, "read timeout on socket:", 4096)
            with self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "marker is missing"):
                GUARD_MODULE.assert_private_artifact_contains(log, "absent", 4096)
            with self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "bounded inspection limit"):
                GUARD_MODULE.assert_private_artifact_contains(log, "fixture", 1)

    def test_linux_guard_bounds_runtime_tree_scan(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory) / "runtime"
            root.mkdir(mode=0o700)
            os.environ[GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV] = str(root)
            self.addCleanup(os.environ.pop, GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV, None)
            (root / "one").write_text("", encoding="utf-8")
            (root / "two").write_text("", encoding="utf-8")
            with patch.object(GUARD_MODULE, "MAX_RUNTIME_TREE_ENTRIES", 1):
                with self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "bounded entry limit"):
                    GUARD_MODULE.assert_no_unix_sockets(root)

    def test_linux_guard_tree_child_open_failure_closes_its_descriptor(self):
        with (
            patch.object(GUARD_MODULE.os, "open", return_value=91),
            patch.object(GUARD_MODULE.os, "fstat", side_effect=OSError("synthetic")),
            patch.object(GUARD_MODULE.os, "close") as close,
        ):
            with self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "cannot safely open"):
                GUARD_MODULE._open_directory_chain_from_fd(17, "child")
        close.assert_called_once_with(91)

    def test_linux_guard_fails_closed_without_nofollow_flag(self):
        with patch.object(GUARD_MODULE.os, "O_NOFOLLOW", None):
            with self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "safe artifact opens"):
                GUARD_MODULE._nofollow_open_flag()

    def test_linux_guard_creates_task_owned_config_and_matches_abort_event(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory) / "runtime"
            root.mkdir(mode=0o700)
            os.environ[GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV] = str(root)
            self.addCleanup(os.environ.pop, GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV, None)
            rules = pathlib.Path(temporary_directory) / 'rules-"quoted"\\path.conf'
            rules.write_text("SecRuleEngine On\n", encoding="utf-8")
            GUARD_MODULE.write_config(root, str(rules), 28184, 28185)
            config = (root / "lighttpd.conf").read_text(encoding="utf-8")
            runtime = (root / "msconnector-runtime.conf").read_text(encoding="utf-8")
            self.assertIn('server.modules = ( "mod_proxy", "mod_msconnector" )', config)
            self.assertIn('msconnector.expose-host-transaction-id = "enable"', config)
            self.assertIn('"/p4/close/"', config)
            self.assertIn("response_body_mode=streaming", runtime)
            self.assertIn(f"rules_file={rules}", runtime)
            self.assertIn(f"event_path={root / 'events.jsonl'}", runtime)
            receipt = root / "raw-receipt.json"
            receipt.write_text(
                '{"host_transaction_id":"lighttpd-60-3","frontend_status":200,'
                '"frontend_content_length":64,"frontend_body_bytes":5}\n',
                encoding="utf-8",
            )
            receipt.chmod(0o600)
            error_log = root / "lighttpd-error.log"
            error_log.write_text(
                "msconnector event=upstream_eof response-body-abort host-transaction-id=lighttpd-60-3 offset=5\n",
                encoding="utf-8",
            )
            error_log.chmod(0o600)
            GUARD_MODULE.assert_abort_event(receipt, error_log, 4096)
            error_log.write_text("msconnector event=upstream_eof response-body-abort host-transaction-id=other offset=5\n", encoding="utf-8")
            with self.assertRaises(GUARD_MODULE.GuardFailure):
                GUARD_MODULE.assert_abort_event(receipt, error_log, 4096)
            error_log.write_text("msconnector event=upstream_eof response-body-abort host-transaction-id=lighttpd-60-3 offset=4\n", encoding="utf-8")
            with self.assertRaises(GUARD_MODULE.GuardFailure):
                GUARD_MODULE.assert_abort_event(receipt, error_log, 4096)
            error_log.write_text("prefixmsconnector event=upstream_eof response-body-abort host-transaction-id=lighttpd-60-3 offset=5\n", encoding="utf-8")
            with self.assertRaises(GUARD_MODULE.GuardFailure):
                GUARD_MODULE.assert_abort_event(receipt, error_log, 4096)
            error_log.write_text(
                "msconnector event=upstream_eof response-body-abort host-transaction-id=lighttpd-60-3 offset=5\n"
                "msconnector event=upstream_eof response-body-abort host-transaction-id=lighttpd-60-3 offset=6\n",
                encoding="utf-8",
            )
            with self.assertRaises(GUARD_MODULE.GuardFailure):
                GUARD_MODULE.assert_abort_event(receipt, error_log, 4096)
            error_log.write_bytes(b"\xff")
            with self.assertRaises(GUARD_MODULE.GuardFailure):
                GUARD_MODULE.assert_abort_event(receipt, error_log, 4096)

    def test_linux_guard_backend_read_timeout_is_optional_bounded_and_exact(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = pathlib.Path(temporary_directory)
            rules = base / "rules.conf"
            rules.write_text("SecRuleEngine On\n", encoding="utf-8")

            default_root = base / "default"
            default_root.mkdir(mode=0o700)
            os.environ[GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV] = str(default_root)
            self.addCleanup(os.environ.pop, GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV, None)
            GUARD_MODULE.write_config(default_root, str(rules), 28184, 28185)
            default_config = (default_root / "lighttpd.conf").read_text(encoding="utf-8")
            self.assertNotIn('"read-timeout"', default_config)
            self.assertIn(
                '  "/p4/close/" => ( ( "host" => "127.0.0.1", "port" => 28185 ) )\n',
                default_config,
            )

            timed_root = base / "timed"
            timed_root.mkdir(mode=0o700)
            os.environ[GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV] = str(timed_root)
            self.addCleanup(os.environ.pop, GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV, None)
            GUARD_MODULE.write_config(timed_root, str(rules), 28184, 28185, backend_read_timeout=7)
            timed_config = (timed_root / "lighttpd.conf").read_text(encoding="utf-8")
            self.assertEqual(timed_config.count('"read-timeout"'), 1)
            self.assertIn(
                '  "/p4/close/" => ( ( "host" => "127.0.0.1", "port" => 28185, "read-timeout" => 7 ) )\n',
                timed_config,
            )

            omitted_cli_root = base / "omitted-cli"
            omitted_cli_root.mkdir(mode=0o700)
            omitted_cli = subprocess.run(
                [
                    sys.executable,
                    str(GUARD),
                    "write-config",
                    "--root",
                    str(omitted_cli_root),
                    "--rules-file",
                    str(rules),
                    "--frontend-port",
                    "28184",
                    "--upstream-port",
                    "28185",
                ],
                capture_output=True,
                text=True,
                timeout=2,
                env={**os.environ, GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV: str(omitted_cli_root)},
            )
            self.assertEqual(omitted_cli.returncode, 0, omitted_cli.stderr)
            self.assertNotIn('"read-timeout"', (omitted_cli_root / "lighttpd.conf").read_text(encoding="utf-8"))

            valid_cli_root = base / "valid-cli"
            valid_cli_root.mkdir(mode=0o700)
            valid_cli = subprocess.run(
                [
                    sys.executable,
                    str(GUARD),
                    "write-config",
                    "--root",
                    str(valid_cli_root),
                    "--rules-file",
                    str(rules),
                    "--frontend-port",
                    "28184",
                    "--upstream-port",
                    "28185",
                    "--backend-read-timeout",
                    "9",
                ],
                capture_output=True,
                text=True,
                timeout=2,
                env={**os.environ, GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV: str(valid_cli_root)},
            )
            self.assertEqual(valid_cli.returncode, 0, valid_cli.stderr)
            self.assertIn(
                '  "/p4/close/" => ( ( "host" => "127.0.0.1", "port" => 28185, "read-timeout" => 9 ) )\n',
                (valid_cli_root / "lighttpd.conf").read_text(encoding="utf-8"),
            )

            for invalid in (0, 31, -1, True, "7", 1.5):
                invalid_root = base / f"invalid-{str(invalid).replace('.', '_')}"
                invalid_root.mkdir(mode=0o700)
                with patch.dict(
                    os.environ,
                    {GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV: str(invalid_root)},
                ):
                    with self.assertRaisesRegex(
                        GUARD_MODULE.GuardFailure,
                        "backend read timeout must be an integer between 1 and 30 seconds",
                    ):
                        GUARD_MODULE.write_config(
                            invalid_root,
                            str(rules),
                            28184,
                            28185,
                            backend_read_timeout=invalid,
                        )
                self.assertFalse((invalid_root / "document-root").exists())
                self.assertFalse((invalid_root / "lighttpd.conf").exists())

            missing_root = base / "missing"
            missing_root.mkdir(mode=0o700)
            missing_argument = subprocess.run(
                [
                    sys.executable,
                    str(GUARD),
                    "write-config",
                    "--root",
                    str(missing_root),
                    "--rules-file",
                    str(rules),
                    "--frontend-port",
                    "28184",
                    "--upstream-port",
                    "28185",
                    "--backend-read-timeout",
                ],
                capture_output=True,
                text=True,
                timeout=2,
                env={**os.environ, GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV: str(missing_root)},
            )
            self.assertEqual(missing_argument.returncode, 2, missing_argument.stderr)
            self.assertFalse((missing_root / "lighttpd.conf").exists())

            invalid_cli_root = base / "invalid-cli"
            invalid_cli_root.mkdir(mode=0o700)
            invalid_argument = subprocess.run(
                [
                    sys.executable,
                    str(GUARD),
                    "write-config",
                    "--root",
                    str(invalid_cli_root),
                    "--rules-file",
                    str(rules),
                    "--frontend-port",
                    "28184",
                    "--upstream-port",
                    "28185",
                    "--backend-read-timeout",
                    "0",
                ],
                capture_output=True,
                text=True,
                timeout=2,
                env={**os.environ, GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV: str(invalid_cli_root)},
            )
            self.assertEqual(invalid_argument.returncode, 1, invalid_argument.stderr)
            self.assertIn("backend read timeout must be an integer between 1 and 30 seconds", invalid_argument.stderr)
            self.assertFalse((invalid_cli_root / "lighttpd.conf").exists())

    def test_linux_guard_json_writer_encodes_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory) / "runtime"
            root.mkdir(mode=0o700)
            os.environ[GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV] = str(root)
            self.addCleanup(os.environ.pop, GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV, None)
            output = root / "provenance.json"
            value = 'path-with-quote=" and newline=\\n'
            GUARD_MODULE.write_json(output, [f"value={value}"])
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["value"], value)
            with self.assertRaises(GUARD_MODULE.GuardFailure):
                GUARD_MODULE.write_json(output, ["value=second-write"])
            with self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "field count"):
                GUARD_MODULE.write_json(
                    root / "too-many-fields.json",
                    [f"field{index}=value" for index in range(GUARD_MODULE.MAX_JSON_FIELDS + 1)],
                )
            with self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "field exceeds"):
                GUARD_MODULE.write_json(
                    root / "oversized-field.json",
                    ["value=" + "x" * GUARD_MODULE.MAX_JSON_FIELD_BYTES],
                )
            with patch.object(GUARD_MODULE, "MAX_JSON_OUTPUT_BYTES", 1):
                with self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "output exceeds"):
                    GUARD_MODULE.write_json(root / "oversized-output.json", ["value=control"])
            self.assertFalse((root / "too-many-fields.json").exists())
            self.assertFalse((root / "oversized-field.json").exists())
            self.assertFalse((root / "oversized-output.json").exists())

    def test_linux_guard_exec_session_rejects_untrusted_executable_metadata(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory)
            executable = root / "helper"
            executable.write_bytes(b"#!/bin/sh\nexit 0\n")
            executable.chmod(0o755)
            self.assertEqual(GUARD_MODULE._validated_executable(str(executable)), str(executable))
            executable.chmod(0o775)
            with self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "not group/world writable"):
                GUARD_MODULE._validated_executable(str(executable))
            symlink = root / "helper-link"
            symlink.symlink_to(executable)
            with self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "symbolic links"):
                GUARD_MODULE._validated_executable(str(symlink))

    def test_linux_guard_confines_artifacts_to_configured_runtime_root(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory) / "runtime"
            root.mkdir(mode=0o700)
            outside = pathlib.Path(temporary_directory) / "outside"
            outside.mkdir(mode=0o700)
            nested = root / "nested"
            nested.mkdir(mode=0o700)
            with patch.dict(
                os.environ,
                {GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV: str(root)},
            ):
                GUARD_MODULE.write_json(root / "control.json", ["status=ok"])
                GUARD_MODULE.write_json(nested / "control.json", ["status=nested-ok"])
                self.assertEqual(
                    (nested / "control.json").read_text(encoding="utf-8"),
                    '{"status": "nested-ok"}\n',
                )
                nested.chmod(0o755)
                with self.assertRaisesRegex(
                    GUARD_MODULE.GuardFailure, "private runner-owned directory"
                ):
                    GUARD_MODULE.write_json(nested / "non-private.json", ["status=bad"])
                nested.chmod(0o700)
                if os.geteuid() == 0:
                    real_lstat = os.lstat
                    foreign_parent_values = list(real_lstat(nested))
                    foreign_parent_values[4] = os.geteuid() + 1
                    foreign_parent_info = os.stat_result(foreign_parent_values)
                    with patch.object(
                        GUARD_MODULE.os,
                        "lstat",
                        side_effect=lambda candidate: (
                            foreign_parent_info
                            if pathlib.Path(candidate) == nested
                            else real_lstat(candidate)
                        ),
                    ):
                        with self.assertRaisesRegex(
                            GUARD_MODULE.GuardFailure, "private runner-owned directory"
                        ):
                            GUARD_MODULE.write_json(
                                nested / "foreign-owned.json", ["status=bad"]
                            )
                with self.assertRaises(GUARD_MODULE.GuardFailure):
                    GUARD_MODULE.write_json(outside / "control.json", ["status=bad"])
                with self.assertRaises(GUARD_MODULE.GuardFailure):
                    GUARD_MODULE.write_json(root / ".." / "outside" / "escape.json", ["status=bad"])
                link = root / "link"
                link.symlink_to(outside, target_is_directory=True)
                with self.assertRaises(GUARD_MODULE.GuardFailure):
                    GUARD_MODULE.write_json(link / "escape.json", ["status=bad"])
                rules = pathlib.Path(temporary_directory) / "rules.conf"
                rules.write_text("SecRuleEngine On\n", encoding="utf-8")
                with self.assertRaises(GUARD_MODULE.GuardFailure):
                    GUARD_MODULE.write_config(outside, str(rules), 28184, 28185)
                self.assertFalse((outside / "document-root").exists())
                with self.assertRaises(GUARD_MODULE.GuardFailure):
                    GUARD_MODULE.assert_no_unix_sockets(outside)

    def test_linux_guard_exec_session_uses_fixed_runner_profiles(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory) / "runtime"
            root.mkdir(mode=0o700)
            module_directory = root / "modules"
            module_directory.mkdir(mode=0o700)
            config = root / "lighttpd.conf"
            config.write_text("server.modules = ()\n", encoding="utf-8")
            config.chmod(0o600)
            lighttpd = root / "lighttpd-test"
            lighttpd.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            lighttpd.chmod(0o700)
            python = root / "python-test"
            python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            python.chmod(0o700)

            config_check_environment = {
                GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV: str(root),
                GUARD_MODULE.SESSION_PROFILE_ENV: "lighttpd-config-check",
                GUARD_MODULE.SESSION_EXECUTABLE_ENV: str(lighttpd),
                GUARD_MODULE.SESSION_MODULE_DIR_ENV: str(module_directory),
                GUARD_MODULE.SESSION_CONFIG_ENV: str(config),
            }
            with patch.dict(os.environ, config_check_environment, clear=True):
                self.assertEqual(
                    GUARD_MODULE._runner_session_command(),
                    [str(lighttpd), "-m", str(module_directory), "-tt", "-f", str(config)],
                )

            server_environment = dict(config_check_environment)
            server_environment[GUARD_MODULE.SESSION_PROFILE_ENV] = "lighttpd-server"
            with patch.dict(os.environ, server_environment, clear=True):
                self.assertEqual(
                    GUARD_MODULE._runner_session_command(),
                    [str(lighttpd), "-D", "-m", str(module_directory), "-f", str(config)],
                )

            ready = root / "ready"
            release = root / "release"
            receipt = root / "receipt.json"
            stock_environment = {
                GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV: str(root),
                GUARD_MODULE.SESSION_PROFILE_ENV: "stock-lifecycle-hold",
                GUARD_MODULE.SESSION_EXECUTABLE_ENV: str(python),
                GUARD_MODULE.SESSION_FRONTEND_PORT_ENV: "18080",
                GUARD_MODULE.SESSION_UPSTREAM_PORT_ENV: "18081",
                GUARD_MODULE.SESSION_READY_ENV: str(ready),
                GUARD_MODULE.SESSION_RELEASE_ENV: str(release),
                GUARD_MODULE.SESSION_RUNTIME_ROOT_ENV: str(root),
                GUARD_MODULE.SESSION_RECEIPT_ENV: str(receipt),
                GUARD_MODULE.SESSION_TIMEOUT_ENV: "5",
            }
            with patch.dict(os.environ, stock_environment, clear=True):
                command = GUARD_MODULE._runner_session_command()
            self.assertEqual(command[0], str(python))
            self.assertEqual(command[1:3], [str(GUARD.resolve().with_name("lighttpd_stock_lifecycle_probe.py")), "hold"])
            self.assertEqual(command[3::2], ["--frontend-port", "--upstream-port", "--ready", "--release", "--runtime-root", "--receipt", "--timeout"])

            invalid = dict(config_check_environment)
            invalid[GUARD_MODULE.SESSION_DURATION_ENV] = "30"
            with patch.dict(os.environ, invalid, clear=True), self.assertRaisesRegex(
                GUARD_MODULE.GuardFailure, "unsupported runner configuration"
            ):
                GUARD_MODULE._runner_session_command()
            with patch.dict(
                os.environ,
                {GUARD_MODULE.SESSION_PROFILE_ENV: "unapproved"},
                clear=True,
            ), self.assertRaisesRegex(GUARD_MODULE.GuardFailure, "not approved"):
                GUARD_MODULE._runner_session_command()
            with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(
                GUARD_MODULE.GuardFailure, "is required"
            ):
                GUARD_MODULE._runner_session_command()

        legacy = subprocess.run(
            [
                sys.executable,
                str(GUARD),
                "exec-session",
                "--file-limit-blocks",
                "16",
                "--",
                os.path.realpath("/usr/bin/sleep"),
                "30",
            ],
            env=_sleep_session_environment(),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(legacy.returncode, 2)

    def test_linux_guard_exec_session_is_a_singleton_process_group(self):
        child = subprocess.Popen(
            [
                sys.executable,
                str(GUARD),
                "exec-session",
                "--file-limit-blocks",
                "16",
            ],
            env=_sleep_session_environment(),
        )
        try:
            deadline = time.monotonic() + 2
            executable = ""
            while time.monotonic() < deadline:
                executable = os.path.realpath(f"/proc/{child.pid}/exe")
                if executable == os.path.realpath("/usr/bin/sleep"):
                    break
                time.sleep(0.01)
            self.assertEqual(executable, os.path.realpath("/usr/bin/sleep"))
            start_time = GUARD_MODULE._start_time(child.pid)
            inventory = GUARD_MODULE.assert_singleton_session(child.pid, start_time, executable)
            self.assertEqual(inventory["members"], [child.pid])
            cli_check = subprocess.run(
                [
                    sys.executable,
                    str(GUARD),
                    "assert-session",
                    "--pid",
                    str(child.pid),
                    "--start-time",
                    start_time,
                    "--exe",
                    executable,
                ],
                capture_output=True,
                text=True,
                timeout=2,
            )
            self.assertEqual(cli_check.returncode, 0, cli_check.stderr)
            GUARD_MODULE.signal_singleton_session(child.pid, start_time, executable, signal.SIGTERM)
            self.assertEqual(child.wait(timeout=2), -signal.SIGTERM)
            GUARD_MODULE.assert_session_absent(child.pid)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=2)

    def test_linux_guard_refuses_live_reused_leader_before_session_signal(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory) / "runtime"
            root.mkdir(mode=0o700)
            os.environ[GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV] = str(root)
            self.addCleanup(os.environ.pop, GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV, None)
            record = root / "session-registration.json"
            executable = os.path.realpath("/usr/bin/sleep")
            environment = _sleep_session_environment()
            environment[GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV] = str(root)
            child = subprocess.Popen(
                [
                    sys.executable,
                    str(GUARD),
                    "exec-session",
                    "--file-limit-blocks",
                    "16",
                    "--session-record",
                    str(record),
                ],
                env=environment,
            )
            original_registration = None
            try:
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    if record.exists() and os.path.realpath(f"/proc/{child.pid}/exe") == executable:
                        break
                    time.sleep(0.01)
                self.assertTrue(record.is_file())
                self.assertEqual(os.path.realpath(f"/proc/{child.pid}/exe"), executable)
                original_registration = json.loads(record.read_text(encoding="utf-8"))
                forged_registration = dict(original_registration)
                forged_registration["leader_start_time"] = "0"
                record.write_text(json.dumps(forged_registration) + "\n", encoding="utf-8")
                record.chmod(0o600)

                with self.assertRaises(GUARD_MODULE.GuardFailure):
                    GUARD_MODULE.terminate_registered_session(record, executable, 0.5)
                self.assertIsNone(child.poll(), "a live unverified PID must not receive a session-wide signal")

                record.write_text(json.dumps(original_registration) + "\n", encoding="utf-8")
                record.chmod(0o600)
                GUARD_MODULE.terminate_registered_session(record, executable, 0.5)
                self.assertEqual(child.wait(timeout=2), -signal.SIGTERM)
                GUARD_MODULE.assert_session_absent(original_registration["session_id"], 2)
            finally:
                if child.poll() is None:
                    if original_registration is not None:
                        record.write_text(json.dumps(original_registration) + "\n", encoding="utf-8")
                        record.chmod(0o600)
                        try:
                            GUARD_MODULE.terminate_registered_session(record, executable, 0.5)
                        except GUARD_MODULE.GuardFailure:
                            pass
                    if child.poll() is None:
                        child.kill()
                        child.wait(timeout=2)

    def _start_forking_leader(self, temporary_directory: str):
        root = pathlib.Path(temporary_directory) / "runtime"
        root.mkdir(mode=0o700)
        os.environ[GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV] = str(root)
        self.addCleanup(os.environ.pop, GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV, None)
        record = root / "session-registration.json"
        fork_program = (
            "import json, os, pathlib, signal, sys, time\n"
            "record = pathlib.Path(sys.argv[1])\n"
            "stat_data = pathlib.Path(f'/proc/{os.getpid()}/stat').read_text()\n"
            "start_time = stat_data.rsplit(')', 1)[1].split()[19]\n"
            "record.write_text(json.dumps({'leader_pid': os.getpid(), 'leader_start_time': start_time, 'process_group': os.getpid(), 'session_id': os.getpid()}) + '\\n')\n"
            "os.chmod(record, 0o600)\n"
            "sys.argv = [sys.argv[0], *sys.argv[2:]]\n"
            "child = os.fork()\n"
            "if child:\n"
            "    print(child, flush=True)\n"
            "    os._exit(0)\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "while True:\n"
            "    time.sleep(1)\n"
        )
        leader = subprocess.Popen(
            [sys.executable, "-c", fork_program, str(record)],
            start_new_session=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return record, leader

    def test_linux_guard_contains_children_when_live_leader_pid_is_reused(self):
        """A foreign live PID never receives a signal, but its old SID's child does."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            record, leader = self._start_forking_leader(temporary_directory)
            task_child_pid = None
            task_child_start_time = None
            task_child_executable = None
            session_id = None
            foreign = None
            foreign_start_time = None
            foreign_executable = None
            try:
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline and not record.exists():
                    time.sleep(0.01)
                self.assertTrue(record.is_file(), "exec-session did not register its task SID/PGID")
                readable, _, _ = select.select([leader.stdout], [], [], 2)
                self.assertTrue(readable, "forking leader did not report its child")
                task_child_pid = int(leader.stdout.readline().strip())
                task_child_start_time = GUARD_MODULE._start_time(task_child_pid)
                task_child_executable = os.path.realpath(f"/proc/{task_child_pid}/exe")
                registration = json.loads(record.read_text(encoding="utf-8"))
                session_id = registration["session_id"]
                self.assertEqual(leader.wait(timeout=2), 0)

                foreign = subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(30)"],
                )
                foreign_start_time = GUARD_MODULE._start_time(foreign.pid)
                foreign_executable = os.path.realpath(f"/proc/{foreign.pid}/exe")
                reused_registration = GUARD_MODULE.RegisteredSession(
                    leader_pid=foreign.pid,
                    leader_start_time="0",
                    process_group=registration["process_group"],
                    session_id=session_id,
                )
                with patch.object(
                    GUARD_MODULE,
                    "_registered_session",
                    return_value=reused_registration,
                ):
                    python_executable = os.path.realpath(sys.executable)
                    with self.assertRaisesRegex(
                        GUARD_MODULE.GuardFailure,
                        "containing other verified task-session members only",
                    ):
                        GUARD_MODULE.terminate_registered_session(
                            record,
                            python_executable,
                            0.5,
                        )
                self.assertIsNone(foreign.poll(), "a reused foreign leader PID must never be signaled")
                GUARD_MODULE.assert_session_absent(session_id, 2)
                self.assertFalse(pathlib.Path(f"/proc/{task_child_pid}/stat").exists())
            finally:
                if foreign is not None and foreign.poll() is None:
                    try:
                        GUARD_MODULE.signal_owned(
                            foreign.pid,
                            foreign_start_time,
                            foreign_executable,
                            signal.SIGKILL,
                        )
                    except GUARD_MODULE.GuardFailure:
                        pass
                    if foreign.poll() is None:
                        foreign.kill()
                    foreign.wait(timeout=2)
                if (
                    task_child_pid is not None
                    and task_child_start_time is not None
                    and task_child_executable is not None
                    and pathlib.Path(f"/proc/{task_child_pid}/stat").exists()
                ):
                    try:
                        GUARD_MODULE.signal_owned(
                            task_child_pid,
                            task_child_start_time,
                            task_child_executable,
                            signal.SIGKILL,
                        )
                    except GUARD_MODULE.GuardFailure:
                        pass
                if leader.poll() is None:
                    try:
                        GUARD_MODULE.terminate_registered_session(
                            record,
                            os.path.realpath(sys.executable),
                            0.5,
                        )
                    except GUARD_MODULE.GuardFailure:
                        pass
                if leader.poll() is None:
                    leader.kill()
                    leader.wait(timeout=2)
                if session_id is not None:
                    try:
                        GUARD_MODULE.assert_session_absent(session_id, 2)
                    except GUARD_MODULE.GuardFailure:
                        pass
                if leader.stdout is not None:
                    leader.stdout.close()
                leader_stderr = leader.stderr
                if leader_stderr is not None:
                    leader_stderr.close()

    def test_linux_guard_contains_forked_member_after_leader_exits(self):
        """A dead leader cannot prevent pidfd cleanup of its live task child."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            record, leader = self._start_forking_leader(temporary_directory)
            root = record.parent
            child_pid = None
            child_start_time = None
            child_executable = None
            session_id = None
            try:
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline and not record.exists():
                    time.sleep(0.01)
                self.assertTrue(record.is_file(), "exec-session did not register its task SID/PGID")
                readable, _, _ = select.select([leader.stdout], [], [], 2)
                self.assertTrue(readable, "forking leader did not report its child")
                child_pid = int(leader.stdout.readline().strip())
                child_start_time = GUARD_MODULE._start_time(child_pid)
                child_executable = os.path.realpath(f"/proc/{child_pid}/exe")
                registration = json.loads(record.read_text(encoding="utf-8"))
                session_id = registration["session_id"]
                self.assertEqual(leader.wait(timeout=2), 0)
                self.assertTrue(pathlib.Path(f"/proc/{child_pid}/stat").exists())

                cleanup_receipt = root / "cleanup-receipt.json"
                cleanup = subprocess.run(
                    [
                        sys.executable,
                        str(GUARD),
                        "cleanup-session",
                        "--session-record",
                        str(record),
                        "--leader-exe",
                        os.path.realpath(sys.executable),
                        "--timeout-seconds",
                        "0.5",
                        "--output",
                        str(cleanup_receipt),
                        "--reject-unexpected-members",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=3,
                )
                self.assertEqual(cleanup.returncode, 1)
                self.assertIn("task session contained unexpected members during cleanup", cleanup.stderr)
                inventory = json.loads(cleanup_receipt.read_text(encoding="utf-8"))
                self.assertIn(child_pid, inventory["term_signaled"])
                self.assertIn(child_pid, inventory["kill_signaled"])
                self.assertEqual(inventory["unexpected_members"], [child_pid])
                GUARD_MODULE.assert_session_absent(session_id, 2)
                self.assertFalse(pathlib.Path(f"/proc/{child_pid}/stat").exists())
            finally:
                if record.exists():
                    try:
                        GUARD_MODULE.terminate_registered_session(
                            record,
                            os.path.realpath(sys.executable),
                            0.5,
                        )
                    except GUARD_MODULE.GuardFailure:
                        pass
                if leader.poll() is None:
                    leader.kill()
                    leader.wait(timeout=2)
                if (
                    child_pid is not None
                    and child_start_time is not None
                    and child_executable is not None
                    and pathlib.Path(f"/proc/{child_pid}/stat").exists()
                ):
                    # A failing regression must not leave its explicit task child;
                    # retain the same pidfd/start-time/executable guard as harness
                    # cleanup rather than falling back to a numeric-PID signal.
                    try:
                        GUARD_MODULE.signal_owned(
                            child_pid,
                            child_start_time,
                            child_executable,
                            signal.SIGKILL,
                        )
                    except GUARD_MODULE.GuardFailure:
                        pass
                if session_id is not None:
                    try:
                        GUARD_MODULE.assert_session_absent(session_id, 2)
                    except GUARD_MODULE.GuardFailure:
                        pass
                if leader.stdout is not None:
                    leader.stdout.close()
                if leader.stderr is not None:
                    leader.stderr.close()

    def test_linux_guard_cleanup_ignores_preexisting_zombie_member(self):
        """A zombie is retained as evidence but cannot fail active cleanup."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory) / "runtime"
            root.mkdir(mode=0o700)
            record = root / "session-registration.json"
            child_file = root / "zombie-child.pid"
            zombie_program = (
                "import json, os, pathlib, signal, sys, time\n"
                "record = pathlib.Path(sys.argv[1])\n"
                "child_file = pathlib.Path(sys.argv[2])\n"
                "stat_data = pathlib.Path(f'/proc/{os.getpid()}/stat').read_text()\n"
                "start_time = stat_data.rsplit(')', 1)[1].split()[19]\n"
                "record.write_text(json.dumps({'leader_pid': os.getpid(), 'leader_start_time': start_time, 'process_group': os.getpid(), 'session_id': os.getpid()}) + '\\n')\n"
                "os.chmod(record, 0o600)\n"
                "child = -1\n"
                "def reap_and_exit(_signal, _frame):\n"
                "    if child > 0:\n"
                "        while True:\n"
                "            try:\n"
                "                os.waitpid(child, 0)\n"
                "                break\n"
                "            except InterruptedError:\n"
                "                continue\n"
                "            except ChildProcessError:\n"
                "                break\n"
                "    os._exit(0)\n"
                "signal.signal(signal.SIGTERM, reap_and_exit)\n"
                "child = os.fork()\n"
                "if child:\n"
                "    child_file.write_text(str(child), encoding='ascii')\n"
                "    while True:\n"
                "        time.sleep(1)\n"
                "os._exit(0)\n"
            )
            leader = subprocess.Popen(
                [sys.executable, "-c", zombie_program, str(record), str(child_file)],
                start_new_session=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            child_pid = None
            session_id = None
            try:
                deadline = time.monotonic() + 2
                child_pid_text = ""
                while time.monotonic() < deadline:
                    if record.is_file() and child_file.is_file():
                        try:
                            child_pid_text = child_file.read_text(encoding="ascii").strip()
                        except OSError:
                            child_pid_text = ""
                        if child_pid_text.isdigit():
                            break
                    time.sleep(0.01)
                self.assertTrue(record.is_file(), "zombie leader did not register its session")
                self.assertTrue(child_file.is_file(), "zombie leader did not report its child")
                self.assertTrue(child_pid_text.isdigit(), "zombie child PID was not written completely")
                child_pid = int(child_pid_text)
                registration = json.loads(record.read_text(encoding="utf-8"))
                session_id = registration["session_id"]
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    if GUARD_MODULE._process_state(child_pid) == "Z":
                        break
                    time.sleep(0.01)
                self.assertEqual(GUARD_MODULE._process_state(child_pid), "Z")

                cleanup_receipt = root / "cleanup-receipt.json"
                cleanup_environment = os.environ.copy()
                cleanup_environment[GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV] = str(root)
                cleanup = subprocess.run(
                    [
                        sys.executable,
                        str(GUARD),
                        "cleanup-session",
                        "--session-record",
                        str(record),
                        "--leader-exe",
                        os.path.realpath(sys.executable),
                        "--timeout-seconds",
                        "0.5",
                        "--output",
                        str(cleanup_receipt),
                        "--reject-unexpected-members",
                    ],
                    env=cleanup_environment,
                    capture_output=True,
                    text=True,
                    timeout=3,
                )
                self.assertEqual(cleanup.returncode, 0, cleanup.stderr)
                inventory = json.loads(cleanup_receipt.read_text(encoding="utf-8"))
                self.assertIn(child_pid, inventory["initial_members"])
                self.assertEqual(inventory["unexpected_members"], [])
                self.assertEqual(leader.wait(timeout=2), 0)
                GUARD_MODULE.assert_session_absent(session_id, 2)
            finally:
                if leader.poll() is None:
                    leader.terminate()
                    try:
                        leader.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        leader.kill()
                        leader.wait(timeout=2)
                if leader.stderr is not None:
                    leader.stderr.close()

    def test_linux_guard_rescans_and_kills_member_forked_during_term_wait(self):
        """A child created after TERM's snapshot is caught in the KILL rescan."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory) / "runtime"
            root.mkdir(mode=0o700)
            os.environ[GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV] = str(root)
            self.addCleanup(os.environ.pop, GUARD_MODULE.TRUSTED_RUNTIME_ROOT_ENV, None)
            record = root / "session-registration.json"
            late_child_file = root / "late-child.pid"
            ready_file = root / "term-handler-ready"
            term_entered_file = root / "term-handler-entered"
            term_release_file = root / "term-handler-release"
            fork_program = (
                "import json, os, pathlib, signal, sys, time\n"
                "record = pathlib.Path(sys.argv[1])\n"
                "stat_data = pathlib.Path(f'/proc/{os.getpid()}/stat').read_text()\n"
                "start_time = stat_data.rsplit(')', 1)[1].split()[19]\n"
                "record.write_text(json.dumps({'leader_pid': os.getpid(), 'leader_start_time': start_time, 'process_group': os.getpid(), 'session_id': os.getpid()}) + '\\n')\n"
                "os.chmod(record, 0o600)\n"
                "child_path = pathlib.Path(sys.argv[2])\n"
                "ready_path = pathlib.Path(sys.argv[3])\n"
                "entered_path = pathlib.Path(sys.argv[4])\n"
                "release_path = pathlib.Path(sys.argv[5])\n"
                "def on_term(_signal, _frame):\n"
                "    entered_path.write_text('entered', encoding='ascii')\n"
                "    while not release_path.exists():\n"
                "        time.sleep(0.01)\n"
                "    late_child = os.fork()\n"
                "    if late_child:\n"
                "        child_path.write_text(str(late_child), encoding='ascii')\n"
                "        os._exit(0)\n"
                "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "    while True:\n"
                "        time.sleep(1)\n"
                "first_child = os.fork()\n"
                "if first_child:\n"
                "    while True:\n"
                "        time.sleep(1)\n"
                "signal.signal(signal.SIGTERM, on_term)\n"
                "ready_path.write_text('ready', encoding='ascii')\n"
                "while True:\n"
                "    time.sleep(1)\n"
            )
            leader = subprocess.Popen(
                [
                    sys.executable, "-c", fork_program,
                    str(record),
                    str(late_child_file),
                    str(ready_file),
                    str(term_entered_file),
                    str(term_release_file),
                ],
                start_new_session=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            session_id = None
            try:
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline and not record.exists():
                    time.sleep(0.01)
                self.assertTrue(record.is_file(), "exec-session did not register its task SID/PGID")
                registration = json.loads(record.read_text(encoding="utf-8"))
                session_id = registration["session_id"]
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline and not ready_file.exists():
                    time.sleep(0.01)
                self.assertTrue(ready_file.is_file(), "TERM handler was not ready")

                cleanup_result = {}
                cleanup_error = []

                def run_cleanup():
                    try:
                        cleanup_result["inventory"] = GUARD_MODULE.terminate_registered_session(
                            record,
                            os.path.realpath(sys.executable),
                            0.5,
                        )
                    except BaseException as exc:  # propagate the worker failure below
                        cleanup_error.append(exc)

                cleanup_thread = threading.Thread(target=run_cleanup)
                cleanup_thread.start()
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline and not term_entered_file.exists():
                    time.sleep(0.01)
                self.assertTrue(term_entered_file.is_file(), "TERM handler did not enter its deterministic barrier")
                term_release_file.write_text("release", encoding="ascii")
                cleanup_thread.join(timeout=3)
                self.assertFalse(cleanup_thread.is_alive(), "cleanup did not finish by its bounded deadline")
                if cleanup_error:
                    raise cleanup_error[0]
                inventory = cleanup_result["inventory"]
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline and not late_child_file.exists():
                    time.sleep(0.01)
                self.assertTrue(late_child_file.is_file(), "TERM handler did not create the late session member")
                late_child = int(late_child_file.read_text(encoding="ascii"))
                self.assertIn(late_child, inventory["kill_signaled"])
                self.assertIn(late_child, inventory["unexpected_members"])
                self.assertEqual(leader.wait(timeout=2), -signal.SIGTERM)
                GUARD_MODULE.assert_session_absent(session_id, 2)
                self.assertFalse(pathlib.Path(f"/proc/{late_child}/stat").exists())
            finally:
                if record.exists():
                    try:
                        GUARD_MODULE.terminate_registered_session(
                            record,
                            os.path.realpath(sys.executable),
                            0.5,
                        )
                    except GUARD_MODULE.GuardFailure:
                        pass
                if leader.poll() is None:
                    leader.kill()
                    leader.wait(timeout=2)
                if session_id is not None:
                    try:
                        GUARD_MODULE.assert_session_absent(session_id, 2)
                    except GUARD_MODULE.GuardFailure:
                        pass
                if leader.stderr is not None:
                    leader.stderr.close()

    def test_upstream_rejects_wrong_request_path(self):
        left, right = socket.socketpair()
        try:
            left.sendall(b"POST /other HTTP/1.1\r\nHost: test\r\n\r\n")
            deadline = time.monotonic() + 1
            with self.assertRaises(PROBE_MODULE.ProbeFailure):
                PROBE_MODULE._read_request(right, "/p4/close/", deadline)
        finally:
            left.close()
            right.close()



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
