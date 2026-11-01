"""Opt-in process regression coverage for the shared HTTP authorization service.

Set MSCONNECTOR_AUTHORIZATION_SERVICE_BINARY and
MSCONNECTOR_AUTHORIZATION_SERVICE_CONFIG to a locally built connector service
and its resolved runtime configuration.  The test deliberately avoids a host
proxy: it validates the connector-owned listener/worker lifecycle first.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import os
import selectors
import socket
import subprocess
import unittest
from pathlib import Path


ROOT = connector_root()
BINARY = os.environ.get("MSCONNECTOR_AUTHORIZATION_SERVICE_BINARY", "")
CONFIG = os.environ.get("MSCONNECTOR_AUTHORIZATION_SERVICE_CONFIG", "")


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _read_ready_line(process: subprocess.Popen[str], timeout: float) -> str:
    if process.stdout is None:
        raise AssertionError("service stdout pipe is unavailable")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        events = selector.select(timeout)
    finally:
        selector.close()
    if not events:
        raise AssertionError("service did not report readiness before its deadline")
    line = process.stdout.readline()
    if not line:
        raise AssertionError("service exited before reporting readiness")
    return line


def _request(port: int, headers: list[tuple[str, str]]) -> bytes:
    request_headers = ["GET / HTTP/1.1", "Host: example.test", "Connection: close"]
    request_headers.extend(f"{name}: {value}" for name, value in headers)
    raw_request = ("\r\n".join(request_headers) + "\r\n\r\n").encode("ascii")
    response = bytearray()
    with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
        connection.sendall(raw_request)
        connection.settimeout(2)
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
    return bytes(response)


@unittest.skipUnless(BINARY and CONFIG, "set built service binary and resolved config")
class HttpAuthorizationServiceRuntimeTests(unittest.TestCase):
    def test_closed_peer_isolated_from_allow_block_controls_and_listener_cleanup(self) -> None:
        binary = Path(BINARY)
        config = Path(CONFIG)
        self.assertTrue(binary.is_file() and os.access(binary, os.X_OK), binary)
        self.assertTrue(config.is_file(), config)
        port = _free_loopback_port()
        process = subprocess.Popen(
            [
                str(binary),
                "--serve",
                "--config",
                str(config),
                "--listen",
                f"127.0.0.1:{port}",
                "--max-requests",
                "3",
            ],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            ready = _read_ready_line(process, 5)
            self.assertIn("status=ready", ready)

            # Close during an incomplete request.  The service attempts its
            # bounded error response on this peer only; a SIGPIPE/EPIPE must
            # not terminate the listener or consume a later control request.
            with socket.create_connection(("127.0.0.1", port), timeout=2) as peer:
                peer.sendall(b"GET / HTTP/1.1\r\nHost: incomplete.example\r\n")

            allow = _request(port, [("X-Request-Id", "runtime-control-allow")])
            self.assertTrue(allow.startswith(b"HTTP/1.1 200 "), allow)
            block = _request(
                port,
                [
                    ("X-Request-Id", "runtime-control-block"),
                    ("X-Modsec-Smoke", "block"),
                ],
            )
            self.assertTrue(block.startswith(b"HTTP/1.1 403 "), block)
            stdout, stderr = process.communicate(timeout=8)
        except BaseException:
            process.terminate()
            try:
                process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=3)
            raise

        self.assertEqual(process.returncode, 0, f"stdout={stdout!r}\nstderr={stderr!r}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(1)
            self.assertNotEqual(probe.connect_ex(("127.0.0.1", port)), 0)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
