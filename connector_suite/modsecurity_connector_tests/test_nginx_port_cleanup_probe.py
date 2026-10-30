"""Exercise the actual NGINX cleanup port check with live kernel sockets."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import errno
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
import unittest


HARNESS = connector_root() / "connectors/nginx/harness/run_nginx_smoke.sh"


def shell_function(source: str, name: str) -> str:
    start = source.index(f"{name}() {{\n")
    search_start = start
    if name in {"port_is_free", "cleanup_port_is_free"}:
        search_start = source.index("\nPY\n", start) + 4
    return source[start:source.index("\n}\n", search_start) + 3]


def cleanup_port_function() -> str:
    source = HARNESS.read_text(encoding="utf-8")
    cleanup = shell_function(source, "record_nginx_cleanup_state")
    match = re.search(r'if ([a-z_]+) "\$PORT"; then', cleanup)
    if match is None:
        raise AssertionError("cleanup port check call not found")
    return shell_function(source, match.group(1)) + f'\n{match.group(1)} "$PORT"\n'


def tcp_states(port: int) -> list[str]:
    states = []
    with Path("/proc/net/tcp").open(encoding="ascii") as table:
        next(table)
        for line in table:
            fields = line.split()
            local_address, local_port = fields[1].split(":")
            if int(local_port, 16) == port and local_address in {"0100007F", "00000000"}:
                states.append(fields[3])
    return states


def bind_errno(port: int, *, reuseaddr: bool) -> int | None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        if reuseaddr:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError as error:
            return error.errno
    return None


class NginxPortCleanupProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.function = cleanup_port_function()

    def probe(self, port: int, protocol: str = "http1") -> tuple[subprocess.CompletedProcess[str], dict]:
        env = {
            "PATH": os.defpath,
            "PYTHON_BIN": sys.executable,
            "PORT": str(port),
            "NGINX_DOWNSTREAM_PROTOCOL": protocol,
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        result = subprocess.run(
            ["sh", "-eu", "-c", self.function], env=env, text=True,
            capture_output=True, check=False, timeout=10,
        )
        records = [json.loads(line.removeprefix("nginx_port_cleanup_probe "))
                   for line in result.stderr.splitlines()
                   if line.startswith("nginx_port_cleanup_probe ")]
        self.assertLessEqual(len(records), 1, result.stderr)
        return result, records[0] if records else {}

    @staticmethod
    def recently_closed_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
            listener.listen(1)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.connect(("127.0.0.1", port))
                with listener.accept()[0] as accepted:
                    accepted.shutdown(socket.SHUT_WR)
                    self_eof = client.recv(1)
                    if self_eof != b"":
                        raise AssertionError("accepted side did not initiate TCP close")
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if "06" in tcp_states(port):
                return port
            time.sleep(0.01)
        raise AssertionError(f"TIME_WAIT not observed on {port}: {tcp_states(port)}")

    def test_time_wait_does_not_mean_live_listener(self) -> None:
        port = self.recently_closed_port()
        self.assertNotIn("0A", tcp_states(port))
        self.assertEqual(bind_errno(port, reuseaddr=False), errno.EADDRINUSE)
        self.assertIsNone(bind_errno(port, reuseaddr=True))
        result, diagnostic = self.probe(port)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(diagnostic.get("result"), "freed")
        self.assertGreaterEqual(diagnostic.get("tcp_time_wait", 0), 1)
        self.assertEqual(diagnostic.get("tcp_listeners"), 0)

    def test_free_ipv4_port_is_accepted_in_current_namespace(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as temporary:
            temporary.bind(("127.0.0.1", 0))
            port = temporary.getsockname()[1]
        result, diagnostic = self.probe(port)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(diagnostic.get("result"), "freed")
        self.assertEqual(diagnostic.get("netns"), os.readlink("/proc/self/ns/net"))
        self.assertEqual(diagnostic.get("family"), "AF_INET")
        self.assertEqual(diagnostic.get("address"), "127.0.0.1")
        self.assertIs(diagnostic.get("tcp_reuseaddr"), True)

    def test_live_loopback_listener_is_rejected(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            self.assertIn("0A", tcp_states(port))
            result, diagnostic = self.probe(port)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(diagnostic.get("result"), "listener_present")
            self.assertGreaterEqual(diagnostic.get("tcp_listeners", 0), 1)
            self.assertEqual(diagnostic.get("tcp_bind"), "skipped")

    def test_wildcard_listener_is_rejected(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("0.0.0.0", 0))
            listener.listen(1)
            result, diagnostic = self.probe(listener.getsockname()[1])
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(diagnostic.get("result"), "listener_present")

    def test_invalid_port_fails_closed_with_diagnostic(self) -> None:
        result, diagnostic = self.probe(0)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(diagnostic.get("result"), "inspection_failed")
        self.assertEqual(diagnostic.get("inspection_error"), "ValueError")

    def test_foreign_process_listener_is_rejected_without_killing_it(self) -> None:
        child = subprocess.Popen(
            [sys.executable, "-u", "-c", "import socket,sys; "
             "s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(1); "
             "print(s.getsockname()[1],flush=True); sys.stdin.read()"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env={"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        try:
            assert child.stdout is not None
            port = int(child.stdout.readline().strip())
            result, diagnostic = self.probe(port)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(diagnostic.get("result"), "listener_present")
            self.assertIsNone(child.poll(), "cleanup probe must not kill a foreign listener")
        finally:
            if child.stdin is not None:
                child.stdin.close()
            child.wait(timeout=5)
            if child.stdout is not None:
                child.stdout.close()
            if child.stderr is not None:
                child.stderr.close()

    def test_http3_udp_port_remains_required(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.bind(("127.0.0.1", 0))
            port = udp.getsockname()[1]
            result, diagnostic = self.probe(port, "h3")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(diagnostic.get("result"), "udp_bind_failed")
            self.assertEqual(diagnostic.get("udp_bind_errno"), errno.EADDRINUSE)

    def test_ipv6_only_listener_does_not_block_ipv4_loopback(self) -> None:
        if not socket.has_ipv6:
            self.skipTest("IPv6 unavailable")
        try:
            listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            listener.bind(("::1", 0))
        except OSError as error:
            self.skipTest(f"IPv6-only loopback unavailable: {error}")
        with listener:
            listener.listen(1)
            port = listener.getsockname()[1]
            result, diagnostic = self.probe(port)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(diagnostic.get("result"), "freed")

    def test_dual_stack_listener_cannot_be_hidden_by_reuseaddr(self) -> None:
        if not socket.has_ipv6:
            self.skipTest("IPv6 unavailable")
        try:
            listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            listener.bind(("::", 0))
        except OSError as error:
            self.skipTest(f"dual-stack listener unavailable: {error}")
        with listener:
            listener.listen(1)
            port = listener.getsockname()[1]
            self.assertEqual(bind_errno(port, reuseaddr=True), errno.EADDRINUSE)
            result, diagnostic = self.probe(port)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(diagnostic.get("result"), "tcp_bind_failed")
            self.assertEqual(diagnostic.get("tcp_bind_errno"), errno.EADDRINUSE)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
