"""Finite-wire client regressions; these do not claim a native NGINX EOS."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch


SCRIPT = source_path("ci/runtime/lifecycle/i12/nginx/wire_client.py")
CLIENT = load_source(SCRIPT)
RUN_ROOT = Path("/var/tmp/codex/ModSecurity-conector/runs")
RUNNER = load_source(SCRIPT.with_name("run_cases.py"))


def response(headers, body=b"", status=b"HTTP/1.1 200 OK"):
    return status + b"\r\n" + headers + b"\r\n\r\n" + body


class FiniteFramingTests(unittest.TestCase):
    def test_content_length_preserves_binary_entity(self):
        body = b"\x00\xffa\r\nb"
        wire = response(b"cOnTeNt-LeNgTh: 6", body)
        status, headers, actual, framing = CLIENT.entity(wire)
        self.assertEqual((status, actual, framing), (200, body, "http1.1-content-length"))
        self.assertEqual(headers + actual, wire)

    def test_empty_finite_entity(self):
        self.assertEqual(CLIENT.entity(response(b"Content-Length: 0"))[2], b"")

    def test_content_length_rejects_incomplete_and_ambiguous(self):
        for headers, body in [
            (b"Content-Length: 4", b"abc"),
            (b"Content-Length: 2", b"abc"),
            (b"Content-Length: 3\r\nContent-Length: 3", b"abc"),
            (b"Content-Length: 3, 3", b"abc"),
            (b"Content-Length: -0", b""),
            (b"Content-Length: +3", b"abc"),
            (b"Content-Length: 0_3", b"abc"),
            (b"Connection: close", b"abc"),
        ]:
            wire = response(headers, body)
            with self.subTest(headers=headers, body=body), self.assertRaises(ValueError):
                CLIENT.entity(wire)

    def test_chunked_decodes_only_complete_terminal_framing(self):
        parsed = CLIENT.entity(response(b"Transfer-Encoding: chunked", b"2\r\nab\r\n1\r\nc\r\n0\r\n\r\n"))
        self.assertEqual((parsed[0], parsed[2], parsed[3]), (200, b"abc", "http1.1-chunked"))
        self.assertEqual(CLIENT.entity(response(b"Transfer-Encoding: chunked", b"0\r\n\r\n"))[2], b"")

    def test_chunked_rejects_truncation_and_unsupported_forms(self):
        for body in (b"", b"3", b"3\r\nab", b"3\r\nabc", b"3\r\nabc\r\n", b"0\r\n",
                     b"0\r\n\r\nextra", b"0\r\nTrailer: value\r\n\r\n", b"1;x=1\r\na\r\n0\r\n\r\n",
                     b"+1\r\na\r\n0\r\n\r\n", b"-1\r\n0\r\n\r\n"):
            wire = response(b"Transfer-Encoding: chunked", body)
            with self.subTest(body=body), self.assertRaises(ValueError):
                CLIENT.entity(wire)

    def test_transfer_encoding_conflicts_are_rejected(self):
        for headers in (b"Transfer-Encoding: chunked\r\nContent-Length: 0",
                        b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked",
                        b"Transfer-Encoding: gzip, chunked", b"Transfer-Encoding: identity"):
            wire = response(headers, b"0\r\n\r\n")
            with self.subTest(headers=headers), self.assertRaises(ValueError):
                CLIENT.entity(wire)


class WaitedClientTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, {"CODEX_TEMP_ROOT": str(RUN_ROOT.parent)})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def execute(self, wire):
        """Use one owned ephemeral listener, and wait for both child and server."""
        failures = []
        RUN_ROOT.mkdir(parents=True, exist_ok=True)
        with socket.socket() as listener, tempfile.TemporaryDirectory(prefix="i12-wire-", dir=RUN_ROOT) as directory:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(5)
            port = listener.getsockname()[1]

            def serve():
                try:
                    stream, _ = listener.accept()
                    with stream:
                        stream.settimeout(5)
                        request = b""
                        while b"\r\n\r\n" not in request:
                            chunk = stream.recv(4096)
                            if not chunk:
                                raise ValueError("client closed before request headers")
                            request += chunk
                        stream.sendall(wire)
                except Exception as exc:
                    failures.append(exc)

            server = threading.Thread(target=serve)
            server.start()
            root = Path(directory)
            request = root / "request.bin"
            request.write_bytes(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            try:
                process = subprocess.run(
                    ["rtk", "proxy", sys.executable, str(SCRIPT), "--port", str(port),
                     "--request", str(request), "--output", str(root / "observation")],
                    capture_output=True, timeout=15, check=False,
                    env=RUNNER.client_environment({"PATH": os.environ["PATH"],
                        "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"}),
                )
            finally:
                server.join(6)
            self.assertFalse(server.is_alive(), "owned loopback server must terminate")
            self.assertEqual(failures, [])
            output = root / "observation"
            observed = json.loads((output / "client-observation.json").read_text())
            self.assertEqual((output / "response.bin").read_bytes(), wire)
            self.assertNotIn("native_eos", observed)
            return process, observed

    def test_filtered_client_environment_only_adds_validated_storage_anchor(self):
        filtered = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "LD_LIBRARY_PATH": "/mnt/artifacts/lib"}
        with patch.dict(os.environ, {"UNRELATED_PRIVATE_VALUE": "must-not-propagate"}):
            actual = RUNNER.client_environment(filtered)
        self.assertEqual(actual, {**filtered, "CODEX_TEMP_ROOT": str(RUN_ROOT.parent)})
        self.assertNotIn("CODEX_TEMP_ROOT", filtered)
        with patch.dict(os.environ, {"CODEX_TEMP_ROOT": ""}):
            with self.assertRaises(ValueError):
                RUNNER.client_environment(filtered)

    def test_client_paths_reject_escape_symlink_and_reused_output(self):
        RUN_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="i12-wire-boundary-", dir=RUN_ROOT) as directory:
            root = Path(directory)
            request = root / "request.bin"
            request.write_bytes(b"request")
            link = root / "link.bin"
            link.symlink_to(request)
            for invalid in (link, root, root / ".." / "escape", Path("/etc/passwd")):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    CLIENT.artifact_path(invalid)
            with self.assertRaises(ValueError):
                CLIENT.artifact_path(root, fresh=True)
            request.chmod(0o666)
            with self.assertRaises(ValueError):
                CLIENT.artifact_path(request)
            request.chmod(0o1666)
            with self.assertRaises(ValueError):
                CLIENT.artifact_path(request)
            request.chmod(0o600)
            root.chmod(0o1777)
            try:
                with self.assertRaises(ValueError):
                    CLIENT.artifact_path(request)
                with self.assertRaises(ValueError):
                    CLIENT.artifact_path(root / "fresh", fresh=True)
            finally:
                root.chmod(0o700)

    def test_client_storage_anchor_is_explicit_private_and_canonical(self):
        RUN_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="i12-wire-anchor-", dir=RUN_ROOT) as directory:
            root = Path(directory)
            for invalid in ("", "relative", str(root) + "/", str(root / ".." / "escape"), "/"):
                with self.subTest(invalid=invalid), patch.dict(os.environ, {"CODEX_TEMP_ROOT": invalid}):
                    with self.assertRaises(ValueError):
                        CLIENT.storage_root()
            with patch.dict(os.environ, {"CODEX_TEMP_ROOT": str(root)}):
                self.assertEqual(CLIENT.storage_root(), root)
                root.chmod(0o1777)
                try:
                    with self.assertRaises(ValueError):
                        CLIENT.storage_root()
                finally:
                    root.chmod(0o700)

    def test_complete_response_is_waited_and_eof_is_transport_only(self):
        process, observed = self.execute(response(b"Content-Length: 3", b"abc"))
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertTrue(observed["framing_complete"])
        self.assertTrue(observed["socket_eof"])
        self.assertIsNone(observed["error"])
        self.assertEqual(observed["body_bytes"], 3)
        self.assertLessEqual(observed["first_response_monotonic_ns"], observed["finished_monotonic_ns"])

    def test_eof_does_not_qualify_incomplete_content_length(self):
        process, observed = self.execute(response(b"Content-Length: 4", b"abc"))
        self.assertEqual(process.returncode, 2, process.stderr)
        self.assertTrue(observed["socket_eof"])
        self.assertFalse(observed["framing_complete"])
        self.assertEqual(observed["fragment_bytes"], 3)

    def test_eof_does_not_supply_chunked_terminator(self):
        process, observed = self.execute(response(b"Transfer-Encoding: chunked", b"3\r\nabc\r\n"))
        self.assertEqual(process.returncode, 2, process.stderr)
        self.assertTrue(observed["socket_eof"])
        self.assertFalse(observed["framing_complete"])

    def test_complete_chunked_response(self):
        process, observed = self.execute(response(b"Transfer-Encoding: chunked", b"3\r\nabc\r\n0\r\n\r\n"))
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(observed["body_bytes"], 3)
        self.assertTrue(observed["framing_complete"])

    def test_malformed_status_still_retains_observation(self):
        process, observed = self.execute(response(b"Content-Length: 0", status=b"HTTP/1.1 broken"))
        self.assertEqual(process.returncode, 2, process.stderr)
        self.assertFalse(observed["framing_complete"])
        self.assertIsNotNone(observed["error"])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
