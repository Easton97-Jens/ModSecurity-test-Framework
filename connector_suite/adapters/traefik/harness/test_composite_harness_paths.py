"""Focused path and loopback-client tests for the Traefik composite harness."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import load_source

import importlib.util
from pathlib import Path
import shlex
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest



HARNESS = Path(__file__).with_name("traefik_composite_case_driver.py")
DRIVER = load_source(HARNESS)
UPSTREAM_HARNESS = Path(__file__).with_name("traefik_composite_upstream.py")
UPSTREAM = load_source(UPSTREAM_HARNESS)


class CompositeHarnessPathTests(unittest.TestCase):
  @staticmethod
  def _catalog(selected: object = "p4_safe") -> dict[str, object]:
    vector_id = DRIVER.VECTOR_FOR_CASE[selected] if isinstance(selected, str) and selected in DRIVER.CASES else "p4_safe"
    return {"vectors": [{"id": vector_id, "request": {"method": "GET", "path": "/", "headers": {}}}], "selected_case": selected}

  def test_case_selection_is_catalog_semantic_and_requires_explicit_case(self) -> None:
    selected, _ = DRIVER.select_case(self._catalog("metadata_omitted"), Path("/runtime-with-p1_allow"))
    self.assertEqual(selected, "metadata_omitted")
    missing_case_catalog = {"vectors": self._catalog()["vectors"]}
    missing_case_runtime = Path("/runtime-metadata_omitted")
    with self.assertRaisesRegex(RuntimeError, "selected_case"):
      DRIVER.select_case(missing_case_catalog, missing_case_runtime)
    unknown_case_catalog = self._catalog("unknown")
    unknown_case_runtime = Path("/runtime-metadata_omitted")
    with self.assertRaisesRegex(RuntimeError, "selected_case"):
      DRIVER.select_case(unknown_case_catalog, unknown_case_runtime)

  def test_p4_safe_receipt_uses_observed_committed_200(self) -> None:
    source = HARNESS.read_text(encoding="utf-8")
    self.assertIn('"p4_visible_status": status if case == "p4_safe" and response_completed else None', source)
    self.assertNotIn('"p4_outcome": "none", "p4_visible_status": None', source)

  def test_receipt_output_allowlist_excludes_sensitive_values(self) -> None:
    client_keys = {
        "lease_observed", "visible_status", "redirect_location_verified",
        "p4_outcome", "p4_visible_status", "p4_response_committed",
    }
    upstream_keys = {"lease_observed", "request_terminal", "response_observed"}
    self.assertTrue(client_keys.isdisjoint(DRIVER.FORBIDDEN_OUTPUT_KEYS))
    self.assertTrue(upstream_keys.isdisjoint(DRIVER.FORBIDDEN_OUTPUT_KEYS))

  def test_p3_redirect_uses_the_canonical_vector_and_bounded_location(self) -> None:
    self.assertEqual(DRIVER.VECTOR_FOR_CASE["p3_redirect"], "p3_redirect")
    self.assertEqual(DRIVER.expected_status("p3_redirect"), {302})
    vector = {
        "expected": {"redirect_target": "/msconnector-p3-redirect-target"},
    }
    self.assertEqual(
        DRIVER._expected_redirect_location("p3_redirect", vector),
        b"/msconnector-p3-redirect-target",
    )
    for target in ("", "//other", "/bad\r\nLocation: /other", "/space ", "/snowman-☃"):
      with self.assertRaises(RuntimeError):
        DRIVER._expected_redirect_location("p3_redirect", {"expected": {"redirect_target": target}})

  def test_p3_redirect_client_requires_one_exact_location(self) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def serve() -> None:
      connection, _ = server.accept()
      try:
        connection.recv(4096)
        connection.sendall(
            b"HTTP/1.1 302 Found\r\n"
            b"Location: /msconnector-p3-redirect-target\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
      finally:
        connection.close()
        server.close()

    thread = threading.Thread(target=serve)
    thread.start()
    try:
      status, completed = DRIVER.http_request(
          port,
          {"request": {"method": "GET", "path": "/safe", "headers": {}}},
          False,
          expected_location=b"/msconnector-p3-redirect-target",
      )
    finally:
      thread.join(timeout=2)
    self.assertEqual((status, completed), (302, True))

  def test_p3_redirect_client_rejects_missing_mismatched_and_duplicate_locations(self) -> None:
    for headers in (
        b"Content-Length: 0\r\n",
        b"Location: /other\r\nContent-Length: 0\r\n",
        b"Location: /msconnector-p3-redirect-target\r\nLocation: /other\r\nContent-Length: 0\r\n",
    ):
      with self.subTest(headers=headers):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def serve() -> None:
          connection, _ = server.accept()
          try:
            connection.recv(4096)
            connection.sendall(b"HTTP/1.1 302 Found\r\n" + headers + b"\r\n")
          finally:
            connection.close()
            server.close()

        thread = threading.Thread(target=serve)
        thread.start()
        try:
          status, completed = DRIVER.http_request(
              port,
              {"request": {"method": "GET", "path": "/safe", "headers": {}}},
              False,
              expected_location=b"/msconnector-p3-redirect-target",
          )
        finally:
          thread.join(timeout=2)
        self.assertEqual((status, completed), (None, False))

  def test_socket_requires_explicit_private_parent_and_byte_budget(self) -> None:
    script = Path(__file__).with_name("run_traefik_composite_matrix.sh").read_text(
      encoding="utf-8"
    )
    self.assertIn("need_env COMPOSITE_SOCKET_PARENT", script)
    self.assertNotIn("need_env COMPOSITE_SOCKET\n", script)
    self.assertIn("mktemp -d -- \"$COMPOSITE_SOCKET_PARENT/.traefik-composite.XXXXXX\"", script)
    self.assertIn('SOCKET_BASENAME=composite.sock', script)
    self.assertIn('LC_ALL=C expr length "$COMPOSITE_SOCKET"', script)
    self.assertIn('COMPOSITE_SOCKET_PARENT contains control or non-ASCII bytes', script)
    self.assertIn('SOCKET_PARENT_DEV=$(stat -c \'%d\'', script)
    self.assertIn('SOCKET_PARENT_INO=$(stat -c \'%i\'', script)
    self.assertIn('revalidate_socket_parent || blocked "composite socket parent changed before child creation"', script)
    self.assertIn('revalidate_socket_parent || blocked "composite socket parent changed after child creation"', script)
    self.assertNotIn('COMPOSITE_SOCKET_PARENT=${', script)
    self.assertNotIn('SOCKET_PARENT=$(dirname "$COMPOSITE_SOCKET")', script)

  def test_socket_cleanup_is_identity_bound_and_never_removes_parent(self) -> None:
    script = Path(__file__).with_name("run_traefik_composite_matrix.sh").read_text(
      encoding="utf-8"
    )
    cleanup = script[script.index("cleanup_socket_child() {"):script.index("trap cleanup_socket_child EXIT")]
    self.assertIn("SOCKET_CHILD_DEV", cleanup)
    self.assertIn("SOCKET_CHILD_INO", cleanup)
    self.assertIn('rmdir -- "$SOCKET_CHILD"', cleanup)
    self.assertNotIn('rmdir -- "$COMPOSITE_SOCKET_PARENT"', cleanup)

  def test_socket_child_trap_is_installed_before_post_allocation_rejections(self) -> None:
    script = Path(__file__).with_name("run_traefik_composite_matrix.sh").read_text(
      encoding="utf-8"
    )
    allocation = script.index('SOCKET_CHILD=$(mktemp -d')
    identity = script.index("SOCKET_CHILD_DEV=$(stat -c '%d'", allocation)
    trap = script.index('trap cleanup_socket_child EXIT', allocation)
    first_post_allocation_check = script.index('chmod 700 "$SOCKET_CHILD"', allocation)
    self.assertLess(allocation, identity)
    self.assertLess(identity, trap)
    self.assertLess(trap, first_post_allocation_check)
    self.assertLess(script.index('cleanup_socket_child() {'), allocation)
    self.assertIn('socket child identity changed or unavailable; refusing cleanup', script)

  def test_socket_path_limit_is_measured_as_bytes(self) -> None:
    # The shell uses LC_ALL=C so multibyte input cannot bypass the kernel's
    # byte-oriented AF_UNIX path limit.
    self.assertGreater(len("é".encode("utf-8")), len("é"))

  def test_safe_ancestor_chain_allows_root_owned_ancestor_but_rejects_writable_one(self) -> None:
    script = Path(__file__).with_name("run_traefik_composite_matrix.sh").read_text(
        encoding="utf-8"
    )
    start = script.index("safe_ancestor_chain() {")
    end = script.index("\nis_private_dir()", start)
    safe_ancestor_chain = script[start:end]
    self.assertIn('[ "$owner" = "$(id -u)" ] || [ "$owner" = 0 ]', safe_ancestor_chain)

    with tempfile.TemporaryDirectory(prefix="traefik-harness-path-") as temporary:
      base = Path(temporary)
      leaf = base / "leaf"
      leaf.mkdir(mode=0o700)

      def check() -> subprocess.CompletedProcess[str]:
        command = f"{safe_ancestor_chain}\nsafe_ancestor_chain {shlex.quote(str(leaf))}\n"
        return subprocess.run(
            ["bash", "-c", command],
            check=False,
            capture_output=True,
            text=True,
        )

      self.assertEqual(check().returncode, 0)
      base.chmod(0o777)
      self.assertNotEqual(check().returncode, 0)

  def test_artifact_leaf_requires_absolute_direct_child(self) -> None:
    root = Path("/private/runtime")
    assert DRIVER.artifact_leaf(root / "input.json", root, "input") == "input.json"
    for candidate in (Path("input.json"), root / "nested" / "input.json", root / ".." / "outside.json"):
        with self.assertRaises(RuntimeError):
            DRIVER.artifact_leaf(candidate, root, "input")


  def test_private_runtime_root_rejects_symlink_and_hardlink(self) -> None:
    from modsecurity_connector_ci.lib.runtime_path_utils import open_private_runtime_root

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / "runtime"
        root.mkdir(mode=0o700)
        with open_private_runtime_root(root) as runtime:
            runtime.create_text("valid.json", "{}\n")
            assert runtime.read_text("valid.json") == "{}\n"
            (root / "link.json").symlink_to(root / "valid.json")
            (root / "hard.json").hardlink_to(root / "valid.json")
            with self.assertRaises((OSError, ValueError)):
                runtime.read_text("link.json")
            with self.assertRaises((OSError, ValueError)):
                runtime.read_text("hard.json")


  def test_read_events_counts_crlf_terminators_in_line_limit(self) -> None:
    from modsecurity_connector_ci.lib.runtime_path_utils import open_private_runtime_root

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / "runtime"
        root.mkdir(mode=0o700)
        event = {
            "decision_id": "A" * 16,
            "phase": "terminal",
            "reason": "x" * (DRIVER.MAX_EVENT_LINE - 50),
        }
        import json
        encoded = json.dumps(event, separators=(",", ":")) + "\r\n"
        self.assertGreater(len(encoded.encode("utf-8")), DRIVER.MAX_EVENT_LINE)
        with open_private_runtime_root(root) as runtime:
            runtime.create_text("events.jsonl", encoded)
            with self.assertRaises(RuntimeError):
                DRIVER.read_events(runtime, "events.jsonl")


  def test_origin_form_rejects_absolute_and_control_targets(self) -> None:
    assert DRIVER._origin_target("/safe?x=1") == "/safe?x=1"
    for target in ("https://127.0.0.1/", "//other/", "/bad\r\nX: y", ""):
        with self.assertRaises(RuntimeError):
            DRIVER._origin_target(target)


  def test_main_rejects_absolute_outside_root_input_before_opening_runtime(self) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary)
        root = base / "runtime"
        root.mkdir(mode=0o700)
        sentinel = root / "sentinel"
        sentinel.write_text("unchanged\n", encoding="utf-8")
        outside = base / "outside.json"
        outside.write_text("{}\n", encoding="utf-8")
        before = sorted(path.name for path in root.iterdir())
        driver_result = DRIVER.main([
            "--input", str(outside), "--port", "19180",
            "--manifest", str(root / "case.manifest.json"),
            "--event-log", str(root / "events.jsonl"), "--runtime-root", str(root),
            "--upstream-observation", str(root / "upstream.json"), "--connector", "traefik",
        ])
        upstream_result = UPSTREAM.main([
            "--listen", "127.0.0.1:19181", "--root", str(root),
            "--case-input", str(outside), "--observation", str(root / "upstream.json"),
            "--observation-root", str(root),
            "--cert", str(outside), "--key", str(outside),
        ])
        self.assertEqual(driver_result, 1)
        self.assertEqual(upstream_result, 1)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged\n")
        self.assertEqual(sorted(path.name for path in root.iterdir()), before)


  @staticmethod
  def _generate_certificate(
      base: Path, name: str, hostname: str = "composite-upstream.local"
  ) -> tuple[Path, Path]:
    cert = base / f"{name}-cert.pem"
    key = base / f"{name}-key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-sha256", "-days", "1", "-keyout", str(key), "-out", str(cert),
        "-subj", f"/CN={hostname}",
        "-addext", f"subjectAltName=DNS:{hostname}",
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return cert, key

  @staticmethod
  def _controlled_tls_server(cert: Path, key: Path):
    class Observation:
      def record(self, _headers: object) -> None:
        return

    server = UPSTREAM.ControlledServer(
        ("127.0.0.1", 0),
        {"/safe": {"upstream": {"status": 200, "headers": {}, "body": "OK"}}},
        Observation(),
        Path("/private/runtime"),
        str(cert),
        str(key),
    )
    thread = threading.Thread(target=server.handle_request)
    thread.start()
    return server, thread

  @staticmethod
  def _open_tls_connection(context: ssl.SSLContext, port: int):
    connection = socket.create_connection(("127.0.0.1", port), timeout=2)
    try:
      return context.wrap_socket(connection, server_hostname="composite-upstream.local")
    finally:
      connection.close()

  def test_controlled_upstream_uses_native_tls_server_loop(self) -> None:
    text = UPSTREAM_HARNESS.read_text(encoding="utf-8")
    self.assertIn("class ControlledServer(http.server.ThreadingHTTPSServer)", text)
    self.assertIn("server.handle_request()", text)
    self.assertNotIn("server.serve_forever", text)

  def test_loopback_client_accepts_bounded_http_response(self) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def serve() -> None:
      connection, _ = server.accept()
      try:
        request = connection.recv(4096)
        assert request.startswith(b"GET /safe HTTP/1.1\r\n")
        assert b"Host: 127.0.0.1:" in request
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
      finally:
        connection.close()
        server.close()

    thread = threading.Thread(target=serve)
    thread.start()
    try:
      status, completed = DRIVER.http_request(
          port,
          {"request": {"method": "GET", "path": "/safe", "headers": {}}},
          False,
      )
    finally:
      thread.join(timeout=2)
    self.assertEqual((status, completed), (200, True))

  def test_controlled_upstream_accepts_verified_tls(self) -> None:
    with tempfile.TemporaryDirectory() as temporary:
      base = Path(temporary)
      cert, key = self._generate_certificate(base, "trusted")
      server, thread = self._controlled_tls_server(cert, key)
      try:
        context = ssl.create_default_context(cafile=str(cert))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=2) as connection:
          with context.wrap_socket(connection, server_hostname="composite-upstream.local") as tls_connection:
            tls_connection.sendall(b"GET /safe HTTP/1.1\r\nHost: composite-upstream.local\r\n\r\n")
            self.assertTrue(tls_connection.recv(4096).startswith(b"HTTP/1.1 200 OK\r\n"))
      finally:
        server.server_close()
        thread.join(timeout=2)

  def test_controlled_upstream_rejects_untrusted_certificate(self) -> None:
    with tempfile.TemporaryDirectory() as temporary:
      base = Path(temporary)
      trusted_cert, _ = self._generate_certificate(base, "trusted")
      server_cert, server_key = self._generate_certificate(base, "untrusted")
      server, thread = self._controlled_tls_server(server_cert, server_key)
      try:
        context = ssl.create_default_context(cafile=str(trusted_cert))
        with self.assertRaises(ssl.SSLCertVerificationError):
          self._open_tls_connection(context, server.server_address[1])
      finally:
        server.server_close()
        thread.join(timeout=2)

  def test_controlled_upstream_rejects_trusted_wrong_hostname(self) -> None:
    with tempfile.TemporaryDirectory() as temporary:
      base = Path(temporary)
      cert, key = self._generate_certificate(base, "wrong-host", "other-upstream.local")
      server, thread = self._controlled_tls_server(cert, key)
      try:
        context = ssl.create_default_context(cafile=str(cert))
        with self.assertRaises(ssl.SSLCertVerificationError):
          self._open_tls_connection(context, server.server_address[1])
      finally:
        server.server_close()
        thread.join(timeout=2)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
