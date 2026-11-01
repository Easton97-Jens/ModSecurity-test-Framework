"""An explicit missing Content-Type must not become a default or empty header."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from urllib.request import build_opener, ProxyHandler

ROOT = connector_root()
MODULE = load_source(source_path('ci/runtime/common/response_fixture_omission.py', root=ROOT))
BACKEND = load_source(source_path('ci/runtime/common/response-header-test-backend.py', root=ROOT))


class ResponseFixtureOmissionTests(unittest.TestCase):
    def test_real_wire_content_type_is_missing_not_empty_or_default(self):
        with tempfile.TemporaryDirectory(prefix="omitted-header-", dir="/var/tmp/codex/ModSecurity-conector/analysis") as temporary:
            root = Path(temporary)
            source = root / "fixture.json"
            source.write_text(json.dumps({"status": 200, "headers": [], "omit_headers": ["Content-Type"]}))
            fixture = BACKEND.response_fixture(status=None, headers=None, fixture_file=source, safe_roots=[root])
            class Handler(BACKEND.Handler):
                body_bytes = b"bounded-fixture"
            Handler.fixture = fixture
            server = BACKEND.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with build_opener(ProxyHandler({})).open(f"http://127.0.0.1:{server.server_port}/", timeout=2) as response:
                    self.assertEqual(response.status, 200)
                    self.assertIsNone(response.headers.get_all("Content-Type"))
                    self.assertEqual(response.read(), b"bounded-fixture")
                    self.assertEqual(response.headers["Content-Length"], "15")
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()
                self.assertFalse(thread.is_alive())

    def test_missing_header_contract_is_explicit_and_closed(self):
        self.assertEqual(MODULE.validate_omitted_headers(["Content-Type"], []), ("content-type",))
        self.assertEqual(MODULE.validate_omitted_headers([], ["Content-Type"]), ())

    def test_framing_and_other_headers_cannot_be_suppressed(self):
        for value in (["Content-Length"], ["Transfer-Encoding"], ["Connection"],
                      ["Server"], ["Content-Type\n"], ["content-type"],
                      ["Content-Type", "Content-Type"], None, "Content-Type"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                MODULE.validate_omitted_headers(value, [])

    def test_configured_empty_or_nonempty_content_type_conflicts(self):
        for name in ("Content-Type", "content-type", "CONTENT-TYPE"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                MODULE.validate_omitted_headers(["Content-Type"], [name])

    def test_backend_validates_json_and_cli_conflicts_before_serving(self):
        with tempfile.TemporaryDirectory(prefix="omission-conflict-", dir="/var/tmp/codex/ModSecurity-conector/analysis") as temporary:
            root = Path(temporary)
            source = root / "fixture.json"
            for headers in ([["Content-Type", ""]], [["Content-Type", "text/plain"]]):
                source.write_text(json.dumps({"status": 200, "headers": headers, "omit_headers": ["Content-Type"]}))
                with self.subTest(headers=headers), self.assertRaises(ValueError):
                    BACKEND.response_fixture(status=None, headers=None, fixture_file=source, safe_roots=[root])
            source.write_text(json.dumps({"status": 200, "headers": [], "omit_headers": ["Content-Type"]}))
            with self.assertRaises(ValueError):
                BACKEND.response_fixture(status=None, headers=[("Content-Type", "")], fixture_file=source, safe_roots=[root])

    def test_other_configured_headers_do_not_affect_omission(self):
        self.assertEqual(MODULE.validate_omitted_headers(["Content-Type"], ["X-Probe"]), ("content-type",))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
