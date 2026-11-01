"""Raw driver guards and bounded real socket capture; no NGINX E2E claim."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import importlib.util
from pathlib import Path
import socket
import threading
import unittest

ROOT = connector_root()


class RawH1DriverTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("raw_h1_driver", source_path('ci/runtime/lifecycle/run-nginx-raw-h1.py', root=ROOT))
        cls.driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.driver)

    def test_config_owns_logs_and_uses_root_nobody_and_loopback_only(self):
        config = self.driver.config_template(Path("/var/tmp/codex/owned"), 23456, 23457)
        for fragment in ('user nobody nogroup;', 'daemon off;', 'listen 127.0.0.1:23456;',
                         'proxy_pass http://127.0.0.1:23457;', 'access_log "/var/tmp/codex/owned/access.jsonl"',
                         'error_log "/var/tmp/codex/owned/nginx-error.log" info;'):
            self.assertIn(fragment, config)

    def test_actual_socket_capture_retains_exact_sent_and_received_bytes(self):
        response = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
        captured = []
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            def serve():
                with listener.accept()[0] as peer:
                    captured.append(peer.recv(1024))
                    peer.sendall(response)
            thread = threading.Thread(target=serve)
            thread.start()
            actual = self.driver.exchange(listener.getsockname()[1], b"owned-wire-input")
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(actual, response)
        self.assertEqual(captured, [b"owned-wire-input"])

    def test_only_one_exact_native_access_entry_is_accepted(self):
        self.assertEqual(self.driver.access_for_path(b'{"uri":"/own","status":400}\n', "/own")["status"], 400)
        for data in (b"", b'{"uri":"/foreign"}\n', b'{"uri":"/own"}\n{"uri":"/own"}\n'):
            with self.assertRaises(ValueError):
                self.driver.access_for_path(data, "/own")

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
