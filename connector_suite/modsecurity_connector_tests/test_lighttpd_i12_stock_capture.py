"""Independent boundary checks for the supplemental stock capture."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest import mock


ROOT = connector_root()
capture = load_source(source_path('ci/runtime/lifecycle/i12/lighttpd/stock_capture.py', root=ROOT))


class StockCaptureTests(unittest.TestCase):
    def test_failed_process_launch_closes_both_log_descriptors(self):
        with tempfile.TemporaryDirectory(dir=capture.EXTERNAL) as temporary:
            before = len(list(Path('/proc/self/fd').iterdir()))
            with mock.patch.object(capture.subprocess, 'Popen', side_effect=OSError('injected spawn failure')):
                with self.assertRaisesRegex(OSError, 'injected'):
                    capture.launch(Path(temporary), 'failed', ['/missing'], {})
            self.assertEqual(len(list(Path('/proc/self/fd').iterdir())), before)

    def test_failed_host_config_releases_backend_socket_and_thread(self):
        with tempfile.TemporaryDirectory(dir=capture.EXTERNAL) as temporary:
            before_threads = {thread.ident for thread in threading.enumerate()}
            before_fds = len(list(Path('/proc/self/fd').iterdir()))
            with mock.patch.object(capture, 'run', side_effect=RuntimeError('config rejected')):
                with self.assertRaisesRegex(RuntimeError, 'config rejected'):
                    capture.capture(Path(temporary), Path('/missing'), Path('/missing'), Path('/missing'))
            self.assertEqual({thread.ident for thread in threading.enumerate()}, before_threads)
            self.assertEqual(len(list(Path('/proc/self/fd').iterdir())), before_fds)

    def test_hardlinked_source_rejected(self):
        with tempfile.TemporaryDirectory(dir=capture.EXTERNAL) as temporary:
            root = Path(temporary)
            (root / 'input').write_bytes(b'owned')
            os.link(root / 'input', root / 'alias')
            with self.assertRaisesRegex(ValueError, 'one link'):
                capture.regular(root / 'input')

    def test_source_tree_symlink_rejected(self):
        with tempfile.TemporaryDirectory(dir=capture.EXTERNAL) as temporary:
            root = Path(temporary)
            source = root / 'source'
            source.mkdir()
            (source / 'alias').symlink_to('/etc/passwd')
            with self.assertRaisesRegex(ValueError, 'symlink'):
                capture.copy_tree(source, root / 'copy')
            self.assertFalse((root / 'copy/alias').exists())

    def test_alias_root_rejected_without_following(self):
        with tempfile.TemporaryDirectory(dir=capture.EXTERNAL) as temporary:
            root = Path(temporary)
            (root / 'alias').symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'symlink'):
                capture.private_root(root / 'alias' / 'new')
            self.assertFalse((root / 'new').exists())

    def test_existing_root_rejected(self):
        with tempfile.TemporaryDirectory(dir=capture.EXTERNAL) as temporary:
            with self.assertRaises(FileExistsError):
                capture.private_root(Path(temporary))

    def test_outside_external_root_rejected(self):
        with self.assertRaisesRegex(ValueError, 'external'):
            capture.private_root(Path('/tmp/not-an-i12-run'))

    def test_client_records_real_peer_eof_and_exact_body(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            requests = []

            def peer():
                with listener.accept()[0] as connection:
                    payload = bytearray()
                    while b'\r\n\r\n' not in payload or not payload.endswith(b'proof-body'):
                        payload.extend(connection.recv(1024))
                    requests.append(bytes(payload))
                    connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nproof')

            worker = threading.Thread(target=peer)
            worker.start()
            result = capture.request(listener.getsockname()[1], '/proof', b'proof-body')
            worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(result['status_line'], 'HTTP/1.1 200 OK')
            self.assertEqual(result['response_body'], 'proof')
            self.assertEqual(result['request_body_bytes'], 10)
            self.assertTrue(requests[0].endswith(b'proof-body'))
            self.assertNotIn('transport_error', result)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
