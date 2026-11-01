"""Controls for the real capture adapters and unknown terminal status."""
from modsecurity_test_framework.connector_context import load_source
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.host_scenarios as HOST
import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.prepare_native as NATIVE
from modsecurity_connector_ci.runtime.lifecycle.i12.envoy.transport import terminal


class CaptureControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parent.parent / 'capture_sources.py'
        capture = load_source(path)
        cls.registry = capture.Registry()
        cls.files = cls.registry.manifest['profiles']['envoy']['capture_files']

    def content(self, name):
        return self.registry.content(self.files[name]['sha256']).decode()

    def test_real_source_adaptations_preserve_required_guards(self):
        driver = HOST.driver_source(self.content('driver.py'))
        self.assertIn('(65534,65534)', driver)
        self.assertIn("record['native_libraries'][0]['sha256'] != SDK_SHA", driver)
        self.assertIn("if sorted(row['path'] for row in receipts) != sorted(expected)", driver)
        self.assertIn("'remaining_owned_processes'", driver)
        self.assertIn("snapshot('after-neighbor'", driver)
        client = HOST.client_source(self.content('client.py'))
        self.assertIn("content_lengths != [str(len(response_body))]", client)
        self.assertIn("'actual_send_calls'", client)
        self.assertIn('status != expected_status', client)
        self.assertIn("transport_tail == b''", client)
        for name in ('backend.py', 'backend-extproc.py'):
            backend = HOST.backend_source(self.content(name))
            self.assertIn('actual_response_send_calls', backend)
            self.assertIn("body != bytes.fromhex(shapes[self.path][0])", backend)

    def test_changed_capture_anchor_refused(self):
        changed = self.content('client.py').replace('connection.sendall(request)', 'connection.send(request)')
        with self.assertRaises(ValueError):
            HOST.client_source(changed)

    def test_e4_capture_verifies_full_registry_and_binds_native_adapter(self):
        inventory = HOST.source_inventory
        manifest = json.loads(inventory.historical_e4_manifest(
            (HOST.HERE.parent / 'manifest.json').read_bytes()))
        metadata = inventory.registry_adapter_metadata(
            manifest, inventory.E4_REVISION, inventory.E4_MANIFEST,
            inventory.E4_CURRENT)
        content = HOST.capture_content(inventory.E4_REVISION, metadata)
        self.assertEqual(content.registry_adapter, metadata)
        self.assertEqual(content('client.py'), self.content('client.py'))
        self.assertEqual(content.registry_adapter['verified_object_count'], 155)
        self.assertEqual(content.registry_adapter['verified_profile_count'], 10)
        for expected in (None, {}, dict(metadata, runtime_written=True),
                         dict(metadata, original_manifest_sha256='0' * 64)):
            with self.subTest(expected=expected), self.assertRaisesRegex(
                    ValueError, 'differs from native build'):
                HOST.capture_content(inventory.E4_REVISION, expected)
        for revision in (None, 'a' * 40, inventory.E4_REVISION[:-1] + '0'):
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                HOST.capture_content(revision, metadata)

    @patch.object(HOST.source_inventory, 'verify')
    def test_substituted_build_source_and_binary_refused(self, inventory):
        root = HOST.STORAGE if HOST.STORAGE is not None and HOST.STORAGE.is_dir() else None
        with tempfile.TemporaryDirectory(prefix='envoy-binding-', dir=root) as name:
            directory = Path(name)
            source = directory / 'source'
            source.mkdir()
            native = source / 'capture.c'
            native.write_text('captured input')
            binary = directory / 'engine'
            binary.write_bytes(b'actual-build')
            proof = {'build_ready': True, 'actual_source_commit': 'a' * 40, 'source_copy': str(source),
                'binaries': {'build/engine': HOST.sha(binary)}, 'module_inputs': {},
                'capture_application': {'exact_written_sha256': {'capture.c': HOST.sha(native)}}}
            HOST.verify_build(source, directory, proof, 'a' * 40)
            inventory.assert_called_once_with(source, proof)
            proof['binaries']['other/engine'] = proof['binaries']['build/engine']
            proof['binaries']['build/engine'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'binary differs'):
                HOST.verify_build(source, directory, proof, 'a' * 40)
            proof['binaries'] = {'build/engine': HOST.sha(binary)}
            with self.assertRaises(ValueError):
                HOST.verify_build(source, directory, proof, 'b' * 40)
            binary.write_bytes(b'substituted')
            with self.assertRaises(ValueError): HOST.verify_build(source, directory, proof, 'a' * 40)
            binary.write_bytes(b'actual-build')
            native.write_text('changed observer')
            with self.assertRaises(ValueError): HOST.verify_build(source, directory, proof, 'a' * 40)
            native.write_text('captured input')
            (source / 'injected').symlink_to(binary)
            with self.assertRaises(ValueError): HOST.verify_build(source, directory, proof, 'a' * 40)

    def test_namespace_pin_requires_same_live_owned_init_before_and_after_open(self):
        boot = {'host_pid': 123, 'namespaces': {'pid': 'pid:[456]'}}
        with patch.object(HOST.os, 'open', return_value=7) as opening, patch.object(HOST.os, 'fstat', return_value=SimpleNamespace(st_ino=456)), patch.object(HOST.os, 'close') as close:
            self.assertEqual(HOST.pin_namespace(boot, Mock(side_effect=[True, True])), 7)
            close.assert_not_called()
            for matcher in [Mock(return_value=False), Mock(side_effect=[True, False])]:
                with self.assertRaises(ValueError): HOST.pin_namespace(boot, matcher)
            close.assert_called_once_with(7)
            opening.assert_called_with('/proc/123/ns/pid', HOST.os.O_RDONLY)
        matcher = Mock(return_value=True)
        with patch.object(HOST.os, 'open', return_value=7), patch.object(HOST.os, 'fstat', return_value=SimpleNamespace(st_ino=999)), patch.object(HOST.os, 'close') as close:
            with self.assertRaises(ValueError): HOST.pin_namespace(boot, matcher)
            close.assert_called_once_with(7)
        with patch.object(HOST.os, 'open', side_effect=FileNotFoundError), patch.object(HOST.os, 'close') as close:
            with self.assertRaises(FileNotFoundError): HOST.pin_namespace(boot, matcher)
            close.assert_not_called()

    @unittest.skipUnless(Path('/usr/lib/x86_64-linux-gnu/libmodsecurity.so').is_file(), 'native SDK unavailable')
    def test_actual_sdk_rejects_incomplete_chained_rule(self):
        good = 'SecRule REQUEST_URI "@streq /target" "id:1900001,phase:3,pass,chain"\nSecRule RESPONSE_HEADERS:Content-Type "@contains text/plain" "t:none"\nSecRule RESPONSE_BODY "@contains marker" "id:1900002,phase:4,pass"\n'
        HOST.check_rules(good)
        incomplete = good.replace(' "t:none"', '')
        with self.assertRaises(ValueError):
            HOST.check_rules(incomplete)

    def test_explicit_status_is_required_even_with_local_close_zero(self):
        for code in (0, 2, None):
            result = terminal({'verified': True, 'numeric_actual_close_code': code,
                               'actual_stream_close': {'text': 'stream 1 closed: 0'}})
            self.assertFalse(result['process']['successful_grpc_completion'])
            self.assertFalse(result['authorization']['successful_grpc_completion'])
            self.assertIsNone(result['process']['remote_grpc_status'])

    def test_reset_is_an_observed_reset(self):
        result = terminal({'verified': True, 'numeric_actual_close_code': 2,
            'actual_pool_request_reset': {'original_line': 3},
            'actual_sent_reset_callback': {'original_line': 4},
            'actual_stream_close': {'original_line': 5}})
        self.assertEqual(result['process']['classification'], 'observed_local_reset')
        self.assertFalse(result['process']['successful_grpc_completion'])

    def test_unary_requires_trailer_close_and_verified_scope(self):
        unary = {'verified': True, 'actual_success_trailer': {'text': "'grpc-status', '0'"},
                 'actual_stream_close': {'text': 'stream 1 closed: 0'}}
        self.assertTrue(terminal({'verified': False}, unary)['authorization']['successful_grpc_completion'])
        for field in unary:
            incomplete = {key: value for key, value in unary.items() if key != field}
            self.assertFalse(terminal({'verified': True}, incomplete)['authorization']['successful_grpc_completion'])
        self.assertFalse(terminal({'verified': True}, dict(unary, verified=False))['authorization']['successful_grpc_completion'])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
