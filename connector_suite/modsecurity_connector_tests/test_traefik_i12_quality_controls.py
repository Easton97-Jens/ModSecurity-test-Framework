"""Negative controls for bounded test-only relay and preparation boundaries."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import argparse
import importlib.util
import io
import os
import runpy
import socket
import stat
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

ROOT = connector_root()
HARNESS = source_path('connectors/traefik/harness', root=ROOT)


def module(name, relative):
    value = load_source(HARNESS / relative)
    return value


with mock.patch.object(Path, 'mkdir'):
    AUTH = module('quality_authorization_relay', 'i12_auth/auth_proxy.py')
FAULT = module('quality_fault_relay', 'i12/native/fault_proxy.py')
NATIVE = module('quality_native_prepare', 'i12/native/prepare.py')
PREPARE = module('quality_auth_prepare', 'i12_auth/prepare.py')
REVIEW = module('quality_auth_review', 'i12_auth/review.py')
CONFIG = module('quality_auth_config', 'i12_auth/validate_config.py')
RUNTIME = runpy.run_path(str(source_path('connectors/traefik/scripts/runtime_native_smoke.py', root=ROOT)))
EXTERNAL = Path('/var/tmp/codex/ModSecurity-conector')


class BoundedRelayControls(unittest.TestCase):
    def test_allowed_authorization_target_preserves_actual_sample_and_headers(self):
        handler = object.__new__(AUTH.Handler)
        handler.path = '/authorize'
        handler.command = 'POST'
        handler.server = types.SimpleNamespace(engine_port=43210)
        handler.headers = {'Content-Length': '3', 'X-Request-Id': 'i12-auth-allow',
                           'X-Forwarded-Uri': '/original?value=1'}
        handler.rfile = io.BytesIO(b'abc')
        handler.write_authorization = mock.Mock()
        response = mock.Mock(status=200)
        response.read.return_value = b'allowed'
        response.headers.get_all.return_value = ['handle']
        with mock.patch.object(AUTH.http.client, 'HTTPConnection') as connect, \
             mock.patch.object(Path, 'write_bytes'), mock.patch.object(Path, 'write_text'):
            connection = connect.return_value
            connection.getresponse.return_value = response
            handler.forward()
            connect.assert_called_once_with('127.0.0.1', 43210, timeout=10)
            connection.request.assert_called_once_with('POST', '/authorize', body=b'abc',
                                                       headers=handler.headers)
            connection.close.assert_called_once()
        self.assertEqual(handler.write_authorization.call_args.args[2], b'allowed')

    def test_only_fixed_origin_authorization_target_reaches_engine(self):
        for target in ('http://169.254.169.254/authorize', '//remote/authorize',
                       '/authorize?target=remote', '/other', '/authorize\r\nInjected: true'):
            with self.subTest(target=target):
                handler = object.__new__(AUTH.Handler)
                handler.path = target
                handler.send_error = mock.Mock()
                with mock.patch.object(AUTH.http.client, 'HTTPConnection') as connect:
                    handler.forward()
                    connect.assert_not_called()
                handler.send_error.assert_called_once_with(400)

    def test_loopback_port_validation_rejects_invalid_ports(self):
        for value in ('0', '-1', '65536'):
            with self.subTest(value=value):
                with self.assertRaises(argparse.ArgumentTypeError):
                    AUTH.port(value)
        self.assertEqual(AUTH.port('1'), 1)
        self.assertEqual(AUTH.port('65535'), 65535)

    def test_relay_rejects_unowned_TLS_material_before_binding(self):
        metadata = types.SimpleNamespace(st_uid=os.getuid() + 1, st_mode=0o100600)
        with mock.patch.object(Path, 'is_symlink', return_value=False), \
             mock.patch.object(Path, 'is_file', return_value=True), \
             mock.patch.object(Path, 'stat', return_value=metadata), \
             mock.patch.object(AUTH.http.server, 'HTTPSServer') as listener:
            with self.assertRaisesRegex(ValueError, 'actual private TLS'):
                AUTH.make_server(12345, 43210)
            listener.assert_not_called()

    def test_fault_ack_requires_actual_opcode_ten(self):
        header, payload = b'MSE1' + b'\0' * 8, b'\x01\x00\x03'
        self.assertEqual(FAULT.reply_fault('fault-ack', 7, 0, header, payload),
                         (header, payload, None))
        head, changed, cause = FAULT.reply_fault('fault-ack', 10, 0, header, payload)
        self.assertEqual(head, header)
        self.assertEqual(changed, b'\x01\x05\x03')
        self.assertEqual(cause, 'technical-result-on-acknowledge-applied')

    def test_postcommit_fault_requires_second_response_chunk(self):
        header, payload = b'MSE1' + b'\0' * 8, b'\x01\x00\x03'
        self.assertIsNone(FAULT.reply_fault('fault-postcommit', 5, 1, header, payload)[2])
        self.assertEqual(FAULT.reply_fault('fault-postcommit', 5, 2, header, payload)[1],
                         b'\x01\x05\x03')
        self.assertEqual(FAULT.reply_fault('allow', 5, 2, header, payload),
                         (header, payload, None))

    def test_socket_paths_cannot_escape_private_task_directory(self):
        for path in ('/tmp/proxy.sock', '/task/sockets/../proxy.sock',
                     'proxy.sock', '/task/sockets/child/proxy.sock'):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    FAULT.validate_socket(path, listener=True)

    def test_socket_symlink_shared_directory_and_wrong_owner_rejected(self):
        for metadata in (types.SimpleNamespace(st_uid=os.getuid(), st_mode=0o40777),
                         types.SimpleNamespace(st_uid=os.getuid()+1, st_mode=0o40700)):
            with mock.patch.object(Path, 'is_symlink', return_value=False), \
                 mock.patch.object(Path, 'stat', return_value=metadata):
                with self.assertRaisesRegex(ValueError, 'private and task-owned'):
                    FAULT.validate_socket('/task/sockets/proxy.sock', listener=True)
        with mock.patch.object(Path, 'is_symlink', return_value=True):
            with self.assertRaisesRegex(ValueError, 'symlink'):
                FAULT.validate_socket('/task/sockets/proxy.sock', listener=True)

    def test_private_fresh_listener_is_allowed(self):
        metadata = types.SimpleNamespace(st_uid=os.getuid(), st_mode=0o40700)
        with mock.patch.object(Path, 'is_symlink', return_value=False), \
             mock.patch.object(Path, 'stat', return_value=metadata), \
             mock.patch.object(Path, 'exists', return_value=False), \
             mock.patch.object(Path, 'is_socket', return_value=True):
            self.assertEqual(FAULT.validate_socket('/task/sockets/proxy.sock', listener=True),
                             '/task/sockets/proxy.sock')
            with self.assertRaisesRegex(ValueError, 'actual engine'):
                FAULT.validate_socket('/task/sockets/other.sock', listener=False)

    def test_engine_socket_created_by_actual_runner_abi_is_allowed(self):
        with tempfile.TemporaryDirectory(prefix='q', dir=EXTERNAL) as temporary:
            root = Path(temporary)
            parent = RUNTIME['EngineSocketParent'](
                path=root, identity=RUNTIME['private_directory_identity'](root, 'test parent'))
            child = RUNTIME['create_private_engine_socket_dir'](parent)
            path = child.path / RUNTIME['ENGINE_SOCKET_FILENAME']
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as engine:
                engine.bind(str(path))
                with mock.patch.object(FAULT, 'SOCKET_ROOT', root):
                    self.assertEqual(FAULT.validate_socket(str(path), listener=False), str(path))
                    with self.assertRaisesRegex(ValueError, 'actual engine'):
                        FAULT.validate_socket(str(root / 'engine.sock'), listener=False)
                    child.path.chmod(0o755)
                    with self.assertRaisesRegex(ValueError, 'private physical'):
                        FAULT.validate_socket(str(path), listener=False)
                    child.path.chmod(0o700)
                    path.unlink()
                    path.write_text('not a socket')
                    with self.assertRaisesRegex(ValueError, 'task-owned engine socket'):
                        FAULT.validate_socket(str(path), listener=False)

    def test_generated_driver_and_validator_agree_on_actual_configuration_abi(self):
        with tempfile.TemporaryDirectory(prefix='quality-config-', dir=EXTERNAL) as temporary:
            base = Path(temporary)
            with mock.patch.dict(os.environ, {'CODEX_TEMP_ROOT': str(EXTERNAL)}):
                PREPARE.prepare(ROOT, base / 'inputs', cases=('allow', 'neighbor'))
            driver = (base / 'inputs/fixtures/driver.py').read_text()
            self.assertIn("config_dir=TASK/'runtime/effective-config'", driver)
            self.assertIn("dynamic=config_dir/'traefik-forwardauth-dynamic.yaml'", driver)
            self.assertEqual(CONFIG.CONFIG_FILE,
                             Path('/task/runtime/effective-config/traefik-forwardauth-dynamic.yaml'))
            physical = base / CONFIG.CONFIG_FILE.relative_to('/task')
            physical.parent.mkdir(parents=True)
            physical.write_text('http: {}\n')
            with mock.patch.object(CONFIG, 'CONFIG_FILE', physical):
                self.assertEqual(CONFIG.read_effective_config(physical), 'http: {}\n')

    def test_configuration_path_symlink_nonregular_and_size_are_bounded(self):
        with tempfile.TemporaryDirectory(prefix='quality-config-', dir=EXTERNAL) as temporary:
            base = Path(temporary)
            physical = base / 'traefik-forwardauth-dynamic.yaml'
            with mock.patch.object(CONFIG, 'CONFIG_FILE', physical):
                with self.assertRaisesRegex(ValueError, 'physical task configuration'):
                    CONFIG.read_effective_config(base / 'unrelated.yaml')
                physical.mkdir()
                with self.assertRaisesRegex(ValueError, 'bounded regular'):
                    CONFIG.read_effective_config(physical)
                physical.rmdir()
                physical.write_bytes(b'x' * 65537)
                with self.assertRaisesRegex(ValueError, 'bounded regular'):
                    CONFIG.read_effective_config(physical)
                physical.unlink()
                target = base / 'actual.yaml'
                target.write_text('http: {}\n')
                physical.symlink_to(target)
                with self.assertRaisesRegex(ValueError, 'physical task configuration'):
                    CONFIG.read_effective_config(physical)

    def test_cleanup_removes_only_owned_socket_inode(self):
        owned = types.SimpleNamespace(st_mode=stat.S_IFSOCK, st_dev=1, st_ino=10)
        replaced = types.SimpleNamespace(st_mode=stat.S_IFSOCK, st_dev=1, st_ino=11)
        with mock.patch.object(Path, 'lstat', return_value=replaced), \
             mock.patch.object(Path, 'unlink') as unlink:
            FAULT.remove_owned_socket(owned)
            unlink.assert_not_called()
        with mock.patch.object(Path, 'lstat', return_value=owned), \
             mock.patch.object(Path, 'unlink') as unlink:
            FAULT.remove_owned_socket(owned)
            unlink.assert_called_once_with()
        with mock.patch.object(Path, 'lstat', side_effect=FileNotFoundError), \
             mock.patch.object(Path, 'unlink') as unlink:
            FAULT.remove_owned_socket(owned)
            unlink.assert_not_called()

    def test_preparers_require_explicit_configured_storage(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            for validate in (lambda: NATIVE.validate_output(Path('/never-create'), fresh=True),
                             lambda: PREPARE.validate_output(Path('/never-create'))):
                with self.subTest(validate=validate):
                    with self.assertRaisesRegex(ValueError, 'configured external storage root required'):
                        validate()

    def test_auth_output_shared_or_foreign_ancestry_is_rejected(self):
        for metadata in (types.SimpleNamespace(st_uid=os.getuid(), st_mode=0o40777),
                         types.SimpleNamespace(st_uid=os.getuid()+1, st_mode=0o40700)):
            with mock.patch.object(Path, 'exists', return_value=True), \
                 mock.patch.object(Path, 'stat', return_value=metadata):
                with self.assertRaisesRegex(ValueError, 'private and task-owned'):
                    PREPARE.validate_owned_ancestor(Path('/synthetic-ancestor'))

    def test_strict_framing_rejects_ambiguous_or_trailing_bytes(self):
        for response in (
            b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\na',
            b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\na',
            b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nextra',
            b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\na\r\n0\r\n\r\n',
        ):
            with self.subTest(response=response):
                self.assertFalse(REVIEW.framing(response)['complete'])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
