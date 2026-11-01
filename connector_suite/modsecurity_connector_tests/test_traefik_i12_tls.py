"""Real verified TLS controls for the synthetic authorization relay only."""
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest
from unittest import mock

from modsecurity_connector_tests import test_traefik_i12_quality_controls as quality

AUTH = quality.AUTH
TLS = quality.module('traefik_i12_tls_fixture', 'i12_auth/tls_fixture.py')


class RelayTLSControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix='i12-relay-tls-', dir=quality.EXTERNAL)
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name).resolve()
        configured = mock.patch.dict(os.environ, {'CODEX_TEMP_ROOT': str(cls.root)})
        configured.start()
        cls.addClassCleanup(configured.stop)
        cls.primary, cls.other = cls.root / 'primary', cls.root / 'other'
        TLS.generate(cls.primary)
        TLS.generate(cls.other)

    def setUp(self):
        self.output = self.root / self._testMethodName
        self.output.mkdir(mode=0o700)
        patch = mock.patch.object(AUTH, 'root', self.output)
        patch.start()
        self.addCleanup(patch.stop)
        self.engine = mock.patch.object(AUTH.http.client, 'HTTPConnection')
        connection = self.engine.start().return_value
        self.addCleanup(self.engine.stop)
        self.connection = connection
        response = mock.Mock(status=200)
        response.read.return_value = b'allowed'
        response.headers.get_all.return_value = []
        response.getheaders.return_value = [('Content-Type', 'text/plain')]
        connection.getresponse.return_value = response
        self.server = AUTH.make_server(0, 43210, self.primary)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': 0.01})
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.assertFalse(self.thread.is_alive())

    def context(self, certificate=None):
        return ssl.create_default_context(cafile=str(certificate or self.primary / 'ca.crt'))

    def verified_request(self):
        connection = http.client.HTTPSConnection('127.0.0.1', self.server.server_port,
                                                context=self.context(), timeout=3)
        try:
            connection.connect()
            self.assertIn(connection.sock.version(), ('TLSv1.2', 'TLSv1.3'))
            self.assertIn(('IP Address', '127.0.0.1'), connection.sock.getpeercert()['subjectAltName'])
            connection.request('POST', '/authorize', body=b'synthetic TLS sample',
                               headers={'X-Request-Id': 'i12-auth-tls-allow'})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), b'allowed')
        finally:
            connection.close()

    def handshake(self, context, hostname='127.0.0.1'):
        with socket.create_connection(('127.0.0.1', self.server.server_port), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname=hostname):
                pass

    def test_verified_ip_SAN_chain_preserves_actual_relay_sample(self):
        self.verified_request()
        self.connection.request.assert_called_once_with('POST', '/authorize',
            body=b'synthetic TLS sample', headers=mock.ANY)
        self.assertEqual((self.output / 'tls-allow.sample.raw').read_bytes(), b'synthetic TLS sample')
        self.assertTrue(self.context().check_hostname)
        self.assertEqual(self.context().verify_mode, ssl.CERT_REQUIRED)

    def test_wrong_CA_missing_CA_and_wrong_SAN_cannot_reach_engine(self):
        for context, hostname in ((self.context(self.other / 'ca.crt'), '127.0.0.1'),
                                  (ssl.create_default_context(), '127.0.0.1'),
                                  (self.context(), 'localhost')):
            with self.subTest(hostname=hostname, context=context):
                with self.assertRaises(ssl.SSLCertVerificationError):
                    self.handshake(context, hostname)
        self.connection.request.assert_not_called()
        self.verified_request()

    def test_plaintext_has_no_fallback_and_neighbor_TLS_stays_healthy(self):
        with socket.create_connection(('127.0.0.1', self.server.server_port), timeout=3) as plain:
            plain.sendall(b'GET /authorize HTTP/1.1\r\nHost: localhost\r\n\r\n')
            try:
                data = plain.recv(1024)
            except ConnectionResetError:
                data = b''
            self.assertEqual(data, b'')
        self.connection.request.assert_not_called()
        self.verified_request()

    def test_only_private_runtime_leaf_key_is_retained(self):
        self.assertEqual((self.primary / 'server.key').stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.primary.stat().st_mode & 0o777, 0o700)
        for name in ('ca.key', 'ca.srl', 'server.csr', 'leaf.ext'):
            self.assertFalse((self.primary / name).exists())
        receipt = json.loads((self.primary / 'tls-receipt.json').read_text())
        self.assertFalse(receipt['ca_private_key_retained'])
        self.assertEqual(set(receipt['public_certificates']), {'ca.crt', 'server.crt'})

    def test_shared_or_symlink_private_key_is_rejected(self):
        key = self.primary / 'server.key'
        key.chmod(0o644)
        try:
            with self.assertRaisesRegex(ValueError, 'must be private'):
                AUTH.make_server(0, 43210, self.primary)
        finally:
            key.chmod(0o600)
        linked = self.output / 'symlink-key'
        linked.mkdir(mode=0o700)
        (linked / 'server.crt').symlink_to(self.primary / 'server.crt')
        (linked / 'server.key').symlink_to(key)
        with self.assertRaisesRegex(ValueError, 'actual private'):
            AUTH.make_server(0, 43210, linked)


class TLSConfigurationControls(unittest.TestCase):
    def test_certificate_generation_does_not_require_host_openssl_configuration(self):
        with tempfile.TemporaryDirectory(prefix='i12-tls-no-host-config-', dir=quality.EXTERNAL) as temporary:
            root = Path(temporary).resolve()
            with mock.patch.dict(os.environ, {'CODEX_TEMP_ROOT': str(root),
                                             'OPENSSL_CONF': str(root / 'absent-openssl.cnf')}):
                directory = root / 'tls'
                receipt = TLS.generate(directory)
                verified = TLS.openssl(directory, 'verify', '-CAfile', 'ca.crt',
                                       '-verify_ip', '127.0.0.1', '-purpose', 'sslserver', 'server.crt')
            self.assertIn('server.crt: OK', verified)
            self.assertFalse(receipt['ca_private_key_retained'])
            self.assertFalse((directory / 'ca.key').exists())
            self.assertEqual((directory / 'server.key').stat().st_mode & 0o777, 0o600)

    def test_exact_host_TLS_CA_contract_preserves_response_capacity(self):
        value = ('        address: http://127.0.0.1:43210/authorize\n'
                 '        maxResponseBodySize: 32768\n        preserveRequestMethod: true\n')
        changed = TLS.configure_forwardauth(value, 43210)
        self.assertIn('address: https://127.0.0.1:43210/authorize', changed)
        self.assertIn('ca: /task/authorization-tls/ca.crt', changed)
        self.assertIn('insecureSkipVerify: false', changed)
        self.assertIn('maxResponseBodySize: 32768', changed)
        for altered in (value.replace('32768', '32769'), value + value, value.replace('43210', '43211'),
                        value + '        tls:\n          insecureSkipVerify: true\n'):
            with self.subTest(altered=altered), self.assertRaises(ValueError):
                TLS.configure_forwardauth(altered, 43210)

    def test_generated_capture_stages_TLS_before_host_and_preserves_capacity(self):
        with tempfile.TemporaryDirectory(prefix='i12-tls-stage-', dir=quality.EXTERNAL) as temporary:
            with mock.patch.dict(os.environ, {'CODEX_TEMP_ROOT': str(quality.EXTERNAL)}):
                output = Path(temporary) / 'inputs'
                receipt = quality.PREPARE.prepare(quality.ROOT, output)
            self.assertFalse(receipt['host_launched'])
            self.assertFalse(receipt['runtime_qualified'])
            self.assertIn('tls_fixture.py', receipt['fixture_files'])
            driver = (output / 'fixtures/driver.py').read_text()
            self.assertLess(driver.index("execute('authorization-relay-tls'"),
                            driver.index("execute('validate-effective-yaml'"))
            self.assertLess(driver.index("execute('authorization-relay-tls'"),
                            driver.index("relay=start('authorization-relay'"))
            self.assertIn('maxResponseBodySize: 32768', driver)
            self.assertIn("'authorization_tls_public'", driver)
            self.assertIn("TASK/'authorization-tls/ca.crt'", driver)
            self.assertNotIn("TASK/'authorization-tls/server.key'", driver)
            self.assertFalse((output / 'fixtures/server.key').exists())

    def test_TLS_material_cannot_reuse_or_escape_the_private_runtime(self):
        with tempfile.TemporaryDirectory(prefix='i12-tls-path-', dir=quality.EXTERNAL) as temporary:
            root = Path(temporary).resolve()
            with mock.patch.dict(os.environ, {'CODEX_TEMP_ROOT': str(root)}):
                with self.assertRaisesRegex(ValueError, 'fresh physical'):
                    TLS.generate(root)
                (root / 'actual').mkdir(mode=0o700)
                (root / 'alias').symlink_to(root / 'actual', target_is_directory=True)
                with self.assertRaisesRegex(ValueError, 'fresh physical'):
                    TLS.generate(root / 'alias' / 'tls')
                (root / 'actual').chmod(0o777)
                with self.assertRaisesRegex(ValueError, 'task-owned and private'):
                    TLS.generate(root / 'actual' / 'tls')



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
