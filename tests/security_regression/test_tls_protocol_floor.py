"""Exercise the five reported TLS contexts with real in-memory TLS peers."""

from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import unittest

from connector_suite.adapters.haproxy.harness import i12_companion_host, i12_native_sequences
from modsecurity_connector_tests import (
    test_envoy_transport_hardening_contract as envoy,
    test_haproxy_htx_transaction_id as htx,
    test_haproxy_i12_companion_host as companion,
)


def handshake(client_context, server_context, hostname="localhost"):
    """Complete bounded TLS negotiation and exchange actual application bytes."""
    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_context.wrap_bio(client_in, client_out, server_hostname=hostname)
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    completed = [False, False]
    for _ in range(64):
        for index, peer in enumerate((client, server)):
            if not completed[index]:
                try:
                    peer.do_handshake()
                    completed[index] = True
                except ssl.SSLWantReadError:
                    pass
        for outgoing, incoming in ((client_out, server_in), (server_out, client_in)):
            if outgoing.pending:
                incoming.write(outgoing.read())
        if all(completed):
            break
    else:
        raise AssertionError("TLS handshake exceeded the bounded exchange limit")
    if client.version() != server.version():
        raise AssertionError("TLS peers disagree on the negotiated version")
    client.write(b"tls-floor-control")
    server_in.write(client_out.read())
    if server.read(17) != b"tls-floor-control":
        raise AssertionError("TLS application bytes were not preserved")
    return client.version()


class TLSProtocolFloorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="tls-floor-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.certificate, cls.private_key = cls.make_certificate(cls.root)
        other = cls.root / "other-authority"
        other.mkdir(mode=0o700)
        cls.other_certificate, cls.other_private_key = cls.make_certificate(other)

    @staticmethod
    def make_certificate(root):
        certificate, private_key = root / "tls.crt", root / "tls.key"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
             "-days", "1", "-subj", "/CN=localhost", "-addext",
             "subjectAltName=DNS:localhost,IP:127.0.0.1",
             "-keyout", str(private_key), "-out", str(certificate)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20,
        )
        private_key.chmod(0o600)
        return certificate, private_key

    def contexts(self):
        return (
            ("haproxy-companion-client", True, i12_companion_host.client_tls_context(self.root)),
            ("haproxy-native-client", True, i12_native_sequences.client_tls_context(self.root)),
            ("envoy-test-server", False, envoy.loopback_tls_context(self.certificate, self.private_key)),
            ("haproxy-htx-test-server", False, htx.loopback_tls_context(self.certificate, self.private_key)),
            ("haproxy-companion-test-server", False, companion.component_tls_context(self.root)),
        )

    def peer_context(self, client, version, *, other_authority=False):
        if client:
            context = ssl.create_default_context(cafile=str(self.certificate))
        else:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            certificate, private_key = (
                (self.other_certificate, self.other_private_key) if other_authority
                else (self.certificate, self.private_key)
            )
            context.load_cert_chain(certificate, private_key)
        context.minimum_version = version
        context.maximum_version = version
        if version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            # Deliberately permissive, socket-free control peers only. Never
            # lower the security level or version floor of the actual subject.
            context.set_ciphers("DEFAULT:@SECLEVEL=0")
        return context

    def test_contexts_require_tls12_without_capping_modern_tls(self):
        for name, client, context in self.contexts():
            with self.subTest(context=name):
                self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
                self.assertEqual(context.maximum_version, ssl.TLSVersion.MAXIMUM_SUPPORTED)
                if client:
                    self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
                    self.assertTrue(context.check_hostname)

    def test_legacy_protocols_fail_after_successful_legacy_controls(self):
        for version, negotiated in ((ssl.TLSVersion.TLSv1, "TLSv1"),
                                    (ssl.TLSVersion.TLSv1_1, "TLSv1.1")):
            with self.subTest(legacy_control=negotiated, control_failure="BLOCKED"):
                # Unavailable legacy controls must fail, never count as rejection.
                actual = handshake(self.peer_context(True, version), self.peer_context(False, version))
                self.assertEqual(actual, negotiated)
            for name, client, context in self.contexts():
                with self.subTest(context=name, rejected=negotiated):
                    peer = self.peer_context(not client, version)
                    client_context, server_context = (context, peer) if client else (peer, context)
                    with self.assertRaises(ssl.SSLError):
                        handshake(client_context, server_context)

    def modern_protocol_control(self, version, negotiated):
        for name, client, context in self.contexts():
            with self.subTest(context=name, accepted=negotiated):
                peer = self.peer_context(not client, version)
                client_context, server_context = (context, peer) if client else (peer, context)
                self.assertEqual(handshake(client_context, server_context), negotiated)

    def test_tls12_handshakes_remain_usable(self):
        self.modern_protocol_control(ssl.TLSVersion.TLSv1_2, "TLSv1.2")

    def test_tls13_handshakes_remain_usable(self):
        if not ssl.HAS_TLSv1_3:
            self.skipTest("BLOCKED: TLS1.3 is unavailable")
        self.modern_protocol_control(ssl.TLSVersion.TLSv1_3, "TLSv1.3")

    def test_clients_reject_wrong_hostname(self):
        for name, client, context in self.contexts():
            if not client:
                continue
            with self.subTest(context=name):
                peer = self.peer_context(False, ssl.TLSVersion.TLSv1_2)
                with self.assertRaises(ssl.SSLCertVerificationError):
                    handshake(context, peer, hostname="unlisted.invalid")

    def test_clients_reject_untrusted_certificate(self):
        for name, client, context in self.contexts():
            if not client:
                continue
            with self.subTest(context=name):
                peer = self.peer_context(False, ssl.TLSVersion.TLSv1_2, other_authority=True)
                with self.assertRaises(ssl.SSLCertVerificationError):
                    handshake(context, peer)

    def test_native_client_copy_keeps_a_standalone_verified_context(self):
        copied = self.root / "client.py"
        copied.write_bytes(Path(i12_native_sequences.__file__).read_bytes())
        program = "\n".join((
            "import pathlib, runpy, ssl, sys",
            "module = runpy.run_path(sys.argv[1])",
            "context = module['client_tls_context'](pathlib.Path(sys.argv[2]))",
            "assert context.minimum_version == ssl.TLSVersion.TLSv1_2",
            "assert context.maximum_version == ssl.TLSVersion.MAXIMUM_SUPPORTED",
            "assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname",
        ))
        subprocess.run([sys.executable, "-I", "-c", program, str(copied), str(self.root)],
                       check=True, capture_output=True, timeout=20)


if __name__ == "__main__":
    unittest.main()
