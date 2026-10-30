"""Evidence paths cannot escape, probe secrets, follow links or change mid-read."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

if __package__:
    from . import evidence_io
else:
    import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.evidence_io as evidence_io


def _private_fixture_root() -> Path:
    from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root

    declared = os.environ.get("I12_TEST_ROOT") or os.environ.get("RUNNER_TEMP")
    if not declared:
        raise RuntimeError("I12_TEST_ROOT or RUNNER_TEMP must name existing private storage")
    return validate_output_root(connector_root(), Path(declared))


class EvidenceIOControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(
            prefix='envoy-io-controls-', dir=_private_fixture_root())
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.roots = (self.root,)
        self.file = self.root / 'receipt.json'
        self.file.write_bytes(b'{"status":"measured"}\n')

    def test_regular_owned_file_and_hash_are_read(self):
        self.assertEqual({'status': 'measured'}, evidence_io.read_json(self.file, self.roots))
        self.assertEqual({'path': str(self.file), 'bytes': 22,
                          'sha256': hashlib.sha256(self.file.read_bytes()).hexdigest()},
                         evidence_io.reference(self.file, self.roots))

    def test_missing_config_has_no_fallback_and_never_probes_filesystem(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(evidence_io.os, 'open') as opened:
            self.assertIsNone(evidence_io.configured_storage(required=False))
            with self.assertRaisesRegex(ValueError, 'CODEX_PROJECT_STATE'):
                evidence_io.configured_storage()
            opened.assert_not_called()

    def test_configured_owned_physical_root_is_used_exactly(self):
        with patch.dict(os.environ, {'CODEX_PROJECT_STATE': str(self.root)}):
            self.assertEqual(self.root, evidence_io.configured_storage())

    def test_configured_writable_root_is_rejected(self):
        self.root.chmod(0o777)
        with (
            patch.dict(os.environ, {'CODEX_PROJECT_STATE': str(self.root)}),
            self.assertRaisesRegex(ValueError, 'not group/other writable'),
        ):
            evidence_io.configured_storage()

    def test_configured_symlink_is_rejected(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with (
            patch.dict(os.environ, {'CODEX_PROJECT_STATE': str(alias)}),
            self.assertRaises(OSError),
        ):
            evidence_io.configured_storage()

    def test_outside_path_is_rejected_before_any_filesystem_probe(self):
        with patch.object(evidence_io.os, 'open') as opened:
            with self.assertRaisesRegex(ValueError, 'outside approved'):
                evidence_io.read_bytes('/etc/shadow', self.roots)
            opened.assert_not_called()

    def test_sibling_with_same_prefix_is_outside(self):
        sibling = str(self.root) + '-other/receipt.json'
        with self.assertRaisesRegex(ValueError, 'outside approved'):
            evidence_io.read_bytes(sibling, self.roots)

    def test_private_configuration_is_rejected_before_filesystem_probe(self):
        with patch.object(evidence_io.os, 'open') as opened:
            with self.assertRaisesRegex(ValueError, 'private configuration'):
                evidence_io.read_bytes(self.root / '.aws' / 'credentials', self.roots)
            opened.assert_not_called()

    def test_traversal_is_rejected_before_any_filesystem_probe(self):
        value = str(self.root / 'nested') + '/../receipt.json'
        with patch.object(evidence_io.os, 'open') as opened:
            with self.assertRaisesRegex(ValueError, 'without traversal'):
                evidence_io.read_bytes(value, self.roots)
            opened.assert_not_called()

    def test_leaf_symlink_is_rejected(self):
        link = self.root / 'link.json'
        link.symlink_to(self.file)
        with self.assertRaises(OSError):
            evidence_io.read_bytes(link, self.roots)

    def test_directory_symlink_is_rejected_even_when_inside_root(self):
        directory = self.root / 'real'
        directory.mkdir()
        (directory / 'data').write_text('measured')
        link = self.root / 'alias'
        link.symlink_to(directory, target_is_directory=True)
        with self.assertRaises(OSError):
            evidence_io.read_bytes(link / 'data', self.roots)

    def test_writable_domain_root_is_rejected(self):
        self.root.chmod(0o777)
        with self.assertRaisesRegex(ValueError, 'not group/other writable'):
            evidence_io.read_bytes(self.file, self.roots)

    def test_writable_file_is_rejected(self):
        self.file.chmod(0o666)
        with self.assertRaisesRegex(ValueError, 'not group/other writable'):
            evidence_io.read_bytes(self.file, self.roots)

    def test_size_limit_is_enforced_before_read(self):
        with self.assertRaisesRegex(ValueError, 'bounded physical regular file'):
            evidence_io.read_bytes(self.file, self.roots, max_bytes=1)

    def test_fifo_is_rejected_without_blocking(self):
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, 'bounded physical regular file'):
            evidence_io.read_bytes(fifo, self.roots)

    def test_in_place_change_is_detected_on_same_descriptor(self):
        def read_while_changed():
            with evidence_io.open_evidence(self.file, self.roots) as (stream, _):
                stream.read()
                self.file.write_bytes(b'changed')

        with self.assertRaisesRegex(ValueError, 'changed while reading'):
            read_while_changed()

    def test_rename_does_not_redirect_an_open_descriptor(self):
        def read_while_renamed():
            with evidence_io.open_evidence(self.file, self.roots) as (stream, _):
                moved = self.root / 'moved.json'
                self.file.rename(moved)
                self.file.write_bytes(b'other')
                self.assertEqual(b'{"status":"measured"}\n', stream.read())

        with self.assertRaisesRegex(ValueError, 'changed while reading'):
            read_while_renamed()



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
