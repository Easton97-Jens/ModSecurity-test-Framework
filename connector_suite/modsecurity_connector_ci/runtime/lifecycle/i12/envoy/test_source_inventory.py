"""Mutation controls for sources outside the capture overlay list."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.source_inventory as inventory


def _private_fixture_root() -> Path:
    from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root

    declared = os.environ.get("I12_TEST_ROOT") or os.environ.get("RUNNER_TEMP")
    if not declared:
        raise RuntimeError("I12_TEST_ROOT or RUNNER_TEMP must name existing private storage")
    return validate_output_root(connector_root(), Path(declared))


class CompleteSourceControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=_private_fixture_root())
        self.root = Path(self.temporary.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        original = {'ci/runtime/lifecycle/i12/manifest.json': json.dumps({'delivery_product_baseline': 'a' * 40}).encode(),
                    'common/runtime/msconnector_runtime.c': b'compiled original source'}
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w') as stream:
            for name, body in original.items():
                item = tarfile.TarInfo(name)
                item.size = len(body)
                stream.addfile(item, io.BytesIO(body))
                path = self.source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(body)
        (self.root / 'native-build').mkdir()
        (self.root / 'native-build/source-archive.stdout').write_bytes(output.getvalue())
        self.proof = {'source_copy': str(self.source), 'actual_source_commit': 'b' * 40,
            'checks': [{'label': 'source-archive', 'exit_code': 0,
                        'argv': ['rtk', 'proxy', 'git', 'archive', '--format=tar', 'b' * 40],
                        'stdout_sha256': inventory.digest(output.getvalue())}],
            'capture_application': {'exact_written_sha256': {}}}
        (self.source / '.i12-disposable-source-copy.json').write_text(json.dumps({
            'format': 'i12-disposable-source-copy-v1', 'path': str(self.source),
            'disposable': True, 'parent_sha': 'a' * 40}))
        (self.source / 'i12-source-application-receipt.json').write_text(
            json.dumps(self.proof['capture_application'], indent=2) + '\n')

    def tearDown(self):
        self.temporary.cleanup()

    def test_unoverlaid_compiled_source_mutation_is_rejected(self):
        self.assertEqual(len(inventory.verify(self.source, self.proof)), 4)
        path = self.source / 'common/runtime/msconnector_runtime.c'
        path.write_bytes(b'different compiled source')
        with self.assertRaisesRegex(ValueError, 'msconnector_runtime.c'):
            inventory.verify(self.source, self.proof)

    def test_injected_missing_and_hardlinked_inputs_are_rejected(self):
        extra = self.source / 'injected.c'
        extra.write_bytes(b'extra compilation unit')
        with self.assertRaises(ValueError): inventory.verify(self.source, self.proof)
        extra.unlink()
        path = self.source / 'common/runtime/msconnector_runtime.c'
        extra.hardlink_to(path)
        with self.assertRaisesRegex(ValueError, 'hard-linked'): inventory.verify(self.source, self.proof)
        extra.unlink()
        path.unlink()
        with self.assertRaises(ValueError): inventory.verify(self.source, self.proof)

    def test_archive_hash_or_revision_substitution_is_rejected(self):
        self.proof['actual_source_commit'] = 'c' * 40
        with self.assertRaisesRegex(ValueError, 'Git archive'): inventory.verify(self.source, self.proof)
        self.proof['actual_source_commit'] = 'b' * 40
        (self.root / 'native-build/source-archive.stdout').write_bytes(b'substituted')
        with self.assertRaisesRegex(ValueError, 'Git archive'): inventory.verify(self.source, self.proof)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
