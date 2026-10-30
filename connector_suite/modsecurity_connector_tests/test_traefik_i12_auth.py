"""Controls for the Traefik-only forwardAuth host capture producer."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import ast
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

ROOT=connector_root()
PREPARE = load_source(source_path('connectors/traefik/harness/i12_auth/prepare.py', root=ROOT))

REVIEW = load_source(source_path('connectors/traefik/harness/i12_auth/review.py', root=ROOT))


def fixture_storage():
    from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root

    selected = os.environ.get('I12_TEST_ROOT') or os.environ['RUNNER_TEMP']
    return validate_output_root(ROOT, Path(selected))


def setUpModule():
    storage = fixture_storage()
    configured = mock.patch.dict(os.environ, {'CODEX_TEMP_ROOT': str(storage)})
    configured.start()
    unittest.addModuleCleanup(configured.stop)


class AuthCaptureControls(unittest.TestCase):
    def test_eof_and_status_do_not_qualify_truncated_client_bytes(self):
        self.assertFalse(REVIEW.framing(b'')['complete'])
        self.assertFalse(REVIEW.framing(b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nab')['complete'])
        full=REVIEW.framing(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nab')
        self.assertTrue(full['complete']);self.assertEqual(full['entity_bytes'],2)
        self.assertFalse(REVIEW.framing(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n')['complete'])
        self.assertTrue(REVIEW.framing(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n0\r\n\r\n')['complete'])

    def test_changed_capture_boundary_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'boundary differs'):
            PREPARE.replace('actual current source', 'historical missing source', 'replacement')
        with self.assertRaisesRegex(ValueError, 'boundary differs'):
            PREPARE.replace('duplicate duplicate', 'duplicate', 'replacement')

    def test_output_must_be_fresh_and_external(self):
        with self.assertRaisesRegex(ValueError, 'fresh output'):
            PREPARE.prepare(ROOT, ROOT)
        with self.assertRaisesRegex(ValueError, 'outside authorized'):
            PREPARE.prepare(ROOT, Path('/root/never-create-i12-auth-test'))

    def test_output_relocation_cannot_escape_through_symlink(self):
        parent=fixture_storage()
        with tempfile.TemporaryDirectory(prefix='i12-auth-path-controls-',dir=parent) as temporary:
            base=Path(temporary);(base/'real').mkdir();(base/'alias').symlink_to(base/'real',target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'physical output'):
                PREPARE.prepare(ROOT,base/'alias'/'never-created')
            self.assertFalse((base/'real'/'never-created').exists())

    def test_case_selection_is_finite_and_rejects_duplicate_probes(self):
        for cases in [('unknown-case',),('allow','allow')]:
            invalid_output = source_path('never-create-invalid-case', root=ROOT)
            with self.assertRaisesRegex(ValueError,'invalid bounded case selection'):
                PREPARE.prepare(ROOT,invalid_output,cases=cases)

    def test_central_capture_is_bound_without_host_execution(self):
        parent=fixture_storage()
        with tempfile.TemporaryDirectory(prefix='i12-auth-controls-', dir=parent) as temporary:
            target=Path(temporary)/'inputs'
            receipt=PREPARE.prepare(ROOT,target)
            self.assertFalse(receipt['host_launched'])
            self.assertFalse(receipt['runtime_qualified'])
            applied=json.loads((target/'source/i12-source-application-receipt.json').read_text())
            self.assertEqual(applied['profile'], 'traefik-forwardauth')
            self.assertFalse(applied['runtime_qualified'])
            driver=(target/'fixtures/driver.py').read_text()
            self.assertIn('maxResponseBodySize: 32768',driver)
            self.assertIn('maxBodySize: 4096',driver)
            self.assertIn('MSCONNECTOR_LIFECYCLE_FD',driver)
            self.assertIn('authorization-relay',driver)
            replacements=[node for node in ast.walk(ast.parse(driver)) if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='replace' and node.args and isinstance(node.args[0],ast.Constant) and node.args[0].value=='\n  middlewares:\n']
            self.assertEqual(len(replacements),1)
            patch=replacements[0]
            dynamic='http:\n  routers:\n    smoke:\n      middlewares:\n      - original\n      service: upstream\n  middlewares:\n    original: {}\n'
            rendered=dynamic.replace(patch.args[0].value,patch.args[1].value,1)
            self.assertIn('      middlewares:\n      - original',rendered)
            self.assertEqual(rendered.count('\n  middlewares:'),1)
            self.assertIn('\n    fault:',rendered)

            self.assertIn("'native_request_limit':1024",driver)
            for name in PREPARE.CASES:self.assertIn(repr(name),driver)
            self.assertEqual(receipt['fixture_files']['client.py'], PREPARE.sha(target/'fixtures/client.py'))


# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':unittest.main()
