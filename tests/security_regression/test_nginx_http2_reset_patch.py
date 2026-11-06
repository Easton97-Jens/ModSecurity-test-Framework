"""Exercise the dependency patch boundary, drift rejection and cache binding."""
from __future__ import annotations

import ast
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PATCH = ROOT / 'ci/provisioning/patches/nginx/h2-close-stream-flush.patch'
SCRIPT = ROOT / 'ci/provisioning/prepare-nginx-build.sh'
HELPER = ROOT / 'connector_suite/modsecurity_connector_ci/provisioning/components/prepare-runtime-components.py'
SOURCE = '''    h2c->processing--;

    if (h2c->processing || h2c->blocked) {
        return;
    }

'''


class NginxHttp2ResetPatchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=os.environ.get('TEST_TMPDIR'))
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def apply(self, source):
        tree = self.root / 'src/http/v2'
        tree.mkdir(parents=True, exist_ok=True)
        target = tree / 'ngx_http_v2.c'
        target.write_text(source)
        result = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1', '-i', str(PATCH)],
                                cwd=self.root, capture_output=True, text=True, check=False)
        return result, target

    def test_patch_preserves_blocked_return_and_schedules_owned_connection_writer(self):
        result, target = self.apply(SOURCE)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('if (h2c->last_out && !h2c->blocked)', target.read_text())
        self.assertIn('ngx_post_event(h2c->connection->write, &ngx_posted_events)', target.read_text())
        # Reapplication must fail instead of accepting an ambiguous source state.
        again = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1', '-i', str(PATCH)],
                               cwd=self.root, capture_output=True, text=True, check=False)
        self.assertNotEqual(again.returncode, 0)

    def test_native_source_drift_is_rejected_without_fuzzy_application(self):
        source = SOURCE.replace('h2c->processing || h2c->blocked', 'h2c->blocked')
        result, target = self.apply(source)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_text(), source)

    def test_patch_bytes_are_part_of_nginx_component_source_identity(self):
        names = {'connector_input_paths', 'hash_file_contents', 'hash_missing_input_root',
                 'skip_input_hash_path', 'hash_directory_input_file',
                 'hash_directory_input_paths', 'hash_input_paths'}
        tree = ast.parse(HELPER.read_text())
        selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
        self.assertEqual(len(selected), len(names))
        namespace = dict(Path=Path, hashlib=hashlib, Any=object)
        exec(compile(ast.Module(body=selected, type_ignores=[]), str(HELPER), 'exec'), namespace)
        framework = self.root / 'framework'
        patch = framework / PATCH.relative_to(ROOT)
        patch.parent.mkdir(parents=True)
        shutil.copy2(PATCH, patch)
        paths = namespace['connector_input_paths'](self.root/'parent', framework, 'nginx')
        self.assertIn(patch.parent, paths)
        before = namespace['hash_input_paths'](paths)
        patch.write_bytes(patch.read_bytes() + b'\n')
        self.assertNotEqual(namespace['hash_input_paths'](paths), before)

    def test_release_verification_precedes_patch_and_patch_precedes_provenance(self):
        source = SCRIPT.read_text().split('build_nginx_from_source() {', 1)[1]
        self.assertLess(source.index('download_nginx_source'), source.index('apply_nginx_http2_patch'))
        self.assertLess(source.index('apply_nginx_http2_patch'), source.index('write_protocol_build_provenance'))
        self.assertEqual(SCRIPT.read_text().count('echo "nginx_http2_patch_sha256=$NGINX_HTTP2_PATCH_SHA256"'), 3)


if __name__ == '__main__':
    unittest.main()
