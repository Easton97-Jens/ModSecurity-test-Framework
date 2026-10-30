"""Committed-source export controls without hosts or repository mutations."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = connector_root()
EXPORT = load_source(source_path('connectors/traefik/harness/i12/source_export.py', root=ROOT))


class SourceExportControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/var/tmp/codex/ModSecurity-conector', prefix='source-export-unit-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = patch.dict(os.environ, {'CODEX_TEMP_ROOT': str(self.root)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.data = b'committed source\n'
        self.blob = hashlib.sha1(b'blob ' + str(len(self.data)).encode() + b'\0' + self.data, usedforsecurity=False).hexdigest()
        self.revision, self.tree = 'a' * 40, 'b' * 40
        self.rows = ('100755 blob ' + self.blob + '\tscript.py\0' + '160000 commit ' + 'c' * 40 + '\tmodules/framework\0').encode()

    def git(self, _repository, *arguments, data=None):
        if arguments == ('rev-parse', '--verify', 'HEAD^{commit}'):
            return self.revision.encode() + b'\n'
        if arguments == ('rev-parse', '--verify', self.revision + '^{tree}'):
            return self.tree.encode() + b'\n'
        if arguments == ('ls-tree', '-rz', self.revision):
            return self.rows
        self.assertEqual(arguments, ('cat-file', '--batch'))
        self.assertEqual(data, (self.blob + '\n').encode())
        return (self.blob + ' blob ' + str(len(self.data)) + '\n').encode() + self.data + b'\n'

    def export(self):
        with patch.object(EXPORT, 'git', side_effect=self.git):
            return EXPORT.export(ROOT, self.root / 'source')

    def test_complete_committed_inventory_modes_and_gitlinks(self):
        result = self.export()
        source = self.root / 'source'
        self.assertEqual((source / 'script.py').read_bytes(), self.data)
        self.assertEqual(result['files']['script.py']['mode'], 493)
        self.assertEqual((source / 'script.py').stat().st_mode & 0o777, 493)
        self.assertEqual(result['gitlinks'], {'modules/framework': 'c' * 40})
        self.assertFalse((source / 'modules').exists())
        marker = json.loads((source / EXPORT.MARKER).read_text())
        self.assertEqual(marker['snapshot_manifest_sha256'], hashlib.sha256((source / EXPORT.SNAPSHOT).read_bytes()).hexdigest())
        self.assertEqual(result['source_revision'], self.revision)
        self.assertEqual(result['git_tree'], self.tree)

    def test_unknown_symlink_and_escape_git_entries_rejected(self):
        for mode, name in [('120000', 'link'), ('100644', '../escape'), ('100644', '.git/config')]:
            with self.subTest(mode=mode, name=name):
                self.rows = (mode + ' blob ' + self.blob + '\t' + name + '\0').encode()
                with self.assertRaises(ValueError):
                    self.export()
                self.assertFalse((self.root / 'source').exists())

    def test_corrupted_git_blob_is_rejected(self):
        self.data += b'changed'
        with self.assertRaisesRegex(ValueError, 'object identity'):
            self.export()

    def test_existing_destination_is_never_overwritten(self):
        (self.root / 'source').mkdir()
        (self.root / 'source/retained').write_text('retain')
        with self.assertRaises(ValueError):
            self.export()
        self.assertEqual((self.root / 'source/retained').read_text(), 'retain')

    def test_missing_configured_root_and_symlink_destination_rejected(self):
        with patch.dict(os.environ, {'CODEX_TEMP_ROOT': ''}):
            with self.assertRaises(ValueError):
                self.export()
        (self.root / 'source').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.export()


    def test_private_nested_destination_is_allowed_without_creating_it(self):
        parent = self.root / 'private'
        parent.mkdir(mode=0o700)
        destination = parent / 'source'
        self.assertIsNone(EXPORT.validate_destination(destination))
        self.assertFalse(destination.exists())

    def test_writable_ancestor_and_foreign_owner_are_rejected(self):
        parent = self.root / 'private'
        parent.mkdir(mode=0o700)
        parent.chmod(0o720)
        try:
            with self.assertRaisesRegex(ValueError, 'private and task-owned'):
                EXPORT.validate_destination(parent / 'source')
        finally:
            parent.chmod(0o700)
        with patch.object(EXPORT.os, 'getuid', return_value=os.getuid() + 1):
            with self.assertRaisesRegex(ValueError, 'private and task-owned'):
                EXPORT.validate_destination(parent / 'source')

    def test_nested_git_marker_file_and_dangling_symlink_are_rejected(self):
        parent = self.root / 'private'
        parent.mkdir(mode=0o700)
        marker = parent / '.git'
        marker.write_text('synthetic repository marker')
        with self.assertRaisesRegex(ValueError, 'Git source destination'):
            EXPORT.validate_destination(parent / 'source')
        marker.unlink()
        marker.symlink_to(parent / 'absent-git-directory')
        with self.assertRaisesRegex(ValueError, 'Git source destination'):
            EXPORT.validate_destination(parent / 'source')

    def test_symlink_ancestor_and_storage_itself_are_rejected(self):
        physical = self.root / 'physical'
        physical.mkdir(mode=0o700)
        link = self.root / 'linked'
        link.symlink_to(physical, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'physical external'):
            EXPORT.validate_destination(link / 'source')
        with self.assertRaisesRegex(ValueError, 'physical external'):
            EXPORT.validate_destination(self.root)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
