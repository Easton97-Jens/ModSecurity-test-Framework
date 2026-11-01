"""Compile copied transport probes and exercise their real private file boundary."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import ctypes
import errno
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from modsecurity_connector_ci.runtime.lifecycle.i12.lighttpd.qualification import EXTERNAL_ROOT, storage_root


SOURCE = connector_root() / 'ci/runtime/lifecycle/i12/lighttpd'
EXTERNAL = EXTERNAL_ROOT
HEADER = 'transport_observation_file.h'
HARNESS = r'''
#define _GNU_SOURCE
#include <fcntl.h>
#include <string.h>
static const char *fixture_root;
static int fixture_open(const char *path, int flags) {
    return open(strcmp(path, "/task") == 0 ? fixture_root : path, flags);
}
/* Redirect only the absolute fixture root; all openat/fstat checks remain real. */
#define open fixture_open
#include "transport_observation_file.h"
#undef open
int fixture_observation_file(const char *root, const char *path) {
    fixture_root = root;
    return observation_file(path);
}
'''


class TransportObservationFileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        storage_root(EXTERNAL)
        cls.build = tempfile.TemporaryDirectory(prefix='i12-transport-build-', dir=EXTERNAL)
        cls.bundle = Path(cls.build.name)
        for name in (HEADER, 'stock_transport_observation.c', 'patched_transport_observation.c'):
            shutil.copyfile(SOURCE / name, cls.bundle / name)
        for name in ('stock', 'patched'):
            source = cls.bundle / f'{name}_transport_observation.c'
            subprocess.run(['rtk', 'proxy', 'cc', '-std=c17', '-Wall', '-Wextra', '-Werror',
                '-fno-lto', '-c', str(source), '-o', str(source.with_suffix('.o'))],
                check=True, capture_output=True)
        harness = cls.bundle / 'boundary.c'
        harness.write_text(HARNESS)
        library = cls.bundle / 'boundary.so'
        subprocess.run(['rtk', 'proxy', 'cc', '-std=c17', '-Wall', '-Wextra', '-Werror',
            '-shared', '-fPIC', str(harness), '-o', str(library)], check=True, capture_output=True)
        cls.library = ctypes.CDLL(str(library))
        cls.opener = cls.library.fixture_observation_file
        cls.opener.argtypes = (ctypes.c_char_p, ctypes.c_char_p)
        cls.opener.restype = ctypes.c_int

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='i12-transport-output-', dir=EXTERNAL)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.child = self.root / 'private'
        self.child.mkdir(mode=0o700)

    def open(self, path, root=None):
        return self.opener(os.fsencode(root or self.root), None if path is None else os.fsencode(path))

    def test_private_nested_output_is_created_0600_and_appends(self):
        for payload in (b'first\n', b'second\n'):
            fd = self.open('/task/private/events.jsonl')
            self.assertGreaterEqual(fd, 0)
            try:
                self.assertFalse(os.get_inheritable(fd))
                os.write(fd, payload)
            finally:
                os.close(fd)
        output = self.child / 'events.jsonl'
        self.assertEqual(output.read_bytes(), b'first\nsecond\n')
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_invalid_components_prefix_and_size_are_rejected(self):
        for path in (None, '/other/events', '/task', '/task/', '/task//events',
                     '/task/./events', '/task/../events', '/task/private/../events',
                     '/task/private/', '/task/missing/events', '/task/' + 'x' * 4096):
            with self.subTest(path=path):
                self.assertEqual(self.open(path), -1)
        self.assertEqual(list(self.child.iterdir()), [])

    def test_root_and_intermediate_directory_permissions_are_required(self):
        for directory in (self.root, self.child):
            directory.chmod(0o750)
            try:
                self.assertEqual(self.open('/task/private/events'), -1)
            finally:
                directory.chmod(0o700)
        self.assertFalse((self.child / 'events').exists())

    def test_symlinks_at_every_component_are_rejected(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.child, target_is_directory=True)
        self.assertEqual(self.open('/task/alias/events'), -1)
        self.assertEqual(self.open('/task/events', root=alias), -1)
        output = self.child / 'events'
        target = self.child / 'target'
        target.write_bytes(b'unchanged')
        target.chmod(0o600)
        output.symlink_to(target)
        self.assertEqual(self.open('/task/private/events'), -1)
        self.assertEqual(target.read_bytes(), b'unchanged')

    def test_nonregular_hardlinked_and_nonprivate_outputs_are_rejected(self):
        output = self.child / 'events'
        output.mkdir(mode=0o700)
        self.assertEqual(self.open('/task/private/events'), -1)
        output.rmdir()
        output.write_bytes(b'original')
        output.chmod(0o640)
        self.assertEqual(self.open('/task/private/events'), -1)
        output.chmod(0o600)
        (self.child / 'other-name').hardlink_to(output)
        self.assertEqual(self.open('/task/private/events'), -1)
        self.assertEqual(output.read_bytes(), b'original')

    @unittest.skipUnless(os.geteuid() == 0, 'changing temporary fixture ownership requires root')
    def test_foreign_directory_and_file_owner_are_rejected(self):
        output = self.child / 'events'
        output.write_bytes(b'original')
        output.chmod(0o600)
        for path in (self.root, self.child, output):
            try:
                os.chown(path, 65534, -1)
            except OSError as error:
                if error.errno in (errno.EPERM, errno.EINVAL):
                    self.skipTest(f'foreign fixture UID unavailable: {error}')
                raise
            try:
                self.assertEqual(self.open('/task/private/events'), -1)
            finally:
                os.chown(path, os.geteuid(), -1)
        self.assertEqual(output.read_bytes(), b'original')

    def test_rejected_opens_release_descriptors(self):
        output = self.child / 'events'
        output.write_bytes(b'original')
        output.chmod(0o644)
        before = len(list(Path('/proc/self/fd').iterdir()))
        for _ in range(128):
            for path in ('/task/private/events', '/task/missing/events', '/task/private/../events'):
                self.assertEqual(self.open(path), -1)
        self.assertEqual(len(list(Path('/proc/self/fd').iterdir())), before)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
