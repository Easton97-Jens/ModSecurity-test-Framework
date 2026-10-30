"""Inert metadata and retained-link boundary regressions; no compiler or host runs."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = connector_root()
LIGHTTPD = source_path('ci/runtime/lifecycle/i12/lighttpd', root=ROOT)


def load(name, source):
    module = load_source(source)
    return module


class MetadataRecipeBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = load('metadata_native_observe',
                          source_path('connectors/haproxy/harness/i12_native_observe.py', root=ROOT))
        cls.stock = load('metadata_stock_qualification', LIGHTTPD / 'stock_qualification.py')
        with patch.dict(sys.modules, {'stock_qualification': cls.stock}):
            cls.link = load('metadata_stock_link', LIGHTTPD / 'stock_link_variant.py')

    def setUp(self):
        run_root = Path(os.environ['I12_TEST_ROOT'])
        scratch = tempfile.TemporaryDirectory(prefix='metadata-boundary-', dir=run_root)
        self.addCleanup(scratch.cleanup)
        self.scratch = Path(scratch.name)
        self.input = self.scratch / 'receipt.json'
        self.input.write_text('{"bound": true}')
        self.input.chmod(0o644)

    def canonical_recipe(self):
        old = self.link.PREVIOUS / 'stock'
        source, build = old / 'capture-04/source', old / 'capture-04/build'
        argv = ['rtk', 'proxy', 'cc', '-std=c17', '-Wall', '-Wextra', '-Werror',
                '-fPIC', '-fno-lto', '-pthread']
        for relative in ('', 'common/include', 'common/runtime', 'ci/runtime/lifecycle',
                         'connectors/lighttpd/stock_sidecar'):
            argv += ['-I', str(source / relative)]
        argv += ['-DMSCONNECTOR_STOCK_SIDECAR_MAIN',
                 str(source / 'connectors/lighttpd/stock_sidecar/stock_sidecar.c'),
                 str(source / 'common/runtime/msconnector_runtime.c'),
                 str(source / 'connectors/profile_registry.c')]
        argv += [str(source / 'common/src' / path.name)
                 for path in sorted((source_path('common/src', root=ROOT)).glob('*.c'))]
        argv += [str(build / (name + '.o')) for name in ('observer', 'host', 'bootstrap', 'sdk')]
        argv += ['-Wl,--wrap=' + name for name in sorted(self.link.WRAPPED_SYMBOLS)]
        return argv + ['-lstdc++', '-lmodsecurity', '-lcrypto', '-lyajl', '-o',
                       str(build / 'lighttpd-stock-sidecar')]

    def test_native_bound_metadata_load_reference_and_hash(self):
        expected = hashlib.sha256(self.input.read_bytes()).hexdigest()
        self.assertEqual(self.native.load(self.input), {'bound': True})
        self.native.require_hash(self.input, expected)
        self.assertEqual(self.native.reference(self.input, 'source_manifest'),
                         {'path': str(self.input), 'sha256': expected,
                          'bytes': self.input.stat().st_size, 'role': 'source_manifest'})

    def test_native_rejects_outside_metadata_before_probe(self):
        with patch.object(self.native.i12_paths, '_configured_roots', return_value=()), \
                patch.object(Path, 'stat', side_effect=AssertionError('unexpected filesystem probe')):
            with self.assertRaisesRegex(ValueError, 'outside approved'):
                self.native.load(Path('/etc/passwd'))

    def test_native_rejects_mismatched_hash(self):
        with self.assertRaisesRegex(ValueError, 'hash differs'):
            self.native.require_hash(self.input, '0' * 64)

    def test_native_rejects_symbolic_link_metadata(self):
        alias = self.scratch / 'alias.json'
        alias.symlink_to(self.input)
        with self.assertRaisesRegex(ValueError, 'physical absolute regular'):
            self.native.load(alias)

    def test_native_rejects_oversized_metadata_before_read(self):
        with self.input.open('wb') as stream:
            stream.truncate(self.native.i12_paths.MAXIMUM_BYTES + 1)
        with self.assertRaisesRegex(ValueError, 'bounded regular'):
            self.native.load(self.input)

    def test_native_rejects_writable_metadata_before_payload_read(self):
        for mode in (0o666, 0o664):
            self.input.chmod(mode)
            with self.subTest(mode=oct(mode)), patch.object(
                    self.native.i12_paths.os, 'fdopen',
                    side_effect=AssertionError('untrusted metadata reached payload read')):
                with self.assertRaisesRegex(ValueError, 'trusted owner|write permissions'):
                    self.native.load(self.input)

    def test_native_rejects_foreign_owned_metadata_before_payload_read(self):
        identity = self.input.stat()
        real_fstat = os.fstat
        foreign_uid = 1 if os.geteuid() != 1 else 2

        def foreign_leaf(descriptor):
            details = real_fstat(descriptor)
            if stat.S_ISREG(details.st_mode) and (
                    details.st_dev, details.st_ino) == (identity.st_dev, identity.st_ino):
                return SimpleNamespace(st_mode=details.st_mode, st_size=details.st_size,
                    st_uid=foreign_uid, st_mtime_ns=details.st_mtime_ns,
                    st_ctime_ns=details.st_ctime_ns)
            return details

        with patch.object(self.native.i12_paths.os, 'fstat', side_effect=foreign_leaf), \
                patch.object(self.native.i12_paths.os, 'fdopen',
                    side_effect=AssertionError('foreign metadata reached payload read')):
            with self.assertRaisesRegex(ValueError, 'trusted owner|write permissions'):
                self.native.load(self.input)

    def test_native_owned_readonly_metadata_preserves_load_reference_and_hash(self):
        expected = hashlib.sha256(self.input.read_bytes()).hexdigest()
        for mode in (0o644, 0o444):
            self.input.chmod(mode)
            with self.subTest(mode=oct(mode)):
                self.assertEqual(self.native.load(self.input), {'bound': True})
                self.native.require_hash(self.input, expected)
                self.assertEqual(self.native.reference(self.input, 'source_manifest'),
                    {'path': str(self.input), 'sha256': expected,
                     'bytes': self.input.stat().st_size, 'role': 'source_manifest'})

    def test_native_independent_source_receipt_needs_no_configured_runtime_root(self):
        external_root = '/var/tmp/codex/ModSecurity-conector'

        def source_paths(value):
            return self.scratch / 'unselected-runtime' if value == external_root else Path(value)

        with patch.object(self.native, 'connector_root', return_value=self.scratch), \
                patch.object(self.native, 'Path', side_effect=source_paths), \
                patch.object(self.native.i12_paths, '_configured_roots', return_value=()):
            self.assertEqual(self.native.load(self.input), {'bound': True})

    def test_native_independent_archive_receipt_needs_no_configured_runtime_root(self):
        archive = self.scratch / 'archive'
        archive.mkdir()
        receipt = archive / 'receipt.json'
        receipt.write_bytes(self.input.read_bytes())
        receipt.chmod(0o644)
        mapped_roots = {
            '/var/tmp/codex/ModSecurity-conector': self.scratch / 'unselected-runtime',
        }

        def archive_paths(value):
            return mapped_roots.get(value, Path(value))

        with patch.dict(os.environ, {'CODEX_CLEANUP_ARCHIVE_ROOT': str(archive)}), \
                patch.object(self.native, 'Path', side_effect=archive_paths), \
                patch.object(self.native.i12_paths, '_configured_roots', return_value=()):
            self.assertEqual(self.native.load(receipt), {'bound': True})

    def test_stock_rejects_outside_metadata_before_probe(self):
        with patch.object(Path, 'stat', side_effect=AssertionError('unexpected filesystem probe')):
            with self.assertRaisesRegex(ValueError, 'outside declared'):
                self.stock.regular(Path('/etc/passwd'))

    def test_stock_pinned_text_preserves_valid_receipt(self):
        self.assertEqual(json.loads(self.stock.read_text(self.input)), {'bound': True})
        self.assertEqual(self.stock.sha(self.input), hashlib.sha256(self.input.read_bytes()).hexdigest())

    def test_stock_rejects_linked_receipt(self):
        alias = self.scratch / 'hardlink.json'
        os.link(self.input, alias)
        with self.assertRaisesRegex(ValueError, 'one regular file link'):
            self.stock.read_text(alias)

    def test_stock_rejects_fifo_receipt_without_blocking(self):
        fifo = self.scratch / 'receipt.fifo'
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, 'one regular file link'):
            self.stock.read_text(fifo)

    def test_recipe_rejects_unapproved_compiler_before_process(self):
        argv = self.canonical_recipe()
        argv[2] = 'unapproved-compiler'
        with patch.object(self.link, 'regular', side_effect=Path), \
                patch.object(self.link, 'read_text', return_value=json.dumps({'argv': argv})), \
                patch.object(self.link.subprocess, 'run') as process:
            with self.assertRaisesRegex(ValueError, 'recipe differs'):
                self.link.build(self.scratch / 'output', self.scratch / 'mime')
        process.assert_not_called()

    def test_recipe_rejects_response_file(self):
        argv = self.canonical_recipe()
        argv.insert(24, '@unapproved.rsp')
        with self.assertRaises(ValueError):
            self.link.validated_recipe(argv, self.link.PREVIOUS / 'stock')

    def test_recipe_rejects_plugin_flag(self):
        argv = self.canonical_recipe()
        argv.insert(24, '-fplugin=/unapproved.so')
        with self.assertRaises(ValueError):
            self.link.validated_recipe(argv, self.link.PREVIOUS / 'stock')

    def test_recipe_rejects_forced_include(self):
        argv = self.canonical_recipe()
        argv[24:24] = ['-include', '/unapproved.h']
        with self.assertRaises(ValueError):
            self.link.validated_recipe(argv, self.link.PREVIOUS / 'stock')

    def test_recipe_rejects_additional_output(self):
        argv = self.canonical_recipe()
        argv[24:24] = ['-o', '/unapproved-output']
        with self.assertRaises(ValueError):
            self.link.validated_recipe(argv, self.link.PREVIOUS / 'stock')

    def test_recipe_rejects_outside_source_operand(self):
        argv = self.canonical_recipe()
        index = next(index for index, value in enumerate(argv) if value.endswith('/common/src/adapter.c'))
        argv[index] = '/unapproved/adapter.c'
        with self.assertRaisesRegex(ValueError, 'unexpected Common inputs'):
            self.link.validated_recipe(argv, self.link.PREVIOUS / 'stock')

    def test_recipe_preserves_private_probe_substitutions(self):
        argv = self.canonical_recipe()
        mime, helper, source = (self.scratch / name for name in ('mime', 'helper', 'source'))
        sink, transport = self.scratch / 'sink.o', self.scratch / 'transport.o'
        with patch.object(self.link, 'regular', side_effect=Path), \
                patch.object(self.link, 'read_text', return_value=json.dumps({'argv': argv})), \
                patch.object(self.link, 'sha', return_value='0' * 64), \
                patch.object(self.link, '_validate_include_directories'), \
                patch.object(self.link.subprocess, 'run',
                             return_value=SimpleNamespace(stdout=b'', stderr=b'', returncode=1)) as process:
            receipt = self.link.build(self.scratch / 'output', mime, sink, source, helper, transport)
        actual = process.call_args.args[0]
        self.assertEqual(receipt['argv'], actual)
        self.assertIn(str(source / 'common/src/adapter.c'), actual)
        self.assertIn(str(mime / 'mime-accessor.o'), actual)
        self.assertIn(str(mime / 'native-observer.o'), actual)
        self.assertIn(str(helper / 'host.o'), actual)
        self.assertIn(str(helper / 'sdk.o'), actual)
        self.assertIn(str(helper / 'bootstrap.o'), actual)
        self.assertIn(str(sink), actual)
        self.assertIn(str(transport), actual)
        self.assertEqual(actual[-7:], ['-Wl,--wrap=fdopen', '-Wl,--wrap=fputs',
                         '-Wl,--wrap=fflush', '-Wl,--wrap=fclose', '-Wl,--wrap=accept',
                         '-Wl,--wrap=send', '-Wl,--wrap=recv'])
        self.assertIn('-lstdc++', actual)
        self.assertEqual(receipt['exit'], 1)


# Parent default discovery uses the one admitted active-case inventory.
if os.environ.get('ON_DEMAND_TESTS') != '1':
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)


if __name__ == '__main__':
    unittest.main()
