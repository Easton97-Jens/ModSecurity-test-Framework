"""Evidence controls: a successful socket exchange cannot invent native EOS."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = connector_root()
REVIEW = load_source(source_path('connectors/traefik/harness/i12/native/review.py', root=ROOT))
EXTERNAL = Path(os.environ.get('I12_TEST_ROOT', '/var/tmp/codex/ModSecurity-conector'))
NATIVE = source_path('connectors/traefik/harness/i12/native', root=ROOT)


def setUpModule():
    EXTERNAL.mkdir(parents=True, exist_ok=True)
    configured = mock.patch.dict(os.environ, {'CODEX_TEMP_ROOT': str(EXTERNAL)})
    configured.start()
    unittest.addModuleCleanup(configured.stop)


def load_preparer(name):
    module = load_source(NATIVE / (name + '.py'))
    return module


PREPARE = load_preparer('prepare')
with mock.patch.dict('sys.modules', {'prepare': PREPARE}):
    FOLLOWUP = load_preparer('prepare_followup')
    HOST_SCOPE = load_preparer('prepare_host_scope')


class NativeOutputGuards(unittest.TestCase):
    @staticmethod
    def unused_toolchain():
        """Output rejection must precede traversal of this unused input."""
        return EXTERNAL / 'unused-private-toolchain'

    def assert_rejected_without_write(self, root, operation):
        before = {str(path.relative_to(root)): path.lstat().st_mode for path in root.rglob('*')}
        with mock.patch.object(PREPARE.shutil, 'copytree') as copy:
            with self.assertRaises(ValueError):
                operation()
            copy.assert_not_called()
        after = {str(path.relative_to(root)): path.lstat().st_mode for path in root.rglob('*')}
        self.assertEqual(before, after)

    def test_openat_bridge_keeps_three_and_four_argument_calls(self):
        compiler = shutil.which('gcc')
        if compiler is None:
            self.skipTest('strict C compiler unavailable')
        with tempfile.TemporaryDirectory(prefix='native-openat-abi-', dir=EXTERNAL) as temporary:
            root = Path(temporary)
            source = root / 'probe.c'
            source.write_text(r'''#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
int main(int argc, char **argv) {
 struct stat info;
 if (argc != 2) return 1;
 umask(0);
 int directory = openat(AT_FDCWD, argv[1], O_RDONLY | O_DIRECTORY);
 if (directory < 0) return 2;
 int created = openat(directory, "created", O_CREAT | O_EXCL | O_RDWR, (mode_t)0600);
 if (created < 0 || fstat(created, &info) != 0 || (info.st_mode & 0777) != 0600) return 3;
 if (close(created) != 0) return 4;
 int existing = openat(directory, "created", O_RDONLY);
 if (existing < 0 || close(existing) != 0) return 5;
 int anonymous = openat(directory, ".", O_TMPFILE | O_RDWR, (mode_t)0640);
 if (anonymous >= 0) {
  if (fstat(anonymous, &info) != 0 || (info.st_mode & 0777) != 0640 || close(anonymous) != 0) return 6;
 } else if (errno != EOPNOTSUPP && errno != EISDIR && errno != EINVAL) return 7;
 return close(directory) != 0;
}
''')
            binary = root / 'probe'
            compiled = subprocess.run([compiler, '-std=c17', '-Wall', '-Wextra', '-Werror',
                '-ffunction-sections', '-fdata-sections', '-I', str(source_path('common/include', root=ROOT)),
                str(source), str(NATIVE / 'acceptance_faults.c'), '-Wl,--wrap=openat',
                '-Wl,--gc-sections', '-o', str(binary)], capture_output=True, text=True, check=False)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(binary), str(root)],
                capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_checkout_output_rejected_before_copy_or_creation(self):
        output = source_path('native-output-must-not-exist', root=ROOT)
        history = EXTERNAL / 'unused-history'
        toolchain = self.unused_toolchain()
        with mock.patch.object(PREPARE.shutil, 'copytree') as copy:
            with self.assertRaises(ValueError):
                PREPARE.prepare(ROOT, history, output, toolchain)
            copy.assert_not_called()
        self.assertFalse(output.exists())

    def test_external_git_ancestor_rejected_before_write(self):
        with tempfile.TemporaryDirectory(prefix='native-guards-', dir=EXTERNAL) as temporary:
            root = Path(temporary)
            (root / '.git').write_text('gitdir: /invalid/test-only\n')
            self.assert_rejected_without_write(
                root, lambda: PREPARE.prepare(ROOT, root / 'unused', root / 'new', self.unused_toolchain()))

    def test_symlink_component_rejected_by_every_preparer(self):
        with tempfile.TemporaryDirectory(prefix='native-guards-', dir=EXTERNAL) as temporary:
            root = Path(temporary)
            (root / 'real').mkdir()
            (root / 'alias').symlink_to(root / 'real', target_is_directory=True)
            for operation in (
                lambda: PREPARE.prepare(ROOT, root / 'unused', root / 'alias/new', self.unused_toolchain()),
                lambda: FOLLOWUP.prepare_followup(root / 'alias', 'mime'),
                lambda: HOST_SCOPE.prepare_scope(root / 'alias')):
                with self.subTest(operation=operation):
                    self.assert_rejected_without_write(root, operation)

    def test_existing_output_is_not_overwritten(self):
        with tempfile.TemporaryDirectory(prefix='native-guards-', dir=EXTERNAL) as temporary:
            root = Path(temporary)
            (root / 'sentinel').write_text('preserve\n')
            self.assert_rejected_without_write(
                root, lambda: PREPARE.prepare(ROOT, root / 'unused', root, self.unused_toolchain()))
            self.assertEqual((root / 'sentinel').read_text(), 'preserve\n')

    def test_cli_does_not_resolve_away_symlink_destination(self):
        with tempfile.TemporaryDirectory(prefix='native-guards-', dir=EXTERNAL) as temporary:
            root = Path(temporary)
            real = root / 'real'
            real.mkdir()
            for name in ('source', 'fixtures', 'artifacts'):
                (real / name).mkdir()
            alias = root / 'alias'
            alias.symlink_to(real, target_is_directory=True)
            commands = (
                [str(NATIVE / 'prepare.py'), '--repo', str(ROOT), '--historical', str(root / 'unused'),
                 '--output', str(alias / 'new'), '--private-toolchain', str(self.unused_toolchain())],
                [str(NATIVE / 'prepare_followup.py'), str(alias), 'mime'],
                [str(NATIVE / 'prepare_host_scope.py'), str(alias)])
            before = sorted(str(path.relative_to(root)) for path in root.rglob('*'))
            for arguments in commands:
                with self.subTest(script=arguments[0]):
                    with mock.patch.object(sys, 'argv', arguments), mock.patch.dict(sys.modules, {'prepare': PREPARE}):
                        with self.assertRaisesRegex(ValueError, 'symlink output components are forbidden'):
                            runpy.run_path(arguments[0], run_name='__main__')
                    self.assertEqual(before, sorted(str(path.relative_to(root)) for path in root.rglob('*')))

    def test_followups_reject_git_root_before_chmod(self):
        with tempfile.TemporaryDirectory(prefix='native-guards-', dir=EXTERNAL) as temporary:
            root = Path(temporary)
            for name in ('source', 'fixtures', 'artifacts'):
                (root / name).mkdir()
            (root / '.git').mkdir()
            for operation in (lambda: FOLLOWUP.prepare_followup(root, 'mime'), lambda: HOST_SCOPE.prepare_scope(root)):
                self.assert_rejected_without_write(root, operation)

    def test_followup_existing_target_rejected_before_copy(self):
        with tempfile.TemporaryDirectory(prefix='native-guards-', dir=EXTERNAL) as temporary:
            root = Path(temporary)
            for name in ('source', 'fixtures', 'artifacts', 'fixtures-mime'):
                (root / name).mkdir()
            self.assert_rejected_without_write(root, lambda: FOLLOWUP.prepare_followup(root, 'mime'))

    def test_fresh_external_path_and_existing_prepared_root_are_admitted(self):
        with tempfile.TemporaryDirectory(prefix='native-guards-', dir=EXTERNAL) as temporary:
            root = Path(temporary)
            self.assertEqual(PREPARE.validate_output(root / 'fresh', fresh=True), root / 'fresh')
            for name in ('source', 'fixtures', 'artifacts'):
                (root / name).mkdir()
            self.assertEqual(PREPARE.validate_prepared_root(root), root)


class NativeMeasurements(unittest.TestCase):
    def test_tcp_eof_and_client_pass_do_not_synthesize_lifecycle(self):
        external = EXTERNAL
        with tempfile.TemporaryDirectory(prefix='review-control-', dir=external) as temporary:
            attempt = Path(temporary)
            client = attempt / 'data/client'
            client.mkdir(parents=True)
            (client / 'allow.receipt.json').write_text(json.dumps({'label': 'allow', 'tcp_eof': True, 'status': 200, 'oracle_pass': True}))
            (attempt / 'controller-result.json').write_text(json.dumps({'exitcode': 0}))
            result = REVIEW.review(attempt)
            case = result['cases'][0]
            self.assertEqual(case['native_request_eos_handoffs'], 0)
            self.assertEqual(case['native_response_eos_handoffs'], 0)
            self.assertEqual(case['independent_backend_request_count'], 0)
            self.assertEqual(case['native_enter_calls'], {})
            self.assertFalse(case['full_lifecycle_qualified'])
            self.assertFalse(result['transport_eof_is_native_eos'])
            self.assertFalse(result['qualification_promoted'])

    def test_native_enter_is_counted_once_not_again_at_return(self):
        external = EXTERNAL
        with tempfile.TemporaryDirectory(prefix='review-control-', dir=external) as temporary:
            attempt = Path(temporary)
            (attempt / 'data/client').mkdir(parents=True)
            (attempt / 'data/client/allow.receipt.json').write_text(json.dumps({'label': 'allow'}))
            logs = attempt / 'data/runtime/logs'
            logs.mkdir(parents=True)
            rows = [{'transaction_id': 'tf-allow', 'function': 'runtime_finish_request_body', 'edge': edge, 'phase': 2} for edge in ('enter', 'return')]
            (logs / 'native-lifecycle.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
            (attempt / 'controller-result.json').write_text('{}')
            case = REVIEW.review(attempt)['cases'][0]
            self.assertEqual(case['native_request_eos_handoffs'], 1)
            self.assertEqual(case['native_enter_calls']['runtime_finish_request_body'], 1)
            self.assertFalse(case['full_lifecycle_qualified'])

    def test_runtime_scope_needs_verified_native_transaction_join(self):
        with tempfile.TemporaryDirectory(prefix='review-control-', dir=EXTERNAL) as temporary:
            attempt = Path(temporary)
            (attempt / 'data/client').mkdir(parents=True)
            (attempt / 'data/client/allow.receipt.json').write_text(json.dumps({'label': 'allow'}))
            logs = attempt / 'data/runtime/logs'
            logs.mkdir(parents=True)
            rows = [
                {'transaction_id': 'tf-allow', 'function': 'native_process_request_body', 'edge': 'enter',
                 'phase': 2, 'allocation_scope_call': 7, 'allocation_join_verified': True},
                {'transaction_id': None, 'function': 'runtime_finish_request_body', 'edge': 'enter',
                 'phase': 2, 'allocation_scope_call': 7, 'allocation_join_verified': True},
                {'transaction_id': None, 'function': 'runtime_finish_request_body', 'edge': 'enter',
                 'phase': 2, 'allocation_scope_call': 8, 'allocation_join_verified': True},
                {'transaction_id': None, 'function': 'runtime_finish_request_body', 'edge': 'enter',
                 'phase': 2, 'allocation_scope_call': 7, 'allocation_join_verified': False}]
            (logs / 'native-lifecycle.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
            (attempt / 'controller-result.json').write_text('{}')
            case = REVIEW.review(attempt)['cases'][0]
            self.assertEqual(case['native_request_eos_handoffs'], 1)
            self.assertEqual(case['verified_runtime_allocation_scopes'], [7])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
