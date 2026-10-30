"""Failure-path checks for the Apache-only lifecycle launch receipt."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest

ROOT = connector_root()


class ApacheLaunchReceiptTests(unittest.TestCase):
    def execute_tail(self, run):
        source = (source_path('ci/runtime/lifecycle/apache-i12/launch.py', root=ROOT)).read_text()
        # Execute the actual command/receipt path with only the external process
        # boundary substituted; admission and host startup are not test claims.
        tail = source[source.index('started=time.monotonic_ns()'):]
        with tempfile.TemporaryDirectory(prefix='apache-launch-', dir=os.environ.get(
                'RUNNER_TEMP', '/var/tmp/codex/ModSecurity-conector')) as temp:
            output = Path(temp)
            owned = output / 'apache2'
            owned.write_bytes(b'bounded-test-owned-binary')
            def task_path(value):
                path = Path(value)
                self.assertTrue(str(path).startswith('/task/'))
                return output / path.name
            scope = dict(time=time, result=None, subprocess=SimpleNamespace(
                run=run, TimeoutExpired=subprocess.TimeoutExpired),
                Path=task_path, argv=['rtk', 'proxy', '/bounded-test-harness'],
                env={}, os=SimpleNamespace(environ={}),
                stop=threading.Event(), thread=SimpleNamespace(join=lambda timeout: None, is_alive=lambda: False),
                owned=owned, hashlib=hashlib, snapshots=[], errors=[], settings={'case_id': 'bounded-test', 'original_selected_id': 'I12::apache-native::bounded-test'}, json=json)
            compiled_tail = compile(tail, '<actual-apache-launch-tail>', 'exec')
            with self.assertRaises(SystemExit) as exit_context:
                exec(compiled_tail, scope)
            serialized = (output / 'apache-lifecycle-command.json').read_text()
            receipt = json.loads(serialized)
            self.assertEqual(serialized, json.dumps(receipt, indent=2, sort_keys=True) + '\n')
            self.assertTrue(scope['stop'].is_set())
            self.assertTrue(receipt['sampler_thread_stopped'])
            return exit_context.exception.code, receipt

    def test_canonical_preamble_is_forwarded_only_for_original_baseline_cases(self):
        source = (source_path('ci/runtime/lifecycle/apache-i12/launch.py', root=ROOT)).read_text()
        node = next(node for node in ast.parse(source).body
            if isinstance(node, ast.If) and isinstance(node.test, ast.Call)
            and isinstance(node.test.func, ast.Attribute) and node.test.func.attr == 'get')
        branch = compile(ast.Module(body=[node], type_ignores=[]), '<actual-preamble-forwarding>', 'exec')
        for canonical in (True, False):
            with self.subTest(canonical=canonical):
                scope = {'settings': {'canonical_no_crs_baseline': canonical}, 'env': {}}
                exec(branch, scope)
                if canonical:
                    self.assertEqual(scope['env']['MODSECURITY_RULE_PREAMBLE_FILE'],
                        '/mnt/framework/tests/rules/no-crs-baseline.conf')
                else:
                    self.assertNotIn('MODSECURITY_RULE_PREAMBLE_FILE', scope['env'])

    def test_timeout_retains_null_driver_exit_and_nonzero_wrapper_exit(self):
        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired(args[0], kwargs['timeout'])
        exit_code, receipt = self.execute_tail(timeout)
        self.assertEqual(exit_code, 124)
        self.assertIsNone(receipt['actual_driver_exit'])
        self.assertTrue(receipt['timed_out'])
        self.assertEqual(receipt['execution_error']['type'], 'TimeoutExpired')

    def test_real_driver_failure_is_preserved(self):
        exit_code, receipt = self.execute_tail(lambda *args, **kwargs: SimpleNamespace(returncode=7))
        self.assertEqual(exit_code, 7)
        self.assertEqual(receipt['actual_driver_exit'], 7)
        self.assertFalse(receipt['timed_out'])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
