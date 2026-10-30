"""Driver shape controls do not prove a real native injected operation."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
import copy
import json
import os
import stat
from contextlib import contextmanager
from pathlib import Path
import unittest
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

ROOT = connector_root()


class InputFaultDriverTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("input_fault_driver", source_path('ci/runtime/lifecycle/run-nginx-common-input-fault.py', root=ROOT))
        cls.driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.driver)

    def test_request_rejects_nonclosed_path_or_port_before_subprocess(self):
        path = "/no-crs/input-fault/header_count_nonzero_with_null_headers"
        invalid = [(12345, path + suffix) for suffix in ("/foreign", "?query", "#fragment", "\n", "%2f..")]
        invalid += [(12345, "--output=/foreign"), (12345, "http://foreign"),
                    (True, path), ("12345", path), (0, path), (65536, path)]
        with tempfile.TemporaryDirectory(dir="/var/tmp/codex/ModSecurity-conector") as temporary:
            for port, request_path in invalid:
                with self.subTest(port=port, path=request_path), patch.object(self.driver.subprocess, "run",
                        return_value=SimpleNamespace(returncode=0, stdout=b"200", stderr=b"")) as running:
                    with self.assertRaises(ValueError):
                        self.driver.request(port, request_path, {}, Path(temporary))
                    running.assert_not_called()

    def test_request_preserves_actual_capture_exit_and_strips_fault_environment(self):
        environment = {"LD_PRELOAD": "fixture", "MSCONNECTOR_OWNED_INPUT_TXID": "a" * 32, "KEEP": "yes"}
        with tempfile.TemporaryDirectory(dir="/var/tmp/codex/ModSecurity-conector") as temporary:
            output = Path(temporary)
            for case in self.driver.CASES:
                path = "/no-crs/input-fault/" + case
                with patch.object(self.driver.subprocess, "run", return_value=SimpleNamespace(
                        returncode=7, stdout=b"400", stderr=b"actual error")) as running:
                    self.assertEqual(self.driver.request(12345, path, environment, output), (7, 400))
                command = running.call_args.args[0]
                self.assertEqual(command[-2:], ["--", "http://127.0.0.1:12345" + path])
                self.assertEqual(running.call_args.kwargs["env"], {"KEEP": "yes"})
                self.assertEqual((output / "client.stdout").read_bytes(), b"400")
                self.assertEqual((output / "client.stderr").read_bytes(), b"actual error")
            self.assertIn("LD_PRELOAD", environment)

    def test_native_environment_keeps_fresh_owned_fd_not_path_authority(self):
        args = SimpleNamespace(case_id=self.driver.CASES[0], library_dir=None, fault_negative_control=False)
        with tempfile.TemporaryDirectory(dir="/var/tmp/codex/ModSecurity-conector") as temporary:
            output = Path(temporary)
            result = self.driver.native_environment(args, output, "a" * 32)
            self.assertIsInstance(result, tuple)
            environment, descriptor = result
            self.addCleanup(os.close, descriptor)
            self.assertGreaterEqual(descriptor, 3)
            self.assertEqual(environment['MSCONNECTOR_OWNED_INPUT_FD'], str(descriptor))
            self.assertNotIn('MSCONNECTOR_OWNED_INPUT_LEDGER', environment)
            details = os.fstat(descriptor)
            self.assertTrue(stat.S_ISREG(details.st_mode))
            self.assertEqual((details.st_uid, stat.S_IMODE(details.st_mode), details.st_nlink, details.st_size), (0, 0o600, 1, 0))
            self.assertFalse(os.get_inheritable(descriptor))
            with self.assertRaises(FileExistsError):
                self.driver.native_environment(args, output, "a" * 32)

    def test_ledger_descriptor_not_in_configtest_and_closed_on_startup_failure(self):
        driver = self.driver
        args = SimpleNamespace(case_id=driver.CASES[0], run_id='unit-fd', library_dir=None,
            fault_negative_control=False, parent_sha='a' * 40, framework_sha='b' * 40,
            mrts_sha='c' * 40, projection_parent='/owned/projection')
        validator = SimpleNamespace(CONTRACTS={args.case_id: {'diagnostic': 'owned'}},
                                    observation_errors=lambda *_: [])
        captured = []
        def failing_start(*_args, **kwargs):
            captured.extend(kwargs['pass_fds'])
            self.assertEqual(len(kwargs['pass_fds']), 1)
            self.assertEqual(os.fstat(captured[0]).st_size, 0)
            raise OSError('controlled startup failure')
        with tempfile.TemporaryDirectory(dir='/var/tmp/codex/ModSecurity-conector') as temporary:
            output = Path(temporary)
            prepared = (output, validator, {}, 'a' * 32, 12345, b'unit-config', Path('/owned/projection/child'))
            with patch.object(driver, 'prepare', return_value=prepared), \
                    patch.object(driver.BASE, 'invoke', return_value=(0, b'', b'', None)) as configtest, \
                    patch.object(driver.subprocess, 'Popen', side_effect=failing_start), \
                    patch.object(driver.STARTUP, 'stop_owned_master', return_value={}), \
                    patch.object(driver.os, 'fsync', wraps=os.fsync) as syncing:
                self.assertFalse(driver.run(args))
            self.assertNotIn('pass_fds', configtest.call_args.kwargs)
            self.assertEqual(len(captured), 1)
            self.assertIn(captured[0], [call.args[0] for call in syncing.call_args_list])
            with self.assertRaises(OSError):
                os.fstat(captured[0])

    def test_root_context_exit_failure_closes_new_ledger_descriptor(self):
        driver = self.driver
        args = SimpleNamespace(case_id=driver.CASES[0], library_dir=None, fault_negative_control=False)
        original_root, original_open = driver.open_private_runtime_root, os.open
        captured = []

        @contextmanager
        def failing_root(output):
            with original_root(output) as root:
                yield root
            raise OSError('controlled root context exit failure')

        def observing_open(path, *values, **kwargs):
            descriptor = original_open(path, *values, **kwargs)
            if path == driver.NATIVE_FAULT_LEDGER:
                captured.append(descriptor)
            return descriptor

        with tempfile.TemporaryDirectory(dir='/var/tmp/codex/ModSecurity-conector') as temporary:
            try:
                with patch.object(driver, 'open_private_runtime_root', side_effect=failing_root), \
                        patch.object(driver.os, 'open', side_effect=observing_open):
                    with self.assertRaisesRegex(OSError, 'controlled root context exit failure'):
                        driver.native_environment(args, Path(temporary), 'a' * 32)
                self.assertEqual(len(captured), 1)
                with self.assertRaises(OSError):
                    os.fstat(captured[0])
            finally:
                # The intended RED must not leave the deliberately exposed FD open.
                for descriptor in captured:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass

    def test_configtest_exception_still_closes_ledger_and_never_starts_native(self):
        driver = self.driver
        args = SimpleNamespace(case_id=driver.CASES[0], run_id='unit-fd', library_dir=None,
            fault_negative_control=False, parent_sha='a' * 40, framework_sha='b' * 40,
            mrts_sha='c' * 40, projection_parent='/owned/projection')
        validator = SimpleNamespace(CONTRACTS={args.case_id: {'diagnostic': 'owned'}},
                                    observation_errors=lambda *_: [])
        captured = []
        original = driver.native_environment
        def observing_environment(*values):
            environment, descriptor = original(*values)
            captured.append(descriptor)
            return environment, descriptor
        with tempfile.TemporaryDirectory(dir='/var/tmp/codex/ModSecurity-conector') as temporary:
            prepared = (Path(temporary), validator, {}, 'a' * 32, 12345, b'unit-config', Path('/owned/projection/child'))
            with patch.object(driver, 'prepare', return_value=prepared), \
                    patch.object(driver, 'native_environment', side_effect=observing_environment), \
                    patch.object(driver.BASE, 'invoke', side_effect=OSError('controlled configtest failure')), \
                    patch.object(driver.subprocess, 'Popen') as starting, \
                    patch.object(driver.STARTUP, 'stop_owned_master', return_value={}):
                self.assertFalse(driver.run(args))
            starting.assert_not_called()
            self.assertEqual(len(captured), 1)
            with self.assertRaises(OSError):
                os.fstat(captured[0])

    def test_config_binds_true_transaction_and_actual_native_sink(self):
        text = self.driver.fault_config(Path("/var/tmp/codex/owned"), 32123, "/var/tmp/codex/projection/child", "a" * 32)
        self.assertIn('modsecurity_transaction_id "' + "a" * 32 + '";', text)
        self.assertIn('"transaction_id":"' + "a" * 32 + '"', text)
        self.assertIn('user nobody nogroup;', text)
        self.assertIn('modsecurity_phase4_log "/var/tmp/codex/owned/phase1-events.jsonl";', text)
        self.assertIn('access_log "/var/tmp/codex/owned/native-access.jsonl" input_fault;', text)

    def test_mismatch_never_equals_true_transaction(self):
        for transaction in ("a" * 32, "0" * 32, "1" * 32):
            actual = self.driver.mismatch_transaction(transaction)
            self.assertNotEqual(actual, transaction)
            self.assertRegex(actual, r"^[0-9a-f]{32}$")

    def test_source_bound_protocol_selection_retains_cleanup_and_raw(self):
        helper_path = Path(os.environ.get("FRAMEWORK_ROOT", source_path('modules/ModSecurity-test-Framework', root=ROOT))) / "tests/runners/nginx_common_input_faults.py"
        if not helper_path.is_file():
            self.skipTest("strict pure Framework helper requires explicit FRAMEWORK_ROOT")
        helper = load_source(helper_path)
        transaction = "a" * 32
        path = "/no-crs/input-fault/header_count_nonzero_with_null_headers"
        event = dict(event="phase1_error", message_id="MSCONN_EVENT_CONNECTOR_ERROR", connector="nginx",
                     integration_mode="native-nginx-http-module", transaction_id=transaction,
                     phase="request_headers", method="", uri="", status="error",
                     reason="connector_error", rule_id="", http_status=500)
        cleanup = dict(event, event="transaction_cleanup", phase="logging",
                       message_id="MSCONN_TRANSACTION_CLEANUP", method="POST", uri=path)
        rows = [event, cleanup]
        retained = copy.deepcopy(rows)
        selected = self.driver.select_mapper_error_events(rows, transaction)
        self.assertEqual(selected, [event])
        self.assertEqual(helper.native_event_errors(selected, transaction), [])
        self.assertEqual(rows, retained)
        with tempfile.TemporaryDirectory(prefix="pointer-selection-", dir="/var/tmp/codex/ModSecurity-conector") as temporary:
            output = Path(temporary)
            leaf = output / "phase1-events.jsonl"
            raw = b"".join((json.dumps(row) + "\n").encode() for row in rows)
            leaf.write_bytes(raw)
            before = self.driver.BASE.digest(self.driver.STARTUP.bounded_capture(leaf))
            self.assertEqual(self.driver.select_mapper_error_events(self.driver.read_rows(output, leaf.name), transaction), [event])
            self.assertEqual(leaf.read_bytes(), raw)
            self.assertEqual(self.driver.BASE.digest(self.driver.STARTUP.bounded_capture(leaf)), before)
        for field, wrong in (("transaction_id", "b" * 32), ("phase", "response_body"),
                             ("uri", path), ("method", "POST"),
                             ("connector", "apache"), ("integration_mode", "synthetic")):
            with self.subTest(field=field):
                selected = self.driver.select_mapper_error_events([dict(event, **{field: wrong}), cleanup], transaction)
                self.assertTrue(helper.native_event_errors(selected, transaction))
        for field in ("method", "uri"):
            missing = dict(event)
            del missing[field]
            self.assertTrue(helper.native_event_errors(
                self.driver.select_mapper_error_events([missing, cleanup], transaction), transaction))
        selected = self.driver.select_mapper_error_events([event, event, cleanup], transaction)
        self.assertTrue(helper.native_event_errors(selected, transaction))

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
