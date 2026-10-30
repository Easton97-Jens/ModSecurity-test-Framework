"""Physical configtest receipts, using real benign subprocesses and files."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch


SOURCE = connector_root() / "ci/runtime/lifecycle/apache-i12/acceptance/batch.py"
BATCH = load_source(SOURCE)


class PhysicalWaiter:
    """Match the final direct-runner's actual RTK launch and wait interface."""

    def waited(self, argv, cwd, prefix, env):
        started = time.time_ns()
        with Path(str(prefix) + ".stdout").open("xb") as stdout, \
                Path(str(prefix) + ".stderr").open("xb") as stderr:
            process = subprocess.Popen(["rtk", "proxy", *argv], cwd=cwd, env=env, stdout=stdout, stderr=stderr)
            process.wait(timeout=10)
        return {"argv": ["rtk", "proxy", *argv], "cwd": str(cwd), "wrapper_pid": process.pid,
                "started_unix_ns": started, "ended_unix_ns": time.time_ns(),
                "waited_exit": process.returncode}


class ConfigCaptureTests(unittest.TestCase):
    def setUp(self):
        storage = Path("/var/tmp/codex/ModSecurity-conector/config-capture-tests")
        storage.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=storage)
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "case"
        self.root.mkdir(mode=0o700)
        (self.base / "native-bin").mkdir(mode=0o700)
        self.owned = self.base / "native-bin/apache2"
        self.config = self.root / "httpd.conf"
        self.config.write_bytes(b"physical fixture configuration\n")

    def run_parser(self, script, waiter=None):
        self.owned.write_bytes(b"#!/bin/sh\n" + script)
        self.owned.chmod(0o700)
        with patch.object(BATCH.paths, "storage_root", return_value=self.base), \
                patch.object(BATCH, "FIXTURE_MOUNT", SOURCE.parent):
            return BATCH.observed_configtest(waiter or PhysicalWaiter(), self.owned,
                                             self.config, self.root, dict(os.environ))

    def test_actual_exit_stream_bytes_and_cleanup_are_bound_without_verdict(self):
        receipt = self.run_parser(b"printf '\\nactual stdout\\n'; printf '\\nactual diagnostic\\nsecond\\n' >&2; exit 7\n")
        self.assertEqual(receipt["raw_returncode"], 7)
        self.assertEqual(receipt["waited_exit"], 7)
        self.assertEqual(receipt["wrapper_process"]["waited_exit"], 0)
        self.assertNotEqual(receipt["parser_pid"], receipt["wrapper_process"]["wrapper_pid"])
        self.assertIsNone(receipt["waited_signal"])
        self.assertEqual(receipt["first_cause"], "actual diagnostic")
        self.assertEqual(receipt["executable_sha256"], hashlib.sha256(self.owned.read_bytes()).hexdigest())
        for stream in ("stdout", "stderr"):
            physical = (self.root / ("configtest." + stream)).read_bytes()
            self.assertEqual(receipt[stream], physical.decode("utf-8"))
            self.assertEqual(receipt[stream + "_bytes"], len(physical))
            self.assertEqual(receipt[stream + "_sha256"], hashlib.sha256(physical).hexdigest())
        cleanup = json.loads((self.root / "configtest-cleanup.json").read_text())
        self.assertEqual(receipt["cleanup"], cleanup)
        self.assertTrue(cleanup["reaped"])
        self.assertTrue(cleanup["proc_pid_absent"])
        self.assertEqual(cleanup["scope"], "parser_pid_only")
        self.assertIsNone(cleanup["descendants_observed"])
        self.assertGreater(cleanup["observed_monotonic_ns"], 0)
        self.assertFalse((Path("/proc") / str(cleanup["pid"])).exists())
        self.assertTrue({"reviewed_by", "oracle", "outcome", "PASS"}.isdisjoint(receipt))

    def test_signal_retains_raw_negative_exit_and_explicit_signal(self):
        receipt = self.run_parser(b"kill -TERM $$\n")
        self.assertEqual(receipt["raw_returncode"], -signal.SIGTERM)
        self.assertEqual(receipt["waited_exit"], -signal.SIGTERM)
        self.assertEqual(receipt["waited_signal"], signal.SIGTERM)
        self.assertEqual(receipt["wrapper_process"]["waited_exit"], 0)
        self.assertNotIn("first_cause", receipt)
        # The previous final path reports RTK's conventional 143, proving why
        # deriving a parser signal from that wrapper returncode was unsound.
        direct_wrapper = PhysicalWaiter().waited([str(self.owned), "-t", "-f", str(self.config)],
                                                self.root, self.root / "old-wrapper", dict(os.environ))
        self.assertEqual(direct_wrapper["waited_exit"], 128 + signal.SIGTERM)

    def test_normal_zero_exit_and_empty_streams_do_not_invent_diagnostic(self):
        receipt = self.run_parser(b"exit 0\n")
        self.assertEqual(receipt["raw_returncode"], 0)
        self.assertIsNone(receipt["waited_signal"])
        self.assertNotIn("first_cause", receipt)
        self.assertEqual(receipt["stdout"], "")
        self.assertEqual(receipt["stderr"], "")

    def test_stdout_diagnostic_preserves_physical_leading_whitespace(self):
        receipt = self.run_parser(b"printf '  \\n  physical diagnostic\\n'\n")
        self.assertEqual(receipt["first_cause"], "  physical diagnostic")

    def test_invalid_utf8_fails_closed_but_retains_raw_stream_and_cleanup(self):
        with self.assertRaisesRegex(ValueError, "helper transport or input identity failed"):
            self.run_parser(b"printf '\\377' >&2\n")
        self.assertEqual((self.root / "configtest.stderr").read_bytes(), b"\xff")
        self.assertTrue(json.loads((self.root / "configtest-cleanup.json").read_text())["reaped"])
        process = json.loads((self.root / "configtest-process.json").read_text())
        self.assertIsNone(process["stderr"])
        self.assertEqual(process["stderr_sha256"], hashlib.sha256(b"\xff").hexdigest())
        self.assertIn("stderr", process["stream_decoding_errors"])

    def test_executable_hash_mutation_after_real_wait_is_rejected(self):
        owned = self.owned

        class MutatingWaiter(PhysicalWaiter):
            def waited(self, *args):
                receipt = super().waited(*args)
                owned.write_bytes(b"changed after wait\n")
                return receipt

        waiter = MutatingWaiter()
        with self.assertRaisesRegex(ValueError, "input identity failed"):
            self.run_parser(b"exit 0\n", waiter)
        self.assertTrue((self.root / "configtest-cleanup.json").is_file())

    def test_stream_hash_keeps_original_byte_identity_after_file_mutation(self):
        receipt = self.run_parser(b"printf 'actual bytes'\n")
        (self.root / "configtest.stdout").write_bytes(b"mutated bytes")
        self.assertNotEqual(receipt["stdout_sha256"],
                            hashlib.sha256((self.root / "configtest.stdout").read_bytes()).hexdigest())
        self.assertEqual(receipt["stdout"], "actual bytes")

    def test_changed_physical_stream_before_import_is_rejected(self):
        root = self.root

        class StreamMutatingWaiter(PhysicalWaiter):
            def waited(self, *args):
                receipt = super().waited(*args)
                (root / "configtest.stdout").write_bytes(b"tampered capture")
                return receipt

        waiter = StreamMutatingWaiter()
        with self.assertRaisesRegex(ValueError, "stream identity changed"):
            self.run_parser(b"printf original\n", waiter)

    def test_raw_signal_cannot_be_replaced_with_normalized_wrapper_code(self):
        root = self.root

        class ReturnMutatingWaiter(PhysicalWaiter):
            def waited(self, *args):
                receipt = super().waited(*args)
                path = root / "configtest-process.json"
                raw = json.loads(path.read_text())
                raw["raw_returncode"] = 143
                path.write_text(json.dumps(raw))
                return receipt

        waiter = ReturnMutatingWaiter()
        with self.assertRaisesRegex(ValueError, "raw wait binding failed"):
            self.run_parser(b"kill -TERM $$\n", waiter)

    def test_sealed_fixture_copy_contract_keeps_runner_beside_batch(self):
        fixtures = self.base / "fixtures"
        fixtures.mkdir(mode=0o700)
        copied_batch = fixtures / "batch.py"
        copied_helper = fixtures / "configtest_runner.py"
        shutil.copyfile(SOURCE, copied_batch)
        shutil.copyfile(SOURCE.with_name("configtest_runner.py"), copied_helper)
        with patch.object(BATCH, "__file__", str(copied_batch)), \
                patch.object(BATCH, "FIXTURE_MOUNT", fixtures):
            # run_parser patches FIXTURE_MOUNT for source-checkout tests, so
            # invoke this production path directly using the copied fixture.
            self.owned.write_bytes(b"#!/bin/sh\nexit 0\n")
            self.owned.chmod(0o700)
            with patch.object(BATCH.paths, "storage_root", return_value=self.base):
                receipt = BATCH.observed_configtest(PhysicalWaiter(), self.owned,
                                                     self.config, self.root, dict(os.environ))
        self.assertEqual(receipt["helper_sha256"], hashlib.sha256(copied_helper.read_bytes()).hexdigest())
        self.assertIn(str(copied_helper), receipt["wrapper_process"]["argv"])

    def test_private_admission_rejects_missing_execution_helper_binding(self):
        helper_dir = self.base / "helpers"
        helper_dir.mkdir(mode=0o700)
        admission_file = self.base / "admission.json"
        admission_file.write_text(json.dumps({"outside_namespaces": {}}))
        required = (self.base / "module.so", Path("/usr/sbin/apache2"),
                    Path("/usr/lib/x86_64-linux-gnu/libmodsecurity.so.3.0.14"))
        (helper_dir / "batch-binding.json").write_text(json.dumps(
            {"input_sha256": {str(path): "0" * 64 for path in required}}))
        direct = Mock()
        module = required[0]
        execution_helpers = {"configtest_runner": SOURCE.with_name("configtest_runner.py")}
        with patch.object(BATCH, "Path", side_effect=lambda value: admission_file
                          if value == "/opt/controller/admission.json" else Path(value)):
            with self.assertRaisesRegex(ValueError, "binding omits"):
                BATCH.private_admission(direct, module, helper_dir,
                                        execution_helpers=execution_helpers)
        direct.admission.assert_not_called()

    def test_actual_timeout_reaps_parser_and_rejects_helper_transport(self):
        class ShortTimeoutWaiter(PhysicalWaiter):
            def waited(self, argv, cwd, prefix, env):
                # Exercise the real helper's capture/status code under RTK,
                # shortening only its internal wait for this actual process.
                program = (
                    "import runpy,sys; from pathlib import Path; "
                    "helper=runpy.run_path(sys.argv[1]); "
                    "receipt=helper['capture'](Path(sys.argv[2]),Path(sys.argv[3]),"
                    "Path(sys.argv[4]),wait_timeout=0.03); "
                    "sys.exit(helper['helper_exit'](receipt))")
                changed = [argv[0], "-c", program, argv[1], argv[3], argv[5], argv[7]]
                return super().waited(changed, cwd, prefix, env)

        waiter = ShortTimeoutWaiter()
        with self.assertRaisesRegex(ValueError, "helper transport or input identity failed"):
            self.run_parser(b"while :; do :; done\n", waiter)
        parser = json.loads((self.root / "configtest-process.json").read_text())
        wrapper = json.loads((self.root / "configtest-wrapper-process.json").read_text())
        self.assertTrue(parser["timeout"])
        self.assertEqual(parser["raw_returncode"], -signal.SIGKILL)
        self.assertEqual(parser["waited_signal"], signal.SIGKILL)
        self.assertEqual(wrapper["waited_exit"], 1)
        self.assertEqual(parser["supervisor_parent_pid"], wrapper["wrapper_pid"])
        self.assertTrue(parser["cleanup"]["reaped"])
        self.assertTrue(parser["cleanup"]["proc_pid_absent"])
        self.assertFalse((Path("/proc") / str(parser["parser_pid"])).exists())
        self.assertEqual(parser["cleanup"]["scope"], "parser_pid_only")
        self.assertIsNone(parser["cleanup"]["descendants_observed"])
        self.assertTrue({"outcome", "executed_case_contract", "full_lifecycle_qualification"}.isdisjoint(parser))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
