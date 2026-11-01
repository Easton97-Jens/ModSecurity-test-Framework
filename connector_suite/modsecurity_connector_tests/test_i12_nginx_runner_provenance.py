"""Synthetic controller-binding tests; these do not qualify a host lifecycle."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch


ROOT = connector_root()
HARNESS = source_path('ci/runtime/lifecycle/i12/nginx', root=ROOT)
spec = importlib.util.spec_from_file_location("nginx_runner_provenance", HARNESS / "run_cases.py")
RUN = importlib.util.module_from_spec(spec)
with patch.object(sys, "path", [str(HARNESS), *sys.path]):
    spec.loader.exec_module(RUN)


class RunnerProvenanceTests(unittest.TestCase):
    def setUp(self):
        root = Path("/var/tmp/codex/ModSecurity-conector/runs")
        root.mkdir(parents=True, exist_ok=True)
        scratch = tempfile.TemporaryDirectory(prefix="nginx-provenance-", dir=root)
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.args = argparse.Namespace(
            output_root=self.root / "cases", run_prefix="actual-run-20261022",
            nginx_binary=self.root / "nginx", module=self.root / "module.so",
            library_dir=self.root / "lib", framework_root=self.root / "framework")
        self.shared_environment = {"PATH": "/usr/bin", RUN.EVENT_RUN_ID: "stale",
                                   RUN.EVENT_CASE_ID: "stale-case"}
        self.raw = Mock()
        self.raw.BASE.configtest_environment.return_value = self.shared_environment
        self.raw.BASE.validate_inputs.side_effect = lambda args: (
            Path(args.nginx_binary), Path(args.module), Path(args.output_root))
        self.raw.config_template.return_value = (
            "events {}\nhttp {\nmodsecurity on;\nlocation / { proxy_pass http://backend; }\n}")
        self.raw.reserve_port.return_value = 18080
        self.maps = Mock()
        self.maps.Capture.return_value.descriptors.return_value = []
        for target, value in (("worker_directory", self.root / "worker"),
                              ("observer_descriptors", [])):
            patched = patch.object(RUN, target, return_value=value)
            patched.start()
            self.addCleanup(patched.stop)
        for owner, target in ((RUN, "HTTPServer"), (RUN.threading, "Thread")):
            patched = patch.object(owner, target)
            patched.start()
            self.addCleanup(patched.stop)
        patched = patch.object(RUN.os, "geteuid", return_value=0)
        patched.start()
        self.addCleanup(patched.stop)

    def prepare(self, name):
        row = {**RUN.cases()[0], "case_id": name}
        return RUN.prepare_case(self.args, row, self.raw, self.maps)

    def test_exact_identity_replaces_inherited_values_without_case_or_process_leakage(self):
        before = dict(os.environ)
        first = self.prepare("first_case")
        second = self.prepare("second_case")
        for context in (first, second):
            expected_run = self.args.run_prefix + "-" + hashlib.sha256(
                context.row["case_id"].encode()).hexdigest()[:16]
            self.assertEqual(context.environment[RUN.EVENT_RUN_ID], expected_run)
            self.assertEqual(context.local_args.run_id, expected_run)
            self.assertEqual(context.environment[RUN.EVENT_CASE_ID],
                             "I12::nginx-native::" + context.row["case_id"])
            self.assertEqual(context.environment[RUN.EVENT_CASE_ID],
                             context.environment["MSCONNECTOR_LIFECYCLE_CASE"])
        self.assertNotEqual(first.environment[RUN.EVENT_RUN_ID], second.environment[RUN.EVENT_RUN_ID])
        self.assertIsNot(first.environment, second.environment)
        self.assertEqual(self.shared_environment[RUN.EVENT_RUN_ID], "stale")
        self.assertEqual(self.shared_environment[RUN.EVENT_CASE_ID], "stale-case")
        self.assertEqual(dict(os.environ), before)

    def test_launch_and_main_context_config_receive_the_same_exact_binding(self):
        context = self.prepare("timeout_case")
        context.backend.server_port = 18081
        context.row["extra_headers"] = [(RUN.EVENT_RUN_ID, "untrusted-header")]
        self.raw.BASE.invoke.return_value = (0, b"", b"", None)
        with patch.object(RUN, "rules", return_value="fixture rules"), \
                patch.object(RUN, "invoke_client"), \
                patch.object(RUN.subprocess, "Popen") as launch:
            RUN.exercise_case(context)
        config = (context.output / "nginx.conf").read_text()
        main_context = config.split("events {}", 1)[0]
        for key in (RUN.EVENT_RUN_ID, RUN.EVENT_CASE_ID):
            self.assertEqual(main_context.count("env " + key + ";"), 1)
            self.assertEqual(launch.call_args.kwargs["env"][key], context.environment[key])
        self.assertIs(launch.call_args.kwargs["env"], context.environment)
        self.assertEqual(context.environment[RUN.EVENT_CASE_ID], "I12::nginx-native::timeout_case")
        self.assertNotIn("untrusted-header", config)
        parser_environment = self.raw.BASE.invoke.call_args.args[1]
        self.assertNotIn(RUN.EVENT_RUN_ID, parser_environment)
        self.assertNotIn(RUN.EVENT_CASE_ID, parser_environment)

    def test_invalid_tokens_fail_before_resource_allocation(self):
        for name in ("bad/case", "bad case", "bad\ncase", "ü", "a" * 111):
            # Fully qualified selected identity has an additional 19 bytes.
            with self.subTest(name=name), patch.object(RUN, "HTTPServer") as backend:
                with self.assertRaises(ValueError):
                    self.prepare(name)
                backend.assert_not_called()
                self.assertFalse(self.args.output_root.exists())
        for prefix in ("bad;run", "bad.run", "bad:run"):
            self.args.run_prefix = prefix
            with self.subTest(prefix=prefix), patch.object(RUN, "HTTPServer") as backend:
                with self.assertRaises(ValueError):
                    self.prepare("valid_case")
                backend.assert_not_called()
                self.assertFalse(self.args.output_root.exists())

    def test_final_run_identity_64_accepted_and_65_rejected_before_allocation(self):
        # The case hash suffix contributes one separator plus 16 hex bytes.
        self.args.run_prefix = "r" * 48
        with patch.object(RUN, "HTTPServer") as backend:
            with self.assertRaises(ValueError):
                self.prepare("boundary_case")
            backend.assert_not_called()
        self.assertFalse(self.args.output_root.exists())
        self.args.run_prefix = "r" * 47
        context = self.prepare("boundary_case")
        self.assertEqual(len(context.local_args.run_id), 64)
        self.assertEqual(context.environment[RUN.EVENT_RUN_ID], context.local_args.run_id)

    def test_token_boundaries_and_missing_or_invalid_config_binding(self):
        self.assertEqual(RUN.event_provenance("a" * 128, "A-z_0.:9"),
                         {RUN.EVENT_RUN_ID: "a" * 128, RUN.EVENT_CASE_ID: "A-z_0.:9"})
        for token in (None, "", "a" * 129, "x\x00y", "x\ny", "é", "x=y"):
            for key in (RUN.EVENT_RUN_ID, RUN.EVENT_CASE_ID):
                values = {RUN.EVENT_RUN_ID: "run", RUN.EVENT_CASE_ID: "case", key: token}
                with self.subTest(key=key, token=token), self.assertRaises(ValueError):
                    RUN.configuration(self.raw, self.root, 1, 2, {}, self.root, values)
        with self.assertRaises(ValueError):
            RUN.configuration(self.raw, self.root, 1, 2, {}, self.root, {})



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
