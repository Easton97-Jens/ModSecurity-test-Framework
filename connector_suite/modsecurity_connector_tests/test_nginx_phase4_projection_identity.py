"""Real projection preparation with controlled pre-native host boundary."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = connector_root()
driver = load_source(source_path('ci/runtime/lifecycle/run-nginx-phase4-cases.py', root=ROOT))


class Phase4ProjectionIdentityTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o711)
        self.parent = self.root / "projections"
        self.parent.mkdir(mode=0o711)
        self.parent.chmod(0o711)
        self.binary = self.root / "binary"
        self.binary.write_bytes(b"controlled-not-executed")
        self.module = self.root / "module"
        self.module.write_bytes(b"controlled-not-loaded")

    def prepare(self, case, run="shared-run", output="out"):
        args = SimpleNamespace(case_id=case, run_id=run, framework_root=str(ROOT),
            projection_parent=str(self.parent), library_dir=None,
            parent_sha="a" * 40, framework_sha="b" * 40, mrts_sha="c" * 40)
        spec = dict(rules="SecRuleEngine On\n", response_chunks=["body"], pause_between_chunks=False,
            request_path="/unit", nginx_phase4_mode="required", operation="native_phase4_request", source_record_id=case)
        class ControlledUpstream:
            port = 32124
            def __init__(self, *args, **kwargs):
                pass
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
        # Managed filesystem cannot represent gid65534. Only this host syscall is
        # controlled; exclusive mkdir, copying, modes and parent guards stay real.
        real_fchown = os.fchown
        def controlled_fchown(fd, uid, gid):
            self.assertEqual(gid, 65534)
            real_fchown(fd, uid, os.getegid())
        with mock.patch.object(driver.HOST.PROJECTION.os, "fchown", side_effect=controlled_fchown), \
             mock.patch.object(driver.HOST.BASE, "validate_inputs", return_value=(self.binary, self.module, self.root / output)), \
             mock.patch.object(driver.socket, "socket") as socket, \
             mock.patch.object(driver.HOST.BASE, "configtest_environment", return_value={}), \
             mock.patch.object(driver.HOST.BASE, "invoke", return_value=(1, b"", b"controlled stop before native", None)), \
             mock.patch.object(driver.HOST, "stop_owned_master", return_value={"verified": False}):
            socket.return_value.__enter__.return_value.getsockname.return_value = ("127.0.0.1", 32123)
            self.assertIs(driver.run_operation(args, spec, input_path=Path(__file__), upstream_path=source_path('ci/runtime/common/nginx_phase4_upstream.py', root=ROOT), upstream_factory=ControlledUpstream), False)
        return json.loads((self.root / output / "source-result.json").read_text())

    def test_two_cases_same_run_prepare_distinct_fresh_direct_children(self):
        first = self.prepare("phase4_body_at_limit", output="first")
        second = self.prepare("phase4_body_over_limit", output="second")
        for receipt in (first, second):
            expected = "phase4-" + hashlib.sha256((receipt["run_id"] + ":" + receipt["case_id"]).encode()).hexdigest()[:24]
            root = Path(receipt["docroot_projection_root"])
            self.assertEqual(root, self.parent / expected)
            self.assertTrue(root.is_dir())
            self.assertEqual(receipt["run_id"], "shared-run")
            self.assertEqual(receipt["canonical_status"], "NOT_EXECUTED")
        self.assertNotEqual(first["docroot_projection_root"], second["docroot_projection_root"])

    def test_same_case_and_run_reuse_is_rejected(self):
        self.prepare("phase4_body_at_limit", output="first")
        with self.assertRaisesRegex(ValueError, "projection root already exists"):
            self.prepare("phase4_body_at_limit", output="second")

    def test_distinct_actual_event_child_runs_remain_distinct(self):
        first = self.prepare("event_json_limit", "shared-run-at255", "first")
        second = self.prepare("event_json_limit", "shared-run-over256", "second")
        self.assertNotEqual(first["docroot_projection_root"], second["docroot_projection_root"])

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
