"""Focused CLI/evidence path controls; no connector hosts are executed."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


def load_fixture(relative):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location("sonar_boundary_" + path.parent.name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


NATIVE = load_fixture("connector_suite/adapters/traefik/harness/i12/native/client.py")
AUTH = load_fixture("connector_suite/adapters/traefik/harness/i12_auth/client.py")
PATCHED = load_fixture("connector_suite/modsecurity_connector_ci/runtime/lifecycle/i12/lighttpd/patched_qualification.py")
INVALID_NAMES = ("../outside", "/absolute", "bad\\leaf", "bad\r\nheader", "x" * 129)


class ClientFilenameBoundaryTest(unittest.TestCase):
    def test_native_rejects_unsafe_names_before_filesystem_or_network(self):
        for label in INVALID_NAMES:
            with self.subTest(label=label), mock.patch.object(NATIVE, "Path") as path, mock.patch.object(
                    NATIVE.socket, "create_connection", side_effect=OSError("test transport unavailable")):
                with self.assertRaisesRegex(ValueError, "bounded filename component"):
                    NATIVE.run(1, label, 200)
                path.assert_not_called()

    def test_auth_rejects_unsafe_names_before_filesystem_or_network(self):
        for name in INVALID_NAMES:
            with self.subTest(name=name), mock.patch.object(AUTH, "Path") as path, mock.patch.object(
                    AUTH.socket, "create_connection", side_effect=OSError("test transport unavailable")):
                with mock.patch.object(AUTH.sys, "argv", ["client.py", "1", name]):
                    with self.assertRaisesRegex(ValueError, "bounded filename component"):
                        AUTH.main()
                path.assert_not_called()

    def test_native_keeps_valid_label_and_failure_receipt(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as temporary:
            directory = Path(temporary) / "client"
            with mock.patch.object(NATIVE, "Path", return_value=directory):
                with mock.patch.object(NATIVE.socket, "create_connection", side_effect=OSError("test transport unavailable")):
                    receipt = NATIVE.run(1, "request-type-missing", 200)
            self.assertFalse(receipt["oracle_pass"])
            self.assertEqual(receipt["error"]["type"], "OSError")
            self.assertEqual({path.name for path in directory.iterdir()}, {
                "request-type-missing.request.raw", "request-type-missing.response.raw",
                "request-type-missing.receipt.json"})
            self.assertIn(b"POST /i12-eos-request-type-missing HTTP/1.1", (directory / "request-type-missing.request.raw").read_bytes())

    def test_auth_keeps_valid_name_and_failure_receipt(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as temporary:
            directory = Path(temporary) / "client"
            with mock.patch.object(AUTH, "Path", return_value=directory):
                with mock.patch.object(AUTH.socket, "create_connection", side_effect=OSError("test transport unavailable")):
                    with mock.patch.object(AUTH.sys, "argv", ["client.py", "1", "p2-deny"]):
                        with self.assertRaises(SystemExit) as stopped:
                            AUTH.main()
            self.assertEqual(stopped.exception.code, 1)
            self.assertEqual({path.name for path in directory.iterdir()}, {
                "p2-deny.request.raw", "p2-deny.response.raw", "p2-deny.receipt.json"})
            receipt = json.loads((directory / "p2-deny.receipt.json").read_text())
            self.assertEqual(receipt["case"], "p2-deny")
            self.assertIn(b"i12-block-request", (directory / "p2-deny.request.raw").read_bytes())


class AdmissionReached(Exception):
    """Stop before historical qualification once current input admission succeeds."""


class ProposalEvidenceBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"])
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.admitted = self.base / "admitted"
        self.admitted.mkdir()
        self.outside = self.base / "outside"
        self.outside.mkdir()
        for root in (self.admitted, self.outside):
            (root / PATCHED.CAPTURE_RECEIPT).write_text("{}")
            (root / PATCHED.FIXTURE_SPEC).write_text('{"fixture": "trusted"}')
            (root / "source-build-binding.json").write_text("{}")
        self.qualifier = self.admitted / "qualifier.py"
        self.qualifier.write_text("# Test input; loading is replaced at the explicit import boundary.\n")
        configured = mock.patch.object(PATCHED, "EXTERNAL_ROOT", self.admitted)
        configured.start()
        self.addCleanup(configured.stop)
        loader = mock.patch.object(PATCHED, "load_source", return_value=SimpleNamespace(reference=lambda *_: None))
        loader.start()
        self.addCleanup(loader.stop)

    def invoke(self, root, inputs):
        return PATCHED.propose(root, self.admitted, inputs, self.admitted / "unused-output", qualifier_path=self.qualifier)

    def test_case_root_outside_declared_evidence_roots_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "outside the declared"):
            self.invoke(self.outside, self.admitted)

    def test_source_binding_outside_declared_evidence_roots_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "outside the declared"):
            self.invoke(self.admitted, self.outside)

    def test_existing_admitted_json_reaches_qualification_boundary(self):
        def reached(spec, root, review):
            self.assertEqual(spec, {"fixture": "trusted"})
            self.assertEqual(root, self.admitted)
            self.assertIsNone(review)
            raise AdmissionReached
        with mock.patch.object(PATCHED, "amend_source_counts", side_effect=reached):
            with self.assertRaises(AdmissionReached):
                self.invoke(self.admitted, self.admitted)


if __name__ == "__main__":
    unittest.main()
