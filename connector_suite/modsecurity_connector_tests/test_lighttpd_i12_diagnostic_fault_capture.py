"""Protect disposable source and identity boundaries of diagnostic injections."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = connector_root()
FAULTS = load_source(source_path('ci/runtime/lifecycle/i12/lighttpd/diagnostic_fault_capture.py', root=ROOT))
HEADER = source_path('ci/runtime/lifecycle/i12/lighttpd/patched_faults.h', root=ROOT)


class DiagnosticFaultBoundaryTests(unittest.TestCase):
    def test_real_runtime_overlay_requires_fresh_marked_copy_and_preserves_input_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            runtime = source / "common/runtime/msconnector_runtime.c"
            runtime.parent.mkdir(parents=True)
            runtime.write_text('#include "diagnostic_faults.h"\n' +
                (source_path('common/runtime/msconnector_runtime.c', root=ROOT)).read_text())
            original = runtime.read_bytes()
            marker = source / ".i12-disposable-source-copy.json"
            marker.write_text(json.dumps({"disposable": True, "path": str(source)}))
            receipt = FAULTS.extend(source, HEADER)
            self.assertTrue(receipt["stripped_input_identity"])
            self.assertFalse(receipt["native_sdk_return_mutated"])
            self.assertNotEqual(runtime.read_bytes(), original)
            changed = runtime.read_bytes()
            self.assertEqual(receipt["input_runtime_sha256"], hashlib.sha256(original).hexdigest())
            self.assertEqual(receipt["fault_runtime_sha256"], hashlib.sha256(changed).hexdigest())
            untrusted_begin, remaining_begins = changed.decode().split(
                "int msconnector_runtime_transaction_begin_request_stream(", 1)
            self.assertIn('i12_pointer_null("headers_null"', untrusted_begin)
            self.assertIn("decision, error, (msconnector_runtime_begin_options){0, NULL});", untrusted_begin)
            self.assertNotIn("injected_request", remaining_begins)
            self.assertIn("decision, error, (msconnector_runtime_begin_options){0, provenance});", remaining_begins)
            self.assertIn("decision, error, (msconnector_runtime_begin_options){1, provenance});", remaining_begins)
            with self.assertRaisesRegex(ValueError, "fresh"):
                FAULTS.extend(source, HEADER)
            self.assertEqual(runtime.read_bytes(), changed)

    def test_missing_or_duplicate_current_begin_anchor_rejects_without_writes(self):
        anchor = ("    return transaction_begin_internal(runtime, request, host_request_id, out,\n"
                  "        decision, error, (msconnector_runtime_begin_options){0, NULL});")
        current = (source_path('common/runtime/msconnector_runtime.c', root=ROOT)).read_text()
        self.assertEqual(current.count(anchor), 1)
        for replacement in ("", anchor + "\n" + anchor):
            with self.subTest(anchor_count=replacement.count(anchor)):
                with tempfile.TemporaryDirectory() as temporary:
                    source = Path(temporary)
                    runtime = source / "common/runtime/msconnector_runtime.c"
                    runtime.parent.mkdir(parents=True)
                    runtime.write_text('#include "diagnostic_faults.h"\n' + current.replace(anchor, replacement))
                    original = runtime.read_bytes()
                    (source / ".i12-disposable-source-copy.json").write_text(
                        json.dumps({"disposable": True, "path": str(source)}))
                    with self.assertRaisesRegex(ValueError, "anchor missing or ambiguous"):
                        FAULTS.extend(source, HEADER)
                    self.assertEqual(runtime.read_bytes(), original)
                    self.assertFalse((source / "patched_faults.h").exists())
                    self.assertFalse((source / "diagnostic_budget_observer.h").exists())
                    self.assertFalse((source / "diagnostic_finish_observer.h").exists())

    def test_symlink_parent_is_rejected_before_touching_real_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            physical = root / "physical"
            physical.mkdir()
            alias = root / "alias"
            alias.symlink_to(physical, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "physical paths"):
                FAULTS.extend(alias, HEADER)
            self.assertEqual(list(physical.iterdir()), [])

    def test_marker_cannot_authorize_a_different_source_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            marker = source / ".i12-disposable-source-copy.json"
            marker.write_text(json.dumps({"disposable": True, "path": str(source / "other")}))
            with self.assertRaisesRegex(ValueError, "exact marked"):
                FAULTS.extend(source, HEADER)
            self.assertEqual(list(source.iterdir()), [marker])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
