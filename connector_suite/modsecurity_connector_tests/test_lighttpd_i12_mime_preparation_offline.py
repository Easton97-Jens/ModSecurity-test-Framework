"""Real MIME/constructor overlays on the exact immutable observer fixture only."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = connector_root()
PRODUCER = "ci/runtime/lifecycle/i12/lighttpd/patched_qualification.py"
CAPTURE = "ci/runtime/lifecycle/i12/capture_sources.py"
OBSERVER = "270245fedf253e4ef502fc1aedcac5406ee516b85c90002cb7deaff69fb91736"
ACCESSOR = "3f0ada7c405a54a28462359711f800ff4e18d0f2bb205b217fb5dfac82a05e0a"


def load(name, relative):
    module = load_source(ROOT / relative)
    return module


class MimePreparationTests(unittest.TestCase):
    def setUp(self):
        parent = os.environ.get("I12_TEST_ROOT") or os.environ.get("RUNNER_TEMP")
        if not parent:
            raise RuntimeError("an explicit external test root is required")
        self.temporary = tempfile.TemporaryDirectory(prefix="lighttpd-mime-offline-", dir=parent)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.external = self.root / "external"
        self.external.mkdir(mode=0o700)
        self.environment = mock.patch.dict(os.environ, {"I12_TEST_ROOT": str(self.external)})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.producer = load("offline_actual_patched_qualification", PRODUCER)
        self.capture = load("offline_actual_mime_store", CAPTURE)
        registry = self.capture.Registry()
        self.original = registry.content(OBSERVER)
        self.accessor_bytes = registry.content(ACCESSOR)
        self.assertEqual(hashlib.sha256(self.original).hexdigest(), OBSERVER)
        self.source = self.external / "source"
        self.collector = self.source / "ci/runtime/lifecycle/native-lifecycle-observer.c"
        self.collector.parent.mkdir(parents=True)
        self.collector.write_bytes(self.original)
        self.marker = self.source / self.producer.DISPOSABLE_MARKER
        self.marker.write_text(json.dumps({"disposable": True, "path": str(self.source)}))
        self.accessor = self.external / "selected-mime-accessor.cpp"
        self.accessor.write_bytes(self.accessor_bytes)
        self.destination = self.source / "ci/runtime/lifecycle/native-lifecycle-sdk-mime.cpp"
        self.maintained_before = {relative: hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
                                  for relative in (PRODUCER, CAPTURE)}
        self.addCleanup(self.assert_maintained_sources_unchanged)

    def assert_maintained_sources_unchanged(self):
        self.assertEqual(self.maintained_before,
                         {relative: hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
                          for relative in self.maintained_before})

    def extend(self):
        return self.producer.extend_mime_capture(self.source, self.accessor)

    def test_exact_mime_and_constructor_overlays_bind_actual_source_bytes(self):
        receipt = self.extend()
        self.assertEqual(Path(self.producer.__file__), ROOT / PRODUCER)
        self.assertEqual(receipt["collector_before_sha256"], OBSERVER)
        self.assertEqual(receipt["collector_after_sha256"], hashlib.sha256(self.collector.read_bytes()).hexdigest())
        self.assertEqual(receipt["accessor_source_sha256"], ACCESSOR)
        self.assertEqual(self.destination.read_bytes(), self.accessor_bytes)
        self.assertIs(receipt["production_sources_changed"], False)
        self.assertIs(receipt["opaque_offsets_used"], False)
        constructor = receipt["constructor_output_observation"]
        self.assertIs(constructor["output_slot_read_after_real_return"], True)
        self.assertIs(constructor["output_handle_dereferenced"], False)
        self.assertIs(constructor["failure_result_replaced"], False)
        text = self.collector.read_text()
        self.assertIn("observed_mime_snapshot(&observed, transaction);", text)
        self.assertIn("int result = __real_msc_process_response_body(transaction);", text)
        self.assertIn("observed.actual_output_handle_present = out != NULL && *out != NULL;", text)
        self.assertNotEqual(self.collector.read_bytes(), self.original)

    def test_wrong_disposable_marker_rejects_before_collector_write(self):
        self.marker.write_text(json.dumps({"disposable": False, "path": str(self.source)}))
        with self.assertRaisesRegex(ValueError, "matching disposable-copy marker"):
            self.extend()
        self.assertEqual(self.collector.read_bytes(), self.original)
        self.assertFalse(self.destination.exists())

    def test_nonregistered_collector_hash_rejects_before_overlay(self):
        changed = self.original + b"\n/* unregistered input */\n"
        self.collector.write_bytes(changed)
        with self.assertRaisesRegex(ValueError, "exact existing lighttpd collector variant"):
            self.extend()
        self.assertEqual(self.collector.read_bytes(), changed)
        self.assertFalse(self.destination.exists())

    def test_symlinked_collector_rejects_without_changing_target(self):
        target = self.external / "target.c"
        target.write_bytes(self.original)
        self.collector.unlink()
        self.collector.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symlink source components"):
            self.extend()
        self.assertEqual(target.read_bytes(), self.original)
        self.assertFalse(self.destination.exists())

    def test_existing_accessor_destination_rejects_without_replacing_bytes(self):
        self.destination.write_bytes(b"retained accessor sentinel")
        with self.assertRaisesRegex(ValueError, "accessor destination already exists"):
            self.extend()
        self.assertEqual(self.destination.read_bytes(), b"retained accessor sentinel")
        self.assertEqual(self.collector.read_bytes(), self.original)


if os.environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)


if __name__ == "__main__":
    unittest.main()
