"""Explicit optional response omission survives only the closed fixture seam."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
from pathlib import Path
import unittest

META = load_source(connector_root() / 'ci/runtime/common/harness-case-metadata.py')


class HarnessOmissionMetadataTest(unittest.TestCase):
    def test_closed_explicit_omission_is_forwarded(self):
        fixture = META.response_fixture({"response": {"content_type": None, "omit_headers": ["Content-Type"]}})
        self.assertEqual(fixture, {"status": 200, "headers": [], "omit_headers": ["Content-Type"]})

    def test_default_fixture_shape_and_other_headers_are_unchanged(self):
        self.assertEqual(META.response_fixture({}), {"status": 200, "headers": []})
        self.assertEqual(META.response_fixture({"response": {"content_type": "text/plain"}}),
                         {"status": 200, "headers": [["Content-Type", "text/plain"]]})

    def test_invalid_or_conflicting_omission_does_not_reach_backend(self):
        for response in ({"omit_headers": ["Content-Length"]},
                         {"content_type": "", "omit_headers": ["Content-Type"]},
                         {"headers": {"content-type": ""}, "omit_headers": ["Content-Type"]}):
            with self.subTest(response=response), self.assertRaises(ValueError):
                META.response_fixture({"response": response})

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
