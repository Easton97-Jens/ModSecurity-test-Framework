"""Regression tests for the controlled connector-guide renderer."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = connector_root()
GENERATOR_PATH = source_path('scripts/generate_connector_guides.py', root=ROOT)
EXPECTED_RENDER_SHA256 = "657040d434be11620a9595a614fd642f8fb54a3fa2ca1e8aa4fdd79157f42f5b"


def load_generator() -> object:
    module = load_source(GENERATOR_PATH)
    return module


GENERATOR = load_generator()


def render_digest() -> tuple[int, str]:
    digest = hashlib.sha256()
    count = 0
    for connector, data in GENERATOR.CONNECTORS.items():
        for kind in GENERATOR.DOCUMENT_KINDS:
            for german in (False, True):
                digest.update(f"{connector}\0{kind}\0{german}\0".encode("utf-8"))
                digest.update(GENERATOR.content(kind, connector, data, german).encode("utf-8"))
                count += 1
    return count, digest.hexdigest()


class ConnectorGuidesTests(unittest.TestCase):
    def test_all_rendered_guides_match_the_current_output_contract(self) -> None:
        count, digest = render_digest()

        self.assertEqual(count, 96)
        self.assertEqual(digest, EXPECTED_RENDER_SHA256)

    def test_configuration_guides_describe_off_without_the_removed_minimal_policy(self) -> None:
        for connector, data in GENERATOR.CONNECTORS.items():
            for german in (False, True):
                with self.subTest(connector=connector, german=german):
                    text = GENERATOR.content("configuration", connector, data, german)
                    self.assertIn("Off", text)
                    self.assertNotIn("Minimal", text)
                    self.assertIn("Late-Policy" if german else "late policy", text)

    def test_main_writes_each_paired_guide_to_a_temporary_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            with mock.patch.object(GENERATOR, "ROOT", temporary_root):
                GENERATOR.main()

            guide_root = temporary_root / "docs" / "connectors"
            expected_paths = set()
            for connector, data in GENERATOR.CONNECTORS.items():
                for kind in GENERATOR.DOCUMENT_KINDS:
                    for german, suffix in ((False, ".md"), (True, ".de.md")):
                        path = guide_root / connector / f"{kind}{suffix}"
                        expected_paths.add(path)
                        self.assertEqual(
                            path.read_text(encoding="utf-8"),
                            GENERATOR.content(kind, connector, data, german),
                        )

            actual_paths = set(guide_root.rglob("*.md"))
            self.assertEqual(actual_paths, expected_paths)
            self.assertEqual(len(actual_paths), 96)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
