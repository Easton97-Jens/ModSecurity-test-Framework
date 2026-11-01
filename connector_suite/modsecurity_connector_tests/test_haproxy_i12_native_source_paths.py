"""Bounded descriptor-relative source admission regression controls."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = connector_root()
HARNESS = source_path('connectors/haproxy/harness', root=ROOT)


def load(name):
    module = load_source(HARNESS / (name + '.py'))
    return module


with patch.dict("sys.modules", {"i12_native_cases": load("i12_native_cases"),
                                "i12_oracle_fixture": load("i12_oracle_fixture")}):
    CONTRACTS = load("i12_native_contracts")


class NativeSourcePathTests(unittest.TestCase):
    def test_private_anchor_is_required(self):
        with tempfile.TemporaryDirectory(dir=CONTRACTS.SOURCE_ROOT) as directory:
            root = Path(directory)
            source = root / "source"
            source.write_bytes(b"actual source")
            root.chmod(0o777)
            try:
                with patch.object(CONTRACTS, "SOURCE_ROOT", root):
                    with self.assertRaisesRegex(ValueError, "privately owned"):
                        CONTRACTS.read_source(source)
            finally:
                root.chmod(0o700)

    def test_relative_boundary_and_leaf_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory(dir=CONTRACTS.SOURCE_ROOT) as directory:
            root = Path(directory)
            source = root / "source"
            source.write_bytes(b"actual source")
            link = root / "link"
            link.symlink_to(source)
            with self.assertRaises(OSError):
                CONTRACTS.read_source(link)
            outside = root.parent / "source"
            with patch.object(CONTRACTS, "SOURCE_ROOT", root):
                with self.assertRaises(ValueError):
                    CONTRACTS.read_source(outside)
            self.assertEqual(CONTRACTS.read_source(source), b"actual source")

    def test_parent_swap_stays_bound_to_held_directory(self):
        with tempfile.TemporaryDirectory(dir=CONTRACTS.SOURCE_ROOT) as directory:
            root = Path(directory)
            parent, replacement = root / "parent", root / "replacement"
            parent.mkdir()
            replacement.mkdir()
            (parent / "source").write_bytes(b"held source")
            (replacement / "source").write_bytes(b"replacement")
            original_open = CONTRACTS.os.open
            changed = False

            def swap_after_open(path, flags, *args, **kwargs):
                nonlocal changed
                descriptor = original_open(path, flags, *args, **kwargs)
                if path == "parent" and not changed:
                    changed = True
                    parent.rename(root / "held-parent")
                    parent.symlink_to(replacement, target_is_directory=True)
                return descriptor

            with patch.object(CONTRACTS.os, "open", side_effect=swap_after_open):
                result = CONTRACTS.read_source(parent / "source")
            self.assertTrue(changed)
            self.assertEqual(result, b"held source")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
