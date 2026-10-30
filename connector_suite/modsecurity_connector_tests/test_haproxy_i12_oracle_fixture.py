"""Protect the lossless HAProxy-only Oracle source-hash representation."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = connector_root()
HARNESS = source_path('connectors/haproxy/harness', root=ROOT)
ORACLES = load_source(HARNESS / 'i12_oracle_fixture.py')
SEMANTIC_SHA256 = "2e9581873d5dfd6acf15b5396acddb690a0de3f71d6f1be0207542c37f2e2689"


class HaproxyI12OracleFixtureTests(unittest.TestCase):
    def test_reviewed_124_rows_preserve_all_frozen_values(self):
        document = json.loads((HARNESS / "fixtures/i12-oracles-20261015.json").read_text())
        self.assertEqual(len(document["records"]), 124)
        self.assertTrue(all(isinstance(row["original_source_hashes"], list) for row in document["records"]))
        self.assertEqual(ORACLES.semantic_sha256(document), SEMANTIC_SHA256)
        migrated = ORACLES.migrate_fixture(ORACLES.canonical_fixture(document))
        self.assertEqual(migrated, document)
        self.assertEqual(json.loads(ORACLES.render_fixture(migrated)), document)

    def test_frozen_inventory_mapping_and_entries_have_identical_order(self):
        mapping = {"framework:catalog.json": "a" * 64, "parent:contract.c": "b" * 64}
        entries = [{"path": path, "sha256": value} for path, value in mapping.items()]
        self.assertEqual(list(ORACLES.source_hash_map(entries).items()), list(mapping.items()))
        self.assertEqual(ORACLES.source_hash_map(mapping), mapping)

    def test_ambiguous_or_invalid_source_bindings_are_rejected(self):
        valid = {"path": "parent:contract.c", "sha256": "a" * 64}
        invalid = [None, "mapping", [valid, valid], [{**valid, "extra": True}],
                   [{"path": "", "sha256": "a" * 64}],
                   [{"path": 1, "sha256": "a" * 64}],
                   [{"path": valid["path"], "sha256": "not-a-sha256"}],
                   {valid["path"]: "A" * 64}, {valid["path"]: None}]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                ORACLES.source_hash_map(value)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
