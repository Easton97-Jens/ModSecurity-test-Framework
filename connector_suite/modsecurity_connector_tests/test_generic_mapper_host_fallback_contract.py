"""Regression contract for the shared no-silent-host-fallback invariant."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import unittest
from pathlib import Path


ROOT = connector_root()
MAPPER = (source_path('common/src/generic_mapper.c', root=ROOT)).read_text(encoding="utf-8")


class GenericMapperHostFallbackContractTest(unittest.TestCase):
    def test_missing_client_hostname_is_not_replaced_with_server_address(self) -> None:
        self.assertIn("out->hostname = src->hostname;", MAPPER)
        self.assertNotIn("out->hostname = src->server.address;", MAPPER)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
