"""Expose Envoy-local I12 controls to Parent unittest discovery."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
from pathlib import Path
import unittest


def load_tests(_loader, _tests, _pattern):
    controls = source_path('ci/runtime/lifecycle/i12/envoy', root=connector_root())
    return unittest.TestLoader().discover(str(controls), pattern='test_*.py', top_level_dir=str(controls))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
