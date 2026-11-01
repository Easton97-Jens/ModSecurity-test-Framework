"""Real loopback HTTP controls for the Apache case request driver."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import unittest

if __package__:
    from . import header_driver_test_support
else:
    import modsecurity_connector_tests.header_driver_test_support as header_driver_test_support


HARNESS = connector_root() / "connectors/apache/harness/run_apache_smoke.sh"


class ApacheEmptyHeaderDriverTest(header_driver_test_support.RealHeaderDriverCase):
    harness = HARNESS
    empty_header_forms = ("X-No-Crs-Empty: \n", "X-No-Crs-Empty:\n")
    ordinary_value = "one: two "
    environment_options = {"CURL_HTTP_STATUS_FORMAT": "%{http_code}"}



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
