"""Default connector discovery uses the admitted Framework inventory."""
from modsecurity_test_framework.connector_context import ConnectorContext


def load_tests(loader, _standard_tests, _pattern):
    from modsecurity_connector_ci.lib.active_test_inventory import load_inventory, python_discovery_suite

    inventory = load_inventory(ConnectorContext.from_environment().connector)
    return python_discovery_suite(inventory, loader)
