"""Transport sequence selections must drive the required actual socket reuse."""
import unittest

from modsecurity_connector_tests import test_nginx_sequence_client as client_tests
from modsecurity_connector_tests import test_nginx_sequence_driver as driver_tests


class TransportSequenceTests(unittest.TestCase):
    server = client_tests.ClientTests.server

    def test_sequential_allow_deny_allow_uses_one_actual_connection(self):
        server = self.server()
        case = "transport_sequential_requests"
        observations = client_tests.CLIENT.run_sequence(
            server.server_address[1], ["/no-crs/sequence/0", "/no-crs/sequence/1", "/no-crs/sequence/2"],
            driver_tests.DRIVER.SEQUENCES[case], keepalive=case in driver_tests.DRIVER.KEEPALIVE)
        self.assertEqual([row["observed_status"] for row in observations], [200, 403, 200])
        self.assertEqual(server.connections, 1)

    def test_keepalive_allow_allow_uses_one_actual_connection(self):
        server = self.server()
        case = "transport_keep_alive"
        client_tests.CLIENT.run_sequence(server.server_address[1], ["/no-crs/sequence/0", "/no-crs/sequence/1"],
                                         driver_tests.DRIVER.SEQUENCES[case], keepalive=case in driver_tests.DRIVER.KEEPALIVE)
        self.assertEqual(server.connections, 1)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
