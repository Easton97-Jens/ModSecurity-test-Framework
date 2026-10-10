"""Closed transport contracts require native same-connection counters."""
import unittest

from tests.no_crs import test_nginx_lifecycle_sequence as sequence_tests


class TransportSequenceTests(unittest.TestCase):
    setUp = sequence_tests.SequenceContractTests.setUp
    observation = sequence_tests.SequenceContractTests.observation

    def test_sequential_rejects_a_reconnected_request(self):
        value = self.observation()
        value["case_id"] = "transport_sequential_requests"
        self.assertEqual(self.helper.observation_errors(value, value["case_id"], "run-1"), [])
        value["native_access"][1]["connection"] = "11"
        self.assertTrue(self.helper.observation_errors(value, value["case_id"], "run-1"))

    def test_sequential_rejects_reset_native_connection_counter(self):
        value = self.observation()
        value["case_id"] = "transport_sequential_requests"
        value["native_access"][1]["connection_requests"] = 1
        self.assertTrue(self.helper.observation_errors(value, value["case_id"], "run-1"))


if __name__ == "__main__":
    unittest.main()
