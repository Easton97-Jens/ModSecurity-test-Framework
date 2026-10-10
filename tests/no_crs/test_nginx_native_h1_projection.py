"""Controlled verified-reader seam inputs; not new runtime evidence."""
from copy import deepcopy
import unittest

from ci.checks.catalog import no_crs_baseline as contract


class NativeH1ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.case = {"case_id": "phase4_strict_http1_client_abort", "request": {"protocol_profile": "http1"},
                     "phase": 4, "expected_rule_id": 1100301}
        self.raw = {"case_id": self.case["case_id"], "run_id": "unit-h1",
                    "integration_mode": "native-nginx-http-module"}
        self.event = {"connector": "nginx", "integration_mode": self.raw["integration_mode"],
                      "event": "phase4_intervention", "message_id": "MSCONN_EVENT_PHASE4_LATE_INTERVENTION",
                      "phase": "response_body", "rule_id": "1100301",
                      "transaction_id": "abc", "uri": "/unit/request"}
        self.proof = {"observation": {"case_id": self.raw["case_id"], "run_id": self.raw["run_id"],
                       "requests": [{"path": "/unit/request", "http_version": 11}],
                       "native_access": [{"uri": "/unit/request", "transaction_id": "abc", "connection": "2"}]}}

    def project(self):
        return contract.native_h1_protocol_projection(self.raw, self.case, self.proof, self.event)

    def test_actual_response_and_native_transaction_bind_h1(self):
        fields, event = self.project()
        self.assertEqual(fields["negotiated_protocol"], "http1")
        self.assertEqual(fields["transport_case_id"], self.case["case_id"])
        self.assertEqual(event["run_id"], self.raw["run_id"])
        self.assertEqual(event["phase"], 4)
        self.assertEqual(self.event["phase"], "response_body")

    def test_mismatched_observation_event_profile_fail_closed(self):
        original = deepcopy((self.raw, self.case, self.proof, self.event))
        mutations = (
            lambda: self.proof["observation"].update(run_id="stale"),
            lambda: self.proof["observation"].update(case_id="foreign"),
            lambda: self.proof["observation"]["requests"][0].update(http_version=20),
            lambda: self.proof["observation"]["requests"][0].pop("http_version"),
            lambda: self.event.update(transaction_id="foreign"),
            lambda: self.event.update(rule_id="1100001"),
            lambda: self.event.update(phase="logging"),
            lambda: self.event.update(uri="/foreign"),
            lambda: self.event.update(run_id="foreign"),
            lambda: self.event.update(integration_mode="foreign"),
            lambda: self.event.update(transport_case_id="foreign"),
            lambda: self.proof.update(observation={}),
        )
        for mutate in mutations:
            self.raw, self.case, self.proof, self.event = deepcopy(original)
            mutate()
            with self.assertRaises(ValueError):
                self.project()

    def test_h2_profile_cannot_borrow_h1_observation(self):
        self.case["request"]["protocol_profile"] = "h2"
        self.assertEqual(self.project(), ({}, None))


if __name__ == "__main__":
    unittest.main()
