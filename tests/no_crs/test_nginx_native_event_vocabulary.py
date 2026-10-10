"""Register bounded real producer vocabulary, never synthetic runtime evidence."""
import copy
import unittest

from tests.no_crs.test_configtest_receipt import no_crs


class NativeEventVocabularyTests(unittest.TestCase):
    def event(self, **values):
        return {"connector": "nginx", "integration_mode": "native-nginx-http-module",
                "event": "transaction_cleanup", "message_id": "MSCONN_TRANSACTION_CLEANUP",
                "transaction_id": "actual-tx", "phase": "logging", "status": "ok",
                "requested_action": "", "actual_action": "allow", "rule_id": "",
                "cleanup_reason": "normal", **values}

    def test_source_actions_and_exact_common_cleanup_classes_are_bounded(self):
        for action in ("allow", "pass", "error"):
            event = self.event(requested_action=action, actual_action=action)
            self.assertEqual(no_crs.canonical_event_errors(event, connector="nginx"), [])
        for reason in ("phase_sequence", "body_limit", "event_limit", "engine_timeout",
                       "engine_unavailable", "invalid_engine_response", "connector_error", "protocol_error",
                       "client_cancel", "upstream_disconnect", "correlation_missing", "correlation_expired",
                       "correlation_mismatch", "cleanup_incomplete"):
            self.assertEqual(no_crs.canonical_event_errors(self.event(cleanup_reason=reason)), [])

    def test_actual_request_and_response_header_timeout_stages_are_accepted(self):
        for stage in ("request_headers", "response_headers"):
            event = self.event(event="engine_timeout", message_id="MSCONN_EVENT_ENGINE_TIMEOUT",
                               status="error", actual_action="error", requested_action="error",
                               timeout_stage=stage, phase=stage)
            self.assertEqual(no_crs.canonical_event_errors(event), [])

    def test_unknown_actions_classes_and_payload_or_nested_fields_still_fail(self):
        for field, value in (("actual_action", "pretend_pass"), ("requested_action", "anything"),
                             ("cleanup_reason", "unknown"), ("timeout_stage", "made_up"),
                             ("request_body", "payload"), ("nested", {"status": "ok"})):
            with self.subTest(field=field):
                event = copy.deepcopy(self.event())
                event[field] = value
                self.assertTrue(no_crs.canonical_event_errors(event))

    def test_cleanup_allow_remains_logging_not_request_phase_identity(self):
        event = self.event()
        self.assertEqual(no_crs.canonical_event_errors(event), [])
        self.assertTrue(no_crs.case_event_identity_errors(
            {"phase": 1, "expected_event_fields": ["actual_action"]}, event, "real-run"))
