"""Independent closed route oracle; no native host is executed."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
from pathlib import Path
import unittest


ROOT = connector_root()
DRIVER = load_source(source_path('ci/runtime/lifecycle/run-selected-nginx-native-operations.py', root=ROOT))
ROUTES = {
    "run-nginx-raw-h1.py": (
        "invalid_content_length", "conflicting_content_length", "duplicate_transfer_encoding", "content_length_overflow"),
    "run-nginx-common-input-fault.py": (
        "header_count_nonzero_with_null_headers", "body_size_nonzero_with_null_data"),
    "run-nginx-mime-cases.py": (
        "phase4_in_scope_content_type", "phase4_content_type_with_charset", "phase4_out_of_scope_content_type", "phase4_missing_content_type"),
    "run-nginx-phase4-cases.py": (
        "phase4_marker_split_across_chunks", "phase4_end_of_stream_evaluation",
        "phase4_deny_after_commit_log_only_minimal", "phase4_body_at_limit", "phase4_body_over_limit",
        "phase4_body_process_partial", "phase4_body_reject", "full_lifecycle_event_metadata_bounded"),
    "run-nginx-lifecycle-sequences.py": (
        "single_request_cleanup", "multiple_sequential_requests", "keep_alive_requests_if_supported", "clean_shutdown",
        "keepalive_allow_allow", "keepalive_allow_deny_allow", "early_mapping_failure_cleanup", "transaction_begin_failure_cleanup",
        "phase4_strict_http1_client_abort", "phase4_strict_host_survives", "phase4_strict_followup_request_succeeds",
        "keepalive_after_strict_new_connection", "keepalive_safe_followup", "response_short_write_resume",
        "response_write_would_block_resume", "transport_keep_alive", "transport_sequential_requests", "finish_failure_propagation",
        "engine_timeout_before_commit", "engine_timeout_after_commit", "transport_http11_content_length", "transport_http11_chunked"),
    "run-nginx-event-boundary-cases.py": ("event_metadata_truncation", "event_json_limit"),
}


class RouteQualityTests(unittest.TestCase):
    def test_all42_actual_script_paths_follow_independent_closed_oracle(self):
        expected_ids = {case for cases in ROUTES.values() for case in cases}
        self.assertEqual(len(expected_ids), 42)
        self.assertEqual(set(DRIVER.CONTRACTS), expected_ids)
        paths = {"prefix": Path("/native"), "framework": Path("/framework"),
                 "output": Path("/owned/output"), "projection": Path("/owned/projection")}
        identities = {key: "a" * 40 for key in ("parent_sha", "framework_sha", "mrts_sha")}
        environment = {key: "/owned/fault.so" for key in DRIVER.FAULT_ENV.values()}
        for script, cases in ROUTES.items():
            for case in cases:
                with self.subTest(case=case):
                    command = DRIVER.command(case, paths, "run", identities, environment)
                    self.assertEqual(Path(command[1]), source_path('ci/runtime/lifecycle', root=ROOT) / script)

    def test_relative_required_fault_library_is_rejected(self):
        paths = {"prefix": Path("/native"), "framework": Path("/framework"),
                 "output": Path("/owned/output"), "projection": Path("/owned/projection")}
        identities = {key: "a" * 40 for key in ("parent_sha", "framework_sha", "mrts_sha")}
        for case, key in DRIVER.FAULT_ENV.items():
            with self.subTest(case=case):
                environment = {key: "relative/fault.so"}
                with self.assertRaisesRegex(ValueError, "required native fault library missing"):
                    DRIVER.command(case, paths, "run", identities, environment)

    def test_duplicate_catalog_identity_is_rejected_even_when_not_selected(self):
        row = {"case_id": "single_request_cleanup", "native_invocations": {
            "nginx": DRIVER.CONTRACTS["single_request_cleanup"]}}
        with self.assertRaisesRegex(ValueError, "duplicate catalog case identity"):
            DRIVER.selected_invocations([row, row], [])

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
