"""Regression contract for Phase 2 when request-body buffering is disabled."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path


SOURCE = (
    connector_root()
    / "common"
    / "runtime"
    / "msconnector_runtime.c"
).read_text(encoding="utf-8")


def test_body_mode_none_finishes_modsecurity_request_body_phase() -> None:
    none_branch = SOURCE.index(
        "runtime->body_policy.request_body_mode == MSCONNECTOR_BODY_MODE_NONE",
        SOURCE.index("static int begin_request_body_processing"),
    )
    buffered_branch = SOURCE.index(
        "runtime->body_policy.request_body_mode == MSCONNECTOR_BODY_MODE_BUFFERED",
        none_branch,
    )
    branch = SOURCE[none_branch:buffered_branch]

    assert "msconnector_runtime_transaction_finish_request_body" in branch
    assert "mark_flow(transaction, MSCONNECTOR_PHASE_REQUEST_BODY" not in branch


def test_finish_request_body_does_not_skip_none_mode() -> None:
    start = SOURCE.index("int msconnector_runtime_transaction_finish_request_body(")
    end = SOURCE.index(
        "int msconnector_runtime_transaction_process_response_headers(", start
    )
    finish_body = SOURCE[start:end]

    assert "msconnector_modsecurity_finish_request_body" in finish_body
    assert "request_body_mode == MSCONNECTOR_BODY_MODE_NONE" not in finish_body

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
