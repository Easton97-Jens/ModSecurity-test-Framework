"""Focused source contract checks for the HAProxy transaction adapter."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from modsecurity_connector_tests.c_source_contract import function_definition


SOURCE = (
    connector_root()
    / "connectors"
    / "haproxy"
    / "src"
    / "haproxy_modsecurity_binding.c"
).read_text(encoding="utf-8")

SPOP_BACKEND_SOURCE = (
    connector_root()
    / "connectors"
    / "haproxy"
    / "src"
    / "haproxy_spop_response_companion_backend.c"
).read_text(encoding="utf-8")

SPOP_BACKEND_HEADER = (
    connector_root()
    / "connectors"
    / "haproxy"
    / "src"
    / "haproxy_spop_response_companion_backend.h"
).read_text(encoding="utf-8")

TRANSPORT_HEADER = (
    connector_root()
    / "common"
    / "runtime"
    / "response_companion_transport.h"
).read_text(encoding="utf-8")


def test_mapping_rejection_is_terminal_and_not_ignored() -> None:
    request_start = SOURCE.index("static int validate_common_mapped_request(")
    request_end = SOURCE.index("static int begin_transaction_protocol(", request_start)
    request_mapper = SOURCE[request_start:request_end]
    assert "haproxy_modsecurity_map_owned_request" in request_mapper
    assert "return 0;" in request_mapper
    assert "common request mapper validation skipped" not in request_mapper

    response_helper_start = SOURCE.index("static int map_response_for_transaction(")
    response_helper_end = SOURCE.index(
        "static int add_response_headers(", response_helper_start
    )
    response_mapper = SOURCE[response_helper_start:response_helper_end]
    response_start = SOURCE.index(
        "int haproxy_modsecurity_transaction_process_response_headers("
    )
    response_end = SOURCE.index(
        "int haproxy_modsecurity_transaction_append_response_body_chunk(",
        response_start,
    )
    response_stage = SOURCE[response_start:response_end]
    assert "haproxy_modsecurity_map_owned_response" in response_mapper
    assert "transaction_failure(transaction, decision, MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR" in response_mapper
    failure = function_definition(SOURCE, "transaction_failure")
    retained = function_definition(SOURCE, "retain_transaction_failure")
    assert "retain_transaction_failure(transaction, decision, error_class)" in failure
    assert "msconnector_transaction_contract_fail(&transaction->contract, error_class, 0U)" in retained
    assert "if (!map_response_for_transaction(transaction, response, decision))" in response_stage
    assert "return 1;" in response_stage
    assert "common response mapper validation skipped" not in response_mapper


def test_body_chunks_use_full_chunks_and_contract_phases() -> None:
    assert "request body exceeds Common limit" not in SOURCE
    assert "response body exceeds Common limit" not in SOURCE
    assert "SIZE_MAX - (size_t)body_len" in SOURCE
    assert "msconnector_transaction_contract_begin_phase" in SOURCE
    assert "msconnector_transaction_contract_complete_phase" in SOURCE
    assert "msconnector_transaction_contract_record_body" in SOURCE


def test_body_preconditions_are_shared_without_changing_phase_specific_messages() -> None:
    helper_start = SOURCE.index("static int validate_body_preconditions(")
    helper_end = SOURCE.index("static int append_body_chunk(", helper_start)
    helper = SOURCE[helper_start:helper_end]
    append_start = SOURCE.index("static int append_body_chunk(")
    append_end = SOURCE.index("static int finish_body(", append_start)
    finish_start = append_end
    finish_end = SOURCE.index("static int load_rules_file(", finish_start)
    append = SOURCE[append_start:append_end]
    finish = SOURCE[finish_start:finish_end]

    assert "phase->missing_message" in helper
    assert "phase->headers_required_message" in helper
    assert "body_processed_message" in helper
    assert append.count("validate_body_preconditions(transaction, decision, phase,") == 1
    assert finish.count("validate_body_preconditions(transaction, decision, phase,") == 1
    assert "phase->append_after_eos_message" in append
    assert "phase->finish_once_message" in finish


def test_body_accounting_precedes_the_native_engine_sink() -> None:
    start = SOURCE.index("static int append_body_chunk(")
    end = SOURCE.index("static int finish_body(", start)
    body_append = SOURCE[start:end]
    common_record = body_append.index(
        "msconnector_transaction_contract_record_body(&transaction->contract,"
    )
    native_append = body_append.index("phase->append_body(transaction->transaction")

    assert common_record < native_append
    assert "MSCONNECTOR_TRANSACTION_TRANSITION_OK" in body_append[common_record:native_append]
    assert "Common body phase is not active" in body_append
    assert "Common body accounting failed" in body_append
    assert "MSCONNECTOR_TRANSACTION_ERROR_PHASE_SEQUENCE" in body_append
    assert "MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE" in body_append[native_append:]
    assert "(void)msconnector_transaction_contract_record_body" not in body_append


def test_body_eos_requires_the_same_active_common_phase_before_native_finish() -> None:
    start = SOURCE.index("static int finish_body(")
    end = SOURCE.index("static int load_rules_file(", start)
    body_finish = SOURCE[start:end]
    phase_check = body_finish.index("Common body phase is not active before EOS")
    native_finish = body_finish.index("phase->finish_body(transaction->transaction)")

    assert phase_check < native_finish
    assert "MSCONNECTOR_TRANSACTION_ERROR_PHASE_SEQUENCE" in body_finish[:native_finish]
    assert "MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE" in body_finish[native_finish:]
    assert "contract_phase, 0U" in body_finish


def test_common_decision_recording_failures_propagate_to_host_callbacks() -> None:
    helper_start = SOURCE.index("static int record_contract_decision(")
    helper_end = SOURCE.index("static int begin_contract_phase(", helper_start)
    helper = SOURCE[helper_start:helper_end]
    assert "return msconnector_transaction_contract_record_decision(" in helper
    assert "(void)msconnector_transaction_contract_record_decision" not in helper

    p1_start = SOURCE.index("static int begin_transaction_protocol(")
    p1_end = SOURCE.index("int haproxy_modsecurity_transaction_begin_request_with_profile(", p1_start)
    p1 = SOURCE[p1_start:p1_end]
    p3_start = SOURCE.index("int haproxy_modsecurity_transaction_process_response_headers(")
    p3_end = SOURCE.index("int haproxy_modsecurity_transaction_append_response_body_chunk(", p3_start)
    p3 = SOURCE[p3_start:p3_end]
    body_start = SOURCE.index("static int finish_body(")
    body_end = SOURCE.index("static int load_rules_file(", body_start)
    body_finish = SOURCE[body_start:body_end]

    assert "failed to record Common P1 decision" in p1
    assert "failed to record Common P3 decision" in p3
    assert "failed to record Common body decision" in body_finish
    assert p1.count("record_contract_decision(transaction, decision)") == 1
    assert p3.count("record_contract_decision(transaction, decision)") == 1
    assert body_finish.count("record_contract_decision(transaction, decision)") == 1


def test_htx_selects_its_own_canonical_profile() -> None:
    htx_source = (
        connector_root()
        / "connectors"
        / "haproxy"
        / "htx-overlay"
        / "haproxy_modsecurity_htx_filter.c"
    ).read_text(encoding="utf-8")
    assert "haproxy_modsecurity_transaction_begin_request_with_profile" in SOURCE
    assert '"haproxy-spoe-spop"' in SOURCE
    assert "haproxy_modsecurity_transaction_begin_request_with_profile" in htx_source
    assert '"haproxy-htx"' in htx_source


def test_spop_uses_direct_request_routes_and_owned_companion_response_routes() -> None:
    start = SOURCE.index("static int profile_has_haproxy_phase_routes(")
    end = SOURCE.index("int haproxy_modsecurity_transaction_begin_request(", start)
    profile_validation = SOURCE[start:end]
    assert "if (!profile_has_haproxy_phase_routes(profile)) {" in profile_validation
    assert "MSCONNECTOR_TRANSACTION_PHASE_ROUTE_DIRECT" in profile_validation
    assert "MSCONNECTOR_TRANSACTION_PHASE_ROUTE_COMPANION_REQUIRED" in profile_validation
    assert "required direct P1/P2 and owned P3/P4 routes" in profile_validation
    assert "response_companion.response_phases_require_companion" in SOURCE
    assert "haproxy_modsecurity_transaction_handoff_response_companion" in SOURCE
    assert "haproxy_modsecurity_transaction_claim_response_companion" in SOURCE
    assert "msconnector_transaction_contract_begin_companion_phase" in SOURCE
    assert "MSCONNECTOR_TRANSACTION_ERROR_CORRELATION_MISSING" in SOURCE
    self_test = (
        connector_root()
        / "connectors"
        / "haproxy"
        / "src"
        / "haproxy_modsecurity_binding_self_test.c"
    ).read_text(encoding="utf-8")
    direct_start = self_test.index("static int run_direct_body_lifecycle(")
    direct_end = self_test.index("static int run_spop_body_lifecycle(", direct_start)
    direct_lifecycle = self_test[direct_start:direct_end]
    spop_start = self_test.index("static int run_spop_body_lifecycle(")
    spop_end = self_test.index(
        "static int run_body_wrapper_lifecycle_self_test(", spop_start
    )
    spop_lifecycle = self_test[spop_start:spop_end]
    assert '"haproxy-htx"' in direct_lifecycle
    assert "test->observed" in direct_lifecycle
    assert "test->transaction" in direct_lifecycle
    assert "haproxy_modsecurity_transaction_abort(transaction);" in self_test
    assert '"haproxy-spoe-spop"' in spop_lifecycle
    assert "test->observed" in spop_lifecycle
    assert "test->transaction" in spop_lifecycle
    assert "haproxy_modsecurity_transaction_handoff_response_companion(\n            *test->transaction)" in spop_lifecycle
    assert "haproxy_modsecurity_transaction_claim_response_companion(\n            *test->transaction)" in spop_lifecycle


def test_finish_reports_incomplete_contract_before_cleanup() -> None:
    finish_start = SOURCE.index("int haproxy_modsecurity_transaction_finish(")
    finish_end = SOURCE.index("void haproxy_modsecurity_transaction_abort(", finish_start)
    finish_path = SOURCE[finish_start:finish_end]
    assert "msconnector_transaction_contract_finish" in finish_path
    assert "msc_process_logging(transaction->transaction)" in finish_path
    assert "msconnector_native_phase_succeeded(logging_result)" in finish_path
    assert "transaction_cleanup(transaction, 0)" in finish_path
    assert "return result;" in finish_path


def test_spop_missing_response_correlation_is_terminal_error() -> None:
    spop_source = (
        connector_root()
        / "connectors"
        / "haproxy"
        / "src"
        / "haproxy_spop_diagnostic_runtime.c"
    ).read_text(encoding="utf-8")
    missing_branch = spop_source[spop_source.index(
        "transaction = transaction_cache_take(state, request->request_id);") :
        spop_source.index("    if (request->http_metadata.is_response_body)", spop_source.index(
            "transaction = transaction_cache_take(state, request->request_id);"))]
    assert "set_response_correlation_failure" in missing_branch
    assert 'runtime_init_decision(decision, phase, "pass"' not in missing_branch
    assert '"correlation-failure"' in spop_source


def test_spop_request_id_parser_validates_length_delimited_bytes_before_copy() -> None:
    spop_source = (
        connector_root()
        / "connectors"
        / "haproxy"
        / "src"
        / "haproxy_spop_diagnostic_runtime.c"
    ).read_text(encoding="utf-8")
    parser_start = spop_source.index("/* Correlation identifiers are not display strings")
    parser_end = spop_source.index("static int read_typed_uint32_value(", parser_start)
    parser = spop_source[parser_start:parser_end]

    assert "msconnector_transaction_contract_validate_transaction_id_bytes" in parser
    assert "value, value_len" in parser
    assert "type == 0U" in parser
    assert "return -1;" in parser
    assert "copy_spop_string(out, out_len, value, value_len);" in parser
    assert parser.index("msconnector_transaction_contract_validate_transaction_id_bytes") < parser.index(
        "copy_spop_string(out, out_len, value, value_len);"
    )
    # These are length-delimited byte cases; a C-string copy would collapse A\0X
    # to A and must therefore never be used as the validation boundary.
    assert "embedded NUL" in parser
    assert "control" in parser
    assert "A\\0X" in parser
    assert "A" in parser
    assert "UUID" in parser
    assert "run_spop_request_id_validation_self_test" in spop_source
    dispatcher = spop_source[spop_source.index("static int run_spop_protocol_self_tests("):
                             spop_source.index("typedef struct spop_self_test_context")]
    assert "run_spop_request_id_validation_self_test() != 0" in dispatcher
    assert '"SPOP protocol self-test failed\\n"' in spop_source


def test_spop_response_body_chunks_do_not_finalize_without_transport_eos() -> None:
    spop_source = (
        connector_root()
        / "connectors"
        / "haproxy"
        / "src"
        / "haproxy_spop_diagnostic_runtime.c"
    ).read_text(encoding="utf-8")
    response_start = spop_source.index(
        "static void process_production_response_notify("
    )
    response_end = spop_source.index(
        "static void build_modsecurity_request_from_notify(", response_start
    )
    response_path = spop_source[response_start:response_end]
    assert "append_response_body_chunk" in response_path
    assert "haproxy_modsecurity_transaction_process_response_body(" not in response_path
    assert "no HTTP response-EOS field" in response_path
    assert "awaiting response EOS" in response_path


def test_spop_pending_response_cache_aborts_on_expiry_eviction_and_shutdown() -> None:
    spop_source = (
        connector_root()
        / "connectors"
        / "haproxy"
        / "src"
        / "haproxy_spop_diagnostic_runtime.c"
    ).read_text(encoding="utf-8")
    expiry_start = spop_source.index("static void transaction_cache_expire(")
    expiry_end = spop_source.index(
        "static int transaction_cache_store(", expiry_start
    )
    expiry_path = spop_source[expiry_start:expiry_end]
    assert "response_body_timeout_ms" in expiry_path
    assert "transaction_slot_clear(slot, 0)" in expiry_path

    eviction_start = spop_source.index("static transaction_slot *transaction_slot_for_store(")
    eviction_end = spop_source.index("static void transaction_cache_expire(", eviction_start)
    assert "transaction_slot_clear(&state->transactions[oldest], 0)" in spop_source[
        eviction_start:eviction_end
    ]

    destroy_start = spop_source.index("static void transaction_cache_destroy(")
    destroy_end = spop_source.index("static void runtime_init_decision(", destroy_start)
    assert "transaction_slot_clear(&state->transactions[i], 0)" in spop_source[
        destroy_start:destroy_end
    ]


def test_spop_rejects_response_body_activation_without_the_native_htx_eos_bridge() -> None:
    spop_source = (
        connector_root()
        / "connectors"
        / "haproxy"
        / "src"
        / "haproxy_spop_diagnostic_runtime.c"
    ).read_text(encoding="utf-8")
    validation_start = spop_source.index("static int validate_production_config(")
    validation_end = spop_source.index(
        "static int run_production_agent_command(", validation_start
    )
    validation_path = spop_source[validation_start:validation_end]
    assert "response_body_limit" not in validation_path
    assert "response_body_timeout_ms > 0U" in validation_path
    assert 'strcmp(config->response_companion, "none") == 0' in validation_path
    assert "must be zero with response-companion=none" in validation_path
    assert "validate_production_config(&config)" in spop_source


def test_spop_native_htx_companion_requires_explicit_private_bridge() -> None:
    spop_source = (
        connector_root()
        / "connectors"
        / "haproxy"
        / "src"
        / "haproxy_spop_diagnostic_runtime.c"
    ).read_text(encoding="utf-8")
    assert '"response-companion", response_companion' in spop_source
    assert '"native-htx"' in spop_source
    validation_start = spop_source.index("static int validate_production_config(")
    validation_end = spop_source.index(
        "static int run_production_agent_command(", validation_start
    )
    validation_path = spop_source[validation_start:validation_end]
    assert "unknown companion rejected" in validation_path
    assert "response_phases_enabled" in validation_path
    assert "native-htx requires response-companion-socket" in validation_path
    assert "response-companion" in validation_path
    assert "native-htx response companion remains gated" not in validation_path
    assert "response-companion=native-htx" in (
        connector_root()
        / "connectors"
        / "haproxy"
        / "README.md"
    ).read_text(encoding="utf-8")


def test_spop_handoff_requires_a_live_common_response_listener() -> None:
    """Ownership reaches the backend only after Common recovers its listener."""
    spop_source = (
        connector_root()
        / "connectors"
        / "haproxy"
        / "src"
        / "haproxy_spop_diagnostic_runtime.c"
    ).read_text(encoding="utf-8")
    request_start = spop_source.index("static void process_production_request_notify(")
    request_end = spop_source.index("static int process_production_notify(", request_start)
    request_path = spop_source[request_start:request_end]
    listener = request_path.index(
        "msconnector_response_companion_transport_ensure_running("
    )
    transaction = request_path.index(
        "haproxy_modsecurity_transaction_handoff_response_companion(transaction)"
    )
    backend = request_path.index("haproxy_spop_response_companion_handoff(")

    assert listener < transaction < backend
    assert "response companion handoff failed closed" in request_path


def test_spop_rejects_p3_only_none_activation_and_admits_the_p4_capable_bridge() -> None:
    spop_source = (
        connector_root()
        / "connectors"
        / "haproxy"
        / "src"
        / "haproxy_spop_diagnostic_runtime.c"
    ).read_text(encoding="utf-8")
    validation_start = spop_source.index("static int validate_production_config(")
    validation_end = spop_source.index(
        "static int run_production_agent_command(", validation_start
    )
    validation_path = spop_source[validation_start:validation_end]
    assert "if (config->response_phases_enabled)" in validation_path
    assert "accepting P3 alone and discarding an unfinished" in validation_path
    assert "response phases require an integrated P3/P4" in validation_path
    assert 'strcmp(config->response_companion, "none") != 0' in validation_path
    assert "return 0;" in validation_path


def test_htx_companion_registers_request_data_filter_for_p2_and_eos() -> None:
    """Companion mode must expose the native request EOS callback without a second engine."""
    source = (
        connector_root()
        / "connectors"
        / "haproxy"
        / "htx-overlay"
        / "haproxy_modsecurity_htx_filter.c"
    ).read_text(encoding="utf-8")
    # Request P2/EOS registration is authoritative in the request-header
    # handler.  The generic HTTP-header dispatcher only selects request versus
    # response and must not be treated as the companion implementation.
    companion_start = source.index(
        "static int haproxy_modsecurity_htx_handle_request_headers("
    )
    companion_start = source.index("if (ctx->companion.mode) {", companion_start)
    companion_end = source.index(
        "    if (haproxy_modsecurity_htx_capture_request_headers",
        companion_start,
    )
    companion_path = source[companion_start:companion_end]
    assert "register_data_filter(s, msg->chn, filter);" in companion_path
    assert "request EOS" in companion_path


def test_spop_failed_release_propagates_native_consumption_before_error() -> None:
    """A failed native finish still owns cleanup; a later FAIL must not abort it."""
    spop_source = (
        connector_root()
        / "connectors"
        / "haproxy"
        / "src"
        / "haproxy_spop_diagnostic_runtime.c"
    ).read_text(encoding="utf-8")
    dispatch_start = spop_source.index(
        "static int spop_response_companion_owner_dispatch("
    )
    dispatch_end = spop_source.index(
        "static void run_spop_owner_queue_self_test_task", dispatch_start
    )
    dispatch = spop_source[dispatch_start:dispatch_end]
    assert "*transaction_consumed = 0;" in dispatch
    consumed = dispatch.index("*transaction_consumed = result.transaction_consumed;")
    failed = dispatch.index("if (!result.success)")
    assert consumed < failed

    request_start = spop_source.index(
        "static void process_production_request_notify("
    )
    request_end = spop_source.index("static int process_production_notify(", request_start)
    request_path = spop_source[request_start:request_end]
    assert request_path.count(
        "haproxy_modsecurity_transaction_abort(transaction);\n            transaction = 0;"
    ) >= 2


def test_spop_expiry_and_terminal_cleanup_are_generation_bound() -> None:
    """Expiry must premark its lease and terminal cleanup must close its gap."""
    assert "int terminal_pending;" in SPOP_BACKEND_HEADER
    assert "int terminal_timed_out;" in SPOP_BACKEND_HEADER
    assert "int terminal_finished;" in SPOP_BACKEND_HEADER
    assert "int terminal_consumed;" in SPOP_BACKEND_HEADER
    assert "in_flight_operation;" in SPOP_BACKEND_HEADER
    assert "terminal_operation;" in SPOP_BACKEND_HEADER
    assert "capture_slot_generation_locked" in SPOP_BACKEND_SOURCE
    assert "generation changed before owner dispatch" in SPOP_BACKEND_SOURCE

    expire_start = SPOP_BACKEND_SOURCE.index(
        "void haproxy_spop_response_companion_backend_expire("
    )
    expire_path = SPOP_BACKEND_SOURCE[expire_start:]
    dispatch_start = expire_path.index("transaction = slot->transaction;")
    dispatch_end = expire_path.index(
        "pthread_mutex_unlock(&backend->lock);", dispatch_start
    )
    dispatch_setup = expire_path[dispatch_start:dispatch_end]
    assert dispatch_setup.index("slot->expire_pending = 1;") < dispatch_setup.index(
        "slot->in_flight = 1;"
    )

    dispatch_finished_start = SPOP_BACKEND_SOURCE.index(
        "int haproxy_spop_response_companion_backend_dispatch_finished("
    )
    dispatch_finished_end = expire_start
    dispatch_finished = SPOP_BACKEND_SOURCE[
        dispatch_finished_start:dispatch_finished_end
    ]
    assert "else if (!terminal_finalizer)" in dispatch_finished
    assert "slot->terminal_finished = 1;" in dispatch_finished
    assert "slot->terminal_consumed = transaction_consumed != 0;" in dispatch_finished
    assert "slot->terminal_timed_out" in dispatch_finished
    assert "slot->in_flight_operation != operation" in dispatch_finished
    assert "slot->terminal_operation == operation" in dispatch_finished

    terminal_start = SPOP_BACKEND_SOURCE.index("static int terminal(")
    terminal_end = SPOP_BACKEND_SOURCE.index("static int cancel(", terminal_start)
    terminal_path = SPOP_BACKEND_SOURCE[terminal_start:terminal_end]
    assert "capture_slot_generation_locked(backend, session, &generation)" in terminal_path
    assert "&transaction_consumed, &generation" in terminal_path
    assert "generation.slot->terminal_finished" in terminal_path
    assert "!generation.slot->terminal_consumed" in terminal_path

    fail_start = SPOP_BACKEND_SOURCE.index("static void fail(")
    fail_end = SPOP_BACKEND_SOURCE.index(
        "int haproxy_spop_response_companion_backend_init(", fail_start
    )
    fail_path = SPOP_BACKEND_SOURCE[fail_start:fail_end]
    assert "capture_slot_generation_locked(backend, session, &generation)" in fail_path
    assert "generation.slot->transaction == generation.transaction" in fail_path
    assert "generation.slot->lease == generation.lease" in fail_path
    assert "generation.slot->session_token == generation.session_token" in fail_path


def test_spop_terminal_timeout_finalizers_have_exactly_once_cleanup_regressions() -> None:
    """The direct backend test covers both finalizer/caller timeout orders."""
    backend_test = (
        connector_root()
        / "tests"
        / "haproxy_spop_response_companion_backend_test.c"
    ).read_text(encoding="utf-8")
    assert "terminal_timed_out" in backend_test
    assert "terminal_timeout_finalizer_consumed" in backend_test
    assert "terminal owner timeout after finalizer" in backend_test
    assert "timed-out terminal owner reports that it did not consume" in backend_test
    assert "early-finalizer ordering with an unconsumed transaction" in backend_test
    assert "terminal owner timeout after stale response finalizer" in backend_test
    assert "delayed response-header finalizer must not become the completion" in backend_test


def test_spop_response_bridge_owns_decision_text_through_the_transport_callback() -> None:
    """Native stack text must be copied into MRC1 session storage before return."""
    spop_source = (
        connector_root()
        / "connectors"
        / "haproxy"
        / "src"
        / "haproxy_spop_diagnostic_runtime.c"
    ).read_text(encoding="utf-8")
    decision_start = spop_source.index("static int copy_bridge_native_decision_text")
    decision_end = spop_source.index(
        "static void run_spop_bridge_native_operation", decision_start
    )
    decision_path = spop_source[decision_start:decision_end]

    assert '#include "msconnector/limits.h"' in spop_source
    assert "#define SPOP_BRIDGE_HEADER_NAME_MAX (MSCONNECTOR_MAX_HEADER_NAME_LENGTH + 1U)" in spop_source
    assert "#define SPOP_BRIDGE_HEADER_VALUE_MAX (MSCONNECTOR_MAX_HEADER_VALUE_LENGTH + 1U)" in spop_source
    assert "storage = context->command.decision_storage;" in decision_path
    assert "storage->redirect_url" in decision_path
    assert "storage->log_message" in decision_path
    set_start = spop_source.index("static int set_bridge_native_decision(")
    set_end = spop_source.index("static void run_spop_bridge_native_operation", set_start)
    set_path = spop_source[set_start:set_end]
    assert "native_decision->redirect_url" not in set_path.split(
        "msconnector_decision_set_redirect", 1
    )[1]
    assert "haproxy_spop_response_companion_decision_storage decision_storage;" in spop_source
    prepare_start = spop_source.index("static int prepare_spop_bridge_context(")
    prepare_end = spop_source.index(
        "static int spop_response_companion_owner_dispatch(", prepare_start
    )
    assert "context->command.decision_storage = &context->decision_storage;" in spop_source[
        prepare_start:prepare_end
    ]
    result_start = spop_source.index("static void copy_spop_bridge_result(")
    result_end = spop_source.index("static int set_bridge_native_decision(", result_start)
    result_copy = spop_source[result_start:result_end]
    assert "&output->decision_storage" in result_copy
    assert "output->decision = context->decision;" not in result_copy
    dispatch_start = spop_source.index("static int spop_response_companion_owner_dispatch(")
    dispatch_end = spop_source.index("static void run_spop_owner_queue_self_test_task", dispatch_start)
    dispatch = spop_source[dispatch_start:dispatch_end]
    assert "copy_spop_bridge_decision(decision, command->decision_storage" in dispatch
    assert dispatch.index("spop_owner_queue_submit") < dispatch.index(
        "copy_spop_bridge_decision(decision, command->decision_storage"
    )
    assert "command.decision_storage = session->decision_storage;" in SPOP_BACKEND_SOURCE
    assert "msconnector_response_companion_decision_storage *decision_storage;" in TRANSPORT_HEADER


def test_spop_delayed_owner_lifetime_harness_is_asan_ubsan_clean() -> None:
    """A delayed P3/P4 owner task cannot write callback storage after return."""
    compiler = shutil.which("cc")
    assert compiler is not None, "requires a C compiler with AddressSanitizer"
    root = connector_root()
    temporary_parent = os.environ.get("TMPDIR")
    with tempfile.TemporaryDirectory(
        prefix="haproxy-spop-owner-lifetime-", dir=temporary_parent
    ) as temporary_directory:
        binary = Path(temporary_directory) / "haproxy_spop_owner_lifetime"
        compiled = subprocess.run(
            [
                compiler,
                "-std=c17",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                "-ffunction-sections",
                "-fdata-sections",
                "-I.",
                "-Icommon/include",
                "-Icommon/runtime",
                "-Iconnectors/haproxy/src",
                "tests/haproxy_spop_response_companion_lifetime_test.c",
                "common/src/decision.c",
                "common/src/decision_action.c",
                "common/src/error.c",
                "common/src/intervention.c",
                "common/src/block_statuses.c",
                "common/src/http_status.c",
                "common/src/memory.c",
                "-Wl,--gc-sections",
                "-pthread",
                "-o",
                str(binary),
            ],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
        )
        assert compiled.returncode == 0, compiled.stderr
        environment = os.environ.copy()
        environment["ASAN_OPTIONS"] = "detect_leaks=1:abort_on_error=1"
        environment["UBSAN_OPTIONS"] = "halt_on_error=1"
        executed = subprocess.run(
            [str(binary)],
            cwd=root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        assert executed.returncode == 0, executed.stderr


def test_spop_stop_failure_exits_without_releasing_worker_owned_state() -> None:
    """Incomplete transport cleanup must terminate before stack state unwinds."""
    spop_source = (
        connector_root()
        / "connectors"
        / "haproxy"
        / "src"
        / "haproxy_spop_diagnostic_runtime.c"
    ).read_text(encoding="utf-8")
    start = spop_source.index("static int destroy_agent_runtime(")
    end = spop_source.index("static int run_agent_server(", start)
    cleanup = spop_source[start:end]
    stop_helper = spop_source[spop_source.index("static void stop_response_transport_or_exit("):
                              spop_source.index("static void destroy_agent_owner_queue_or_exit(")]
    stop = stop_helper.index("spop_transport_stop_bounded")
    failure = stop_helper.index("event=spop-response-transport-shutdown-failed")
    terminal = stop_helper[failure:stop_helper.index("    }\n", failure)]
    assert "_Exit(SPOP_OWNER_RESTART_EXIT_CODE);" in terminal
    assert "close_owned_stream" not in terminal
    assert "haproxy_spop_response_companion_backend_expire" not in terminal
    assert "spop_owner_queue_destroy(state)" not in terminal
    assert stop < failure
    assert cleanup.index("stop_response_transport_or_exit(state);") < cleanup.index(
        "expire_agent_response_backend(state);")


def test_htx_early_response_uses_common_phase_error_path() -> None:
    htx_source = (
        connector_root()
        / "connectors"
        / "haproxy"
        / "htx-overlay"
        / "haproxy_modsecurity_htx_filter.c"
    ).read_text(encoding="utf-8")
    assert "response_started_before_request_eos" not in htx_source
    # Response processing is owned by the response-header handler; the generic
    # dispatcher only routes the callback and is not the phase implementation.
    response_headers = htx_source[htx_source.index(
        "static int haproxy_modsecurity_htx_handle_response_headers") :
        htx_source.index("static int haproxy_modsecurity_htx_handle_request_headers")]
    assert "haproxy_modsecurity_htx_process_response_headers(s, filter, msg)" in response_headers
    assert "leave this response uninspected" not in response_headers


def test_binding_keeps_one_validated_transaction_id_for_common_and_native() -> None:
    helper_start = SOURCE.index("static int copy_valid_haproxy_transaction_id(")
    helper_end = SOURCE.index("static void init_decision(", helper_start)
    helper = SOURCE[helper_start:helper_end]
    assert "bounded_cstring_length(value, out_size, &length)" in helper
    assert "msconnector_transaction_contract_validate_transaction_id_bytes(value," in helper

    begin_start = SOURCE.index("static int begin_request_with_scope(")
    begin_end = SOURCE.index("int haproxy_modsecurity_transaction_begin_request(", begin_start)
    begin = SOURCE[begin_start:begin_end]
    assert "invalid HAProxy transaction id" in begin
    assert "create_request_transaction_with_id(engine->modsec," in begin
    assert "engine->rules, created->request_id)" in begin

    self_test = (
        connector_root()
        / "connectors"
        / "haproxy"
        / "src"
        / "haproxy_modsecurity_binding_self_test.c"
    ).read_text(encoding="utf-8")
    assert "run_request_id_boundary_self_test" in self_test
    assert "maximum-length transaction id" in self_test
    assert "overlong transaction id" in self_test
    assert "control-character transaction id" in self_test



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("HAProxy transaction contract binding tests: PASS")
