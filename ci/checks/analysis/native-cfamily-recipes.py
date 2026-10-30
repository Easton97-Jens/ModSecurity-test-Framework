"""Closed native compile inventory and genuine shared HAProxy fixture materializer."""

from __future__ import annotations

import hashlib
from pathlib import Path
import runpy


NATIVE_UNITS = (
    "connector_suite/adapters/apache/harness/mod_phase4_terminal_rogue.c",
    "connector_suite/adapters/envoy/src/envoy_ext_authz_response_companion_test.c",
    "connector_suite/adapters/haproxy/harness/i12_request_scope_observer.c",
    "connector_suite/adapters/haproxy/src/haproxy_modsecurity_binding_self_test.c",
    "connector_suite/adapters/lighttpd/stock_sidecar/runtime_begin_smoke.c",
    "connector_suite/adapters/traefik/harness/i12/native/acceptance_faults.c",
    "connector_suite/adapters/traefik/harness/i12/native/acceptance_syscalls.c",
    "connector_suite/adapters/traefik/harness/i12_file/sdk_capability.c",
    "connector_suite/adapters/traefik/src/traefik_forwardauth_response_companion_test.c",
    "connector_suite/common/scripts/modsecurity_targeted_eval.cc",
    "connector_suite/common/src/test_result.c",
    "connector_suite/common/src/test_result_json.c",
    "connector_suite/fuzz/common_http_headers_fuzz.c",
    "connector_suite/modsecurity_connector_ci/checks/common/http_authorization_service_timeout_smoke.c",
    "connector_suite/modsecurity_connector_ci/checks/connectors/apache/apache_request_transaction_cleanup.c",
    "connector_suite/modsecurity_connector_ci/checks/connectors/apache/apache_rules_set_cleanup.c",
    "connector_suite/modsecurity_connector_ci/runtime/lifecycle/apache-i12/acceptance/common_sink_boundary.c",
    "connector_suite/modsecurity_connector_ci/runtime/lifecycle/apache-i12/acceptance/fault_boundary.c",
    "connector_suite/modsecurity_connector_ci/runtime/lifecycle/apache-i12/acceptance/host_bucket.c",
    "connector_suite/modsecurity_connector_ci/runtime/lifecycle/apache-i12/acceptance/host_io.c",
    "connector_suite/modsecurity_connector_ci/runtime/lifecycle/apache-i12/acceptance/multipart_observer.cpp",
    "connector_suite/modsecurity_connector_ci/runtime/lifecycle/apache-i12/apr_sink_fault.c",
    "connector_suite/modsecurity_connector_ci/runtime/lifecycle/i12/lighttpd/patched_sdk_observation.cpp",
    "connector_suite/modsecurity_connector_ci/runtime/lifecycle/i12/lighttpd/patched_transport_observation.c",
    "connector_suite/modsecurity_connector_ci/runtime/lifecycle/i12/lighttpd/stock_sink_faults.c",
    "connector_suite/modsecurity_connector_ci/runtime/lifecycle/i12/lighttpd/stock_spool_floor.c",
    "connector_suite/modsecurity_connector_ci/runtime/lifecycle/i12/lighttpd/stock_transport_observation.c",
    "connector_suite/modsecurity_connector_ci/runtime/lifecycle/i12/nginx/invalid_return.c",
    "connector_suite/modsecurity_connector_ci/runtime/lifecycle/native-lifecycle-observer.c",
    "connector_suite/modsecurity_connector_ci/runtime/lifecycle/native-lifecycle-sdk.cpp",
    "connector_suite/modsecurity_connector_ci/tools/native_modsecurity_oracle.c",
    "connector_suite/modsecurity_connector_tests/active_header_case.c",
    "connector_suite/modsecurity_connector_tests/apache_header_semantics_probe.c",
    "connector_suite/modsecurity_connector_tests/apache_i12_mapper_probe.c",
    "connector_suite/modsecurity_connector_tests/engine_http_request_stream_test.c",
    "connector_suite/modsecurity_connector_tests/engine_response_limit_test.c",
    "connector_suite/modsecurity_connector_tests/event_json_query_redaction_test.c",
    "connector_suite/modsecurity_connector_tests/event_json_utf8_smoke.c",
    "connector_suite/modsecurity_connector_tests/fixtures/lighttpd_i10_native.c",
    "connector_suite/modsecurity_connector_tests/fixtures/lighttpd_i10_sidecar.c",
    "connector_suite/modsecurity_connector_tests/fixtures/nginx_common_input_fault.c",
    "connector_suite/modsecurity_connector_tests/fixtures/nginx_common_input_fault_scope.c",
    "connector_suite/modsecurity_connector_tests/fixtures/nginx_common_input_validation.c",
    "connector_suite/modsecurity_connector_tests/fixtures/nginx_engine_budget_fault.c",
    "connector_suite/modsecurity_connector_tests/fixtures/nginx_finish_fault.c",
    "connector_suite/modsecurity_connector_tests/fixtures/nginx_phase4_observation.c",
    "connector_suite/modsecurity_connector_tests/fixtures/nginx_response_body_limit.c",
    "connector_suite/modsecurity_connector_tests/fixtures/nginx_transaction_fault.c",
    "connector_suite/modsecurity_connector_tests/fixtures/nginx_worker_self_maps.c",
    "connector_suite/modsecurity_connector_tests/fixtures/nginx_write_fault.c",
    "connector_suite/modsecurity_connector_tests/haproxy_common_event_stream_test.c",
    "connector_suite/modsecurity_connector_tests/haproxy_i10_binding_caller_test.c",
    "connector_suite/modsecurity_connector_tests/haproxy_i10_host_caller_test.c",
    "connector_suite/modsecurity_connector_tests/haproxy_i10_spop_caller_test.c",
    "connector_suite/modsecurity_connector_tests/haproxy_request_authorization_contract_test.c",
    "connector_suite/modsecurity_connector_tests/haproxy_spop_request_target_test.c",
    "connector_suite/modsecurity_connector_tests/haproxy_spop_response_companion_backend_test.c",
    "connector_suite/modsecurity_connector_tests/haproxy_spop_response_companion_lifetime_test.c",
    "connector_suite/modsecurity_connector_tests/http_authorization_service_detached_worker_smoke.c",
    "connector_suite/modsecurity_connector_tests/http_authorization_service_peer_close_smoke.c",
    "connector_suite/modsecurity_connector_tests/http_authorization_service_response_companion_lifecycle_smoke.c",
    "connector_suite/modsecurity_connector_tests/http_authorization_service_trusted_binding_smoke.c",
    "connector_suite/modsecurity_connector_tests/intervention_normalization_test.c",
    "connector_suite/modsecurity_connector_tests/nginx_body_buffer_fixture/ngx_http_body_buffer_fixture_module.c",
    "connector_suite/modsecurity_connector_tests/nginx_p3_header_injector_fixture/ngx_http_p3_header_injector_fixture_module.c",
    "connector_suite/modsecurity_connector_tests/nginx_p3_header_observer_fixture/ngx_http_p3_header_observer_fixture_module.c",
    "connector_suite/modsecurity_connector_tests/private_event_file_smoke.c",
    "connector_suite/modsecurity_connector_tests/request_body_telemetry_test.c",
    "connector_suite/modsecurity_connector_tests/response_companion_client_test.c",
    "connector_suite/modsecurity_connector_tests/response_companion_transport_test.c",
    "connector_suite/modsecurity_connector_tests/test_nginx_cleanup_observation.c",
    "connector_suite/modsecurity_connector_tests/test_nginx_engine_call_budget.c",
    "connector_suite/modsecurity_connector_tests/test_resource_limits_hard_caps.c",
    "connector_suite/modsecurity_connector_tests/traefik_engine_worker_lifecycle_test.c",
    "connector_suite/modsecurity_connector_tests/traefik_i10_dispatcher_test.c",
    "connector_suite/modsecurity_connector_tests/traefik_i12_companion_invalid_outcome_probe.c",
    "connector_suite/modsecurity_connector_tests/traefik_i12_companion_metadata_probe.c",
    "connector_suite/modsecurity_connector_tests/traefik_i12_mse1_metadata_probe.c",
    "connector_suite/modsecurity_connector_tests/transaction_phase_contract_test.c",
    "connector_suite/modsecurity_connector_tests/transaction_phase_runtime_companion_test.c",
    "src/v3-api-smoke/v3_api_smoke.c",
)

HOST_FUNCTIONS = (
    "request_version",
    "observed_error_phase",
    "event_reason",
    "event_eos",
    "prepare_event",
    "event_sink_failed",
    "write_event",
    "companion_cancel_cause_from_error",
    "companion_cancel_and_close",
    "abort_context",
    "finish_context",
    "error_phase",
    "report_error",
    "apply_precommit_deny",
    "apply_precommit_redirect",
    "apply_precommit_decision",
    "fail_closed_precommit",
    "abort_response_stream",
    "fail_closed_postcommit",
    "fail_closed_request_phase",
    "apply_precommit_decision_or_fail_closed",
    "companion_result_is_forwardable",
    "companion_record_precommit_outcome",
    "companion_record_terminal_outcome",
    "companion_open_and_claim",
    "companion_commit",
    "process_companion_response_headers",
    "send_companion_response_chunk",
    "finish_companion_response",
    "handle_response_headers",
    "filter_request_payload",
    "filter_response_payload",
    "filter_http_payload",
    "finish_request",
    "finish_response",
    "filter_http_end",
    "filter_http_headers",
)


def materialize_host_includes(source: str, output: Path) -> dict[str, str]:
    """Extract the same complete Product structs and functions used by native tests."""
    if (
        any(parent.is_symlink() for parent in (output, *output.parents))
        or not output.is_dir()
    ):
        raise ValueError("private fixture include directory is required")
    root = Path(__file__).resolve().parents[3]
    definition = runpy.run_path(
        str(root / "connector_suite/modsecurity_connector_tests/c_source_contract.py")
    )["function_definition"]
    structs = source[
        source.index("struct haproxy_modsecurity_htx_filter_config {") : source.index(
            "typedef int (*haproxy_modsecurity_htx_append_body_chunk)"
        )
    ]
    bodies = []
    for suffix in HOST_FUNCTIONS:
        body = definition(source, "haproxy_modsecurity_htx_" + suffix)
        start = source.index(body)
        previous = source[source.rfind("\n", 0, start - 1) + 1 : start].strip()
        bodies.append(
            previous + "\n" + body if not body.startswith("static ") else body
        )
    result = {}
    for name, text in (
        ("native-haproxy-product-structs.inc", structs),
        ("native-haproxy-product-functions.inc", "\n\n".join(bodies)),
    ):
        path = output / name
        if path.exists() or path.is_symlink():
            raise ValueError("generated native include must be fresh")
        with path.open("x", encoding="utf-8") as stream:
            stream.write(text + "\n")
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


LIGHTTPD_NATIVE_FUNCTIONS = (
    "mod_msconnector_record_api_failure",
    "mod_msconnector_error_response",
    "mod_msconnector_fail_request",
    "mod_msconnector_apply_decision",
    "mod_msconnector_response_headers_committed",
    "mod_msconnector_response_body_committed",
    "mod_msconnector_finish_request_body",
    "mod_msconnector_finish_response_body",
    "mod_msconnector_handle_response_body",
    "mod_msconnector_handle_response_abort",
    "mod_msconnector_append_request_body_range",
    "mod_msconnector_reject_request_body_gate_conflict",
    "mod_msconnector_handle_request_body",
)
LIGHTTPD_SIDECAR_FUNCTIONS = (
    "sidecar_shutdown_owned_socket",
    "sidecar_now_ms",
    "sidecar_remaining",
    "sidecar_wait",
    "sidecar_send_all_observed",
    "sidecar_send_all",
    "sidecar_recv_some_with_flags",
    "sidecar_recv_some",
    "sidecar_headers_release",
    "sidecar_write_error",
    "sidecar_record_failure_action",
    "sidecar_failure_error_class",
    "sidecar_exchange_state_init",
    "sidecar_release_request_spool",
    "sidecar_read_response_body",
    "sidecar_phase4_action",
    "sidecar_finish_strict_response",
    "sidecar_exchange_response",
    "sidecar_exchange_error",
    "sidecar_exchange",
)


def lighttpd_parts(
    native: str | None = None, sidecar: str | None = None
) -> dict[str, str]:
    """Preserve the existing exact productive lighttpd test extraction."""
    root = Path(__file__).resolve().parents[3]
    helper = runpy.run_path(
        str(root / "connector_suite/modsecurity_connector_tests/c_source_contract.py")
    )
    definition, matching = helper["function_definition"], helper["matching_delimiter"]
    result = {}
    if native is not None:
        definitions = [definition(native, name) for name in LIGHTTPD_NATIVE_FUNCTIONS]
        for name in (
            "mod_msconnector_handle_uri_clean",
            "mod_msconnector_handle_response_start",
            "mod_msconnector_handle_request_reset",
        ):
            start = native.index("REQUEST_FUNC(" + name + ") {")
            opening = native.index("{", start)
            end = matching(native, opening, "{", "}")
            definitions.append(native[start : end + 1])
        result["native-lighttpd-definitions.inc"] = "\n".join(definitions)
    if sidecar is not None:
        types = sidecar[
            sidecar.index("typedef struct sidecar_options") : sidecar.index(
                "typedef struct sidecar_runtime_context"
            )
        ]
        types += sidecar[
            sidecar.index("typedef enum sidecar_failure_origin") : sidecar.index(
                "static uint64_t sidecar_now_ms"
            )
        ]
        types += sidecar[
            sidecar.index("typedef struct sidecar_exchange_payload") : sidecar.index(
                "static int sidecar_capture_request_endpoints"
            )
        ]
        result["native-lighttpd-sidecar-types.inc"] = types
        result["native-lighttpd-sidecar-definitions.inc"] = "\n".join(
            definition(sidecar, name) for name in LIGHTTPD_SIDECAR_FUNCTIONS
        )
    return result


def write_lighttpd_includes(parts: dict[str, str], output: Path) -> dict[str, str]:
    allowed = {
        "native-lighttpd-definitions.inc",
        "native-lighttpd-sidecar-types.inc",
        "native-lighttpd-sidecar-definitions.inc",
    }
    if (
        not parts
        or not set(parts) <= allowed
        or any(parent.is_symlink() for parent in (output, *output.parents))
        or not output.is_dir()
    ):
        raise ValueError(
            "private lighttpd include directory and closed names are required"
        )
    result = {}
    for name, text in parts.items():
        destination = output / name
        with destination.open("x", encoding="utf-8") as stream:
            stream.write(text + "\n")
        result[name] = hashlib.sha256(destination.read_bytes()).hexdigest()
    return result


def spop_fixture_helper() -> str:
    """Read the exact extracted Framework helper used by the real caller fixture."""
    root = Path(__file__).resolve().parents[3]
    definition = runpy.run_path(
        str(root / "connector_suite/modsecurity_connector_tests/c_source_contract.py")
    )["function_definition"]
    source = (
        root
        / "connector_native_tests/connectors/haproxy/src/haproxy_spop_diagnostic_runtime.inc"
    ).read_text()
    return definition(source, "payload_has_set_var_blocked_true")
