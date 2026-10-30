from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
from pathlib import Path
import re
import unittest
from unittest.mock import patch

from modsecurity_connector_tests.c_source_contract import function_definition, matching_delimiter


ROOT = connector_root()
NGINX_SOURCE = source_path('connectors/nginx/src', root=ROOT)
ACCESS = NGINX_SOURCE / "ngx_http_modsecurity_access.c"
BODY = NGINX_SOURCE / "ngx_http_modsecurity_body_filter.c"
COMMON = NGINX_SOURCE / "ngx_http_modsecurity_common.h"
HEADER = NGINX_SOURCE / "ngx_http_modsecurity_header_filter.c"
MODULE = NGINX_SOURCE / "ngx_http_modsecurity_module.c"
CAPABILITIES = source_path('connectors/nginx/capabilities.json', root=ROOT)


def conditional_block(source: str, marker: str, start: int = 0) -> str:
    condition = source.index(marker, start)
    opening = source.index("{", condition)
    return source[condition : matching_delimiter(source, opening, "{", "}") + 1]


class NginxUpstreamSecurityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.access = ACCESS.read_text(encoding="utf-8")
        cls.body = BODY.read_text(encoding="utf-8")
        cls.common = COMMON.read_text(encoding="utf-8")
        cls.header = HEADER.read_text(encoding="utf-8")
        cls.module = MODULE.read_text(encoding="utf-8")
        cls.capabilities = json.loads(CAPABILITIES.read_text(encoding="utf-8"))

    def test_context_creation_returns_only_context_or_null(self) -> None:
        create_ctx = function_definition(
            self.module, "ngx_http_modsecurity_create_ctx"
        )
        self.assertNotIn("return NGX_CONF_ERROR;", create_ctx)
        self.assertIn("msc_new_transaction_with_id", create_ctx)
        self.assertIn("msc_new_transaction", create_ctx)
        self.assertIn("if (ctx->modsec_transaction == NULL)", create_ctx)
        self.assertLess(
            create_ctx.index("if (ctx->modsec_transaction == NULL)"),
            create_ctx.index("ngx_http_set_ctx(r, ctx, ngx_http_modsecurity_module);"),
        )
        self.assertIn("ngx_pool_cleanup_add(r->pool, 0)", create_ctx)
        self.assertIn("return ctx;", create_ctx)

    def test_native_header_sinks_have_shared_bounded_fail_closed_gate(self) -> None:
        self.assertIn('#include "msconnector/limits.h"', self.common)

        gate = function_definition(self.common, "ngx_http_modsecurity_validate_header")
        self.assertIn("name_len > MSCONNECTOR_MAX_HEADER_NAME_LENGTH", gate)
        self.assertIn("value_len > MSCONNECTOR_MAX_HEADER_VALUE_LENGTH", gate)
        self.assertIn("name_len > MSCONNECTOR_MAX_TOTAL_HEADER_BYTES - value_len", gate)
        self.assertIn("current_bytes = name_len + value_len", gate)
        self.assertIn("MSCONNECTOR_MAX_HEADER_COUNT", gate)
        self.assertIn("return NGX_ERROR;", gate)

        request = function_definition(
            self.common, "ngx_http_modsecurity_add_n_request_header"
        )
        response = function_definition(
            self.common, "ngx_http_modsecurity_add_n_response_header"
        )
        self.assertLess(
            request.index("ngx_http_modsecurity_validate_header"),
            request.index("msc_add_n_request_header"),
        )
        self.assertLess(
            response.index("ngx_http_modsecurity_validate_header"),
            response.index("msc_add_n_response_header"),
        )
        self.assertNotIn("msc_add_n_request_header", self.access)
        self.assertNotIn("msc_add_n_response_header", self.header)

        add_response = function_definition(
            self.header, "ngx_http_modsecurity_add_response_headers"
        )
        self.assertIn("return NGX_ERROR;", add_response)
        header_filter = function_definition(self.header, "ngx_http_modsecurity_header_filter")
        self.assertIn(
            "if (ngx_http_modsecurity_add_response_headers(r, ctx) != NGX_OK)",
            header_filter,
        )
        self.assertIn("return NGX_ERROR;", header_filter)

    def test_native_response_header_failure_is_terminal_and_never_reaches_next_filter(self) -> None:
        header_filter = function_definition(
            self.header, "ngx_http_modsecurity_header_filter"
        )

        self.assertIn("unsigned response_headers_processing_failed:1;", self.common)
        retry_guard = header_filter.index("if (ctx->response_headers_processing_failed)")
        intervention_guard = header_filter.index("if (ctx->intervention_triggered)")
        processed_guard = header_filter.index("if (ctx && ctx->processed)")
        native_call = header_filter.index(
            "ret = msc_process_response_headers(ctx->modsec_transaction, status, http_response_ver);"
        )
        native_failure = conditional_block(header_filter, "if (ret != 1)", native_call)
        completion = header_filter.index(
            "if (ngx_http_modsecurity_contract_complete(ctx,", native_call
        )
        response_headers_seen = header_filter.index("ctx->response_headers_seen = 1;", completion)
        intervention = header_filter.index(
            "ret = ngx_http_modsecurity_process_intervention", response_headers_seen
        )

        self.assertLess(retry_guard, intervention_guard)
        self.assertLess(retry_guard, processed_guard)
        self.assertIn("ngx_http_modsecurity_pcre_malloc_done(old_pool);", native_failure)
        self.assertEqual(
            native_failure.count("ngx_http_modsecurity_pcre_malloc_done(old_pool);"), 1
        )
        self.assertIn("ctx->response_headers_processing_failed = 1;", native_failure)
        self.assertIn("ctx->intervention_triggered = 1;", native_failure)
        self.assertIn(
            "MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE", native_failure
        )
        self.assertIn("msconnector_transaction_contract_fail(&ctx->contract,", native_failure)
        self.assertIn("return NGX_ERROR;", native_failure)
        self.assertNotIn("ngx_http_modsecurity_contract_complete", native_failure)
        self.assertNotIn("ctx->response_headers_seen = 1;", native_failure)
        self.assertNotIn("ngx_http_modsecurity_process_intervention", native_failure)
        self.assertNotIn("ngx_http_next_header_filter", native_failure)
        self.assertLess(native_call, completion)
        self.assertLess(completion, response_headers_seen)
        self.assertLess(response_headers_seen, intervention)

    def test_request_derived_transaction_id_is_validated_before_retention_or_native_use(self) -> None:
        create_ctx = function_definition(
            self.module, "ngx_http_modsecurity_create_ctx"
        )
        validation = create_ctx.index(
            "msconnector_transaction_contract_validate_transaction_id_bytes"
        )
        retention = create_ctx.index("transaction_id = ngx_pnalloc", validation)
        native = create_ctx.index("msc_new_transaction_with_id", retention)
        contract = create_ctx.index("msconnector_transaction_contract_init")
        self.assertLess(validation, retention)
        self.assertLess(retention, contract)
        self.assertLess(contract, native)
        self.assertIn("s.data == NULL", create_ctx)
        self.assertIn(
            "invalid canonical transaction identifier", create_ctx
        )
        native_failure = conditional_block(
            create_ctx, "if (ctx->modsec_transaction == NULL)"
        )
        self.assert_native_creation_failure_cleanup(native_failure, self.module)

    def assert_native_creation_failure_cleanup(self, failure: str, module: str) -> None:
        self.assertIn("MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR, 0U", failure)
        self.assertIn("MSCONNECTOR_PHASE_REQUEST_HEADERS, ctx->contract.error_class", failure)
        self.assertIn("NGX_HTTP_INTERNAL_SERVER_ERROR", failure)
        self.assertIn("ngx_http_modsecurity_cleanup(ctx);", failure)
        self.assertLess(failure.index("msconnector_transaction_contract_fail"),
                        failure.index("ngx_http_modsecurity_log_technical_failure"))
        self.assertLess(failure.index("ngx_http_modsecurity_log_technical_failure"),
                        failure.index("ngx_http_modsecurity_cleanup(ctx);"))
        self.assertLess(failure.index("ngx_http_modsecurity_cleanup(ctx);"),
                        failure.index("return NULL;"))
        self.assertNotIn("ctx->contract_initialized = 0;", failure)
        cleanup = function_definition(module, "ngx_http_modsecurity_cleanup")
        common = conditional_block(cleanup, "if (observed_contract)")
        self.assertIn("common_return = msconnector_transaction_contract_cleanup(&ctx->contract, 0U);", common)
        self.assertLess(common.index("msconnector_transaction_contract_cleanup"),
                        common.index("ctx->contract_initialized = 0;"))
        native = conditional_block(cleanup, "if (ctx->modsec_transaction != NULL)")
        self.assertIn("msc_transaction_cleanup(ctx->modsec_transaction);", native)
        self.assertLess(native.index("msc_transaction_cleanup"),
                        native.index("ctx->modsec_transaction = NULL;"))
        self.assertLess(native.index("ctx->modsec_transaction = NULL;"),
                        native.index("native_cleanup_completed = 1;"))
        self.assertLess(cleanup.index(common), cleanup.index(native))
        self.assertLess(cleanup.index(native), cleanup.index("ngx_http_modsecurity_cleanup_log_event"))

    def test_native_creation_cleanup_guard_rejects_missing_or_late_cleanup(self) -> None:
        failure = conditional_block(function_definition(self.module,
            "ngx_http_modsecurity_create_ctx"), "if (ctx->modsec_transaction == NULL)")
        for replacement in ("", "return NULL; ngx_http_modsecurity_cleanup(ctx);"):
            with self.subTest(replacement=replacement):
                changed = failure.replace("ngx_http_modsecurity_cleanup(ctx);", replacement, 1)
                with self.assertRaises(AssertionError):
                    self.assert_native_creation_failure_cleanup(changed, self.module)

    def test_native_creation_cleanup_guard_rejects_missing_common_cleanup(self) -> None:
        failure = conditional_block(function_definition(self.module,
            "ngx_http_modsecurity_create_ctx"), "if (ctx->modsec_transaction == NULL)")
        changed = self.module.replace(
            "common_return = msconnector_transaction_contract_cleanup(&ctx->contract, 0U);",
            "common_return = 0;", 1)
        self.assertNotEqual(changed, self.module)
        with self.assertRaises(AssertionError):
            self.assert_native_creation_failure_cleanup(failure, changed)

    def test_transaction_id_complex_value_does_not_append_a_synthetic_nul(self) -> None:
        setter = function_definition(self.module, "ngx_conf_set_transaction_id")
        create_ctx = function_definition(
            self.module, "ngx_http_modsecurity_create_ctx"
        )

        self.assertIn("ngx_memzero(&ccv", setter)
        self.assertIn("ccv.zero = 0;", setter)
        self.assertNotIn("ccv.zero = 1;", setter)
        self.assertIn(
            "msconnector_transaction_contract_validate_transaction_id_bytes",
            create_ctx,
        )
        self.assertIn(
            "transaction_id = ngx_pnalloc(r->pool, s.len + 1U);", create_ctx
        )
        self.assertIn("ngx_memcpy(transaction_id, s.data, s.len);", create_ctx)
        self.assertIn("transaction_id[s.len] = '\\0';", create_ctx)

    def test_disruptive_interventions_record_terminal_contract_decisions_before_host_sinks(self) -> None:
        record = function_definition(
            self.module, "ngx_http_modsecurity_contract_record_intervention"
        )
        intervention = function_definition(
            self.module, "ngx_http_modsecurity_process_intervention"
        )

        self.assertIn("ctx->contract_initialized", record)
        self.assertIn("MSCONNECTOR_TRANSACTION_DECISION_REDIRECT", record)
        self.assertIn("MSCONNECTOR_TRANSACTION_DECISION_RATE_LIMIT", record)
        self.assertIn("MSCONNECTOR_TRANSACTION_DECISION_BLOCK", record)
        self.assertIn("NGX_HTTP_TOO_MANY_REQUESTS", record)
        self.assertIn("ctx->last_intervention_rule_id", record)
        self.assertIn("msconnector_transaction_contract_record_decision", record)
        self.assertIn("MSCONNECTOR_TRANSACTION_TRANSITION_OK", record)
        self.assertIn("canonical intervention decision", record)

        extract_helper = function_definition(
            self.module, "ngx_http_modsecurity_extract_intervention_rule_id"
        )
        self.assertIn("if (intervention->log != NULL)", extract_helper)
        self.assertIn("msconnector_rule_id_extract_from_message(intervention->log,", extract_helper)
        self.assertIn("sizeof(ctx->last_intervention_rule_id)", extract_helper)
        self.assertNotIn("phase4_log_file", extract_helper)
        self.assertNotIn(
            "mcf->phase4_log_file != NULL && intervention.log != NULL",
            intervention,
        )
        self.assertEqual(intervention.count("ngx_http_modsecurity_extract_intervention_rule_id(ctx, &intervention);"), 1)
        extract = intervention.index("ngx_http_modsecurity_extract_intervention_rule_id(ctx, &intervention);")
        terminal = intervention.index(
            "ngx_http_modsecurity_contract_record_intervention(r, ctx, &intervention)"
        )
        redirect = intervention.index("ngx_http_modsecurity_process_redirect_intervention")
        status = intervention.index("ngx_http_modsecurity_process_status_intervention")
        self.assertLess(extract, terminal)
        self.assertLess(terminal, redirect)
        self.assertLess(terminal, status)
        self.assertLess(extract, intervention.rindex("msc_intervention_cleanup(&intervention)"))

    def test_rule_id_helper_guard_rejects_missing_late_or_unbounded_extraction(self) -> None:
        call = "ngx_http_modsecurity_extract_intervention_rule_id(ctx, &intervention);"
        mutations = (
            self.module.replace(call, "/* extraction omitted */"),
            self.module.replace(call, "").replace("msc_intervention_cleanup(&intervention);",
                "msc_intervention_cleanup(&intervention); " + call),
            self.module.replace("sizeof(ctx->last_intervention_rule_id)", "unbounded_size"),
            self.module.replace("if (intervention->log != NULL)", "if (ctx->r && intervention->log != NULL)"),
        )
        for index, source in enumerate(mutations):
            with self.subTest(mutation=index), patch.object(self, "module", source):
                with self.assertRaises((AssertionError, ValueError)):
                    self.test_disruptive_interventions_record_terminal_contract_decisions_before_host_sinks()

    def test_final_body_processing_accepts_only_success_one(self) -> None:
        request = function_definition(
            self.access, "ngx_http_modsecurity_inspect_request_body"
        )
        request_assignment = request.index("ret = msc_process_request_body")
        request_failure = conditional_block(
            request, "if (!msconnector_native_phase_succeeded(ret))", request_assignment
        )
        self.assertIn("ctx->intervention_triggered = 1;", request_failure)
        self.assertIn("return NGX_HTTP_INTERNAL_SERVER_ERROR;", request_failure)
        self.assertIn("MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE", request_failure)
        self.assertNotIn("ngx_http_modsecurity_contract_complete", request_failure)
        self.assertNotIn("ctx->request_body_processed = 1;", request_failure)
        self.assertLess(
            request.index("if (!msconnector_native_phase_succeeded(ret))"),
            request.index("ngx_http_modsecurity_contract_complete"),
        )
        self.assertLess(
            request.index("ngx_http_modsecurity_contract_complete"),
            request.index("ctx->request_body_processed = 1;"),
        )

        response = function_definition(
            self.body, "ngx_http_modsecurity_process_final_response_body"
        )
        response_assignment = response.index("ret = msc_process_response_body")
        response_failure = conditional_block(
            response, "if (!msconnector_native_phase_succeeded(ret))", response_assignment
        )
        self.assertIn("ctx->intervention_triggered = 1;", response_failure)
        self.assertIn("MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE", response_failure)
        committed_mark = conditional_block(response_failure, "if (r->header_sent)")
        self.assertIn("r->connection->error = 1;", committed_mark)
        # Failure metadata is emitted after the abort flag and before either
        # terminal return. The committed path must never render a second HTTP
        # response or turn an engine failure into the Safe log-only policy.
        logged = response_failure.index("ngx_http_modsecurity_phase4_log_failure(r, mcf, ctx)")
        committed_return = conditional_block(response_failure, "if (r->header_sent)", logged)
        self.assertIn("return NGX_ERROR;", committed_return)
        self.assertNotRegex(
            committed_mark + committed_return,
            re.compile(r"ngx_http_filter_finalize_request\s*\("),
        )
        self.assertNotIn("ngx_http_modsecurity_phase4_handle_intervention", response_failure)
        self.assertNotIn("ngx_http_modsecurity_contract_complete", response_failure)
        self.assertIn("NGX_HTTP_INTERNAL_SERVER_ERROR", response_failure)

    def test_partial_body_append_and_file_paths_remain_nonfatal(self) -> None:
        request_append = function_definition(
            self.access, "ngx_http_modsecurity_append_request_chunk"
        )
        self.assertRegex(
            request_append,
            re.compile(
                r"msc_append_request_body\s*\(.*?\);\s*"
                r"ctx->native_event_phase_active\s*=\s*0;",
                re.DOTALL,
            ),
        )
        request_append_failure = conditional_block(
            request_append, "if (!msconnector_native_body_append_can_continue(ret))"
        )
        self.assertIn("return NGX_HTTP_INTERNAL_SERVER_ERROR;", request_append_failure)
        self.assertIn("MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE", request_append_failure)

        request_file = function_definition(
            self.access, "ngx_http_modsecurity_inspect_request_body_file"
        )
        self.assertIn("ngx_fd_info(file->fd, &file_info)", request_file)
        self.assertIn("ngx_is_file(&file_info)", request_file)
        self.assertIn("ngx_file_size(&file_info) != file_size", request_file)
        self.assertIn("ngx_read_file(file, ctx->scratch_buffers.request_file_scratch", request_file)
        self.assertIn("ngx_http_modsecurity_append_request_chunk(r, ctx", request_file)
        self.assertIn("read_size < 0 || (size_t)read_size != amount", request_file)
        self.assertNotIn("msc_request_body_from_file", request_file)
        self.assertNotIn("request_body_limit", request_file)

        response_append = function_definition(
            self.body, "ngx_http_modsecurity_append_response_body_chunk"
        )
        self.assert_response_append_return_guard(response_append)
        failed_append = conditional_block(response_append, "if (!msconnector_native_body_append_can_continue")
        self.assertIn("MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE", failed_append)
        self.assertIn("return NGX_ERROR;", failed_append)
        self.assertNotIn("return NGX_OK;", failed_append)
        self.assertNotIn("bytes_inspected +=", failed_append)
        self.assertLess(
            response_append.index("if (!msconnector_native_body_append_can_continue"),
            response_append.index("ctx->response_body_bytes_inspected += bytes;"),
        )
        self.assertNotRegex(
            response_append,
            re.compile(r"msc_append_response_body\s*\(.*?\)\s*!=\s*1", re.DOTALL),
        )

    def assert_response_append_return_guard(self, append: str) -> None:
        call = "native_result = msc_append_response_body(ctx->modsec_transaction, data, bytes);"
        guard = "if (!msconnector_native_body_append_can_continue(native_result))"
        self.assertEqual(append.count(call), 1)
        self.assertIn(guard, append)
        between = append[append.index(call) + len(call):append.index(guard)]
        self.assertEqual(between.strip(), "ctx->native_event_phase_active = 0;")
        self.assertLess(append.index(guard), append.index("ctx->response_body_bytes_inspected += bytes;"))
        self.assertLess(append.index(guard), append.index("ctx->response_body_append_calls++;"))

    def test_response_append_guard_rejects_ignored_overwritten_or_unchecked_results(self) -> None:
        append = function_definition(self.body, "ngx_http_modsecurity_append_response_body_chunk")
        changes = (
            ("native_result = msc_append_response_body", "msc_append_response_body"),
            ("ctx->native_event_phase_active = 0;", "ctx->native_event_phase_active = 0; native_result = 1;"),
            ("msconnector_native_body_append_can_continue(native_result)", "msconnector_native_body_append_can_continue(1)"),
            ("ctx->native_event_phase_active = 0;", "ctx->native_event_phase_active = 0; ctx->response_body_append_calls++;"),
        )
        for old, new in changes:
            with self.subTest(replacement=new):
                changed = append.replace(old, new, 1)
                self.assertNotEqual(changed, append)
                with self.assertRaises(AssertionError):
                    self.assert_response_append_return_guard(changed)

    def test_connection_and_uri_preserve_the_shared_failure_boundary(self) -> None:
        helper_name = "ngx_http_modsecurity_request_native_result"
        helper = function_definition(self.access, helper_name)
        failure = conditional_block(helper, "if (!msconnector_native_phase_succeeded(native_result))")
        dispatch = helper.index("result = ngx_http_modsecurity_process_intervention")
        self.assertLess(helper.index(failure), dispatch)
        self.assertIn("MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE", failure)
        self.assertIn("ctx->intervention_triggered = 1;", failure)
        self.assertIn("return NGX_HTTP_INTERNAL_SERVER_ERROR;", failure)
        self.assertNotIn("ngx_http_modsecurity_process_intervention", failure)
        nonzero = conditional_block(helper, "if (result != 0)", dispatch)
        self.assertIn("ctx->intervention_triggered = 1;", nonzero)
        self.assertIn("return result > 0 ? result : NGX_HTTP_INTERNAL_SERVER_ERROR;", nonzero)
        self.assertIn("return NGX_OK;", helper)
        for name, native, label in (
            ("ngx_http_modsecurity_process_connection", "msc_process_connection", "connection"),
            ("ngx_http_modsecurity_process_request_uri", "msc_process_uri", "URI"),
        ):
            with self.subTest(function=name):
                caller = function_definition(self.access, name)
                expected = f'return {helper_name}(r, ctx, ret, "{label}");'
                self.assertEqual(caller.count(expected), 1)
                self.assertLess(caller.index(f"ret = {native}"), caller.index("ngx_http_modsecurity_pcre_malloc_done"))
                self.assertLess(caller.index("ngx_http_modsecurity_pcre_malloc_done"), caller.index(expected))
                self.assertNotIn("ngx_http_modsecurity_process_intervention", caller)

    def test_negative_interventions_fail_closed_before_response_commit(self) -> None:
        # Connection/URI callers are covered together with their real helper
        # above and by the compiled request-phase-completion regressions.
        for name in (
            "ngx_http_modsecurity_process_request_headers",
            "ngx_http_modsecurity_inspect_request_body",
        ):
            with self.subTest(function=name):
                function = function_definition(self.access, name)
                intervention = function.index("ret = ngx_http_modsecurity_process_intervention")
                if name == "ngx_http_modsecurity_process_request_headers":
                    self.assertIn(
                        "ngx_http_modsecurity_intervention_disposition(ret,",
                        function[intervention:],
                    )
                    negative = conditional_block(
                        function,
                        "if (disposition == MSCONNECTOR_NGINX_INTERVENTION_FAILURE)",
                        intervention,
                    )
                else:
                    negative = conditional_block(function, "if (ret < 0)", intervention)
                self.assertIn("ctx->intervention_triggered = 1;", negative)
                self.assertIn("return NGX_HTTP_INTERNAL_SERVER_ERROR;", negative)

        header_filter = function_definition(self.header, "ngx_http_modsecurity_header_filter")
        self.assertIn(
            "ngx_http_modsecurity_handle_response_header_intervention(r, ctx,",
            header_filter,
        )
        header_intervention = function_definition(
            self.header, "ngx_http_modsecurity_handle_response_header_intervention"
        )
        self.assertIn(
            "ngx_http_modsecurity_intervention_disposition(ret,",
            header_intervention,
        )
        negative = conditional_block(
            header_intervention,
            "if (disposition == MSCONNECTOR_NGINX_INTERVENTION_FAILURE)",
        )
        self.assertIn("ctx->intervention_triggered = 1;", negative)
        self.assertIn("return NGX_ERROR;", negative)
        self.assertNotIn("ngx_http_filter_finalize_request", negative)

        body_filter = function_definition(self.body, "ngx_http_modsecurity_body_filter")
        terminal = function_definition(
            self.body, "ngx_http_modsecurity_finalize_terminal_response_body"
        )
        self.assertIn("ngx_http_modsecurity_process_response_body_chain", body_filter)
        self.assertIn("ngx_http_modsecurity_process_final_response_body", terminal)
        body_intervention = function_definition(
            self.body, "ngx_http_modsecurity_process_final_response_body"
        )
        normal_intervention = conditional_block(body_intervention, "if (ret == 0)")
        self.assertIn("return NGX_OK;", normal_intervention)
        self.assertIn(
            "ngx_http_modsecurity_phase4_handle_intervention(r, mcf)",
            body_intervention,
        )
        phase4_intervention = body_intervention[
            body_intervention.index("ctx->phase4_intervention = 1;") :
        ]
        self.assertNotRegex(
            phase4_intervention,
            re.compile(r"ngx_http_filter_finalize_request\s*\("),
        )

    def test_precommit_redirect_is_atomic_and_replaces_the_old_body(self) -> None:
        redirect = function_definition(
            self.module, "ngx_http_modsecurity_process_redirect_intervention"
        )
        for required in (
            "ngx_http_clear_content_length(r);",
            "ngx_http_clear_last_modified(r);",
            "ngx_http_clear_etag(r);",
            "ngx_http_clear_accept_ranges(r);",
            "ngx_str_null(&r->headers_out.content_type);",
            "r->headers_out.content_type_len = 0;",
        ):
            with self.subTest(required=required):
                self.assertIn(required, redirect)

        self.assertIn("unsigned response_replaced:1;", self.common)
        self.assertIn(
            "unsigned intervention_redirect_location_installed:1;", self.common
        )
        self.assertEqual(
            (self.access + self.body + self.header + self.module).count(
                "ctx->intervention_redirect_location_installed = 1;"
            ),
            1,
        )
        self.assertIn(
            "ctx->intervention_redirect_location_installed = 1;", redirect
        )
        self.assertLess(
            redirect.index("r->headers_out.location->hash = 1;"),
            redirect.index("ctx->intervention_redirect_location_installed = 1;"),
        )
        header_filter = function_definition(self.header, "ngx_http_modsecurity_header_filter")
        header_intervention = function_definition(
            self.header, "ngx_http_modsecurity_handle_response_header_intervention"
        )
        normal_intervention = conditional_block(
            header_intervention,
            "if (disposition == MSCONNECTOR_NGINX_INTERVENTION_ALLOW)",
        )
        self.assertIn("return ngx_http_next_header_filter(r);", normal_intervention)
        positive_intervention = header_intervention[
            header_intervention.index("mcf = ngx_http_get_module_loc_conf") :
        ]
        redirect_branch = conditional_block(
            positive_intervention,
            "if (ctx->intervention_redirect_location_installed &&",
        )
        self.assertIn("r->headers_out.location != NULL", redirect_branch)
        for required in (
            "ctx->response_replaced = 1;",
            "r->headers_out.content_length_n = 0;",
            "r->header_only = 1;",
            "return ngx_http_next_header_filter(r);",
        ):
            with self.subTest(required=required):
                self.assertIn(required, redirect_branch)
        self.assertIn("ctx->intervention_triggered = 1;", positive_intervention)
        self.assertLess(
            positive_intervention.index("ctx->intervention_triggered = 1;"),
            positive_intervention.index(
                "if (ctx->intervention_redirect_location_installed &&"
            ),
        )
        self.assertNotIn("return ngx_http_filter_finalize_request", redirect_branch)
        self.assertRegex(
            positive_intervention,
            re.compile(
                r"return ngx_http_filter_finalize_request\(r,\s*"
                r"&ngx_http_modsecurity_module,\s*ret\);"
            ),
        )
        self.assertNotIn(
            "if (r->headers_out.location != NULL)", positive_intervention
        )

        prepare = function_definition(
            self.body, "ngx_http_modsecurity_prepare_response_body_filter"
        )
        replacement_drain = function_definition(
            self.body, "ngx_http_modsecurity_discard_replaced_response_body"
        )
        response_replaced = conditional_block(prepare, "if (ctx->response_replaced)")
        self.assertLess(
            prepare.index("if (ctx->response_replaced)"),
            prepare.index("if (ctx->intervention_triggered || ctx->phase4_processed)"),
        )
        self.assertRegex(
            replacement_drain,
            re.compile(r"\w+->buf->pos\s*=\s*\w+->buf->last;"),
        )
        self.assertIn(
            "ngx_http_modsecurity_discard_replaced_response_body(in);",
            response_replaced,
        )
        body_filter = function_definition(self.body, "ngx_http_modsecurity_body_filter")
        self.assertIn(
            "return ngx_http_next_body_filter(r, in);",
            conditional_block(body_filter, "if (status == NGX_DECLINED)"),
        )

    def test_response_protocol_metadata_and_transaction_grammar_are_exact(self) -> None:
        content_length = function_definition(
            self.header, "ngx_http_modsecurity_resolv_header_content_length"
        )
        self.assertIn("if (r->headers_out.content_length_n >= 0)", content_length)

        connection = function_definition(
            self.header, "ngx_http_modsecurity_resolv_header_connection"
        )
        h2_guard = conditional_block(connection, "if (r->stream)")
        self.assertIn("return 1;", h2_guard)
        self.assertLess(
            connection.index("if (r->stream)"), connection.index('"Keep-Alive"')
        )
        h3_guard = conditional_block(
            connection, "if (r->http_version == NGX_HTTP_VERSION_30)"
        )
        self.assertIn("return 1;", h3_guard)
        self.assertLess(
            connection.index("if (r->http_version == NGX_HTTP_VERSION_30)"),
            connection.index('"Keep-Alive"'),
        )

        header_filter = function_definition(self.header, "ngx_http_modsecurity_header_filter")
        self.assertIn("NGX_HTTP_VERSION_30", header_filter)
        self.assertIn('http_response_ver = "HTTP 3.0";', header_filter)

        directive = self.module[
            self.module.index("ngx_string(MSCONNECTOR_DIRECTIVE_TRANSACTION_ID)") : self.module.index(
                "ngx_conf_set_transaction_id",
                self.module.index("ngx_string(MSCONNECTOR_DIRECTIVE_TRANSACTION_ID)"),
            )
        ]
        self.assertIn("NGX_CONF_TAKE1", directive)
        self.assertNotIn("NGX_CONF_1MORE", directive)

    def test_header_registration_warnings_are_static_and_value_free(self) -> None:
        warning_calls = []
        for source in (self.access, self.header):
            warning_calls.extend(
                match.group(0)
                for match in re.finditer(
                    r"ngx_log_error\(\s*NGX_LOG_WARN\b.*?\);", source, re.DOTALL
                )
                if "failed to add" in match.group(0)
            )

        self.assertGreaterEqual(len(warning_calls), 3)
        for warning in warning_calls:
            with self.subTest(warning=warning):
                self.assertRegex(
                    warning,
                    re.compile(
                        r'"ModSecurity: failed to add (?:request|synthetic response|response) '
                        r'header for inspection"\s*\);'
                    ),
                )

    def test_phase4_finalization_stops_inspection_but_keeps_forwarding(self) -> None:
        body_filter = function_definition(self.body, "ngx_http_modsecurity_body_filter")
        prepare = function_definition(
            self.body, "ngx_http_modsecurity_prepare_response_body_filter"
        )
        body_chain = function_definition(
            self.body, "ngx_http_modsecurity_process_response_body_chain"
        )
        terminal = function_definition(
            self.body, "ngx_http_modsecurity_finalize_terminal_response_body"
        )
        append = body_chain.index("ngx_http_modsecurity_append_response_chain_buffer")
        already_finalized = prepare.index(
            "if (ctx->intervention_triggered || ctx->phase4_processed)"
        )
        self.assertLess(already_finalized, prepare.index("*context = ctx;"))
        self.assertIn(
            "return ngx_http_next_body_filter(r, in);",
            conditional_block(body_filter, "if (status == NGX_DECLINED)"),
        )

        tail = body_chain[
            body_chain.index("ngx_http_modsecurity_finalize_terminal_response_body") :
        ]
        self.assertIn("break;", tail)
        self.assertIn("return ngx_http_next_body_filter(r, in);", tail)
        self.assertLess(tail.index("break;"), tail.rindex("return ngx_http_next_body_filter(r, in);"))
        self.assertLess(
            append,
            body_chain.index("ngx_http_modsecurity_finalize_terminal_response_body"),
        )
        self.assertIn("ngx_http_modsecurity_process_final_response_body", terminal)

    def test_terminal_chain_releases_progressive_prefix_before_eos_decision(self) -> None:
        body_chain = function_definition(
            self.body, "ngx_http_modsecurity_process_response_body_chain"
        )
        prefix = function_definition(
            self.body, "ngx_http_modsecurity_forward_response_body_prefix"
        )
        self.assertIn("ngx_chain_t *segment_start = in;", body_chain)
        self.assertIn("ngx_chain_t *segment_previous = NULL;", body_chain)
        self.assertIn("segment_previous->next = NULL;", prefix)
        self.assertIn("prefix_ret = ngx_http_next_body_filter(r, segment_start);", prefix)
        self.assertIn("segment_previous->next = chain;", prefix)
        self.assertLess(
            body_chain.index("ngx_http_modsecurity_forward_response_body_prefix"),
            body_chain.index("ngx_http_modsecurity_finalize_terminal_response_body"),
        )

    def test_phase4_counter_and_late_policy_preserve_exact_body_start_state(self) -> None:
        plan = function_definition(
            self.body, "ngx_http_modsecurity_account_response_body"
        )
        self.assertNotIn("msconnector_body_limit_plan_chunk", plan)
        self.assertNotIn("MSCONNECTOR_BODY_LIMIT_ACTION_REJECT", plan)
        self.assertNotIn("MSCONNECTOR_TRANSACTION_ERROR_BODY_LIMIT", plan)
        self.assertIn("SIZE_MAX - ctx->response_body_bytes_seen", plan)
        self.assertIn("ctx->response_body_bytes_seen += len;", plan)
        self.assertIn("MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR", plan)

        phase4 = function_definition(
            self.body, "ngx_http_modsecurity_phase4_handle_intervention"
        )
        resolver = phase4[phase4.index("msconnector_late_intervention_resolve"):]
        self.assertIn("ngx_http_modsecurity_phase4_response_started(r, ctx)", resolver)
        self.assertNotIn(
            "r->header_sent ? 1 : 0,\n        r->header_sent ? 1 : 0",
            resolver,
        )

    def test_phase4_mime_is_engine_owned_and_off_keeps_native_interventions(self) -> None:
        plan = function_definition(self.body, "ngx_http_modsecurity_account_response_body")
        append = function_definition(self.body, "ngx_http_modsecurity_append_response_body_chunk")
        append_chain = function_definition(self.body, "ngx_http_modsecurity_append_response_chain_buffer")
        self.assertNotIn("phase4_in_scope", self.body)
        self.assertNotIn("phase4_content_types", self.module + self.common)
        self.assertNotIn("content_type", append_chain)
        self.assertNotIn("msconnector_phase4_effective_body_limit(", plan)
        self.assertNotIn("common_config.phase4_body_limit", plan)
        self.assertNotIn("MSCONNECTOR_BODY_LIMIT_ACTION_REJECT", plan)
        self.assertIn("msc_append_response_body", append)
        self.assertIn("ngx_http_modsecurity_append_response_body_buffer", append_chain)

        final = function_definition(self.body, "ngx_http_modsecurity_process_final_response_body")
        native = final.index("ret = ngx_http_modsecurity_process_intervention")
        off = final.index("mcf->phase4_mode == MSCONNECTOR_PHASE4_MODE_OFF")
        policy = final.index("ngx_http_modsecurity_phase4_handle_intervention(r, mcf)")
        self.assertLess(final.index("msc_process_response_body"), native)
        self.assertLess(native, off)
        self.assertLess(off, policy)
        self.assertIn(
            "return ret;",
            conditional_block(final, "if (mcf != NULL && mcf->phase4_mode == MSCONNECTOR_PHASE4_MODE_OFF)"),
        )
        phase4 = function_definition(self.body, "ngx_http_modsecurity_phase4_handle_intervention")
        self.assertNotIn("content_type_not_in_scope", phase4)
        reason = self.capabilities["capabilities"]["content_type_scope"]["reason"]
        self.assertIn("SecResponseBodyMimeType", reason)
        self.assertIn("no connector-owned MIME allowlist", reason)

    def test_file_backed_phase4_buffers_are_boundedly_materialized(self) -> None:
        body_chain = function_definition(
            self.body, "ngx_http_modsecurity_process_response_body_chain"
        )
        append_chain = function_definition(
            self.body, "ngx_http_modsecurity_append_response_chain_buffer"
        )
        buffer_append = function_definition(
            self.body, "ngx_http_modsecurity_append_response_body_buffer"
        )
        file_append = function_definition(
            self.body, "ngx_http_modsecurity_append_file_response_body"
        )
        plan = function_definition(
            self.body, "ngx_http_modsecurity_account_response_body"
        )

        self.assertIn("ngx_http_modsecurity_append_response_body_buffer", append_chain)
        self.assertIn("if (ngx_buf_in_memory(buffer))", buffer_append)
        self.assertIn("if (buffer->in_file)", buffer_append)
        memory_append = conditional_block(
            buffer_append, "if (ngx_buf_in_memory(buffer))"
        )
        self.assertIn("u_char *data = buffer->pos;", memory_append)
        self.assertIn("buffer->last >= buffer->pos", memory_append)
        self.assertNotIn(
            "u_char *data = buffer->pos;",
            buffer_append[: buffer_append.index("if (ngx_buf_in_memory(buffer))")],
        )
        file_call = body_chain.index("ngx_http_modsecurity_append_response_chain_buffer(")
        self.assertLess(
            file_call,
            body_chain.index("is_request_processed =", file_call),
        )
        for required in (
            "buffer->file_pos < 0",
            "buffer->file_last < buffer->file_pos",
            "buffer->file == NULL",
            "ngx_read_file(buffer->file, ctx->scratch_buffers.phase4_file_scratch",
            "NGX_HTTP_MODSECURITY_PHASE4_FILE_READ_CHUNK",
            "ngx_http_modsecurity_append_response_body_chunk",
            "MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR",
        ):
            with self.subTest(required=required):
                self.assertIn(required, file_append)
        self.assertIn("read_count < 0 || (size_t)read_count != chunk", file_append)
        self.assertNotIn("buffer->file_pos =", file_append)
        self.assertNotIn("buffer->file_last =", file_append)
        self.assertNotIn("MSCONNECTOR_BODY_LIMIT_ACTION_REJECT", plan)
        self.assertIn("ctx->response_body_bytes_seen += len", plan)
        self.assertNotIn("ctx->response_body_truncated = 1", plan)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
