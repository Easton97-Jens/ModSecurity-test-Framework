#!/usr/bin/env python3
"""Focused source contracts for current Sonar reliability repairs."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from modsecurity_connector_tests.c_source_contract import function_definition


ROOT = connector_root()


class SonarReliabilityContractTests(unittest.TestCase):
    def test_traefik_result_payload_uses_fail_closed_bounded_copies(self) -> None:
        source = (
            source_path('connectors/traefik/src/traefik_engine_service.c', root=ROOT)
        ).read_text(encoding="utf-8")
        send_result = source[source.index("static int traefik_engine_send_result") :]

        helper_start = source.index("static int traefik_engine_copy_bounded_text")
        helper_end = source.index("\n}\n\nstatic uint16_t", helper_start)
        helper = source[helper_start:helper_end]

        self.assertNotIn("traefik_engine_empty_text", source)
        self.assertIn("if (size == 0U)", helper)
        self.assertIn("if (destination == NULL || source == NULL)", helper)
        self.assertIn("for (size_t offset = 0U; offset < size; ++offset)", helper)
        self.assertIn("destination[offset] = (unsigned char)source[offset];", helper)
        for field in ("transaction_id", "rule_id", "redirect"):
            self.assertIn(f"const char *{field} = NULL;", send_result)
            self.assertIn(f"{field}_size", send_result)

        self.assertEqual(send_result.count("traefik_engine_copy_bounded_text("), 3)
        self.assertNotIn("memcpy(payload + offset", send_result)

        self.assertIn("const char *const runtime_transaction_id", send_result)
        self.assertIn("const char *const decision_rule_id", send_result)
        self.assertIn("const char *const decision_redirect", send_result)

    def test_traefik_result_payload_wire_contract_for_optional_text(self) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("requires a C compiler")

        engine_source = (
            source_path('connectors/traefik/src/traefik_engine_service.c', root=ROOT)
        )
        harness_source = r'''
#define main traefik_engine_service_program_main
#include "__ENGINE_SOURCE__"
#undef main

#include <assert.h>

static const char *test_runtime_transaction_id = NULL;

const char *msconnector_runtime_transaction_id(
    const msconnector_runtime_transaction *transaction)
{
    (void)transaction;
    return test_runtime_transaction_id;
}

static void read_exact(int fd, unsigned char *out, size_t size)
{
    size_t offset = 0U;

    while (offset < size) {
        ssize_t received = recv(fd, out + offset, size - offset, 0);

        assert(received > 0);
        offset += (size_t)received;
    }
}

static void assert_result_frame(int fd, uint8_t command, uint8_t result_code,
    uint8_t action, uint8_t phase, uint16_t status, uint16_t flags,
    const char *transaction_id, const char *rule_id, const char *redirect)
{
    unsigned char header[TRAEFIK_ENGINE_PROTOCOL_HEADER_SIZE];
    unsigned char payload[4096U];
    size_t transaction_id_size = strlen(transaction_id);
    size_t rule_id_size = strlen(rule_id);
    size_t redirect_size = strlen(redirect);
    size_t expected_size = 14U + transaction_id_size + rule_id_size + redirect_size;
    size_t offset = 14U;

    assert(expected_size <= sizeof(payload));
    read_exact(fd, header, sizeof(header));
    assert(memcmp(header, "MSE1", 4U) == 0);
    assert(header[4] == TRAEFIK_ENGINE_PROTOCOL_VERSION);
    assert(header[5] == TRAEFIK_ENGINE_PROTOCOL_RESULT);
    assert(header[6] == 0U && header[7] == 0U);
    assert(traefik_engine_read_u32(header + 8U) == expected_size);
    read_exact(fd, payload, expected_size);
    assert(payload[0] == command);
    assert(payload[1] == result_code);
    assert(payload[2] == action);
    assert(payload[3] == phase);
    assert(traefik_engine_read_u16(payload + 4U) == status);
    assert(traefik_engine_read_u16(payload + 6U) == flags);
    assert(traefik_engine_read_u16(payload + 8U) == transaction_id_size);
    assert(traefik_engine_read_u16(payload + 10U) == rule_id_size);
    assert(traefik_engine_read_u16(payload + 12U) == redirect_size);
    assert(memcmp(payload + offset, transaction_id, transaction_id_size) == 0);
    offset += transaction_id_size;
    assert(memcmp(payload + offset, rule_id, rule_id_size) == 0);
    offset += rule_id_size;
    assert(memcmp(payload + offset, redirect, redirect_size) == 0);
}

int main(void)
{
    int sockets[2];
    traefik_engine_session session;
    msconnector_decision decision;
    unsigned char copy_probe[2U] = {0xa5U, 0x5aU};
    char maximum_transaction_id[TRAEFIK_ENGINE_PROTOCOL_MAX_TRANSACTION_ID + 1U];
    char maximum_rule_id[TRAEFIK_ENGINE_PROTOCOL_MAX_RULE_ID + 1U];
    char maximum_redirect[TRAEFIK_ENGINE_PROTOCOL_MAX_REDIRECT + 1U];

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(traefik_engine_copy_bounded_text(copy_probe, NULL, 0U) == 1);
    assert(traefik_engine_copy_bounded_text(copy_probe, NULL, 1U) == 0);
    assert(copy_probe[0] == 0xa5U && copy_probe[1] == 0x5aU);
    memset(&session, 0, sizeof(session));
    session.transaction = (msconnector_runtime_transaction *)(uintptr_t)1U;
    memset(&decision, 0, sizeof(decision));
    test_runtime_transaction_id = NULL;
    assert(traefik_engine_send_result(sockets[0],
        TRAEFIK_ENGINE_PROTOCOL_BEGIN, TRAEFIK_ENGINE_PROTOCOL_RESULT_OK,
        &session, &decision) == 1);
    assert_result_frame(sockets[1], TRAEFIK_ENGINE_PROTOCOL_BEGIN,
        TRAEFIK_ENGINE_PROTOCOL_RESULT_OK, MSCONNECTOR_DECISION_KIND_ALLOW,
        MSCONNECTOR_PHASE_CONNECTION, 0U, 0U, "", "", "");

    test_runtime_transaction_id = "transaction-7";
    memset(&decision, 0, sizeof(decision));
    decision.kind = MSCONNECTOR_DECISION_KIND_REDIRECT;
    decision.phase = MSCONNECTOR_PHASE_RESPONSE_HEADERS;
    decision.http_status = 307;
    decision.rule_id = "942100";
    decision.redirect_url = "https://example.test/blocked";
    decision.disruptive = 1;
    decision.late_intervention = 1;
    assert(traefik_engine_send_result(sockets[0],
        TRAEFIK_ENGINE_PROTOCOL_RESPONSE_HEADERS,
        TRAEFIK_ENGINE_PROTOCOL_RESULT_RUNTIME, &session, &decision) == 1);
    assert_result_frame(sockets[1], TRAEFIK_ENGINE_PROTOCOL_RESPONSE_HEADERS,
        TRAEFIK_ENGINE_PROTOCOL_RESULT_RUNTIME,
        MSCONNECTOR_DECISION_KIND_REDIRECT,
        MSCONNECTOR_PHASE_RESPONSE_HEADERS, 307U,
        TRAEFIK_ENGINE_PROTOCOL_RESULT_DISRUPTIVE |
            TRAEFIK_ENGINE_PROTOCOL_RESULT_LATE,
        "transaction-7", "942100", "https://example.test/blocked");

    memset(maximum_transaction_id, 't',
        TRAEFIK_ENGINE_PROTOCOL_MAX_TRANSACTION_ID);
    maximum_transaction_id[TRAEFIK_ENGINE_PROTOCOL_MAX_TRANSACTION_ID] = '\0';
    memset(maximum_rule_id, 'r', TRAEFIK_ENGINE_PROTOCOL_MAX_RULE_ID);
    maximum_rule_id[TRAEFIK_ENGINE_PROTOCOL_MAX_RULE_ID] = '\0';
    memset(maximum_redirect, 'u', TRAEFIK_ENGINE_PROTOCOL_MAX_REDIRECT);
    maximum_redirect[TRAEFIK_ENGINE_PROTOCOL_MAX_REDIRECT] = '\0';
    test_runtime_transaction_id = maximum_transaction_id;
    decision.rule_id = maximum_rule_id;
    decision.redirect_url = maximum_redirect;
    assert(traefik_engine_send_result(sockets[0],
        TRAEFIK_ENGINE_PROTOCOL_RESPONSE_HEADERS,
        TRAEFIK_ENGINE_PROTOCOL_RESULT_RUNTIME, &session, &decision) == 1);
    assert_result_frame(sockets[1], TRAEFIK_ENGINE_PROTOCOL_RESPONSE_HEADERS,
        TRAEFIK_ENGINE_PROTOCOL_RESULT_RUNTIME,
        MSCONNECTOR_DECISION_KIND_REDIRECT,
        MSCONNECTOR_PHASE_RESPONSE_HEADERS, 307U,
        TRAEFIK_ENGINE_PROTOCOL_RESULT_DISRUPTIVE |
            TRAEFIK_ENGINE_PROTOCOL_RESULT_LATE,
        maximum_transaction_id, maximum_rule_id, maximum_redirect);

    assert(close(sockets[0]) == 0);
    assert(close(sockets[1]) == 0);
    return 0;
}
'''.replace("__ENGINE_SOURCE__", engine_source.as_posix())
        temporary_parent = os.environ.get("TMPDIR")
        with tempfile.TemporaryDirectory(
            prefix="traefik-result-optional-text-", dir=temporary_parent
        ) as temporary_directory:
            temporary_root = Path(temporary_directory)
            harness = temporary_root / "traefik_result_optional_text.c"
            binary = temporary_root / "traefik_result_optional_text"
            harness.write_text(harness_source, encoding="utf-8")
            compile_result = subprocess.run(
                [
                    compiler,
                    "-std=c17",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-ffunction-sections",
                    "-fdata-sections",
                    "-I",
                    str(ROOT),
                    "-I",
                    str(source_path('common/include', root=ROOT)),
                    "-I",
                    str(source_path('common/runtime', root=ROOT)),
                    "-I",
                    str(source_path('connectors/traefik', root=ROOT)),
                    "-I",
                    str(source_path('connectors/traefik/src', root=ROOT)),
                    str(harness),
                    "-Wl,--gc-sections",
                    "-pthread",
                    "-o",
                    str(binary),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run(
                [str(binary)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(run_result.returncode, 0, run_result.stderr)

    def test_authorization_listener_initializes_peer_and_local_socket_state(self) -> None:
        source = (
            source_path('common/runtime/http_authorization_service.c', root=ROOT)
        ).read_text(encoding="utf-8")
        self.assertIn("struct sockaddr_in local = {0};", source)
        self.assertIn("struct sockaddr_in peer = {0};", source)

    def test_traefik_runtime_lock_pairs_keep_stable_service_references(self) -> None:
        source = (
            source_path('connectors/traefik/src/traefik_engine_service.c', root=ROOT)
        ).read_text(encoding="utf-8")
        destroy_start = source.index("static void traefik_engine_session_destroy")
        destroy_end = source.index(
            "\n}\n\nstatic int traefik_engine_handle_begin", destroy_start
        )
        destroy = source[destroy_start:destroy_end]
        begin_start = destroy_end
        begin_end = source.index(
            "\n}\n\nstatic int traefik_engine_handle_request_chunk", begin_start
        )
        begin = source[begin_start:begin_end]

        self.assertNotIn("traefik_engine_lock_runtime", source)
        self.assertNotIn("traefik_engine_unlock_runtime", source)
        self.assertIn("traefik_engine_service *service;", destroy)
        self.assertIn("service = session->service;", destroy)
        self.assertIn("pthread_mutex_lock(&service->runtime_lock)", destroy)
        self.assertIn("pthread_mutex_unlock(&service->runtime_lock)", destroy)
        self.assertNotIn("session->service->runtime_lock", destroy)
        self.assertEqual(destroy.count("session->service"), 1)
        self.assertIn("traefik_engine_service *service;", begin)
        self.assertIn("service = session->service;", begin)
        self.assertIn("pthread_mutex_lock(&service->runtime_lock)", begin)
        self.assertIn("pthread_mutex_unlock(&service->runtime_lock)", begin)
        self.assertIn(
            "msconnector_runtime_transaction_begin_request_stream(service->runtime,",
            begin,
        )
        self.assertLess(
            begin.index("pthread_mutex_lock(&service->runtime_lock)"),
            begin.index("msconnector_runtime_transaction_begin_request_stream("),
        )
        self.assertLess(
            begin.index("msconnector_runtime_transaction_begin_request_stream("),
            begin.index("pthread_mutex_unlock(&service->runtime_lock)"),
        )
        self.assertNotIn("session->service->runtime_lock", begin)
        self.assertEqual(begin.count("session->service"), 1)

    def test_traefik_unread_peer_send_path_has_a_monotonic_deadline(self) -> None:
        source = (
            source_path('connectors/traefik/src/traefik_engine_service.c', root=ROOT)
        ).read_text(encoding="utf-8")
        remaining_start = source.index(
            "static int traefik_engine_deadline_remaining_milliseconds"
        )
        remaining_end = source.index(
            "\n}\n\nstatic int traefik_engine_wait_for_socket_event",
            remaining_start,
        )
        remaining = source[remaining_start:remaining_end]
        wait_start = source.index(
            "static int traefik_engine_wait_for_socket_event", remaining_end
        )
        wait_end = source.index(
            "\n}\n\nstatic int traefik_engine_send_deadline", wait_start
        )
        wait = source[wait_start:wait_end]
        send_start = source.index(
            "static int traefik_engine_send_deadline", wait_end
        )
        send_end = source.index(
            "\n}\n\n/* Returns 1 for a complete read", send_start
        )
        send = source[send_start:send_end]
        frame_start = source.index("static int traefik_engine_send_frame")
        frame_end = source.index(
            "\n}\n\nstatic int traefik_engine_reader_u16", frame_start
        )
        frame = source[frame_start:frame_end]

        self.assertIn("#include <time.h>", source)
        self.assertIn("TRAEFIK_ENGINE_SOCKET_TIMEOUT_SECONDS", source)
        self.assertIn("clock_gettime(CLOCK_MONOTONIC, &now)", remaining)
        self.assertIn("milliseconds > INT_MAX", remaining)
        self.assertIn(
            "traefik_engine_deadline_remaining_milliseconds(deadline, &timeout)",
            wait,
        )
        self.assertIn("poll(&descriptor, 1U, timeout)", wait)
        self.assertIn("descriptor.events = events", wait)
        self.assertIn("clock_gettime(CLOCK_MONOTONIC, &deadline)", frame)
        self.assertIn(
            "deadline.tv_sec += TRAEFIK_ENGINE_SOCKET_TIMEOUT_SECONDS;", frame
        )
        self.assertIn("MSG_NOSIGNAL | MSG_DONTWAIT", send)
        self.assertIn(
            "traefik_engine_wait_for_socket_event(socket_fd, POLLOUT, deadline)",
            send,
        )
        self.assertIn(
            "if (written >= 0 || (errno != EINTR && errno != EAGAIN &&\n"
            "                errno != EWOULDBLOCK)) {",
            send,
        )
        self.assertIn(
            "traefik_engine_send_deadline(socket_fd, header, sizeof(header)",
            frame,
        )
        self.assertIn(
            "traefik_engine_send_deadline(socket_fd, payload, payload_size,",
            frame,
        )

    def test_oracle_handles_a_missing_optional_json_string_without_dereference(self) -> None:
        source = (source_path('ci/tools/native_modsecurity_oracle.c', root=ROOT)).read_text(
            encoding="utf-8"
        )
        self.assertIn("if (value == NULL)", source)
        self.assertIn('fputs("\\\"\\\"", out);', source)
        self.assertIn("cursor = (const unsigned char *)value;", source)
        self.assertIn("json_string(out, result->whoami);", source)
        self.assertNotIn('json_string(out, result->whoami ? result->whoami : "");', source)

    def test_oracle_result_context_keeps_phase_processing_out_of_main(self) -> None:
        source = (source_path('ci/tools/native_modsecurity_oracle.c', root=ROOT)).read_text(
            encoding="utf-8"
        )
        main = source[source.index("int main(int argc, char **argv)") :]

        self.assertIn("struct result_context {", source)
        self.assertIn("static void write_result(const struct result_context *result,", source)
        self.assertNotIn("static void write_result(const char *path", source)
        self.assertIn("static const char *process_request(Transaction *transaction,", source)
        self.assertIn("request_error = process_request(transaction, &request, &observed, &body);", main)
        self.assertNotIn("msc_process_connection(transaction", main)
        self.assertNotIn("msc_process_uri(transaction", main)
        self.assertNotIn("msc_process_request_headers(transaction", main)
        self.assertNotIn("msc_process_request_body(transaction", main)

    def test_haproxy_startup_diagnostics_guard_the_standard_error_stream(self) -> None:
        source = (
            source_path('connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c', root=ROOT)
        ).read_text(encoding="utf-8")
        self.assertGreaterEqual(source.count("if (stderr != NULL)"), 2)

    def test_haproxy_append_bytes_checks_the_source_extent_before_copying(self) -> None:
        source = (
            source_path('connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c', root=ROOT)
        ).read_text(encoding="utf-8")
        append_bytes = source[
            source.index("static int append_bytes")
            : source.index("static int append_uint32")
        ]
        self.assertIn(
            "const void *data, size_t data_len, size_t len",
            append_bytes,
        )
        self.assertIn("if (len > data_len ||", append_bytes)
        self.assertLess(append_bytes.index("len > data_len"), append_bytes.index("memcpy("))
        self.assertIn(
            "append_bytes(buf, &net, sizeof(net), sizeof(net))",
            source,
        )
        self.assertNotIn("append_bytes(buf, value, len, len)", source)
        self.assertIn(
            "append_bytes(frame, payload->data, sizeof(payload->data), payload->len)",
            source,
        )

    def test_common_error_descriptions_are_private_and_keyed(self) -> None:
        source = (source_path('common/src/error.c', root=ROOT)).read_text(encoding="utf-8")
        descriptions = source[
            source.index("const char *msconnector_error_code_name") : source.index(
                "enum msconnector_status msconnector_error_status"
            )
        ]

        self.assertIn("typedef struct msconnector_error_description", source)
        self.assertIn(
            "static const msconnector_error_description msconnector_error_descriptions[]",
            source,
        )
        self.assertIn(
            "msconnector_error_descriptions[index].code == code",
            source,
        )
        self.assertIn("return &msconnector_error_descriptions[index];", source)
        self.assertNotIn("msconnector_error_descriptions[code]", source)
        self.assertNotIn("switch (code)", descriptions)
        self.assertIn("msconnector_error_description_for_code(code)", descriptions)
        self.assertIn("return description->name;", descriptions)
        self.assertIn("return description->default_message;", descriptions)
        self.assertIn('return "internal";', descriptions)
        self.assertIn('return "Internal connector error";', descriptions)

    def test_haproxy_accept_loop_retries_only_interrupted_accepts(self) -> None:
        source = (
            source_path('connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c', root=ROOT)
        ).read_text(encoding="utf-8")
        accept_loop_start = source.index("static int accept_loop(")
        accept_loop_end = source.index(
            "\n}\n\nstatic int client_expect_frame", accept_loop_start
        )
        accept_loop = source[accept_loop_start:accept_loop_end]
        failed_accept_start = accept_loop.index("if (fd < 0) {")
        success_start = accept_loop.index(
            "spawn_spop_connection_worker(config, &gate", failed_accept_start
        )
        failed_accept = accept_loop[failed_accept_start:success_start]
        error_handler_start = source.index("static int handle_spop_accept_error(")
        error_handler_end = source.index(
            "\n}\n\nstatic spop_accept_iteration_result", error_handler_start
        )
        error_handler = source[error_handler_start:error_handler_end]

        self.assertNotIn("if (errno == EINTR)", failed_accept)
        self.assertIn("handle_spop_accept_error(state, log, &loop_rc)", failed_accept)
        self.assertIn("int loop_running = 1;", accept_loop)
        self.assertIn("while (loop_running && !stop_requested &&", accept_loop)
        self.assertIn("loop_running = 0;", failed_accept)
        self.assertNotIn("goto accept_loop_complete;", failed_accept)
        self.assertNotIn("accept_loop_complete:", accept_loop)
        self.assertIn("continue;", failed_accept)
        self.assertLess(
            failed_accept.index("loop_running = 0;"),
            failed_accept.index("continue;"),
        )
        self.assertIn(
            'log_line(log, "accept failed errno=%d", errno);', error_handler
        )
        self.assertIn("*loop_rc = 1;", error_handler)
        self.assertIn("if (errno != EINTR)", error_handler)
        self.assertIn("return stop_requested != 0;", error_handler)
        self.assertLess(
            error_handler.index('log_line(log, "accept failed errno=%d", errno);'),
            error_handler.index("*loop_rc = 1;"),
        )
        self.assertNotIn("handle_connection(", failed_accept)
        self.assertNotIn("close(fd);", failed_accept)
        self.assertNotIn("handled++;", failed_accept)

        worker_start = source.index("static int spawn_spop_connection_worker(")
        worker_end = source.index("\n}\n\nstatic int accept_loop", worker_start)
        worker_spawn = source[worker_start:worker_end]
        self.assertIn("if (gate->active >= gate->limit)", worker_spawn)
        self.assertIn(
            '"event=spop-peer-capacity-rejected action=close reason=worker-capacity"',
            worker_spawn,
        )
        self.assertIn("gate->active++", worker_spawn)
        self.assertIn("pthread_create(&thread", worker_spawn)
        self.assertIn("close(fd);", worker_spawn)
        self.assertIn("handled++;", accept_loop)
        result_handler_start = source.index(
            "static spop_accept_iteration_result process_spop_worker_result"
        )
        result_handler_end = source.index("\n}\n\nstatic int accept_loop", result_handler_start)
        result_handler = source[result_handler_start:result_handler_end]
        self.assertIn("SPOP_CONNECTION_WORKER_CAPACITY_REJECTED", result_handler)
        self.assertIn("SPOP_CONNECTION_WORKER_STOPPED", result_handler)
        self.assertIn("return SPOP_ACCEPT_ITERATION_CONTINUE;", result_handler)
        self.assertIn("return SPOP_ACCEPT_ITERATION_STOP;", result_handler)
        self.assertIn("iteration_result == SPOP_ACCEPT_ITERATION_CONTINUE", accept_loop)
        self.assertIn("iteration_result == SPOP_ACCEPT_ITERATION_STOP", accept_loop)
        iteration_stop = accept_loop.index(
            "iteration_result == SPOP_ACCEPT_ITERATION_STOP"
        )
        self.assertLess(
            iteration_stop,
            accept_loop.index("loop_running = 0;", iteration_stop),
        )
        self.assertLess(
            accept_loop.index("loop_running = 0;", iteration_stop),
            accept_loop.index("handled++;"),
        )

    def test_haproxy_legacy_spop_path_has_bounded_timeout(self) -> None:
        source = (
            source_path('connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c', root=ROOT)
        ).read_text(encoding="utf-8")
        self.assertIn("#define SPOP_LEGACY_TIMEOUT_MS 2000U", source)
        handle_start = source.index("static int handle_connection(")
        handle_end = source.index(
            "\n}\n\nstatic int bind_localhost", handle_start
        )
        handle = source[handle_start:handle_end]
        self.assertIn("unsigned int timeout_ms = peer_timeout_ms;", handle)
        self.assertIn("if (timeout_ms == 0U) {", handle)
        self.assertIn(
            "timeout_ms = state != 0 ? state->config.spoe_timeout_ms :\n            SPOP_LEGACY_TIMEOUT_MS;",
            handle,
        )
        self.assertIn("recv_frame(fd, &frame, timeout_ms)", handle)
        self.assertNotIn(
            "state != 0 ? state->config.spoe_timeout_ms : 0U", handle
        )
        self.assertIn(
            "config->spoe_timeout_ms = 2000U;", source
        )
        scalar_start = source.index("static int config_set_scalar_identity(")
        scalar_end = source.index("static int config_set_endpoint(", scalar_start)
        scalar = source[scalar_start:scalar_end]
        self.assertIn(
            "return parse_bounded_uint(value, 60000UL, &config->spoe_timeout_ms) == 0 ? 1 : -1;",
            scalar,
        )

    def test_haproxy_transaction_cache_config_is_bounded_before_calloc(self) -> None:
        source = (
            source_path('connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c', root=ROOT)
        ).read_text(encoding="utf-8")
        self.assertIn("#define SPOP_DEFAULT_MAX_TRANSACTIONS 4096U", source)
        self.assertIn("#define SPOP_MAX_TRANSACTIONS 4096U", source)
        self.assertIn("#define SPOP_MAX_TRANSACTION_SLOTS_TOTAL 65536U", source)

        config_start = source.index('if (strcmp(key, "max-transactions") == 0)')
        config_end = source.index(
            'if (strcmp(key, "debug") == 0)', config_start
        )
        config_branch = source[config_start:config_end]
        self.assertIn(
            "return parse_bounded_uint(value, SPOP_MAX_TRANSACTIONS,",
            config_branch,
        )
        self.assertNotIn("strtoul", config_branch)

        cache_start = source.index("static int transaction_cache_init")
        cache_end = source.index(
            "static transaction_slot *transaction_slot_find", cache_start
        )
        cache = source[cache_start:cache_end]
        self.assertIn(
            "if (state == 0 || !production_config_has_safe_peer_limits(&state->config))",
            cache,
        )
        self.assertIn("capacity > SIZE_MAX / sizeof(*state->transactions)", cache)
        self.assertLess(cache.index("capacity > SIZE_MAX"), cache.index("calloc("))
        self.assertIn("SPOP_DEFAULT_MAX_TRANSACTIONS", cache)

    def test_haproxy_append_string_preflights_payload_before_mutating_the_frame(self) -> None:
        source = (
            source_path('connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c', root=ROOT)
        ).read_text(encoding="utf-8")
        varint_encoded_length = source[
            source.index("static size_t varint_encoded_length")
            : source.index("static int append_varint")
        ]
        append_string = source[
            source.index("static int append_string")
            : source.index("static int append_typed_string")
        ]

        self.assertIn("if (value >= 240U)", varint_encoded_length)
        self.assertIn("value = (value - 240U) >> 4;", varint_encoded_length)
        self.assertIn("while (value >= 128U)", varint_encoded_length)
        self.assertIn("value = (value - 128U) >> 7;", varint_encoded_length)

        self.assertIn(
            "buf == 0 || bounded_cstring_length(value, SPOP_FRAME_MAX, &len) != 0",
            append_string,
        )
        self.assertIn("encoded_len = varint_encoded_length(len);", append_string)
        self.assertIn("remaining = sizeof(buf->data) - buf->len;", append_string)
        capacity_check = "if (encoded_len > remaining || len > remaining - encoded_len)"
        self.assertIn(capacity_check, append_string)
        self.assertLess(
            append_string.index(capacity_check),
            append_string.index("if (append_varint(buf, len) != 0)"),
        )
        self.assertIn("for (size_t index = 0; index < len; ++index)", append_string)
        self.assertIn(
            "append_byte(buf, (unsigned int)(unsigned char)value[index])",
            append_string,
        )
        self.assertNotIn("append_bytes(buf, value, len, len)", append_string)

    def test_haproxy_append_string_runtime_boundaries(self) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("requires a C compiler")

        runtime_source = (
            source_path('connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c', root=ROOT)
        )
        harness_source = r'''
#define main haproxy_spop_diagnostic_runtime_program_main
#include "__RUNTIME_SOURCE__"
#include "__TRANSACTION_STATE_SOURCE__"
#undef main

#include <assert.h>

static unsigned int cached_transaction_finish_calls;
static unsigned int transaction_begin_calls;
static int transaction_begin_result = 1;
static int transaction_begin_disruptive;
static int transport_stop_result = 1;
static int transport_stop_hangs;

int msconnector_response_companion_transport_stop(
        msconnector_response_companion_transport *transport,
        msconnector_error *error) {
    (void)transport;
    (void)error;
    while (transport_stop_hangs) {
        pause();
    }
    return transport_stop_result;
}

void haproxy_spop_response_companion_backend_expire(
        haproxy_spop_response_companion_backend *backend, uint64_t now_ms) {
    (void)backend;
    (void)now_ms;
}

int haproxy_spop_response_companion_backend_destroy(
        haproxy_spop_response_companion_backend *backend,
        msconnector_error *error) {
    (void)backend;
    (void)error;
    return 1;
}

void haproxy_modsecurity_engine_destroy(haproxy_modsecurity_engine *engine) {
    (void)engine;
}

int haproxy_modsecurity_transaction_finish(
        haproxy_modsecurity_transaction *transaction) {
    (void)transaction;
    cached_transaction_finish_calls++;
    return 0;
}

void haproxy_modsecurity_transaction_abort(
        haproxy_modsecurity_transaction *transaction) {
    (void)transaction;
}

int haproxy_modsecurity_transaction_finish_with_decision(
        haproxy_modsecurity_transaction *transaction,
        haproxy_modsecurity_decision *decision) {
    (void)decision;
    return haproxy_modsecurity_transaction_finish(transaction);
}

void haproxy_modsecurity_transaction_abort_with_error(
        haproxy_modsecurity_transaction *transaction,
        msconnector_transaction_error_class error) {
    (void)error;
    haproxy_modsecurity_transaction_abort(transaction);
}

int haproxy_modsecurity_transaction_begin(
        haproxy_modsecurity_engine *engine,
        const haproxy_modsecurity_request *request,
        haproxy_modsecurity_decision *decision,
        haproxy_modsecurity_transaction **transaction) {
    transaction_begin_calls++;
    (void)engine;
    (void)request;
    if (transaction_begin_result == 0) {
        decision->disruptive = transaction_begin_disruptive;
        decision->status = transaction_begin_disruptive ? 403 : 200;
        copy_spop_string(decision->action, sizeof(decision->action),
            (const unsigned char *)(transaction_begin_disruptive ? "deny" : "pass"),
            transaction_begin_disruptive ? sizeof("deny") - 1U :
            sizeof("pass") - 1U);
        *transaction = (haproxy_modsecurity_transaction *)(uintptr_t)1U;
    }
    return transaction_begin_result;
}

int haproxy_modsecurity_transaction_begin_request_authorization(
        haproxy_modsecurity_engine *engine,
        const haproxy_modsecurity_request *request,
        haproxy_modsecurity_decision *decision,
        haproxy_modsecurity_transaction **transaction) {
    return haproxy_modsecurity_transaction_begin(
        engine, request, decision, transaction);
}

int haproxy_modsecurity_eval_request(
        const haproxy_modsecurity_request *request,
        haproxy_modsecurity_decision *decision) {
    (void)request;
    (void)decision;
    return -1;
}

int haproxy_modsecurity_phase1_header_eval(
        const char *method, const char *uri, const char *host,
        const char *test_header_value,
        haproxy_modsecurity_decision *decision) {
    (void)method;
    (void)uri;
    (void)host;
    (void)test_header_value;
    (void)decision;
    return -1;
}

int haproxy_modsecurity_crs_sqli_eval(
        const char *method, const char *uri, const char *host,
        const char *crs_preamble_file,
        haproxy_modsecurity_decision *decision) {
    (void)method;
    (void)uri;
    (void)host;
    (void)crs_preamble_file;
    (void)decision;
    return -1;
}

int haproxy_modsecurity_transaction_handoff_response_companion(
        haproxy_modsecurity_transaction *transaction) {
    (void)transaction;
    return -1;
}

int haproxy_modsecurity_transaction_process_response_headers(
        haproxy_modsecurity_transaction *transaction,
        const haproxy_modsecurity_response *response,
        haproxy_modsecurity_decision *decision) {
    (void)transaction;
    (void)response;
    (void)decision;
    return 1;
}

int haproxy_modsecurity_transaction_append_response_body_chunk(
        haproxy_modsecurity_transaction *transaction,
        const unsigned char *body,
        unsigned int body_len,
        haproxy_modsecurity_decision *decision) {
    (void)transaction;
    (void)body;
    (void)body_len;
    (void)decision;
    return 1;
}

int haproxy_spop_response_companion_handoff(
        haproxy_spop_response_companion_backend *backend,
        haproxy_modsecurity_transaction *transaction, uint64_t now_ms,
        char handle[HAPROXY_SPOP_RESPONSE_COMPANION_HANDLE_STORAGE],
        msconnector_error *error) {
    (void)backend;
    (void)transaction;
    (void)now_ms;
    (void)handle;
    (void)error;
    return 0;
}

int msconnector_response_companion_transport_ensure_running(
        msconnector_response_companion_transport *transport,
        msconnector_error *error) {
    (void)transport;
    (void)error;
    return 0;
}

void msconnector_late_intervention_policy_init(
        msconnector_late_intervention_policy *policy) {
    if (policy != 0) {
        policy->default_action = MSCONNECTOR_LATE_INTERVENTION_LOG_ONLY;
        policy->strict_action = MSCONNECTOR_LATE_INTERVENTION_LOG_ONLY;
    }
}

const char *msconnector_late_intervention_action_name(
        msconnector_late_intervention_action action) {
    (void)action;
    return "log-only";
}

msconnector_late_intervention_action msconnector_late_intervention_resolve(
        const msconnector_late_intervention_policy *policy,
        int response_headers_committed, int response_body_started,
        int strict_mode) {
    (void)policy;
    (void)response_headers_committed;
    (void)response_body_started;
    (void)strict_mode;
    return MSCONNECTOR_LATE_INTERVENTION_LOG_ONLY;
}

void msconnector_event_init(msconnector_event *event) {
    if (event != 0) {
        memset(event, 0, sizeof(*event));
    }
}

const char *msconnector_event_default_level(const char *message_id) {
    (void)message_id;
    return "error";
}

const char *msconnector_event_default_message(const char *message_id) {
    (void)message_id;
    return "test event";
}

int msconnector_event_write_jsonl_line(const msconnector_event *event,
        char *dst, size_t dst_size, int *truncated) {
    (void)event;
    if (dst == 0 || dst_size < 4U) {
        return 0;
    }
    memcpy(dst, "{}\n", 4U);
    if (truncated != 0) {
        *truncated = 0;
    }
    return 1;
}

static void fill_string(char *value, size_t len, char byte) {
    memset(value, byte, len);
    value[len] = '\0';
}

static void test_varint_length_contract(void) {
    spop_buffer buffer;

    for (uint64_t value = 0; value <= SPOP_FRAME_MAX; ++value) {
        buffer.len = 0U;
        assert(append_varint(&buffer, value) == 0);
        assert(buffer.len == varint_encoded_length(value));
    }
}

static void test_varint_boundaries(void) {
    char value_239[240];
    char value_240[241];
    spop_buffer buffer;
    size_t pos;
    uint64_t decoded;
    const uint64_t values[] = {240U, 2288U, UINT64_MAX};

    fill_string(value_239, 239U, 'a');
    fill_string(value_240, 240U, 'b');
    memset(&buffer, 0, sizeof(buffer));

    assert(append_string(&buffer, value_239) == 0);
    assert(buffer.len == 240U);
    assert(buffer.data[0] == 239U);
    assert(memcmp(buffer.data + 1U, value_239, 239U) == 0);

    memset(&buffer, 0, sizeof(buffer));
    assert(append_string(&buffer, value_240) == 0);
    assert(buffer.len == 242U);
    assert(buffer.data[0] == 240U);
    assert(buffer.data[1] == 0U);
    assert(memcmp(buffer.data + 2U, value_240, 240U) == 0);

    for (size_t index = 0U; index < sizeof(values) / sizeof(values[0]); ++index) {
        memset(&buffer, 0, sizeof(buffer));
        assert(append_varint(&buffer, values[index]) == 0);
        pos = 0U;
        decoded = 0U;
        assert(read_varint(buffer.data, buffer.len, &pos, &decoded) == 0);
        assert(pos == buffer.len);
        assert(decoded == values[index]);
    }
}

static void test_exact_fit_and_overflow_are_atomic(void) {
    char value[240];
    spop_buffer buffer;
    spop_buffer before;
    const size_t exact_offset = SPOP_FRAME_MAX - 240U;

    fill_string(value, 239U, 'c');
    memset(&buffer, 0x5a, sizeof(buffer));
    buffer.len = exact_offset;
    assert(append_string(&buffer, value) == 0);
    assert(buffer.len == SPOP_FRAME_MAX);
    assert(buffer.data[exact_offset] == 239U);
    assert(memcmp(buffer.data + exact_offset + 1U, value, 239U) == 0);

    memset(&buffer, 0x7b, sizeof(buffer));
    buffer.len = SPOP_FRAME_MAX - 239U;
    before = buffer;
    assert(append_string(&buffer, value) == -1);
    assert(memcmp(&buffer, &before, sizeof(buffer)) == 0);
}

static void test_unterminated_input_does_not_mutate(void) {
    char unterminated[SPOP_FRAME_MAX];
    spop_buffer buffer;
    spop_buffer before;

    memset(unterminated, 'u', sizeof(unterminated));
    memset(&buffer, 0x3d, sizeof(buffer));
    buffer.len = 17U;
    before = buffer;
    assert(append_string(&buffer, unterminated) == -1);
    assert(memcmp(&buffer, &before, sizeof(buffer)) == 0);
    assert(append_string(0, "valid") == -1);
}

static void test_spop_duplicate_request_id_preserves_active_transaction(void) {
    agent_state state;
    transaction_slot *slot;
    haproxy_modsecurity_transaction *original =
        (haproxy_modsecurity_transaction *)(uintptr_t)1U;
    haproxy_modsecurity_transaction *duplicate =
        (haproxy_modsecurity_transaction *)(uintptr_t)2U;

    memset(&state, 0, sizeof(state));
    transaction_begin_calls = 0U;
    state.transaction_capacity = 2U;
    state.transactions = (transaction_slot *)calloc(state.transaction_capacity,
        sizeof(*state.transactions));
    assert(state.transactions != 0);

    assert(transaction_cache_store(&state, "request-1", original) == 0);
    slot = transaction_slot_find(&state, "request-1");
    assert(slot != 0 && slot->transaction == original);

    /* A duplicate incoming request must fail without touching the original. */
    assert(transaction_cache_store(&state, "request-1", duplicate) == -1);
    assert(cached_transaction_finish_calls == 0U);
    slot = transaction_slot_find(&state, "request-1");
    assert(slot != 0 && slot->transaction == original);

    /* The original can still be resumed by its response notification. */
    assert(transaction_cache_take(&state, "request-1") == original);
    assert(transaction_slot_find(&state, "request-1") == 0);

    /* A unique replacement after that legitimate continuation is accepted. */
    assert(transaction_cache_store(&state, "request-1", duplicate) == 0);
    assert(transaction_cache_take(&state, "request-1") == duplicate);
    free(state.transactions);
}

static void test_notify_header_argument(
        const char *argument_name,
        unsigned int type,
        const spop_buffer *headers,
        int expected_response,
        int expected_binary,
        int expected_text,
        unsigned int expected_header_count) {
    spop_buffer argument;
    notify_request request;
    size_t pos = 0U;

    memset(&argument, 0, sizeof(argument));
    memset(&request, 0, sizeof(request));
    assert(append_byte(&argument, type) == 0);
    assert(append_bytes(&argument, headers->data, sizeof(headers->data), headers->len) == 0);
    assert(parse_notify_header_argument(&request,
        (const unsigned char *)argument_name, strlen(argument_name),
        argument.data, argument.len, &pos) == 0);
    assert(pos == argument.len);
    assert(request.header_count == expected_header_count);
    assert(strcmp(request.headers[0].value, "one") == 0);
    if (expected_header_count > 1U) {
        assert(strcmp(request.headers[1].value, "two") == 0);
    }
    assert(request.http_metadata.is_response == expected_response);
    assert(request.has_headers_bin == expected_binary);
    assert(request.has_headers_text == expected_text);
    free_notify_request(&request);
}

static void test_notify_header_arguments_preserve_type_and_response_role(void) {
    spop_buffer header_pairs;
    spop_buffer binary_headers;
    spop_buffer text_headers;

    memset(&header_pairs, 0, sizeof(header_pairs));
    assert(append_string(&header_pairs, "X-One") == 0);
    assert(append_string(&header_pairs, "one") == 0);
    assert(append_string(&header_pairs, "X-Two") == 0);
    assert(append_string(&header_pairs, "two") == 0);
    assert(append_string(&header_pairs, "") == 0);
    assert(append_string(&header_pairs, "") == 0);
    memset(&binary_headers, 0, sizeof(binary_headers));
    assert(append_varint(&binary_headers, header_pairs.len) == 0);
    assert(append_bytes(
        &binary_headers, header_pairs.data, sizeof(header_pairs.data), header_pairs.len) == 0);

    memset(&text_headers, 0, sizeof(text_headers));
    assert(append_string(&text_headers, "X-One: one\r\nX-Two: two\r\n\r\n") == 0);

    test_notify_header_argument(
        "headers_bin", SPOP_DATA_BIN, &binary_headers, 0, 1, 0, 2U);
    test_notify_header_argument(
        "response_headers_bin", SPOP_DATA_BIN, &binary_headers, 1, 1, 0, 2U);
    test_notify_header_argument(
        "headers", SPOP_DATA_STR, &text_headers, 0, 0, 1, 2U);
    test_notify_header_argument(
        "response_headers", SPOP_DATA_STR, &text_headers, 1, 0, 1, 2U);
}

static void test_spop_binary_header_terminator_requires_full_consumption(void) {
    spop_buffer valid_headers;
    spop_buffer trailing_headers;
    notify_request request;

    memset(&valid_headers, 0, sizeof(valid_headers));
    assert(append_string(&valid_headers, "X-One") == 0);
    assert(append_string(&valid_headers, "one") == 0);
    assert(append_string(&valid_headers, "") == 0);
    assert(append_string(&valid_headers, "") == 0);
    memset(&request, 0, sizeof(request));
    assert(parse_headers_bin(&request,
        valid_headers.data, valid_headers.len) == 0);
    assert(request.has_headers_bin == 1);
    assert(request.header_count == 1U);
    assert(strcmp(request.headers[0].name, "X-One") == 0);
    assert(strcmp(request.headers[0].value, "one") == 0);
    free_notify_request(&request);

    trailing_headers = valid_headers;
    trailing_headers.data[trailing_headers.len++] = 0x01U;
    memset(&request, 0, sizeof(request));
    assert(parse_headers_bin(&request,
        trailing_headers.data, trailing_headers.len) == -1);
    assert(request.has_headers_bin == 0);
    free_notify_request(&request);
}

static void test_response_header_key_rejects_nonbytes(void) {
    spop_buffer argument;
    notify_request request;
    size_t pos = 0U;

    memset(&argument, 0, sizeof(argument));
    memset(&request, 0, sizeof(request));
    assert(append_typed_bool(&argument, 1) == 0);
    assert(parse_notify_header_argument(&request,
        (const unsigned char *)"response_headers", sizeof("response_headers") - 1U,
        argument.data, argument.len, &pos) == -1);
    assert(pos == argument.len);
    assert(request.header_count == 0U);
    assert(request.http_metadata.is_response == 0);
    free_notify_request(&request);
}

static void test_notify_body_key_argument(
        const char *argument_name,
        unsigned int type,
        int expected_body,
        int expected_response,
        int expected_response_body) {
    spop_buffer argument;
    notify_request request;
    size_t pos = 0U;

    memset(&argument, 0, sizeof(argument));
    memset(&request, 0, sizeof(request));
    if (type == SPOP_DATA_BIN) {
        assert(append_byte(&argument, SPOP_DATA_BIN) == 0);
        assert(append_varint(&argument, 4U) == 0);
        assert(append_bytes(&argument, "body", 4U, 4U) == 0);
    } else if (type == SPOP_DATA_STR) {
        assert(append_typed_string(&argument, "body") == 0);
    } else {
        assert(append_typed_bool(&argument, 1) == 0);
    }
    assert(parse_notify_body_key_argument(&request,
        (const unsigned char *)argument_name, strlen(argument_name),
        argument.data, argument.len, &pos) == (expected_body ? 0 : -1));
    assert(pos == argument.len);
    assert(request.has_body == expected_body);
    assert(request.http_metadata.is_response == expected_response);
    assert(request.http_metadata.is_response_body == expected_response_body);
    if (expected_body) {
        assert(request.body_len == 4U);
        assert(memcmp(request.body, "body", 4U) == 0);
    }
    free_notify_request(&request);
}

static void test_notify_body_arguments_preserve_type_and_response_role(void) {
    test_notify_body_key_argument("body", SPOP_DATA_STR, 1, 0, 0);
    test_notify_body_key_argument("body", SPOP_DATA_BIN, 1, 0, 0);
    test_notify_body_key_argument("response_body", SPOP_DATA_STR, 1, 1, 1);
    test_notify_body_key_argument("response_body", SPOP_DATA_BIN, 1, 1, 1);
    test_notify_body_key_argument("response_body", SPOP_DATA_BOOL, 0, 0, 0);
}

static void test_unknown_body_key_does_not_consume_or_mutate(void) {
    spop_buffer argument;
    notify_request request;
    size_t pos = 0U;

    memset(&argument, 0, sizeof(argument));
    memset(&request, 0, sizeof(request));
    assert(append_typed_string(&argument, "body") == 0);
    assert(parse_notify_body_key_argument(&request,
        (const unsigned char *)"unknown_body", sizeof("unknown_body") - 1U,
        argument.data, argument.len, &pos) == 1);
    assert(pos == 0U);
    assert(request.has_body == 0);
    assert(request.http_metadata.is_response == 0);
    assert(request.http_metadata.is_response_body == 0);
    free_notify_request(&request);
}

static void test_spop_rejects_overflow_and_truncated_protocol_values(void) {
    unsigned char overflow[] = {240U, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
        0xffU, 0xffU, 0xffU, 0xffU, 0x01U};
    unsigned char unterminated[] = {240U, 0x80U, 0x80U, 0x80U, 0x80U,
        0x80U, 0x80U, 0x80U, 0x80U, 0x80U};
    unsigned char too_wide[] = {240U, 0x80U, 0x80U, 0x80U, 0x80U,
        0x80U, 0x80U, 0x80U, 0x80U, 0x10U};
    static const unsigned char truncated_notify[] = {5U, 'c', 'h', 'e', 'c'};
    char boundary_uri[MSCONNECTOR_MAX_PATH_LENGTH + 1U];
    char oversized_uri[MSCONNECTOR_MAX_PATH_LENGTH + 2U];
    spop_buffer argument;
    spop_buffer notify;
    notify_request request;
    size_t pos;
    uint64_t decoded;

    pos = 0U;
    decoded = 0U;
    assert(read_varint(overflow, sizeof(overflow), &pos, &decoded) == -1);
    pos = 0U;
    assert(read_varint(unterminated, sizeof(unterminated), &pos, &decoded) == -1);
    pos = 0U;
    assert(read_varint(too_wide, sizeof(too_wide), &pos, &decoded) == -1);

    memset(&request, 0, sizeof(request));
    assert(parse_notify_payload(0, 0U, &request) == -1);
    assert(request.has_notify == 0);
    free_notify_request(&request);

    memset(&request, 0, sizeof(request));
    assert(parse_notify_payload(truncated_notify, sizeof(truncated_notify),
        &request) == -1);
    assert(request.has_notify == 0);
    free_notify_request(&request);

    /* A declared message-name length cannot consume the absent count byte. */
    /* A complete zero-argument control still parses through the same header. */
    memset(&notify, 0, sizeof(notify));
    assert(append_string(&notify, "check-request") == 0);
    memset(&request, 0, sizeof(request));
    assert(parse_notify_payload(notify.data, notify.len, &request) == -1);
    assert(request.has_notify == 0);
    free_notify_request(&request);
    assert(append_byte(&notify, 0U) == 0);
    memset(&request, 0, sizeof(request));
    assert(parse_notify_payload(notify.data, notify.len, &request) == 0);
    assert(request.has_notify == 1);
    assert(request.http_metadata.is_response == 0);
    assert(strcmp(request.message_name, "check-request") == 0);
    free_notify_request(&request);

    memset(&argument, 0, sizeof(argument));
    assert(append_byte(&argument, SPOP_DATA_UINT32) == 0);
    assert(append_varint(&argument, UINT32_MAX) == 0);
    memset(&request, 0, sizeof(request));
    pos = 0U;
    {
        unsigned int decoded_uint32 = 0U;
        int present = 0;
        assert(read_typed_uint32_value(argument.data, argument.len, &pos,
            &decoded_uint32, &present) == 0);
        assert(decoded_uint32 == UINT32_MAX);
        assert(present == 1);
    }
    memset(&argument, 0, sizeof(argument));
    assert(append_byte(&argument, SPOP_DATA_UINT32) == 0);
    assert(append_varint(&argument, (uint64_t)UINT32_MAX + 1U) == 0);
    pos = 0U;
    {
        unsigned int decoded_uint32 = 0U;
        int present = 0;
        assert(read_typed_uint32_value(argument.data, argument.len, &pos,
            &decoded_uint32, &present) == -1);
        assert(present == 0);
    }

    memset(boundary_uri, 'b', sizeof(boundary_uri) - 1U);
    boundary_uri[sizeof(boundary_uri) - 1U] = '\0';
    memset(&argument, 0, sizeof(argument));
    assert(append_typed_string(&argument, boundary_uri) == 0);
    memset(&request, 0, sizeof(request));
    pos = 0U;
    assert(parse_notify_string_argument(&request,
        (const unsigned char *)"uri", sizeof("uri") - 1U,
        argument.data, argument.len, &pos) == 0);
    assert(request.has_uri == 1);
    assert(strlen(request.uri) == MSCONNECTOR_MAX_PATH_LENGTH);
    assert(memcmp(request.uri, boundary_uri,
        MSCONNECTOR_MAX_PATH_LENGTH) == 0);
    free_notify_request(&request);

    memset(oversized_uri, 'u', sizeof(oversized_uri) - 1U);
    oversized_uri[sizeof(oversized_uri) - 1U] = '\0';
    memset(&argument, 0, sizeof(argument));
    assert(append_typed_string(&argument, oversized_uri) == 0);
    memset(&request, 0, sizeof(request));
    pos = 0U;
    assert(parse_notify_string_argument(&request,
        (const unsigned char *)"uri", sizeof("uri") - 1U,
        argument.data, argument.len, &pos) == -1);
    assert(request.has_uri == 0);
    free_notify_request(&request);
}

static void test_spop_read_byte_requires_a_remaining_byte(void) {
    static const unsigned char input[] = {0xa5U};
    unsigned char value = 0x5aU;
    size_t pos = 0U;

    assert(read_byte(input, sizeof(input), &pos, &value) == 0);
    assert(value == 0xa5U);
    assert(pos == sizeof(input));

    value = 0x5aU;
    assert(read_byte(input, sizeof(input), &pos, &value) == -1);
    assert(value == 0x5aU);
    assert(pos == sizeof(input));

    pos = sizeof(input) + 1U;
    assert(read_byte(input, sizeof(input), &pos, &value) == -1);
    assert(value == 0x5aU);
    assert(pos == sizeof(input) + 1U);

    pos = SIZE_MAX;
    assert(read_byte(input, sizeof(input), &pos, &value) == -1);
    assert(value == 0x5aU);
    assert(pos == SIZE_MAX);

    pos = 0U;
    assert(read_byte(input, 0U, &pos, &value) == -1);
    assert(value == 0x5aU);
    assert(pos == 0U);
    assert(read_byte(0, sizeof(input), &pos, &value) == -1);
    assert(value == 0x5aU);
    assert(pos == 0U);
    assert(read_byte(input, sizeof(input), 0, &value) == -1);
    assert(read_byte(input, sizeof(input), &pos, 0) == -1);
}

static void test_spop_typed_ip_arguments_are_canonical_and_bounded(void) {
    static const unsigned char ipv4[] = {192U, 0U, 2U, 10U};
    static const unsigned char ipv6[] = {0x20U, 0x01U, 0x0dU, 0xb8U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U};
    spop_buffer argument;
    notify_request request;
    size_t pos;

    memset(&argument, 0, sizeof(argument));
    assert(append_byte(&argument, SPOP_DATA_IPV4) == 0);
    assert(append_bytes(&argument, ipv4, sizeof(ipv4), sizeof(ipv4)) == 0);
    memset(&request, 0, sizeof(request));
    pos = 0U;
    assert(parse_notify_string_argument(&request,
        (const unsigned char *)"client_ip", sizeof("client_ip") - 1U,
        argument.data, argument.len, &pos) == 0);
    assert(request.has_client_ip == 1);
    assert(strcmp(request.client_ip, "192.0.2.10") == 0);
    free_notify_request(&request);

    memset(&argument, 0, sizeof(argument));
    assert(append_byte(&argument, SPOP_DATA_IPV6) == 0);
    assert(append_bytes(&argument, ipv6, sizeof(ipv6), sizeof(ipv6)) == 0);
    memset(&request, 0, sizeof(request));
    pos = 0U;
    assert(parse_notify_string_argument(&request,
        (const unsigned char *)"server_ip", sizeof("server_ip") - 1U,
        argument.data, argument.len, &pos) == 0);
    assert(request.has_server_ip == 1);
    assert(strcmp(request.server_ip, "2001:db8::1") == 0);
    free_notify_request(&request);

    memset(&argument, 0, sizeof(argument));
    assert(append_byte(&argument, SPOP_DATA_IPV4) == 0);
    assert(append_bytes(&argument, ipv4, sizeof(ipv4), sizeof(ipv4) - 1U) == 0);
    memset(&request, 0, sizeof(request));
    pos = 0U;
    assert(parse_notify_string_argument(&request,
        (const unsigned char *)"client_ip", sizeof("client_ip") - 1U,
        argument.data, argument.len, &pos) == -1);
    assert(request.has_client_ip == 0);
    free_notify_request(&request);

    memset(&argument, 0, sizeof(argument));
    assert(append_typed_string(&argument, "192.0.2.10") == 0);
    memset(&request, 0, sizeof(request));
    pos = 0U;
    assert(parse_notify_string_argument(&request,
        (const unsigned char *)"client_ip", sizeof("client_ip") - 1U,
        argument.data, argument.len, &pos) == -1);
    assert(request.has_client_ip == 0);
    free_notify_request(&request);
}

static void test_spop_rejects_header_injection_and_invalid_names(void) {
    notify_request request;

    memset(&request, 0, sizeof(request));
    assert(add_request_header(&request,
        (const unsigned char *)"X-Good", 6U,
        (const unsigned char *)"ok", 2U) == 0);
    assert(add_request_header(&request,
        (const unsigned char *)"X-Bad", 5U,
        (const unsigned char *)"ok\r\nInjected: yes", 16U) == -1);
    assert(add_request_header(&request,
        (const unsigned char *)"Bad Name", 8U,
        (const unsigned char *)"ok", 2U) == -1);
    assert(request.header_count == 1U);
    free_notify_request(&request);
}

static int append_notify_message_start(spop_buffer *payload,
        const char *message_name, unsigned int argument_count) {
    return append_string(payload, message_name) != 0 ||
        append_byte(payload, argument_count) != 0 ? -1 : 0;
}

static void test_spop_typed_ip_payload_requires_exact_frame_consumption(void) {
    static const unsigned char ipv4[] = {192U, 0U, 2U, 10U};
    spop_buffer payload;
    notify_request request;

    memset(&payload, 0, sizeof(payload));
    assert(append_notify_message_start(&payload, "check-request", 1U) == 0);
    assert(append_string(&payload, "client_ip") == 0);
    assert(append_byte(&payload, SPOP_DATA_IPV4) == 0);
    assert(append_bytes(&payload, ipv4, sizeof(ipv4), sizeof(ipv4)) == 0);
    memset(&request, 0, sizeof(request));
    assert(parse_notify_payload(payload.data, payload.len, &request) == 0);
    assert(request.has_client_ip == 1);
    assert(strcmp(request.client_ip, "192.0.2.10") == 0);
    free_notify_request(&request);

    assert(append_byte(&payload, 0U) == 0);
    memset(&request, 0, sizeof(request));
    assert(parse_notify_payload(payload.data, payload.len, &request) == -1);
    free_notify_request(&request);
}

static void test_spop_missing_endpoints_fail_closed_when_engine_is_open(void) {
    agent_state state;
    notify_request request;
    haproxy_modsecurity_decision decision;
    int modsec_processed = 0;
    spop_ack_decision_origin decision_origin = SPOP_ACK_FAILURE_DECISION;
    const char *decision_text = 0;
    char response_handle[HAPROXY_SPOP_RESPONSE_COMPANION_HANDLE_STORAGE];

    memset(&state, 0, sizeof(state));
    config_init(&state.config);
    copy_spop_string(state.config.fail_mode, sizeof(state.config.fail_mode),
        (const unsigned char *)"open", sizeof("open") - 1U);
    memset(&request, 0, sizeof(request));
    request.has_method = 1;
    request.has_path = 1;
    request.has_uri = 1;
    request.has_host = 1;
    copy_spop_string(request.method, sizeof(request.method),
        (const unsigned char *)"GET", sizeof("GET") - 1U);
    copy_spop_string(request.path, sizeof(request.path),
        (const unsigned char *)"/", sizeof("/") - 1U);
    copy_spop_string(request.uri, sizeof(request.uri),
        (const unsigned char *)"/", sizeof("/") - 1U);
    copy_spop_string(request.host, sizeof(request.host),
        (const unsigned char *)"example.test", sizeof("example.test") - 1U);
    memset(&decision, 0, sizeof(decision));
    memset(response_handle, 0, sizeof(response_handle));

    process_production_request_notify(&state, &request, &decision,
        &modsec_processed, &decision_origin, &decision_text, response_handle);

    assert(modsec_processed == 0);
    assert(transaction_begin_calls == 0U);
    assert(decision.disruptive == 1);
    assert(decision.status == 503);
    assert(strcmp(decision.action, "deny") == 0);
    assert(strcmp(decision_text, "admission-failure") == 0);
    assert(decision_origin == SPOP_ACK_FAILURE_DECISION);
    free_notify_request(&request);
}

static void test_spop_missing_endpoints_bypass_queue_and_ack_deny(void) {
    static const char *const fail_modes[] = {"open", "closed"};
    static const char *const modes[] = {"block", "detect-only"};

    for (size_t index = 0U;
            index < sizeof(fail_modes) / sizeof(fail_modes[0]); ++index) {
        for (size_t mode_index = 0U;
                mode_index < sizeof(modes) / sizeof(modes[0]); ++mode_index) {
        int sockets[2] = {-1, -1};
        agent_state state;
        notify_request request;
        spop_frame frame;
        spop_frame ack;
        spop_buffer ack_payload;

        memset(&state, 0, sizeof(state));
        config_init(&state.config);
        assert(pthread_mutex_init(&state.decision_log_lock, NULL) == 0);
        state.decision_log_lock_initialized = 1;
        copy_spop_string(state.config.fail_mode, sizeof(state.config.fail_mode),
            (const unsigned char *)fail_modes[index], strlen(fail_modes[index]));
        copy_spop_string(state.config.mode, sizeof(state.config.mode),
            (const unsigned char *)modes[mode_index], strlen(modes[mode_index]));
        assert(production_ack_enforces(&state.config,
            SPOP_ACK_FAILURE_DECISION));
        memset(&request, 0, sizeof(request));
        request.has_method = 1;
        request.has_path = 1;
        request.has_uri = 1;
        request.has_host = 1;
        copy_spop_string(request.method, sizeof(request.method),
            (const unsigned char *)"GET", sizeof("GET") - 1U);
        copy_spop_string(request.path, sizeof(request.path),
            (const unsigned char *)"/", sizeof("/") - 1U);
        copy_spop_string(request.uri, sizeof(request.uri),
            (const unsigned char *)"/", sizeof("/") - 1U);
        copy_spop_string(request.host, sizeof(request.host),
            (const unsigned char *)"example.test", sizeof("example.test") - 1U);
        memset(&frame, 0, sizeof(frame));
        frame.type = SPOP_FRM_NOTIFY;
        frame.stream_id = 7U;
        frame.frame_id = 11U;
        transaction_begin_calls = 0U;
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
        assert(process_production_notify(sockets[0], &frame, &state, 0,
            &request) == 0);
        assert(recv_frame(sockets[1], &ack, SPOP_LEGACY_TIMEOUT_MS) == 0);
        assert(ack.type == SPOP_FRM_ACK);
        assert(ack.stream_id == frame.stream_id);
        assert(ack.frame_id == frame.frame_id);
        memset(&ack_payload, 0, sizeof(ack_payload));
        ack_payload.len = ack.payload_len;
        memcpy(ack_payload.data, ack.payload, ack.payload_len);
        assert(payload_has_set_var_blocked_true(&ack_payload));
        assert(transaction_begin_calls == 0U);
        assert(close(sockets[0]) == 0);
        assert(close(sockets[1]) == 0);
        assert(pthread_mutex_destroy(&state.decision_log_lock) == 0);
        free_notify_request(&request);
        }
    }
}

static void test_spop_valid_engine_decision_stays_detect_only(void) {
    int sockets[2] = {-1, -1};
    agent_state state;
    notify_request request;
    spop_frame frame;
    spop_frame ack;
    spop_buffer ack_payload;

    memset(&state, 0, sizeof(state));
    config_init(&state.config);
    assert(pthread_mutex_init(&state.decision_log_lock, NULL) == 0);
    state.decision_log_lock_initialized = 1;
    copy_spop_string(state.config.mode, sizeof(state.config.mode),
        (const unsigned char *)"detect-only", sizeof("detect-only") - 1U);
    state.engine = (haproxy_modsecurity_engine *)(uintptr_t)1U;
    assert(!production_ack_enforces(&state.config,
        SPOP_ACK_ENGINE_DECISION));
    assert(spop_owner_queue_init(&state) == 0);
    memset(&request, 0, sizeof(request));
    request.has_headers_bin = 1;
    request.has_body = request.has_body_len_arg = 1;
    request.http_metadata.has_http_version = 1;
    strcpy(request.http_metadata.http_version, "1.1");
    request.has_method = 1;
    request.has_path = 1;
    request.has_uri = 1;
    request.has_host = 1;
    request.has_client_ip = 1;
    request.has_server_ip = 1;
    copy_spop_string(request.method, sizeof(request.method),
        (const unsigned char *)"GET", sizeof("GET") - 1U);
    copy_spop_string(request.path, sizeof(request.path),
        (const unsigned char *)"/", sizeof("/") - 1U);
    copy_spop_string(request.uri, sizeof(request.uri),
        (const unsigned char *)"/", sizeof("/") - 1U);
    copy_spop_string(request.host, sizeof(request.host),
        (const unsigned char *)"example.test", sizeof("example.test") - 1U);
    copy_spop_string(request.client_ip, sizeof(request.client_ip),
        (const unsigned char *)"192.0.2.10", sizeof("192.0.2.10") - 1U);
    copy_spop_string(request.server_ip, sizeof(request.server_ip),
        (const unsigned char *)"198.51.100.10", sizeof("198.51.100.10") - 1U);
    memset(&frame, 0, sizeof(frame));
    frame.type = SPOP_FRM_NOTIFY;
    frame.stream_id = 15U;
    frame.frame_id = 17U;
    transaction_begin_calls = 0U;
    transaction_begin_result = 0;
    transaction_begin_disruptive = 1;
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(process_production_notify(sockets[0], &frame, &state, 0,
        &request) == 0);
    assert(recv_frame(sockets[1], &ack, SPOP_LEGACY_TIMEOUT_MS) == 0);
    memset(&ack_payload, 0, sizeof(ack_payload));
    ack_payload.len = ack.payload_len;
    memcpy(ack_payload.data, ack.payload, ack.payload_len);
    assert(!payload_has_set_var_blocked_true(&ack_payload));
    assert(transaction_begin_calls == 1U);
    assert(close(sockets[0]) == 0);
    assert(close(sockets[1]) == 0);
    spop_owner_queue_destroy(&state);
    assert(pthread_mutex_destroy(&state.decision_log_lock) == 0);
    transaction_begin_result = 1;
    transaction_begin_disruptive = 0;
}

static void test_spop_valid_engine_block_is_enforced_after_owner_queue(void) {
    int sockets[2] = {-1, -1};
    agent_state state;
    notify_request request;
    spop_frame frame;
    spop_frame ack;
    spop_buffer ack_payload;

    memset(&state, 0, sizeof(state));
    config_init(&state.config);
    assert(pthread_mutex_init(&state.decision_log_lock, NULL) == 0);
    state.decision_log_lock_initialized = 1;
    /* The explicit availability override must not bypass a successful
     * blocking engine decision. */
    copy_spop_string(state.config.fail_mode, sizeof(state.config.fail_mode),
        (const unsigned char *)"open", sizeof("open") - 1U);
    state.engine = (haproxy_modsecurity_engine *)(uintptr_t)1U;
    assert(production_ack_enforces(&state.config, SPOP_ACK_ENGINE_DECISION));
    assert(spop_owner_queue_init(&state) == 0);
    memset(&request, 0, sizeof(request));
    request.has_headers_bin = 1;
    request.has_body = request.has_body_len_arg = 1;
    request.http_metadata.has_http_version = 1;
    strcpy(request.http_metadata.http_version, "1.1");
    request.has_method = 1;
    request.has_path = 1;
    request.has_uri = 1;
    request.has_host = 1;
    request.has_client_ip = 1;
    request.has_server_ip = 1;
    copy_spop_string(request.method, sizeof(request.method),
        (const unsigned char *)"GET", sizeof("GET") - 1U);
    copy_spop_string(request.path, sizeof(request.path),
        (const unsigned char *)"/", sizeof("/") - 1U);
    copy_spop_string(request.uri, sizeof(request.uri),
        (const unsigned char *)"/", sizeof("/") - 1U);
    copy_spop_string(request.host, sizeof(request.host),
        (const unsigned char *)"example.test", sizeof("example.test") - 1U);
    copy_spop_string(request.client_ip, sizeof(request.client_ip),
        (const unsigned char *)"192.0.2.10", sizeof("192.0.2.10") - 1U);
    copy_spop_string(request.server_ip, sizeof(request.server_ip),
        (const unsigned char *)"198.51.100.10", sizeof("198.51.100.10") - 1U);
    memset(&frame, 0, sizeof(frame));
    frame.type = SPOP_FRM_NOTIFY;
    frame.stream_id = 19U;
    frame.frame_id = 23U;
    transaction_begin_calls = 0U;
    transaction_begin_result = 0;
    transaction_begin_disruptive = 1;
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(process_production_notify(sockets[0], &frame, &state, 0,
        &request) == 0);
    assert(recv_frame(sockets[1], &ack, SPOP_LEGACY_TIMEOUT_MS) == 0);
    memset(&ack_payload, 0, sizeof(ack_payload));
    ack_payload.len = ack.payload_len;
    memcpy(ack_payload.data, ack.payload, ack.payload_len);
    assert(payload_has_set_var_blocked_true(&ack_payload));
    assert(transaction_begin_calls == 1U);
    assert(close(sockets[0]) == 0);
    assert(close(sockets[1]) == 0);
    spop_owner_queue_destroy(&state);
    assert(pthread_mutex_destroy(&state.decision_log_lock) == 0);
    transaction_begin_result = 1;
    transaction_begin_disruptive = 0;
}

static void test_spop_malformed_notify_ack_stays_blocking_in_detect_only(void) {
    int sockets[2] = {-1, -1};
    agent_state state;
    spop_buffer payload;
    spop_buffer ack_payload;
    spop_frame frame;
    spop_frame ack;

    memset(&state, 0, sizeof(state));
    config_init(&state.config);
    assert(pthread_mutex_init(&state.decision_log_lock, NULL) == 0);
    state.decision_log_lock_initialized = 1;
    copy_spop_string(state.config.mode, sizeof(state.config.mode),
        (const unsigned char *)"detect-only", sizeof("detect-only") - 1U);
    state.engine = (haproxy_modsecurity_engine *)(uintptr_t)1U;
    assert(mode_enforces(&state.config) == 0);

    memset(&payload, 0, sizeof(payload));
    assert(append_notify_message_start(&payload, "check-request", 1U) == 0);
    assert(append_string(&payload, "headers") == 0);
    assert(append_typed_string(&payload,
        "X-Good: yes\r\nInjected-Without-Value\r\n") == 0);
    memset(&frame, 0, sizeof(frame));
    frame.type = SPOP_FRM_NOTIFY;
    frame.stream_id = 9U;
    frame.frame_id = 13U;
    frame.payload_len = payload.len;
    memcpy(frame.payload, payload.data, payload.len);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(handle_notify_frame(sockets[0], &frame, &state, 0, 0, 0) == -1);
    assert(recv_frame(sockets[1], &ack, SPOP_LEGACY_TIMEOUT_MS) == 0);
    assert(ack.type == SPOP_FRM_ACK);
    assert(ack.stream_id == frame.stream_id);
    assert(ack.frame_id == frame.frame_id);
    memset(&ack_payload, 0, sizeof(ack_payload));
    ack_payload.len = ack.payload_len;
    memcpy(ack_payload.data, ack.payload, ack.payload_len);
    assert(payload_has_set_var_blocked_true(&ack_payload));
    assert(close(sockets[0]) == 0);
    assert(close(sockets[1]) == 0);
    assert(pthread_mutex_destroy(&state.decision_log_lock) == 0);
}

static void test_spop_notify_message_and_argument_contract(void) {
    spop_buffer payload;
    notify_request request;
    spop_buffer header_pairs;

    memset(&payload, 0, sizeof(payload));
    assert(append_notify_message_start(&payload, "check-request", 1U) == 0);
    assert(append_string(&payload, "host") == 0);
    assert(append_typed_string(&payload, "example.test") == 0);
    assert(parse_notify_payload(payload.data, payload.len, &request) == 0);
    assert(request.has_host == 1 && strcmp(request.host, "example.test") == 0);
    free_notify_request(&request);

    memset(&payload, 0, sizeof(payload));
    assert(append_notify_message_start(&payload, "unsupported", 0U) == 0);
    memset(&request, 0, sizeof(request));
    assert(parse_notify_payload(payload.data, payload.len, &request) == -1);
    free_notify_request(&request);

    memset(&payload, 0, sizeof(payload));
    assert(append_notify_message_start(&payload, "check-request", 0U) == 0);
    assert(append_notify_message_start(&payload, "check-response", 0U) == 0);
    memset(&request, 0, sizeof(request));
    assert(parse_notify_payload(payload.data, payload.len, &request) == -1);
    free_notify_request(&request);

    memset(&payload, 0, sizeof(payload));
    assert(append_notify_message_start(&payload, "check-request", 2U) == 0);
    assert(append_string(&payload, "host") == 0);
    assert(append_typed_string(&payload, "first.test") == 0);
    assert(append_string(&payload, "host") == 0);
    assert(append_typed_string(&payload, "second.test") == 0);
    memset(&request, 0, sizeof(request));
    assert(parse_notify_payload(payload.data, payload.len, &request) == -1);
    free_notify_request(&request);

    /* Neither representation may hide an incomplete header collection. */
    memset(&payload, 0, sizeof(payload));
    assert(append_notify_message_start(&payload, "check-request", 2U) == 0);
    assert(append_string(&payload, "headers_bin") == 0);
    assert(append_typed_empty_string(&payload) == 0);
    assert(append_string(&payload, "headers") == 0);
    assert(append_typed_string(&payload, "X-Fallback: yes\n") == 0);
    memset(&request, 0, sizeof(request));
    assert(parse_notify_payload(payload.data, payload.len, &request) == -1);
    free_notify_request(&request);

    /* Two complete representations must describe the same headers. */
    memset(&header_pairs, 0, sizeof(header_pairs));
    assert(append_string(&header_pairs, "X-Fallback") == 0);
    assert(append_string(&header_pairs, "yes") == 0);
    assert(append_string(&header_pairs, "") == 0);
    assert(append_string(&header_pairs, "") == 0);
    for (int mismatch = 0; mismatch <= 1; ++mismatch) {
        memset(&payload, 0, sizeof(payload));
        assert(append_notify_message_start(&payload, "check-request", 2U) == 0);
        assert(append_string(&payload, "headers_bin") == 0);
        assert(append_byte(&payload, SPOP_DATA_BIN) == 0);
        assert(append_varint(&payload, header_pairs.len) == 0);
        assert(append_bytes(&payload, header_pairs.data, sizeof(header_pairs.data),
            header_pairs.len) == 0);
        assert(append_string(&payload, "headers") == 0);
        assert(append_typed_string(&payload,
            mismatch ? "X-Fallback: no\n\n" : "X-Fallback: yes\n\n") == 0);
        memset(&request, 0, sizeof(request));
        assert(parse_notify_payload(payload.data, payload.len, &request) ==
            (mismatch ? -1 : 0));
        assert(request.header_count == (mismatch ? 0U : 1U));
        free_notify_request(&request);
    }
}

static void test_spop_rejects_response_arguments_on_request_messages(void) {
    spop_buffer payload;
    notify_request request;

    /* A response argument must not flip a request into a response after the
     * request-host gate; it is a phase mismatch and is rejected. */
    memset(&payload, 0, sizeof(payload));
    assert(append_notify_message_start(&payload, "check-request", 1U) == 0);
    assert(append_string(&payload, "response_headers") == 0);
    assert(append_typed_string(&payload, "X-Response: yes\r\n\r\n") == 0);
    memset(&request, 0, sizeof(request));
    assert(parse_notify_payload(payload.data, payload.len, &request) == -1);
    free_notify_request(&request);

    /* The same response wire is valid when the message itself is a response. */
    memset(&payload, 0, sizeof(payload));
    assert(append_notify_message_start(&payload, "check-response", 1U) == 0);
    assert(append_string(&payload, "response_headers") == 0);
    assert(append_typed_string(&payload, "X-Response: yes\r\n\r\n") == 0);
    memset(&request, 0, sizeof(request));
    assert(parse_notify_payload(payload.data, payload.len, &request) == 0);
    assert(request.http_metadata.is_response == 1);
    assert(request.header_count == 1U);
    free_notify_request(&request);
}

static void test_spop_rejects_malformed_text_headers_and_bounds_count(void) {
    spop_buffer argument;
    notify_request request;

    memset(&argument, 0, sizeof(argument));
    assert(append_typed_string(&argument, "Malformed-Header\n") == 0);
    memset(&request, 0, sizeof(request));
    {
        size_t pos = 0U;
        assert(parse_notify_header_argument(&request,
            (const unsigned char *)"headers", sizeof("headers") - 1U,
            argument.data, argument.len, &pos) == -1);
        assert(request.header_count == 0U);
    }
    free_notify_request(&request);

    memset(&argument, 0, sizeof(argument));
    assert(append_typed_string(&argument, "X-One: one\r\nX-Two: two\r\n\r\n") == 0);
    memset(&request, 0, sizeof(request));
    {
        size_t pos = 0U;
        assert(parse_notify_header_argument(&request,
            (const unsigned char *)"headers", sizeof("headers") - 1U,
            argument.data, argument.len, &pos) == 0);
        assert(request.header_count == 2U);
        assert(strcmp(request.headers[0].value, "one") == 0);
        assert(strcmp(request.headers[1].value, "two") == 0);
    }
    free_notify_request(&request);

    memset(&argument, 0, sizeof(argument));
    assert(append_typed_string(&argument, "X-One: one\r\n\r\ntrailing") == 0);
    memset(&request, 0, sizeof(request));
    {
        size_t pos = 0U;
        assert(parse_notify_header_argument(&request,
            (const unsigned char *)"headers", sizeof("headers") - 1U,
            argument.data, argument.len, &pos) == -1);
    }
    free_notify_request(&request);

    memset(&request, 0, sizeof(request));
    for (unsigned int index = 0U; index < MSCONNECTOR_MAX_HEADER_COUNT; ++index) {
        assert(add_request_header(&request,
            (const unsigned char *)"X-Count", sizeof("X-Count") - 1U,
            (const unsigned char *)"value", sizeof("value") - 1U) == 0);
    }
    assert(request.header_count == MSCONNECTOR_MAX_HEADER_COUNT);
    assert(add_request_header(&request,
        (const unsigned char *)"X-Overflow", sizeof("X-Overflow") - 1U,
        (const unsigned char *)"value", sizeof("value") - 1U) == -1);
    assert(request.header_count == MSCONNECTOR_MAX_HEADER_COUNT);
    free_notify_request(&request);
}

static void test_spop_frame_read_has_a_bounded_liveness_deadline(void) {
    int descriptors[2];
    unsigned char byte = 0U;
    uint64_t deadline;

    assert(pipe(descriptors) == 0);
    deadline = monotonic_milliseconds();
    assert(deadline > 0U);
    assert(read_full_until(descriptors[0], &byte, 1U, deadline + 20U) == -1);
    close(descriptors[0]);
    close(descriptors[1]);
}

static void test_spop_rejects_unenforced_timeout_and_worker_settings(void) {
    agent_config config;

    config_init(&config);
    assert(config_set(&config, "spoe-timeout", "25") == 0);
    assert(config.spoe_timeout_ms == 25U);
    assert(config_set(&config, "spoe-timeout", "0") == -1);
    assert(config_set(&config, "worker-count", "2") == 0);
    /* Parsing keeps the bounded value so native-htx can use it, but the
     * response-companion=none production profile rejects it before startup. */
    assert(config_set(&config, "response-body-timeout", "5") == 0);
    assert(config.response_body_timeout_ms == 5U);
    assert(validate_production_config(&config) != 0);
    assert(config_set(&config, "max-transactions", "4096") == 0);
    assert(config.max_transactions == SPOP_MAX_TRANSACTIONS);
    assert(config_set(&config, "max-transactions", "4097") == -1);
    assert(config_set(&config, "max-transactions", "0") == -1);
    assert(config_set(&config, "max-transactions", "999999999999999999999") == -1);
    assert(config_set(&config, "request-body-limit", "10485760") == -1);
    assert(config_set(&config, "request-body-limit", "10485761") == -1);
    assert(config_set(&config, "request-body-limit", "4294967296") == -1);
    assert(config_set(&config, "request-body-limit", "not-a-number") == -1);
    assert(config_set(&config, "response-body-limit", "0") == -1);
    assert(config_set(&config, "response-body-limit", "10485760") == -1);
    assert(config_set(&config, "response-body-limit", "10485761") == -1);
    assert(config_set(&config, "port", "65535") == 0);
    assert(config.port == 65535U);
    assert(config_set(&config, "port", "65536") == -1);
    assert(config_set(&config, "port", "0") == -1);
    assert(config_set(&config, "port", "4294967296") == -1);
}

static void test_spop_listener_enforces_loopback_at_every_boundary(void) {
    agent_config config;
    unsigned int bound_port = 0U;
    int fd;

    config_init(&config);
    assert(config_set(&config, "host", "0.0.0.0") == -1);
    assert(strcmp(config.host, "127.0.0.1") == 0);
    assert(config_set(&config, "host", "192.0.2.1") == -1);
    assert(config_set(&config, "host", "127.0.0.1") == 0);
    assert(parse_listen(&config, "0.0.0.0:12345") == -1);
    assert(strcmp(config.host, "127.0.0.1") == 0);
    assert(parse_listen(&config, "192.0.2.1:12345") == -1);
    assert(parse_listen(&config, "127.0.0.1:12345") == 0);
    assert(config.port == 12345U);
    assert(validate_production_config(&config) == 0);
    copy_spop_string(config.host, sizeof(config.host),
        (const unsigned char *)"0.0.0.0", sizeof("0.0.0.0") - 1U);
    assert(validate_production_config(&config) == -1);
    assert(bind_localhost("0.0.0.0", 0U, &bound_port) == -1);
    fd = bind_localhost("127.0.0.1", 0U, &bound_port);
    assert(fd >= 0);
    assert(bound_port != 0U);
    close(fd);
}

static void test_spop_unquiesced_owner_uses_direct_restart_exit(void) {
    pid_t child = fork();
    int status = 0;

    assert(child >= 0);
    if (child == 0) {
        agent_state state;
        spop_owner_queue_gate_context gate;
        spop_owner_queue_submit_thread submitter;
        pthread_t submitter_thread;
        FILE *log = 0;
        FILE *decision_log = 0;

        memset(&state, 0, sizeof(state));
        memset(&gate, 0, sizeof(gate));
        if (spop_owner_queue_init(&state) != 0 ||
                pthread_mutex_init(&gate.lock, 0) != 0 ||
                pthread_cond_init(&gate.changed, 0) != 0) {
            _Exit(90);
        }
        submitter.state = &state;
        submitter.context = &gate;
        submitter.rc = 0;
        submitter.timeout_ms = 25U;
        if (pthread_create(&submitter_thread, 0,
                spop_owner_queue_submit_gate_thread, &submitter) != 0) {
            _Exit(91);
        }
        pthread_mutex_lock(&gate.lock);
        while (!gate.started) {
            pthread_cond_wait(&gate.changed, &gate.lock);
        }
        pthread_mutex_unlock(&gate.lock);
        if (pthread_join(submitter_thread, 0) != 0 || submitter.rc == 0 ||
                !spop_owner_queue_requires_restart(&state)) {
            _Exit(92);
        }
        destroy_agent_runtime(&state, -1, &log, 0, &decision_log, 0);
        _Exit(93);
    }
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == SPOP_OWNER_RESTART_EXIT_CODE);
}

static void test_spop_pre_queue_cleanup_does_not_read_uninitialized_atomic(void) {
    agent_state state;
    FILE *log = 0;
    FILE *decision_log = 0;

    memset(&state, 0, sizeof(state));
    assert(!spop_owner_queue_requires_restart(&state));
    assert(destroy_agent_runtime(
        &state, -1, &log, 0, &decision_log, 0) == 0);
}

static void test_spop_transport_stop_failure_uses_direct_restart_exit(void) {
    pid_t child = fork();
    int status = 0;

    assert(child >= 0);
    if (child == 0) {
        agent_state state;
        FILE *log = 0;
        FILE *decision_log = 0;

        alarm(3U);
        memset(&state, 0, sizeof(state));
        state.response_transport_started = 1;
        transport_stop_result = 0;
        destroy_agent_runtime(&state, -1, &log, 0, &decision_log, 0);
        _Exit(94);
    }
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == SPOP_OWNER_RESTART_EXIT_CODE);
}

static void test_spop_hanging_transport_stop_is_outer_bounded(void) {
    pid_t child = fork();
    int status = 0;

    assert(child >= 0);
    if (child == 0) {
        agent_state state;
        FILE *log = 0;
        FILE *decision_log = 0;

        alarm(3U);
        memset(&state, 0, sizeof(state));
        state.response_transport_started = 1;
        transport_stop_hangs = 1;
        destroy_agent_runtime(&state, -1, &log, 0, &decision_log, 0);
        _Exit(95);
    }
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == SPOP_OWNER_RESTART_EXIT_CODE);
}

int main(void) {
    test_varint_length_contract();
    test_varint_boundaries();
    test_exact_fit_and_overflow_are_atomic();
    test_unterminated_input_does_not_mutate();
    test_spop_duplicate_request_id_preserves_active_transaction();
    test_notify_header_arguments_preserve_type_and_response_role();
    test_spop_binary_header_terminator_requires_full_consumption();
    test_response_header_key_rejects_nonbytes();
    test_notify_body_arguments_preserve_type_and_response_role();
    test_unknown_body_key_does_not_consume_or_mutate();
    test_spop_rejects_overflow_and_truncated_protocol_values();
    test_spop_read_byte_requires_a_remaining_byte();
    test_spop_typed_ip_arguments_are_canonical_and_bounded();
    test_spop_typed_ip_payload_requires_exact_frame_consumption();
    test_spop_missing_endpoints_fail_closed_when_engine_is_open();
    test_spop_missing_endpoints_bypass_queue_and_ack_deny();
    test_spop_valid_engine_decision_stays_detect_only();
    test_spop_valid_engine_block_is_enforced_after_owner_queue();
    test_spop_malformed_notify_ack_stays_blocking_in_detect_only();
    test_spop_rejects_header_injection_and_invalid_names();
    test_spop_notify_message_and_argument_contract();
    test_spop_rejects_response_arguments_on_request_messages();
    test_spop_rejects_malformed_text_headers_and_bounds_count();
    test_spop_frame_read_has_a_bounded_liveness_deadline();
    test_spop_rejects_unenforced_timeout_and_worker_settings();
    test_spop_listener_enforces_loopback_at_every_boundary();
    test_spop_pre_queue_cleanup_does_not_read_uninitialized_atomic();
    assert(run_spop_owner_queue_self_test() == 0);
    test_spop_unquiesced_owner_uses_direct_restart_exit();
    test_spop_transport_stop_failure_uses_direct_restart_exit();
    test_spop_hanging_transport_stop_is_outer_bounded();
    return 0;
}
'''.replace("__RUNTIME_SOURCE__", runtime_source.as_posix()).replace(
            "__TRANSACTION_STATE_SOURCE__",
            (source_path('common/src/transaction_state.c', root=ROOT)).as_posix(),
        )
        binding_source = (
            source_path('connectors/haproxy/src/haproxy_modsecurity_binding.c', root=ROOT)
        ).read_text(encoding="utf-8")
        harness_source += "\n" + "\n".join(
            function_definition(binding_source, name)
            for name in (
                "contract_phase_from_decision",
                "haproxy_modsecurity_error_event_write_checked",
            )
        )
        event_source = (source_path('common/src/event_jsonl.c', root=ROOT)).read_text(
            encoding="utf-8"
        )
        harness_source += "\n" + "\n".join(
            function_definition(event_source, name)
            for name in (
                "event_stream_error",
                "msconnector_event_file_write",
                "msconnector_event_file_close",
            )
        )
        temporary_parent = os.environ.get("TMPDIR")
        with tempfile.TemporaryDirectory(
            prefix="haproxy-append-string-boundary-", dir=temporary_parent
        ) as temporary_directory:
            temporary_root = Path(temporary_directory)
            harness = temporary_root / "haproxy_append_string_boundaries.c"
            binary = temporary_root / "haproxy_append_string_boundaries"
            harness.write_text(harness_source, encoding="utf-8")
            compile_result = subprocess.run(
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
                    "-I",
                    str(source_path('common/include', root=ROOT)),
                    "-I",
                    str(source_path('connectors/haproxy/src', root=ROOT)),
                    str(harness),
                    str(source_path('common/src/error.c', root=ROOT)),
                    "-Wl,--gc-sections",
                    "-o",
                    str(binary),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run(
                [str(binary)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(run_result.returncode, 0, run_result.stderr)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
