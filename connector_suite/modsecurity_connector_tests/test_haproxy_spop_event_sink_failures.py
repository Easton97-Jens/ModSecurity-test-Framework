"""Compile real SPOP event writer/decision/ACK paths with real stdio faults.

Common serialization is linked unchanged. Native processing and network send are
controlled collaborators; this is compiled ownership/error evidence, not a live
HAProxy host claim. The sink lives in a private 0700 temporary directory.
"""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

from modsecurity_connector_tests.c_source_contract import function_definition

ROOT = connector_root()
SOURCE = source_path('connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c', root=ROOT)
FUNCTIONS = (
    "bounded_cstring_length", "close_owned_stream", "open_private_file", "open_private_event_stream", "mkdir_p",
    "dirname_to_buffer", "open_append_file_or_standard", "log_streams_share_inode",
    "open_agent_logs", "close_agent_owned_streams", "json_write_string",
    "safe_decision_name", "phase4_requested_action", "phase4_common_event_write",
    "safe_decision_reason_code", "decision_log_render_metadata", "decision_log_finish_staging",
    "decision_log_stage_error_event", "decision_log_write", "decision_log_failed",
    "copy_spop_string", "copy_cstring", "runtime_init_decision", "set_response_phase_disabled_failure",
    "set_admission_failure", "ensure_notify_request_id", "notify_request_has_required_endpoints",
    "protocol_failure_requires_enforcement", "mode_enforces", "production_ack_enforces",
    "process_production_notify", "finish_production_response_transaction", "process_production_response_notify",
    "set_processing_failure", "set_response_correlation_failure",
    "build_response_from_notify",
    "parse_sample_content_length", "notify_request_has_complete_body_sample", "process_production_request_notify", "build_modsecurity_request_from_notify",
    "notify_request_method", "notify_request_uri", "finish_or_store_request_transaction",
)
STUBS = r'''
static int ack_calls, abort_calls, finish_calls, store_calls, handoff_calls;
static int fail_staging, fail_finish, finish_fault;
static FILE *finish_sink;
static ssize_t staging_allocation_failure(void *cookie, const char *data, size_t size) {
    (void)cookie; (void)data; (void)size;
    errno = ENOMEM;
    return -1;
}
/* The production caller still uses a real stdio stream. This collaborator
 * models the memory stream's allocation failure without exhausting the host. */
static FILE *fixture_open_memstream(char **buffer, size_t *size) {
    cookie_io_functions_t functions = { .write = staging_allocation_failure };
    FILE *file;
    if (!fail_staging) {
        return open_memstream(buffer, size);
    }
    *buffer = NULL;
    *size = 0U;
    file = fopencookie(NULL, "w", functions);
    if (file != NULL && setvbuf(file, NULL, _IONBF, 0U) != 0) {
        fclose(file);
        return NULL;
    }
    return file;
}
#define open_memstream fixture_open_memstream
int haproxy_modsecurity_transaction_begin(haproxy_modsecurity_engine *engine,
        const haproxy_modsecurity_request *request, haproxy_modsecurity_decision *decision,
        haproxy_modsecurity_transaction **out) {
    (void)engine; (void)request;
    *out = (haproxy_modsecurity_transaction *)decision;
    runtime_init_decision(decision, 2, "pass", 200, "original engine failure");
    return 0;
}
int haproxy_modsecurity_transaction_begin_request_authorization(
        haproxy_modsecurity_engine *engine, const haproxy_modsecurity_request *request,
        haproxy_modsecurity_decision *decision, haproxy_modsecurity_transaction **out) {
    return haproxy_modsecurity_transaction_begin(engine, request, decision, out);
}
int haproxy_modsecurity_transaction_handoff_response_companion(
        haproxy_modsecurity_transaction *transaction) {
    (void)transaction; ++handoff_calls; return 0;
}
int msconnector_response_companion_transport_ensure_running(
        msconnector_response_companion_transport *transport, msconnector_error *error) {
    (void)transport; (void)error; return 1;
}
int haproxy_spop_response_companion_handoff(haproxy_spop_response_companion_backend *backend,
        haproxy_modsecurity_transaction *transaction, uint64_t now,
        char handle[HAPROXY_SPOP_RESPONSE_COMPANION_HANDLE_STORAGE], msconnector_error *error) {
    (void)backend; (void)transaction; (void)now; (void)handle; (void)error;
    ++handoff_calls; return 1;
}
static haproxy_modsecurity_transaction *transaction_cache_take(agent_state *state,
        const char *request_id) {
    (void)request_id;
    return (haproxy_modsecurity_transaction *)state;
}
static int transaction_cache_store(agent_state *state, const char *request_id,
        haproxy_modsecurity_transaction *transaction) {
    (void)state; (void)request_id; (void)transaction;
    ++store_calls;
    return 0;
}
void haproxy_modsecurity_transaction_abort(haproxy_modsecurity_transaction *transaction) {
    (void)transaction; ++abort_calls;
}
void haproxy_modsecurity_transaction_abort_with_error(haproxy_modsecurity_transaction *transaction, msconnector_transaction_error_class error) {
    (void)error; haproxy_modsecurity_transaction_abort(transaction);
}
int haproxy_modsecurity_transaction_finish_with_decision(haproxy_modsecurity_transaction *transaction, haproxy_modsecurity_decision *decision) {
    (void)transaction; ++finish_calls;
    if (fail_finish) {
        decision->error_class = MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE;
        decision->phase = 5;
        if (finish_fault && close(fileno(finish_sink)) != 0) { abort(); }
        return 1;
    }
    return 0;
}
int haproxy_modsecurity_transaction_finish(haproxy_modsecurity_transaction *transaction) {
    (void)transaction; ++finish_calls; return 0;
}
int haproxy_modsecurity_transaction_append_response_body_chunk(
        haproxy_modsecurity_transaction *transaction, const unsigned char *body,
        unsigned int size, haproxy_modsecurity_decision *decision) {
    (void)transaction; (void)body; (void)size;
    runtime_init_decision(decision, 4, "deny", 403, "original engine failure");
    decision->disruptive = 1;
    return 0;
}
int haproxy_modsecurity_transaction_process_response_headers(
        haproxy_modsecurity_transaction *transaction,
        const haproxy_modsecurity_response *response, haproxy_modsecurity_decision *decision) {
    (void)response;
    return haproxy_modsecurity_transaction_append_response_body_chunk(transaction,
        NULL, 0U, decision);
}
#define log_line(log, ...) do { if ((log) != NULL) { fprintf((log), __VA_ARGS__); } } while (0)
static void submit_production_notify_task(agent_state *state, notify_request *request,
        int phase, spop_production_result *result) {
    runtime_init_decision(result->decision, phase, "deny", 502, "original engine failure");
    result->decision->disruptive = 1;
    *result->decision_text = "fail-closed";
    (void)decision_log_write(state, request, result->decision, 0, *result->decision_text);
}
static int build_decision_ack_payload(spop_buffer *payload,
        const haproxy_modsecurity_decision *decision, const char *reason,
        int enforce, const char *handle) {
    (void)payload; (void)decision; (void)reason; (void)enforce; (void)handle;
    ++ack_calls;
    return 0;
}
static int send_frame_timeout(int fd, unsigned int type, uint64_t stream,
        uint64_t frame, const spop_buffer *payload, unsigned int timeout) {
    (void)fd; (void)type; (void)stream; (void)frame; (void)payload; (void)timeout;
    return 0;
}
'''
MAIN = r'''
int main(int argc, char **argv) {
    agent_state state = {0};
    notify_request request = {0};
    haproxy_modsecurity_decision decision = {0};
    msconnector_error error;
    spop_frame frame = {0};
    FILE *file;
    int first, again, code, caller = 0, cleanup, log_owned = 0, decision_owned = 0;
    int failure_enforced = -1;
    FILE *log = NULL;
    long size = 0;
    if (argc != 3) { return 2; }
    if (pthread_mutex_init(&state.decision_log_lock, NULL) != 0) { return 3; }
    state.decision_log_lock_initialized = 1;
    strcpy(state.config.mode, "detect-only");
    strcpy(state.config.fail_mode, "open");
    strcpy(state.config.decision_log, "configured");
    strcpy(request.request_id, "private-fixture");
    request.has_request_id = 1;
    request.http_metadata.is_response = 1;
    request.http_metadata.is_response_body = 1;
    request.response_status = 200;
    request.http_metadata.has_response_status = 1;
    runtime_init_decision(&decision, 4, "deny", 403, "original engine failure");
    decision.disruptive = 1;
    if (strncmp(argv[1], "technical-", 10U) == 0) {
        decision.error_class = MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE;
        argv[1] += 10;
    }
    msconnector_error_init(&error);
    fail_staging = strcmp(argv[1], "stage-allocation") == 0;
    if (strncmp(argv[1], "open-", 5U) == 0) {
        strcpy(state.config.log_file, "-");
        snprintf(state.config.decision_log, sizeof(state.config.decision_log), "%s", argv[2]);
        first = open_agent_logs(&state.config, &log, &log_owned,
            &state.decision_log, &decision_owned);
        again = decision_log_write(&state, &request, &decision, 1, "deny");
        code = state.decision_log_error.code;
        cleanup = close_agent_owned_streams(&log, log_owned,
            &state.decision_log, decision_owned);
    } else {
        file = fopen(argv[2], "w+");
        if (file == NULL) { return 4; }
        state.decision_log = file;
        if (strncmp(argv[1], "finish-", 7U) == 0) {
            fail_finish = 1;finish_sink = file;
            finish_fault = strcmp(argv[1], "finish-success") != 0;
            if (setvbuf(file,NULL,strcmp(argv[1], "finish-write")==0 ? _IONBF : _IOFBF,8192U)!=0) { return 5; }
        }
        if (strcmp(argv[1], "close") == 0) {
            if (close(fileno(file)) != 0) { return 5; }
        } else if (strcmp(argv[1], "write") == 0 || strcmp(argv[1], "ownership") == 0 || strcmp(argv[1], "request-ownership") == 0 || strcmp(argv[1], "direct-write") == 0) {
            if (setvbuf(file, NULL, _IONBF, 0U) != 0 || close(fileno(file)) != 0) { return 5; }
        } else if (strcmp(argv[1], "flush") == 0 || strcmp(argv[1], "direct-flush") == 0) {
            if (setvbuf(file, NULL, _IOFBF, 8192U) != 0 || close(fileno(file)) != 0) { return 6; }
        }
        if (strcmp(argv[1], "close") == 0) {
            first = again = 0;
            code = 0;
        } else if (strcmp(argv[1], "direct-write") == 0 || strcmp(argv[1], "direct-flush") == 0) {
            first = phase4_common_event_write(file, &request, &decision,
                "deny", "", "fixture", &error);
            code = error.code;
            again = first;
        } else if (strcmp(argv[1], "serialize") == 0) {
            char reason[8192];
            memset(reason, 'r', sizeof(reason) - 1U);
            reason[sizeof(reason) - 1U] = '\0';
            first = phase4_common_event_write(file, &request, &decision,
                "deny", "", reason, &error);
            code = error.code;
            again = first;
            size = ftell(file);
        } else if (strcmp(argv[1], "invalid") == 0) {
            first = phase4_common_event_write(file, NULL, &decision,
                "deny", "", "fixture", &error);
            code = error.code;
            again = first;
            size = ftell(file);
        } else {
            if (strcmp(argv[1], "request-ownership") == 0 || fail_finish) {
                int processed = 0;
                spop_ack_decision_origin origin = SPOP_ACK_FAILURE_DECISION;
                const char *text = "pass";
                char handle[HAPROXY_SPOP_RESPONSE_COMPANION_HANDLE_STORAGE] = {0};
                state.config.response_phases_enabled = 1;
                if (fail_finish) { state.config.response_phases_enabled=0; }
                else { strcpy(state.config.response_companion, "native-htx"); }
                request.http_metadata.is_response = request.http_metadata.is_response_body = 0;
                /* Complete HTTP/1.1 bodyless request with an explicitly
                 * observed empty sample and complete empty header block. */
                request.has_headers_bin = 1;
                request.has_body = request.has_body_len_arg = 1;
                request.body_len = request.http_metadata.advertised_body_len = 0U;
                request.http_metadata.has_http_version = 1;
                strcpy(request.http_metadata.http_version, "1.1");
                request.has_client_ip = request.has_server_ip = 1;
                strcpy(request.client_ip, "127.0.0.1");
                strcpy(request.server_ip, "127.0.0.1");
                process_production_request_notify(&state, &request, &decision,
                    &processed, &origin, &text, handle);
                failure_enforced = production_ack_enforces(&state.config, origin);
                first = !decision_log_failed(&state);
            } else if (strcmp(argv[1], "ownership") == 0) {
                int processed = 0;
                spop_ack_decision_origin origin = SPOP_ACK_FAILURE_DECISION;
                const char *text = "pass";
                state.config.response_phases_enabled = 1;
                process_production_response_notify(&state, &request, &decision,
                    &processed, &origin, &text);
                first = !decision_log_failed(&state);
            } else {
                first = decision_log_write(&state, &request, &decision, 1, "deny");
            }
            code = state.decision_log_error.code;
            /* Repair the physical descriptor. A sticky failure must still not
             * retry, nor consume a later record or return a successful ACK. */
            if (code != MSCONNECTOR_ERROR_NONE) {
                int fd = open(argv[2], O_WRONLY | O_APPEND);
                if (fd < 0) { return 7; }
                if (fd != fileno(file)) {
                    if (dup2(fd, fileno(file)) < 0) { return 8; }
                    close(fd);
                }
                clearerr(file);
            }
            if (fail_finish && code == MSCONNECTOR_ERROR_NONE) {
                again = first;
            } else {
                again = decision_log_write(&state, &request, &decision, 1, "deny");
                caller = process_production_notify(-1, &frame, &state, NULL, &request);
            }
            size = ftell(file);
        }
        cleanup = close_agent_owned_streams(&log, 0, &state.decision_log, 1);
    }
    printf("{\"status\":%d,\"disruptive\":%d,\"failure_enforced\":%d,\"first\":%d,\"again\":%d,\"code\":%d,\"io\":%d,"
        "\"too_large\":%d,\"internal\":%d,\"caller\":%d,\"ack_calls\":%d,"
        "\"invalid_native\":%d,\"native_class\":%d,\"native_phase\":%d,\"size\":%ld,\"cleanup\":%d,\"abort\":%d,\"finish\":%d,\"store\":%d,\"handoff\":%d,\"retained_code\":%d,\"original\":%d}\n",
        decision.status, decision.disruptive, failure_enforced, first, again, code, MSCONNECTOR_ERROR_IO, MSCONNECTOR_ERROR_EVENT_TOO_LARGE,
        MSCONNECTOR_ERROR_INTERNAL, caller, ack_calls, MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE, decision.error_class, decision.phase, size, cleanup,
        abort_calls, finish_calls, store_calls, handoff_calls, state.decision_log_error.code,
        strcmp(decision.log_message, "original engine failure") == 0);
    pthread_mutex_destroy(&state.decision_log_lock);
    return 0;
}
'''


class HaproxySpopEventSinkFailureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("a C compiler is required for SPOP sink tests")
        parent = Path(os.environ.get("RUNNER_TEMP") or os.environ.get("TMPDIR") or "/var/tmp/codex/ModSecurity-conector/tmp")
        parent.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix="haproxy-spop-sink-", dir=parent)
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        os.chmod(cls.directory, 0o700)
        source = SOURCE.read_text(encoding="utf-8")
        preamble = "#define _GNU_SOURCE\n" + source[:source.index("static volatile sig_atomic_t stop_requested")]
        types = source[source.index("typedef enum spop_ack_decision_origin"):source.index("static void run_spop_production_task(void *opaque);")]
        # production_ack_enforces is provided through the real extracted definition.
        definition = function_definition(types, "production_ack_enforces")
        types = types.replace(definition, "")
        definitions = [function_definition(source, name) for name in FUNCTIONS]
        declarations = "\n".join(value[:value.index("{")] + ";" for value in definitions)
        binding = (source_path('connectors/haproxy/src/haproxy_modsecurity_binding.c', root=ROOT)).read_text()
        serializers = "\n".join(function_definition(binding, name) for name in
            ("contract_phase_from_decision", "haproxy_modsecurity_error_event_write_checked"))
        text = preamble + types + declarations + serializers + STUBS + "\n".join(definitions) + MAIN
        cls.binaries = {}
        cls.compile_fixture(compiler, text, "current")
        anchor = """    if (error.code == MSCONNECTOR_ERROR_NONE &&
            !msconnector_event_file_write(state->decision_log, serialized, &error)) {
        msconnector_error_set(&error, MSCONNECTOR_ERROR_IO,
            "SPOP decision sink write or flush failed", "haproxy-spoe-spop");
    }"""
        if text.count(anchor) != 1:
            raise AssertionError("unchecked-write negative-control anchor drifted")
        old = text.replace(anchor, """    if (error.code == MSCONNECTOR_ERROR_NONE) {
        (void)fputs(serialized, state->decision_log);
        (void)fflush(state->decision_log);
    }""", 1)
        cls.compile_fixture(compiler, old, "unchecked")
        staging_anchor = """    if (!event_serialized && error->code == MSCONNECTOR_ERROR_IO) {
        msconnector_error_set(error, MSCONNECTOR_ERROR_INTERNAL,
            "SPOP event staging failed", "haproxy-spoe-spop");
    }"""
        if text.count(staging_anchor) != 1:
            raise AssertionError("staging-classification negative-control anchor drifted")
        cls.compile_fixture(compiler, text.replace(staging_anchor, "", 1), "old-staging-class")

    @classmethod
    def compile_fixture(cls, compiler: list[str], text: str, variant: str) -> None:
        fixture = cls.directory / (variant + ".c")
        fixture.write_text(text, encoding="utf-8")
        binary = cls.directory / variant
        command = compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread",
                              "-I", str(source_path('common/include', root=ROOT)), "-I", str(source_path('connectors/haproxy/src', root=ROOT)),
                              str(fixture)]
        command += [str(source_path('common/src', root=ROOT) / name) for name in
                    ("error.c", "status.c", "event.c", "event_jsonl.c", "json_escape.c", "http_status.c", "transaction_state.c")]
        command += ["-o", str(binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)
        if result.returncode:
            raise AssertionError("SPOP sink fixture compilation failed:\n" + result.stderr[-6000:])
        cls.binaries[variant] = binary

    def case(self, scenario: str, path: Path | None = None, variant: str = "current") -> tuple[dict, Path]:
        target = path or self.directory / (scenario + ".jsonl")
        result = subprocess.run([str(self.binaries[variant]), scenario, str(target)],
                                capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        return json.loads(result.stdout), target

    def test_successful_event_and_ack_control(self) -> None:
        result, path = self.case("success")
        self.assertEqual(result["first"], 1)
        self.assertEqual(result["again"], 1)
        self.assertEqual(result["code"], 0)
        self.assertEqual(result["caller"], 0)
        self.assertEqual(result["ack_calls"], 1)
        records = [json.loads(line) for line in path.read_text().splitlines()]
        self.assertGreaterEqual(len(records), 3)
        event = next(record for record in records if record.get("event") == "engine_decision")
        self.assertEqual(event["requested_action"], "deny")
        self.assertEqual(event["actual_action"], "")
        self.assertEqual(event["original_http_status"], records[0]["original_http_status"])
        self.assertEqual(event["visible_http_status"], records[0]["visible_http_status"])
        self.assertEqual(event["original_http_status"], 200)
        self.assertEqual(event["visible_http_status"], 200)
        self.assertEqual(result["original"], 1)

    def assert_failure(self, scenario: str) -> None:
        result, path = self.case(scenario)
        self.assertEqual(result["first"], 0)
        self.assertEqual(result["again"], 0)
        self.assertEqual(result["code"], result["io"])
        self.assertEqual(result["retained_code"], result["code"])
        self.assertEqual(result["caller"], -1)
        self.assertEqual(result["ack_calls"], 0)
        self.assertEqual(result["original"], 1)
        self.assertEqual(path.stat().st_size, 0, "repair must not cause replay or duplicate terminal records")

    def test_fputs_eof_propagates_and_never_retries(self) -> None:
        self.assert_failure("write")

    def test_buffered_flush_failure_propagates_without_successful_fallback(self) -> None:
        self.assert_failure("flush")

    def test_request_finish_failure_emits_one_typed_terminal_event(self) -> None:
        result, path = self.case("finish-success")
        self.assertEqual(result["first"], 1)
        self.assertEqual(result["code"], 0)
        self.assertEqual(result["finish"], 1)
        self.assertEqual(result["abort"], 0)
        self.assertEqual(result["native_phase"], 5)
        self.assertEqual(result["native_class"], result["invalid_native"])
        self.assertEqual((result["status"], result["disruptive"], result["failure_enforced"]), (503, 1, 1))
        events = [json.loads(line) for line in path.read_text().splitlines()]
        terminal = [event for event in events if event.get("event") == "invalid_engine_response"]
        self.assertEqual(len(terminal), 1)
        self.assertEqual(terminal[0]["actual_action"], "")

    def test_request_finish_write_and_flush_failures_preserve_native_cause_without_ack(self) -> None:
        for scenario in ("finish-write", "finish-flush"):
            with self.subTest(scenario=scenario):
                result, path = self.case(scenario)
                self.assertEqual(result["first"], 0)
                self.assertEqual(result["again"], 0)
                self.assertEqual(result["code"], result["io"])
                self.assertEqual(result["retained_code"], result["io"])
                self.assertEqual(result["native_phase"], 5)
                self.assertEqual(result["native_class"], result["invalid_native"])
                self.assertEqual((result["status"], result["disruptive"], result["failure_enforced"]), (503, 1, 1))
                self.assertEqual(result["finish"], 1)
                self.assertEqual(result["abort"], 0)
                self.assertEqual(result["caller"], -1)
                self.assertEqual(result["ack_calls"], 0)
                events = [json.loads(line) for line in path.read_text().splitlines()]
                self.assertFalse(any(event.get("event") == "invalid_engine_response" for event in events))

    def test_technical_event_write_failure_is_sticky_and_has_no_ack(self) -> None:
        self.assert_failure("technical-write")

    def test_technical_event_flush_failure_is_sticky_and_has_no_ack(self) -> None:
        self.assert_failure("technical-flush")

    def test_technical_serialization_failure_is_internal_without_physical_write(self) -> None:
        result, path = self.case("technical-stage-allocation")
        self.assertEqual(result["first"], 0)
        self.assertEqual(result["again"], 0)
        self.assertEqual(result["code"], result["internal"])
        self.assertEqual(result["caller"], -1)
        self.assertEqual(result["ack_calls"], 0)
        self.assertEqual(path.stat().st_size, 0)

    def test_oversized_serialization_never_touches_sink(self) -> None:
        result, path = self.case("serialize")
        self.assertEqual(result["first"], 0)
        self.assertEqual(result["code"], result["too_large"])
        self.assertEqual(path.stat().st_size, 0)

    def test_invalid_serialization_inputs_never_touch_sink(self) -> None:
        result, path = self.case("invalid")
        self.assertEqual(result["first"], 0)
        self.assertEqual(result["code"], result["internal"])
        self.assertEqual(path.stat().st_size, 0)

    def test_open_directory_failure_cannot_become_optional_log_success(self) -> None:
        result, _ = self.case("open-directory", self.directory)
        self.assertEqual(result["first"], -1)
        self.assertEqual(result["again"], 0)
        self.assertEqual(result["code"], result["io"])

    def test_real_response_caller_aborts_without_successful_finish_or_cache(self) -> None:
        result, path = self.case("ownership")
        self.assertEqual(result["first"], 0)
        self.assertEqual(result["code"], result["io"])
        self.assertEqual(result["abort"], 1)
        self.assertEqual(result["finish"], 0)
        self.assertEqual(result["store"], 0)
        self.assertEqual(result["caller"], -1)
        self.assertEqual(result["ack_calls"], 0)
        self.assertEqual(path.stat().st_size, 0)

    def test_real_request_caller_aborts_before_companion_handoff_or_finish(self) -> None:
        result, path = self.case("request-ownership")
        self.assertEqual(result["first"], 0)
        self.assertEqual(result["code"], result["io"])
        self.assertEqual(result["abort"], 1)
        self.assertEqual(result["finish"], 0)
        self.assertEqual(result["store"], 0)
        self.assertEqual(result["handoff"], 0)
        self.assertEqual(result["caller"], -1)
        self.assertEqual(result["ack_calls"], 0)
        self.assertEqual(path.stat().st_size, 0)

    def test_direct_common_event_stdio_failures_remain_physical_io(self) -> None:
        for scenario in ("direct-write", "direct-flush"):
            with self.subTest(scenario=scenario):
                result, path = self.case(scenario)
                self.assertEqual(result["first"], 0)
                self.assertEqual(result["code"], result["io"])
                self.assertEqual(path.stat().st_size, 0)

    def test_memory_stream_stdio_failure_is_serialization_not_physical_io(self) -> None:
        result, path = self.case("stage-allocation")
        self.assertEqual(result["first"], 0)
        self.assertEqual(result["code"], result["internal"])
        self.assertNotEqual(result["code"], result["io"])
        self.assertEqual(result["retained_code"], result["code"])
        self.assertEqual(result["again"], 0)
        self.assertEqual(result["caller"], -1)
        self.assertEqual(result["ack_calls"], 0)
        self.assertEqual(path.stat().st_size, 0)

    def test_compiled_old_staging_classification_control_reproduces_io_misclassification(self) -> None:
        result, path = self.case("stage-allocation", variant="old-staging-class")
        self.assertEqual(result["first"], 0)
        self.assertEqual(result["code"], result["io"])
        self.assertNotEqual(result["code"], result["internal"])
        self.assertEqual(path.stat().st_size, 0)

    def test_close_failure_is_a_failed_runtime_cleanup(self) -> None:
        result, _ = self.case("close")
        self.assertEqual(result["cleanup"], 1)

    def test_compiled_unchecked_writer_control_reproduces_false_success(self) -> None:
        result, _ = self.case("flush", variant="unchecked")
        self.assertEqual(result["first"], 1)
        self.assertEqual(result["code"], 0)
        self.assertEqual(result["caller"], 0)
        self.assertEqual(result["ack_calls"], 1)

    def test_open_invalid_parent_failure_propagates(self) -> None:
        parent = self.directory / "regular-parent"
        parent.write_text("not a directory", encoding="utf-8")
        result, _ = self.case("open-parent", parent / "event.jsonl")
        self.assertEqual(result["first"], -1)
        self.assertEqual(result["again"], 0)
        self.assertEqual(result["code"], result["io"])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
