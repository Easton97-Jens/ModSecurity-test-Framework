"""Compiled regression for the unsupported SPOP response-body timeout."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest


ROOT = connector_root()
RUNTIME_SOURCE = (
    source_path('connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c', root=ROOT)
)


def _compile_and_run_contract(
    test_case: unittest.TestCase,
    harness_source: str,
    prefix: str,
    binary_name: str,
    *,
    config_contents: str | None = None,
    run_in_temp: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Compile and execute one self-contained C contract harness."""
    compiler = shutil.which("cc")
    if compiler is None:
        test_case.skipTest("requires a C compiler")

    with tempfile.TemporaryDirectory(
        prefix=prefix,
        dir=os.environ.get("TMPDIR"),
    ) as temporary_directory:
        temporary_root = Path(temporary_directory)
        config_path = temporary_root / "config.conf"
        if config_contents is not None:
            config_path.write_text(config_contents, encoding="utf-8")
        harness = temporary_root / f"{binary_name}.c"
        binary = temporary_root / binary_name
        harness.write_text(
            harness_source.replace("__RUNTIME_SOURCE__", RUNTIME_SOURCE.as_posix())
            .replace("CONFIG_FILE_PLACEHOLDER", config_path.as_posix()),
            encoding="utf-8",
        )
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
                str(source_path('common/include', root=ROOT)),
                "-I",
                str(source_path('connectors/haproxy/src', root=ROOT)),
                str(harness),
                "-Wl,--gc-sections",
                "-Wl,--unresolved-symbols=ignore-all",
                "-o",
                str(binary),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        test_case.assertEqual(compile_result.returncode, 0, compile_result.stderr)
        return subprocess.run(
            [str(binary)],
            cwd=temporary_root if run_in_temp else ROOT,
            check=False,
            capture_output=True,
            text=True,
        )


class HAProxySPOPResponseTimeoutContractTests(unittest.TestCase):
    """Reject an unenforceable timeout while preserving the zero default."""

    def test_config_and_cli_nonzero_timeout_are_rejected(self) -> None:
        harness_source = r'''
#define main haproxy_spop_diagnostic_runtime_program_main
#include "__RUNTIME_SOURCE__"
#undef main

#include <assert.h>

int main(void) {
    agent_config config;
    char *cli_rejected[] = {"runtime", "--response-body-timeout", "25"};
    char *cli_zero[] = {"runtime", "--response-body-timeout", "0"};
    char *cli_invalid[] = {"runtime", "--response-body-timeout", "not-a-number"};

    config_init(&config);
    assert(config_set(&config, "response-body-timeout", "0") == 0);
    assert(config.response_body_timeout_ms == 0U);

    config_init(&config);
    assert(config_set(&config, "response-body-timeout", "25") == 0);
    assert(config.response_body_timeout_ms == 25U);
    assert(validate_production_config(&config) != 0);

    config_init(&config);
    assert(config_set(&config, "response-body-timeout", "not-a-number") != 0);

    config_init(&config);
    assert(config_set(&config, "response-body-timeout", "-1") != 0);

    config_init(&config);
    assert(parse_production_options(&config, 3, cli_rejected) == 0);
    assert(validate_production_config(&config) != 0);

    config_init(&config);
    assert(parse_production_options(&config, 3, cli_zero) == 0);
    assert(config.response_body_timeout_ms == 0U);

    config_init(&config);
    assert(parse_production_options(&config, 3, cli_invalid) != 0);

    {
        FILE *config_file = fopen("__CONFIG_FILE__", "w");
        assert(config_file != NULL);
        assert(fputs("response-body-timeout=25\n", config_file) >= 0);
        assert(fclose(config_file) == 0);
    }
    config_init(&config);
    assert(load_config_file(&config, "__CONFIG_FILE__") == 0);
    assert(validate_production_config(&config) != 0);

    return 0;
}
'''.replace("__CONFIG_FILE__", "CONFIG_FILE_PLACEHOLDER")

        run_result = _compile_and_run_contract(
            self, harness_source, "haproxy-spop-response-timeout-", "response_timeout_contract"
        )
        self.assertEqual(run_result.returncode, 0, run_result.stderr)
        self.assertGreaterEqual(
            run_result.stderr.count("response-body-timeout must be zero"), 3
        )

    def test_production_entry_point_rejects_response_phases_before_server_start(self) -> None:
        harness_source = r'''
#define main haproxy_spop_diagnostic_runtime_program_main
#include "__RUNTIME_SOURCE__"
#undef main

#include <assert.h>

int main(void) {
    char *response_limit[] = {
        "runtime", "--port", "1", "--rules-file", "/dev/null",
        "--response-body-limit", "1"
    };
    char *response_headers[] = {
        "runtime", "--port", "1", "--rules-file", "/dev/null",
        "--enable-response-headers"
    };
    char *response_phases[] = {
        "runtime", "--port", "1", "--rules-file", "/dev/null",
        "--response-phases", "true"
    };
    char *config_file[] = {
        "runtime", "--config", "CONFIG_FILE_PLACEHOLDER",
        "--port", "1", "--rules-file", "/dev/null"
    };

    /* Every response-phase form must fail before run_agent_server(). */
    assert(run_production_agent_command(
        (int)(sizeof(response_limit) / sizeof(response_limit[0])), response_limit) == 2);
    assert(run_production_agent_command(
        (int)(sizeof(response_headers) / sizeof(response_headers[0])), response_headers) == 2);
    assert(run_production_agent_command(
        (int)(sizeof(response_phases) / sizeof(response_phases[0])), response_phases) == 2);
    assert(run_production_agent_command(
        (int)(sizeof(config_file) / sizeof(config_file[0])), config_file) == 2);
    return 0;
}
'''
        run_result = _compile_and_run_contract(
            self,
            harness_source,
            "haproxy-spop-production-gate-",
            "production_gate_contract",
            config_contents="response-body-limit=1\n",
        )
        self.assertEqual(run_result.returncode, 0, run_result.stderr)
        # Both removed CLI/config forms failed during parsing (exit 2),
        # before any production server could start.
        self.assertGreaterEqual(
            run_result.stderr.count("response phases require an integrated P3/P4"), 2
        )

    def test_disabled_response_notify_is_rejected_before_transaction_processing(self) -> None:
        harness_source = r'''
#define main haproxy_spop_diagnostic_runtime_program_main
#include "__RUNTIME_SOURCE__"
#undef main

#include <assert.h>
#include <sys/socket.h>
#include <unistd.h>

static int payload_contains_literal(const spop_buffer *payload, const char *literal) {
    size_t literal_len = strlen(literal);

    for (size_t index = 0U; index + literal_len <= payload->len; ++index) {
        if (memcmp(payload->data + index, literal, literal_len) == 0) {
            return 1;
        }
    }
    return 0;
}

int main(void) {
    agent_state state;
    notify_request request;
    spop_frame frame;
    spop_frame ack;
    spop_buffer ack_payload;
    FILE *log = fopen("guard.log", "w+");
    int sockets[2];

    assert(log != NULL);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    memset(&state, 0, sizeof(state));
    assert(pthread_mutex_init(&state.decision_log_lock, NULL) == 0);
    state.decision_log_lock_initialized = 1;
    config_init(&state.config);
    state.config.response_phases_enabled = 0;
    assert(config_set(&state.config, "mode", "detect-only") == 0);
    state.engine = (haproxy_modsecurity_engine *)0x1;
    state.log = log;
    memset(&request, 0, sizeof(request));
    strcpy(request.message_name, "check-response");
    strcpy(request.request_id, "peer-response");
    request.has_request_id = 1;
    request.http_metadata.is_response = 1;
    memset(&frame, 0, sizeof(frame));
    frame.stream_id = 7;
    frame.frame_id = 9;

    /* A response-typed peer frame must be rejected before the fake engine is
     * touched, while the peer still receives a protocol ACK. */
    assert(process_production_notify(sockets[0], &frame, &state, log,
        &request) == 0);
    assert(recv_frame(sockets[1], &ack, 3000U) == 0);
    assert(ack.type == SPOP_FRM_ACK);
    ack_payload.len = ack.payload_len;
    memcpy(ack_payload.data, ack.payload, ack.payload_len);
    assert(payload_has_set_var_blocked_true(&ack_payload));
    assert(payload_contains_literal(&ack_payload,
        "response_phase_disabled_closed"));
    assert(state.transactions == NULL);

    assert(pthread_mutex_destroy(&state.decision_log_lock) == 0);
    state.decision_log_lock_initialized = 0;
    fclose(log);
    close(sockets[0]);
    close(sockets[1]);
    return 0;
}
'''
        run_result = _compile_and_run_contract(
            self,
            harness_source,
            "haproxy-spop-response-phase-guard-",
            "response_phase_guard_contract",
            run_in_temp=True,
        )
        self.assertEqual(run_result.returncode, 0, run_result.stderr)

    def test_concatenated_response_then_request_notify_is_rejected_fail_closed(self) -> None:
        harness_source = r'''
#define main haproxy_spop_diagnostic_runtime_program_main
#include "__RUNTIME_SOURCE__"
#undef main

#include <assert.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    agent_state state;
    notify_request request;
    spop_frame frame;
    spop_frame ack;
    spop_buffer payload;
    spop_buffer ack_payload;
    FILE *log = fopen("mixed.log", "w+");
    int sockets[2];

    assert(log != NULL);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    memset(&state, 0, sizeof(state));
    config_init(&state.config);
    state.config.response_phases_enabled = 0;
    state.engine = (haproxy_modsecurity_engine *)0x1;
    state.log = log;
    assert(pthread_mutex_init(&state.decision_log_lock, NULL) == 0);
    state.decision_log_lock_initialized = 1;

    /* A SPOP NOTIFY contains exactly one message.  A concatenated response
     * and request message must not be reclassified or partially accepted. */
    payload.len = 0;
    assert(append_string(&payload, "check-response") == 0);
    assert(append_byte(&payload, 0U) == 0);
    assert(append_string(&payload, "check-request") == 0);
    assert(append_byte(&payload, 0U) == 0);
    memset(&frame, 0, sizeof(frame));
    frame.stream_id = 11;
    frame.frame_id = 13;
    frame.payload_len = payload.len;
    memcpy(frame.payload, payload.data, payload.len);

    assert(handle_notify_frame(sockets[0], &frame, &state, log, NULL, NULL) != 0);
    assert(recv_frame(sockets[1], &ack, 3000U) == 0);
    assert(ack.type == SPOP_FRM_ACK);
    ack_payload.len = ack.payload_len;
    memcpy(ack_payload.data, ack.payload, ack.payload_len);
    assert(payload_has_set_var_blocked_true(&ack_payload));
    assert(state.transactions == NULL);

    /* A normal request-only payload still reaches the ordinary request path. */
    payload.len = 0;
    assert(append_string(&payload, "check-request") == 0);
    assert(append_byte(&payload, 0U) == 0);
    frame.payload_len = payload.len;
    memcpy(frame.payload, payload.data, payload.len);
    memset(&request, 0, sizeof(request));
    assert(parse_notify_payload(frame.payload, frame.payload_len, &request) == 0);
    assert(request.http_metadata.is_response == 0);
    /* The ordinary request classification remains unchanged.  The engine
     * path itself is covered by the existing request/decision contracts; this
     * focused control avoids substituting an invalid fake engine pointer. */
    free_notify_request(&request);

    assert(pthread_mutex_destroy(&state.decision_log_lock) == 0);
    fclose(log);
    close(sockets[0]);
    close(sockets[1]);
    return 0;
}
'''
        run_result = _compile_and_run_contract(
            self,
            harness_source,
            "haproxy-spop-mixed-notify-",
            "mixed_notify_contract",
            run_in_temp=True,
        )
        self.assertEqual(run_result.returncode, 0, run_result.stderr)

    def test_empty_notify_payload_is_rejected_before_default_request_processing(self) -> None:
        harness_source = r'''
#define main haproxy_spop_diagnostic_runtime_program_main
#include "__RUNTIME_SOURCE__"
#undef main

#include <assert.h>

int main(void) {
    notify_request request;
    unsigned char malformed[] = {SPOP_DATA_STR};
    unsigned char normal[] = {13, 'c', 'h', 'e', 'c', 'k', '-', 'r', 'e', 'q', 'u', 'e', 's', 't', 0};

    memset(&request, 0xA5, sizeof(request));
    assert(parse_notify_payload(NULL, 0U, &request) != 0);
    assert(request.has_notify == 0);
    assert(request.http_metadata.is_response == 0);
    assert(request.message_name[0] == '\0');

    /* A nonempty malformed payload remains malformed. */
    memset(&request, 0xA5, sizeof(request));
    assert(parse_notify_payload(malformed, sizeof(malformed), &request) != 0);
    assert(request.has_notify == 0);

    /* A normal request message remains a valid request classification. */
    memset(&request, 0, sizeof(request));
    assert(parse_notify_payload(normal, sizeof(normal), &request) == 0);
    assert(request.has_notify == 1);
    assert(request.http_metadata.is_response == 0);
    assert(strcmp(request.message_name, "check-request") == 0);
    free_notify_request(&request);
    return 0;
}
'''
        run_result = _compile_and_run_contract(
            self,
            harness_source,
            "haproxy-spop-empty-notify-",
            "empty_notify_contract",
            run_in_temp=True,
        )
        self.assertEqual(run_result.returncode, 0, run_result.stderr)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
