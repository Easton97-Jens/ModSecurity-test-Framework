"""Execute the real companion body handler with bounded backend/wire seams."""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile
import unittest

from modsecurity_test_framework.connector_context import connector_root

ROOT = connector_root()


def section(source, start, end):
    return source[source.index(start):source.index(end, source.index(start))]


def fixture(source, *, restore_cumulative_limit=False):
    definitions = section(source, '#define RESPONSE_COMPANION_MAGIC',
                          'enum response_companion_opcode')
    frame = section(source, 'typedef struct response_companion_frame {',
                    'typedef struct response_companion_reader {')
    state = section(source, 'typedef struct response_companion_session_state {',
                    'static void response_companion_reset_session_state(')
    worker = section(source, 'struct msconnector_response_companion_transport_worker {',
                     'static uint16_t response_companion_read_u16(')
    handler = section(source, 'static int response_companion_handle_body(',
                      'static int response_companion_handle_eos(')
    if restore_cumulative_limit:
        marker = 'frame->payload_size <= MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_MAX_BODY_CHUNK &&'
        if handler.count(marker) != 1:
            raise AssertionError('body-handler chunk boundary changed')
        handler = handler.replace(marker, marker + '\n'
            '        frame->payload_size <= SIZE_MAX - state->response_body_bytes &&', 1)
    return r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "response_companion_transport.h"
#include "msconnector/transaction_contract.h"
/* Model the cumulative host-width boundary without changing pointers, chunk
 * sizes, native APIs or the actual production counter declaration. */
#if MODEL_HOST_32
#undef SIZE_MAX
#define SIZE_MAX UINT32_MAX
#endif
''' + definitions + frame + state + worker + r'''
static int append_calls, fail_calls, backend_error, sent_success;
static msconnector_error_code sent_error;

static int response_companion_backend_append_response_body_chunk(
    msconnector_response_companion_transport *transport,
    const msconnector_response_companion_backend_session *session,
    const unsigned char *data, size_t size, msconnector_error *error)
{
    (void)transport;
    (void)session;
    assert(data != NULL && size == 3U);
    ++append_calls;
    if (backend_error) {
        msconnector_error_set(error, MSCONNECTOR_ERROR_MODSECURITY_FAILURE,
            "controlled native append failure", "fixture");
        return 0;
    }
    return 1;
}

static msconnector_transaction_error_class
response_companion_error_class_from_error(const msconnector_error *error)
{
    (void)error;
    return MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR;
}

static void response_companion_fail_session(
    msconnector_response_companion_transport *transport,
    response_companion_session_state *state,
    msconnector_transaction_error_class error_class)
{
    (void)transport;
    (void)state;
    (void)error_class;
    ++fail_calls;
}

static int response_companion_send_result(
    const msconnector_response_companion_transport *transport, int socket_fd,
    uint8_t opcode, int success, const msconnector_decision *decision,
    const msconnector_error *error)
{
    (void)transport;
    (void)socket_fd;
    (void)opcode;
    (void)decision;
    sent_success = success;
    sent_error = error->code;
    return 1;
}
''' + handler + r'''
_Static_assert(sizeof(((response_companion_session_state *)0)->response_body_bytes)
    >= sizeof(uint64_t), "response observation must not narrow to size_t");

static void reset(response_companion_session_state *state)
{
    memset(state, 0, sizeof(*state));
    state->response_headers = 1;
    state->committed = 1;
    append_calls = fail_calls = backend_error = sent_success = 0;
    sent_error = MSCONNECTOR_ERROR_NONE;
}

static void check_boundaries(msconnector_response_companion_transport_worker *worker,
    response_companion_session_state *state, const response_companion_frame *frame)
{
    reset(state);
    state->response_body_bytes = UINT32_MAX;
    assert(response_companion_handle_body(worker, state, frame));
    assert(state->response_body_bytes == UINT64_C(4294967298));
    assert(append_calls == 1 && fail_calls == 0 && sent_success);
    state->response_body_bytes = UINT64_MAX - 1U;
    assert(response_companion_handle_body(worker, state, frame));
    assert(state->response_body_bytes == UINT64_MAX);
    assert(response_companion_handle_body(worker, state, frame));
    assert(state->response_body_bytes == UINT64_MAX);
    assert(append_calls == 3 && fail_calls == 0 && sent_success);
}

static void check_failures(msconnector_response_companion_transport_worker *worker,
    response_companion_session_state *state, response_companion_frame *frame)
{
    reset(state);
    frame->payload_size = MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_MAX_BODY_CHUNK + 1U;
    assert(!response_companion_handle_body(worker, state, frame));
    assert(append_calls == 0 && fail_calls == 1 && !sent_success);
    assert(sent_error == MSCONNECTOR_ERROR_PROTOCOL && state->response_body_bytes == 0U);
    frame->payload_size = 3U;
    reset(state);
    backend_error = 1;
    assert(!response_companion_handle_body(worker, state, frame));
    assert(append_calls == 1 && fail_calls == 1 && !sent_success);
    assert(sent_error == MSCONNECTOR_ERROR_MODSECURITY_FAILURE);
    assert(state->response_body_bytes == 0U);
    reset(state);
    state->response_eos = 1;
    assert(!response_companion_handle_body(worker, state, frame));
    assert(append_calls == 0 && sent_error == MSCONNECTOR_ERROR_PHASE_SEQUENCE);
    reset(state);
    state->committed = 0;
    assert(!response_companion_handle_body(worker, state, frame));
    assert(append_calls == 0 && sent_error == MSCONNECTOR_ERROR_PHASE_SEQUENCE);
}

int main(void)
{
    unsigned char data[3] = {1, 2, 3};
    response_companion_frame frame = {3, data, sizeof(data)};
    response_companion_session_state state;
    msconnector_response_companion_transport_worker worker = {0};
    check_boundaries(&worker, &state, &frame);
    check_failures(&worker, &state, &frame);
    return 0;
}
'''


class ResponseCompanionCounterTests(unittest.TestCase):
    def compile_and_run(self, model_32, *, restore_cumulative_limit=False):
        source = (ROOT / 'common/runtime/response_companion_transport.c').read_text()
        with tempfile.TemporaryDirectory(dir=os.environ['RUNNER_TEMP']) as temporary:
            directory = Path(temporary)
            candidate, binary = directory / 'counter.c', directory / 'counter'
            candidate.write_text(fixture(source, restore_cumulative_limit=restore_cumulative_limit))
            command = shlex.split(os.environ.get('CC', 'cc')) + [
                '-std=c17', '-Wall', '-Wextra', '-Werror', '-pedantic-errors',
                f'-DMODEL_HOST_32={int(model_32)}', '-I', str(ROOT / 'common/include'),
                '-I', str(ROOT / 'common/runtime'), str(candidate),
                str(ROOT / 'common/src/error.c'), '-ffunction-sections', '-fdata-sections',
                '-Wl,--gc-sections', '-o', str(binary),
            ]
            compiled = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            return subprocess.run([str(binary)], cwd=directory, capture_output=True, text=True, timeout=5, check=False)

    def test_actual_handler_crosses_modelled_32_bit_boundary_and_saturates(self):
        result = self.compile_and_run(True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_actual_handler_retains_chunk_phase_and_backend_errors_on_64_bit_host(self):
        result = self.compile_and_run(False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_reintroduced_cumulative_guard_reproduces_the_delivery_failure(self):
        result = self.compile_and_run(True, restore_cumulative_limit=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('response_companion_handle_body(worker, state, frame)', result.stderr)


if os.environ.get('ON_DEMAND_TESTS') != '1':
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
