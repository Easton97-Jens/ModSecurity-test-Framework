"""Compile production UDS handlers against controlled Common/transport seams."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = connector_root()

from modsecurity_connector_tests.c_source_contract import function_definition


class NativeAPIResults(unittest.TestCase):
    def test_commit_and_terminal_transport_failure(self):
        source = (source_path('connectors/traefik/src/traefik_engine_service.c', root=ROOT)).read_text()
        commit = function_definition(source, "traefik_engine_handle_response_commit")
        frame = function_definition(source, "traefik_engine_process_frame")
        failure = function_definition(source, "traefik_engine_record_transport_failure")
        cleanup = function_definition(source, "traefik_engine_session_destroy")
        poll_error = function_definition(source, "traefik_engine_poll_error")
        harness = r'''
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include "common/runtime/msconnector_runtime.h"
#include "connectors/traefik/src/traefik_engine_protocol.h"
typedef struct { pthread_mutex_t runtime_lock; } traefik_engine_service;
typedef struct { traefik_engine_service *service; msconnector_runtime_transaction *transaction;
 int begun, finished, destroyed, terminal, response_headers, response_headers_sent, response_body_started;
} traefik_engine_session;
typedef struct { uint8_t opcode; unsigned char *payload; size_t payload_size; } traefik_engine_frame;
static int commit_result=1, commits, replies, dispatches, received_result=1, dispatched_result=-1;
static int cancellations,timeouts,failures,cleanups;
static msconnector_transaction_error_class cause;
void msconnector_error_init(msconnector_error *e) { memset(e,0,sizeof(*e)); }
static uint8_t traefik_engine_result_for_runtime_error(const msconnector_error *e) { (void)e; return TRAEFIK_ENGINE_PROTOCOL_RESULT_RUNTIME; }
static void traefik_engine_set_allow_phase(msconnector_decision *d, enum msconnector_phase p) { memset(d,0,sizeof(*d)); d->phase=p; }
int msconnector_runtime_transaction_set_response_commit_state_checked(msconnector_runtime_transaction *t,int h,int b,msconnector_error *e) {
 (void)t; (void)h; (void)b; ++commits; e->code=MSCONNECTOR_ERROR_HOST_API_FAILURE; return commit_result;
}
void msconnector_runtime_transaction_set_response_commit_state(msconnector_runtime_transaction *t,int h,int b) {
 msconnector_error e; (void)msconnector_runtime_transaction_set_response_commit_state_checked(t,h,b,&e);
}
static int traefik_engine_receive_frame(int fd,traefik_engine_frame *f) { (void)fd; (void)f; return received_result; }
static int traefik_engine_dispatch(traefik_engine_session *s,const traefik_engine_frame *f,msconnector_decision *d,uint8_t *r) {
 (void)s; (void)f; (void)d; ++dispatches; *r=TRAEFIK_ENGINE_PROTOCOL_RESULT_RUNTIME; return dispatched_result;
}
void msconnector_decision_init(msconnector_decision *d) { memset(d,0,sizeof(*d)); }
static int traefik_engine_is_command_opcode(uint8_t op) { (void)op; return 1; }
static int traefik_engine_send_result(int fd,uint8_t op,uint8_t r,traefik_engine_session *s,msconnector_decision *d) {
 (void)fd;(void)op;(void)r;(void)s;(void)d;++replies;return 1;
}
int msconnector_runtime_transaction_cancel(msconnector_runtime_transaction *t,int upstream,msconnector_error *e) {(void)t;(void)e;assert(upstream==0);++cancellations;return 1;}
int msconnector_runtime_transaction_timeout(msconnector_runtime_transaction *t,msconnector_error *e) {(void)t;(void)e;++timeouts;return 1;}
int msconnector_runtime_transaction_fail(msconnector_runtime_transaction *t,msconnector_transaction_error_class c,msconnector_error *e) {(void)t;(void)e;cause=c;++failures;return 1;}
void msconnector_runtime_transaction_destroy(msconnector_runtime_transaction **t) {assert(*t!=0);++cleanups;*t=0;}
__COMMIT__
__FAILURE__
__FRAME__
__CLEANUP__
__POLL_ERROR__
int main(void) {
 assert(traefik_engine_poll_error(POLLERR)==EIO);
 assert(traefik_engine_poll_error(POLLHUP)==ECONNRESET);
 assert(traefik_engine_poll_error(POLLNVAL)==EBADF);
 assert(traefik_engine_poll_error(POLLHUP|POLLERR)==ECONNRESET);
 assert(traefik_engine_poll_error(POLLNVAL|POLLHUP|POLLERR)==EBADF);
 (void)&traefik_engine_result_for_runtime_error;
 traefik_engine_service service; pthread_mutex_init(&service.runtime_lock,0);
 traefik_engine_session s={.service=&service,.transaction=(void*)1,.begun=1,.response_headers=1};
 unsigned char p[]={1,0}; traefik_engine_frame f={.opcode=TRAEFIK_ENGINE_PROTOCOL_RESPONSE_COMMIT,.payload=p,.payload_size=2};
 msconnector_decision d; uint8_t r=0;
 assert(traefik_engine_handle_response_commit(&s,&f,&d,&r)==1);assert(s.response_headers_sent==1);assert(commits==1);
 s.response_headers_sent=0;commit_result=0;
 assert(traefik_engine_handle_response_commit(&s,&f,&d,&r)==-1);assert(r==TRAEFIK_ENGINE_PROTOCOL_RESULT_RUNTIME);
 assert(s.response_headers_sent==0);assert(commits==2);
 int alive=traefik_engine_process_frame(&s,-1,&f);
 assert(alive==0);assert(replies==1);assert(dispatches==1);
 assert(failures==1);assert(cause==MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR);
 dispatched_result=0;assert(traefik_engine_process_frame(&s,-1,&f)==0);assert(cause==MSCONNECTOR_TRANSACTION_ERROR_PROTOCOL);
 received_result=-1;errno=ETIMEDOUT;assert(traefik_engine_process_frame(&s,-1,&f)==0);assert(timeouts==1);
 errno=EPROTO;assert(traefik_engine_process_frame(&s,-1,&f)==0);assert(cause==MSCONNECTOR_TRANSACTION_ERROR_PROTOCOL);
 received_result=0;assert(traefik_engine_process_frame(&s,-1,&f)==0);assert(cancellations==1);
 received_result=-1;errno=ENOMEM;assert(traefik_engine_process_frame(&s,-1,&f)==0);assert(cause==MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR);
 errno=ECANCELED;assert(traefik_engine_process_frame(&s,-1,&f)==0);assert(cause==MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR);assert(cancellations==1);
 traefik_engine_session_destroy(&s);traefik_engine_session_destroy(&s);assert(cleanups==1);assert(s.destroyed);
 pthread_mutex_destroy(&service.runtime_lock);return 0;
}
'''.replace("__COMMIT__", commit).replace("__FAILURE__", failure).replace("__FRAME__", frame).replace("__CLEANUP__", cleanup).replace("__POLL_ERROR__", poll_error)
        with tempfile.TemporaryDirectory(prefix="i09-traefik-") as tmp:
            path = Path(tmp)
            (path / "test.c").write_text(harness)
            result = subprocess.run([os.environ.get("CC", "cc"), "-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread", "-I", str(ROOT), "-I", str(source_path('common/include', root=ROOT)), str(path / "test.c"), "-o", str(path / "test")], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(path / "test")], cwd=path, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
