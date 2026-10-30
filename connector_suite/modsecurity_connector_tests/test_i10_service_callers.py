"""Compiled productive HTTP/MRC1 callers; controlled runtime/backend seams.

Socket bytes and callback results are observed here, not live proxy transport.
Mutation checks use external source copies and keep checkout assertions intact.
"""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = connector_root()

AUTH = r'''
#include "common/runtime/http_authorization_service.c"
#include "connectors/profile_registry.h"
#include "connectors/envoy/src/envoy_modsecurity_mapper.h"
#include "connectors/traefik/src/traefik_modsecurity_mapper.h"
#include <assert.h>
struct msconnector_runtime { int mode; };
struct msconnector_runtime_transaction { int unused; };
static msconnector_runtime runtime;
static msconnector_runtime_transaction native;
static int raw, stage, begin_calls, finish_calls, destroy_calls, handoff_calls;
static int append_calls, stream_peer_fd;
static msconnector_error_code cause, selected_error;
int msconnector_runtime_error_log_enabled(const msconnector_runtime *r) { (void)r; return 0; }
int msconnector_runtime_error_http_status(const msconnector_runtime *r, msconnector_error_code c) {
    (void)r; selected_error = c; return msconnector_error_http_status(c);
}
int msconnector_runtime_transaction_begin_request_stream(msconnector_runtime *r, const msconnector_request *q,
    const char *id, msconnector_runtime_transaction **out, msconnector_decision *d, msconnector_error *e) {
    (void)r; (void)q; (void)id; ++begin_calls; *out = &native;
    msconnector_decision_set_deny(d, 403, "stale-rule", "stale");
    if (stage == 0) { msconnector_error_set(e, cause, "first failure", "fixture"); return raw; }
    msconnector_decision_set_allow(d); return 1;
}
msconnector_body_mode msconnector_runtime_request_body_mode(const msconnector_runtime *r) {
    (void)r; return MSCONNECTOR_BODY_MODE_STREAMING;
}
int msconnector_runtime_transaction_append_request_body_chunk(msconnector_runtime_transaction *t,
    const unsigned char *body, size_t size, msconnector_error *e) {
    (void)t; (void)body;
    ++append_calls;
    if (stage == 4) { msconnector_error_set(e, cause, "body append failure", "fixture"); return raw; }
    if (stage == 6) {
        if (append_calls == 1) {
            assert(size == 0U);
            assert(send(stream_peer_fd, "b", 1U, MSG_NOSIGNAL) == 1);
        } else {
            assert(append_calls == 2 && size == 1U);
            msconnector_error_set(e, cause, "streamed body append failure", "fixture");
            return raw;
        }
    }
    return 1;
}
int msconnector_runtime_transaction_finish_request_body(msconnector_runtime_transaction *t,
    msconnector_decision *d, msconnector_error *e) {
    (void)t;
    if (stage == 5) { msconnector_error_set(e, cause, "body EOS failure", "fixture"); return raw; }
    msconnector_decision_set_allow(d); return 1;
}
int msconnector_runtime_transaction_fail(msconnector_runtime_transaction *t,
    msconnector_transaction_error_class failure, msconnector_error *e) {
    (void)t; (void)failure; (void)e; return 1;
}
int msconnector_runtime_transaction_finish(msconnector_runtime_transaction *t, msconnector_error *e) {
    (void)t; ++finish_calls;
    if (stage == 2) { msconnector_error_set(e, cause, "finish failure", "fixture"); return raw; }
    if (stage == 0 || stage == 4 || stage == 5 || stage == 6) {
        msconnector_error_set(e, MSCONNECTOR_ERROR_IO, "later cleanup", "fixture"); return 0;
    }
    return 1;
}
void msconnector_runtime_transaction_destroy(msconnector_runtime_transaction **t) {
    if (*t != NULL) { ++destroy_calls; *t = NULL; }
}
int msconnector_runtime_transaction_begin_request_stream_with_trusted_provenance(
    msconnector_runtime *r, const msconnector_request *q, const char *id,
    const msconnector_runtime_trusted_provenance *provenance,
    msconnector_runtime_transaction **out, msconnector_decision *d, msconnector_error *e) {
    if (provenance != NULL) {
        if (out != NULL) *out = NULL;
        msconnector_error_set(e, MSCONNECTOR_ERROR_UNSUPPORTED_PHASE,
            "trusted provenance is outside this legacy fixture", "fixture");
        return 0;
    }
    return msconnector_runtime_transaction_begin_request_stream(r, q, id, out, d, e);
}
int msconnector_runtime_transaction_finalize_and_snapshot(
    msconnector_runtime_transaction **t, msconnector_runtime_transaction_snapshot *snapshot,
    msconnector_error *e) {
    if (t == NULL || *t == NULL || snapshot == NULL ||
        msconnector_runtime_transaction_finish(*t, e) != 1) return 0;
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->finished = 1;
    snapshot->contract.cleanup_started = 1;
    snapshot->contract.cleanup_complete = 1;
    snapshot->contract.status = MSCONNECTOR_TRANSACTION_STATUS_CLEANED;
    msconnector_runtime_transaction_destroy(t);
    return 1;
}
static int handoff(const msconnector_runtime *r, msconnector_runtime_transaction *t,
    void *u, char handle[MSCONNECTOR_RUNTIME_RESPONSE_COMPANION_HANDLE_SIZE], msconnector_error *e) {
    (void)r; (void)t; (void)u; ++handoff_calls; memset(handle, 'a', 64U); handle[64] = '\0';
    if (stage == 1) { msconnector_error_set(e, cause, "handoff failure", "fixture"); return raw; }
    return 1;
}
int main(int argc, char **argv) {
    int pair[2], result;
    char wire[4096]; ssize_t count;
    struct sockaddr_in address = {0};
    connection_deadline deadline;
    authorization_service service = {0};
    msconnector_http_authorization_profile profile = {0};
    static const char request[] = "GET /ok HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n";
    static const char streamed_request[] = "POST /ok HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1\r\nConnection: close\r\n\r\n";
    const char *wire_request;
    assert(argc == 7); stage = atoi(argv[2]); raw = atoi(argv[3]);
    cause = (msconnector_error_code)atoi(argv[4]); runtime.mode = atoi(argv[5]);
    profile.transaction_profile = msconnector_profile_registry_find(argv[1]);
    assert(profile.transaction_profile != NULL);
    profile.connector_name = profile.transaction_profile->connector_id;
    profile.integration_mode = profile.transaction_profile->host_adapter_id;
    profile.map_request = strcmp(argv[1], "envoy-ext-authz") == 0 ?
        envoy_modsecurity_map_request : traefik_modsecurity_map_request;
    if (stage == 1 || stage == 3) { profile.handoff_response_companion = handoff; }
    service.runtime = &runtime; service.profile = &profile; service.connection_timeout_ms = 1000UL;
    service.request_limits.total_header_limit = 8192U;
    service.request_limits.header_count_limit = 32U;
    msconnector_request_mapper_contract_init(&service.request_limits.mapper_contract);
    assert(pthread_mutex_init(&service.runtime_lock, NULL) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    stream_peer_fd = pair[1];
    wire_request = stage == 6 ? streamed_request : request;
    assert(send(pair[1], wire_request, strlen(wire_request), MSG_NOSIGNAL) == (ssize_t)strlen(wire_request));
    if (atoi(argv[6])) { assert(shutdown(pair[1], SHUT_RD) == 0); }
    address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(8080U);
    assert(connection_deadline_init(&deadline, 1000UL));
    result = handle_authorization_request(&(authorization_connection){pair[0], &address, &address, &deadline}, &service);
    assert(begin_calls == 1);
    if (stage == 6) { assert(append_calls == 2); }
    if (stage != 3 || atoi(argv[6])) { assert(result == 0); }
    if (stage != 3 && !atoi(argv[6])) { assert(selected_error == cause); }
    if (!atoi(argv[6])) {
        count = recv(pair[1], wire, sizeof(wire)-1U, 0); assert(count > 0); wire[count] = '\0';
        if (stage != 3) {
            char status[64]; snprintf(status, sizeof(status), "HTTP/1.1 %d ", msconnector_error_http_status(cause));
            assert(strncmp(wire, status, strlen(status)) == 0);
            assert(strstr(wire, "x-msconnector-decision: runtime_error") != NULL);
            assert(strstr(wire, "stale-rule") == NULL);
            assert(strstr(wire, "x-msconnector-response-handle") == NULL);
        } else { assert(result == 1 && strncmp(wire, "HTTP/1.1 200 ", 13U) == 0); }
    }
    if (stage != 3) { assert(finish_calls == 1 && destroy_calls == 1); }
    else { assert(finish_calls == 0 && destroy_calls == 0); }
    assert(handoff_calls == (stage == 1 || stage == 3));
    close(pair[0]); close(pair[1]); assert(pthread_mutex_destroy(&service.runtime_lock) == 0);
    return 0;
}
'''

TRANSPORT = r'''
#include "common/runtime/response_companion_transport.c"
#include <assert.h>
static int raw, calls, failures;
static msconnector_error_code cause;
static int callback(msconnector_error *e) {
    ++calls;
    if (raw != 1) { msconnector_error_set(e, cause, "typed failure", "fixture"); }
    return raw;
}
static int claim(void *c, const char *h, msconnector_response_companion_backend_session *s, msconnector_error *e) {
    (void)h; s->opaque=c; return callback(e);
}
static int headers(void *c, const msconnector_response_companion_backend_session *s,
    const msconnector_response *r, msconnector_decision *d, msconnector_error *e) {
    (void)c; (void)s; (void)r; msconnector_decision_set_allow(d); return callback(e);
}
static int body(void *c, const msconnector_response_companion_backend_session *s,
    const unsigned char *b, size_t n, msconnector_error *e) {
    (void)c; (void)s; (void)b; (void)n; return callback(e);
}
static int eos(void *c, const msconnector_response_companion_backend_session *s,
    msconnector_decision *d, msconnector_error *e) {
    (void)c; (void)s; msconnector_decision_set_allow(d); return callback(e);
}
static int commit(void *c, const msconnector_response_companion_backend_session *s,
    int h, int b, msconnector_error *e) { (void)c; (void)s; (void)h; (void)b; return callback(e); }
static int outcome(void *c, const msconnector_response_companion_backend_session *s,
    const msconnector_response_companion_host_action *a, msconnector_error *e) {
    (void)c; (void)s; (void)a; return callback(e);
}
static int release(void *c, msconnector_response_companion_backend_session *s, msconnector_error *e) {
    (void)c; int r=callback(e); if (r==1) { s->opaque=NULL; } return r;
}
static int cancel(void *c, msconnector_response_companion_backend_session *s, int u, msconnector_error *e) {
    (void)u; return release(c,s,e);
}
static void fail(void *c, msconnector_response_companion_backend_session *s, msconnector_transaction_error_class f) {
    (void)c; assert(f != MSCONNECTOR_TRANSACTION_ERROR_NONE); ++failures; s->opaque=NULL;
    if (cause == MSCONNECTOR_ERROR_MODSECURITY_FAILURE) { assert(f == MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE); }
    if (cause == MSCONNECTOR_ERROR_PROTOCOL) { assert(f == MSCONNECTOR_TRANSACTION_ERROR_PROTOCOL); }
    if (cause == MSCONNECTOR_ERROR_TIMEOUT) { assert(f == MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT); }
    if (cause == MSCONNECTOR_ERROR_RUNTIME_UNAVAILABLE) { assert(f == MSCONNECTOR_TRANSACTION_ERROR_ENGINE_UNAVAILABLE); }
}
int main(int argc, char **argv) {
    msconnector_response_companion_transport transport={0};
    response_companion_session_state state;
    response_companion_frame frame={0};
    msconnector_response_companion_transport_worker worker={0};
    unsigned char payload[128]={0}, header[12], reply[4096]={0};
    int pair[2], result; size_t size;
    assert(argc==4); raw=atoi(argv[2]); cause=(msconnector_error_code)atoi(argv[3]);
    transport.config.backend=(msconnector_response_companion_backend){
        .context=&transport,.allow_parallel_callbacks=1,.claim=claim,.process_response_headers=headers,
        .append_response_body_chunk=body,.finish_response_body=eos,.set_response_commit_state=commit,
        .record_host_action=outcome,.cancel=cancel,.release=release,.fail=fail};
    atomic_init(&transport.synchronization.backend_faulted,0);
    transport.config.operation_timeout_ms=1000U; transport.config.max_header_count=32U;
    transport.config.max_header_bytes=8192U;
    response_companion_reset_session_state(&state); state.claimed=1; state.session.opaque=&transport;
    state.response_headers=1; state.committed=1; state.has_decision=1;
    msconnector_decision_set_deny(&state.latest_decision,403,"stale-rule","stale");
    assert(socketpair(AF_UNIX,SOCK_STREAM,0,pair)==0); worker.transport=&transport; worker.socket_fd=pair[0];
    frame.payload=payload;
    if (strcmp(argv[1],"claim")==0) {
        state.claimed=0; state.session.opaque=NULL; memset(payload,'a',64U);
        frame.opcode=RESPONSE_COMPANION_CLAIM; frame.payload_size=64U;
        result=response_companion_handle_claim(&worker,&state,&frame);
    } else if (strcmp(argv[1],"headers")==0) {
        state.response_headers=0; state.committed=0;
        response_companion_write_u16(payload,200U); response_companion_write_u16(payload+2U,8U);
        memcpy(payload+4U,"HTTP/1.1",8U); frame.payload_size=14U;
        frame.opcode=RESPONSE_COMPANION_RESPONSE_HEADERS;
        result=response_companion_handle_headers(&worker,&state,&frame);
    } else if (strcmp(argv[1],"commit")==0) {
        state.committed=0; payload[0]=1; frame.payload_size=2U; frame.opcode=RESPONSE_COMPANION_COMMIT;
        result=response_companion_handle_commit(&worker,&state,&frame);
    } else if (strcmp(argv[1],"body")==0) {
        frame.payload_size=1U; frame.opcode=RESPONSE_COMPANION_RESPONSE_BODY;
        result=response_companion_handle_body(&worker,&state,&frame);
    } else if (strcmp(argv[1],"eos")==0) {
        frame.opcode=RESPONSE_COMPANION_RESPONSE_EOS;
        result=response_companion_handle_eos(&worker,&state,&frame);
    } else if (strcmp(argv[1],"outcome")==0) {
        frame.opcode=RESPONSE_COMPANION_OUTCOME; frame.payload_size=4U;
        payload[0]=MSCONNECTOR_DECISION_ACTION_DENY; response_companion_write_u16(payload+2U,403U);
        result=response_companion_handle_outcome(&worker,&state,&frame);
    } else if (strcmp(argv[1],"cancel")==0) {
        frame.opcode=RESPONSE_COMPANION_CANCEL; frame.payload_size=1U;
        result=response_companion_handle_cancel(&worker,&state,&frame);
    } else {
        state.response_eos=1; frame.opcode=RESPONSE_COMPANION_RELEASE;
        result=response_companion_handle_release(&worker,&state,&frame);
    }
    assert(calls==1); assert(recv(pair[1],header,sizeof(header),MSG_WAITALL)==12);
    size=response_companion_read_u32(header+8U); assert(size<=sizeof(reply));
    assert(recv(pair[1],reply,size,MSG_WAITALL)==(ssize_t)size);
    if (raw != 1) {
        assert(result==0 && reply[1]==1U);
        assert(response_companion_read_u16(reply+6U)==(unsigned int)cause);
        assert(state.session.opaque==NULL && failures==1);
        assert(strstr((char *)reply+12U,"stale-rule")==NULL);
        response_companion_abort_session(&transport,&state,MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR);
        assert(failures==1 && calls==1);
    } else { assert(result==1 && reply[1]==0U && failures==0); }
    close(pair[0]); close(pair[1]); return 0;
}
'''


class ServiceCallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="i10-service-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(cls.temp.cleanup)
        cls.directory = Path(cls.temp.name)
        cls.auth = cls.compile(AUTH, "auth")
        cls.transport = cls.compile(TRANSPORT, "transport")

    @classmethod
    def compile(cls, fixture, name, include_root=ROOT):
        source = cls.directory / f"{name}.c"
        binary = cls.directory / f"{name}.bin"
        source.write_text(fixture)
        command = shlex.split(os.environ.get("CC", "cc")) + [
            "-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread",
            "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
            "-I", str(include_root), "-I", str(ROOT), "-I", str(source_path('common/include', root=ROOT)),
            "-I", str(source_path('common/runtime', root=ROOT)), str(source),
        ]
        command += [str(p) for p in sorted((source_path('common/src', root=ROOT)).glob("*.c"))]
        command += [str(source_path('connectors/profile_registry.c', root=ROOT)),
                    str(source_path('connectors/envoy/src/envoy_modsecurity_mapper.c', root=ROOT)),
                    str(source_path('connectors/traefik/src/traefik_modsecurity_mapper.c', root=ROOT)), "-o", str(binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)
        if result.returncode:
            raise AssertionError(result.stderr[-6000:])
        return binary

    def run_case(self, binary, *args, expected=0):
        result = subprocess.run([str(binary), *map(str, args)], capture_output=True, text=True, timeout=5, check=False)
        if expected == 0:
            self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        else:
            self.assertNotEqual(result.returncode, 0, "mutation unexpectedly passed")

    def test_authz_and_forwardauth_technical_errors_reach_http_without_stale_rule(self):
        # Public error codes: invalid engine, connector, protocol, timeout, unavailable.
        for profile in ("envoy-ext-authz", "traefik-forwardauth"):
            for mode in (0, 1):  # adapter is mode-independent; Common policy tested separately
                for stage in (0, 1, 2, 4, 5, 6):
                    for cause in (12, 20, 15, 13, 4):
                        for raw in (0, -1, 2):
                            with self.subTest(profile=profile, mode=mode, stage=stage, cause=cause, raw=raw):
                                self.run_case(self.auth, profile, stage, raw, cause, mode, 0)

    def test_failed_authorization_write_is_not_success(self):
        self.run_case(self.auth, "envoy-ext-authz", 2, 1, 12, 1, 1)

    def test_legitimate_allow_keeps_companion_ownership(self):
        for profile in ("envoy-ext-authz", "traefik-forwardauth"):
            self.run_case(self.auth, profile, 3, 1, 12, 1, 0)

    def test_mrc1_callbacks_propagate_typed_errors_and_cleanup_once(self):
        for operation in ("claim", "headers", "commit", "body", "eos", "outcome", "cancel", "release"):
            for cause in (12, 20, 15, 13, 4):
                for raw in (0, -1, 2):
                    with self.subTest(operation=operation, cause=cause, raw=raw):
                        self.run_case(self.transport, operation, raw, cause)

    def test_valid_mrc1_callbacks_still_acknowledge_success(self):
        for operation in ("claim", "headers", "commit", "body", "eos", "outcome", "cancel", "release"):
            self.run_case(self.transport, operation, 1, 12)

    def test_mutations_cannot_convert_errors_into_success(self):
        for relative, fixture, old, new, args in (
            ("common/runtime/http_authorization_service.c", AUTH,
             "&transaction, &decision, &common_error, &binding_claimed) != 1", "&transaction, &decision, &common_error, &binding_claimed) == 0",
             ("envoy-ext-authz", 0, -1, 13, 1, 0)),
            ("common/runtime/http_authorization_service.c", AUTH,
             "parsed->body, parsed->body_size, error) != 1", "parsed->body, parsed->body_size, error) == 0",
             ("traefik-forwardauth", 4, -1, 20, 1, 0)),
            ("common/runtime/http_authorization_service.c", AUTH,
             "transaction, &decision, &common_error, lock_held) != 1", "transaction, &decision, &common_error, lock_held) == 0",
             ("envoy-ext-authz", 5, -1, 13, 1, 0)),
            ("common/runtime/http_authorization_service.c", AUTH,
             "scratch, received_size, error) != 1", "scratch, received_size, error) == 0",
             ("traefik-forwardauth", 6, -1, 13, 1, 0)),
            ("common/runtime/response_companion_transport.c", TRANSPORT,
             "if (result == 1) {\n        return 1;", "if (result != 0) {\n        return 1;",
             ("body", -1, 12)),
            ("common/runtime/response_companion_transport.c", TRANSPORT,
             "case MSCONNECTOR_ERROR_MODSECURITY_FAILURE:\n        return MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE;",
             "case MSCONNECTOR_ERROR_MODSECURITY_FAILURE:\n        return MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR;",
             ("body", 0, 12)),
        ):
            with self.subTest(source=relative, args=args):
                mutation_root = self.directory / ("mutated-auth" if fixture == AUTH else "mutated-transport")
                path = mutation_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                text = (ROOT / relative).read_text()
                self.assertEqual(text.count(old), 1)
                path.write_text(text.replace(old, new, 1))
                binary = self.compile(fixture, mutation_root.name, mutation_root)
                self.run_case(binary, *args, expected=1)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
