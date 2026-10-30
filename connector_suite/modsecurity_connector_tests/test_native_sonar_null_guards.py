"""Eight host-free native unit inputs; no Apache/lighttpd process or campaign.

Productive helper bodies are extracted unchanged. Host/runtime and real-APR
callbacks are explicit controlled seams, not evidence of native SDK operation.
These core tests compile/run local unit executables and cannot use the separate
Python-only offline exception's process-denial guard.
"""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from modsecurity_connector_tests.c_source_contract import function_definition

ROOT = connector_root()
LIGHTTPD = "connectors/lighttpd/module/mod_msconnector.c"
APR = "ci/runtime/lifecycle/apache-i12/apr_sink_fault.c"
COMMON = ("decision.c", "decision_action.c", "intervention.c", "block_statuses.c",
          "error.c", "status.c", "late_intervention.c", "http_status.c",
          "event.c", "json_escape.c", "transaction_state.c")
LIGHTTPD_FUNCTIONS = (
    "mod_msconnector_response_headers_committed",
    "mod_msconnector_response_body_committed",
    "mod_msconnector_finish_request_body",
    "mod_msconnector_reject_request_body_gate_conflict",
    "mod_msconnector_prepare_request_body",
    "mod_msconnector_finish_response_body",
)

LIGHTTPD_SEAMS = r'''
#include "common/runtime/msconnector_runtime.h"
#include "msconnector/late_intervention.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
typedef enum { HANDLER_GO_ON, HANDLER_FINISHED, HANDLER_ERROR,
               HANDLER_WAIT_FOR_EVENT } handler_t;
typedef enum { PLUGIN_BODY_HOOK_CONTINUE, PLUGIN_BODY_HOOK_ERROR,
               PLUGIN_BODY_HOOK_ABORT } plugin_body_hook_result;
typedef struct request_st request_st;
typedef struct { handler_t (*reqbody_read)(request_st *); } connection;
struct request_st {
    struct { void *errh; int stream_request_body; } conf;
    struct { off_t bytes_out; } write_queue;
    size_t resp_header_len;
    int http_status, http_version;
    off_t reqbody_length;
    connection *con;
};
struct msconnector_runtime { enum msconnector_phase4_mode mode; };
struct msconnector_runtime_transaction { unsigned marker; };
typedef struct { msconnector_runtime *runtime; int request_body_hooks_enabled; } plugin_data;
typedef struct {
    msconnector_runtime_transaction *transaction;
    int technical_failed, api_failed, request_body_finished, request_intervened;
    int request_body_gate_rejected, response_body_finished;
} handler_ctx;
#define HTTP_VERSION_1_1 1
#define FDEVENT_STREAM_REQUEST 1
#define FDEVENT_STREAM_REQUEST_BUFMIN 2
#define HTTP_HEADER_INCREMENTAL 1
#define HTTP_HEADER_UPGRADE 2
#define CONST_STR_LEN(x) (x), sizeof(x)-1U
static int native_calls, commits, host_calls, decision_calls, read_calls, header_calls;
static char log_buffer[1024];
#define log_error(h,f,l,...) ((void)(h),(void)(f),(void)(l), \
    (void)snprintf(log_buffer,sizeof(log_buffer),__VA_ARGS__))
static handler_t mod_msconnector_fail_request(request_st *r, msconnector_runtime *p,
        handler_ctx *ctx, msconnector_error_code code) {
    (void)r; (void)p; (void)ctx; (void)code; ++host_calls; return HANDLER_ERROR;
}
static handler_t mod_msconnector_apply_decision(request_st *r, const plugin_data *p,
        handler_ctx *ctx, const msconnector_decision *decision) {
    (void)r; (void)p; (void)ctx;
    assert(!msconnector_decision_is_disruptive(decision));
    ++decision_calls;
    return HANDLER_GO_ON;
}
static handler_t http_status_set_err(request_st *r, int status) {
    ++host_calls; r->http_status=status; return HANDLER_FINISHED;
}
static const void *http_header_request_get(request_st *r, int name,
        const char *text, size_t size) {
    (void)r; (void)name; (void)text; (void)size; ++header_calls; return NULL;
}
static handler_t read_body(request_st *r) {
    (void)r; ++read_calls; return HANDLER_GO_ON;
}
enum msconnector_phase4_mode msconnector_runtime_phase4_mode(const msconnector_runtime *r) {
    return r->mode;
}
int msconnector_runtime_transaction_finish_request_body(msconnector_runtime_transaction *t,
        msconnector_decision *d, msconnector_error *e) {
    assert(t != NULL && t->marker == 42U); (void)e; ++native_calls;
    msconnector_decision_init(d); return 1;
}
int msconnector_runtime_transaction_finish_response_body(msconnector_runtime_transaction *t,
        msconnector_decision *d, msconnector_error *e) {
    assert(t != NULL && t->marker == 42U); (void)e; ++native_calls;
    msconnector_decision_init(d); return 1;
}
int msconnector_runtime_transaction_set_response_commit_state_checked(
        msconnector_runtime_transaction *t, int headers, int body, msconnector_error *e) {
    assert(t != NULL && t->marker == 42U); assert(headers == 0 && body == 0);
    (void)e; ++commits; return 1;
}
int msconnector_runtime_transaction_record_host_action(msconnector_runtime_transaction *t,
        const msconnector_decision *d, msconnector_decision_action action, int status,
        const char *transport, int aborted, msconnector_error *e) {
    (void)t; (void)d; (void)action; (void)status; (void)transport; (void)aborted;
    (void)e; ++host_calls; return 1;
}
'''

APR_SEAMS = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
typedef int apr_status_t;
typedef int apr_os_file_t;
typedef size_t apr_size_t;
typedef struct { int fd; } apr_file_t;
#define APR_SUCCESS 0
typedef apr_status_t (*apr_file_write_full_function)(apr_file_t *,const void *,apr_size_t,apr_size_t *);
typedef apr_status_t (*apr_os_file_get_function)(apr_os_file_t *,apr_file_t *);
static _Atomic unsigned fired;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct { apr_file_t *file; int fd; } tracked[256];
static int real_calls, mode_reads, drop_mode;
static const void *expected_buffer;
static char *controlled_getenv(const char *name) {
    if (strcmp(name,"I12_SINK_FAULT") == 0) {
        ++mode_reads;
        if (drop_mode && mode_reads > 2) return NULL;
    }
    return getenv(name);
}
static apr_status_t real_get(apr_os_file_t *fd,apr_file_t *file) {
    assert(file != NULL); *fd=file->fd; return APR_SUCCESS;
}
static apr_status_t real_write(apr_file_t *file,const void *buffer,apr_size_t size,apr_size_t *written) {
    assert(file != NULL && buffer == expected_buffer && size == 7U && written != NULL);
    ++real_calls; *written=3U; errno=EACCES; return 37;
}
static void *symbol(const char *name) {
    if (strcmp(name,"apr_file_write_full") == 0) return (void *)&real_write;
    assert(strcmp(name,"apr_os_file_get") == 0); return (void *)&real_get;
}
#define getenv controlled_getenv
'''


class NativeSonarNullGuardTests(unittest.TestCase):
    def setUp(self):
        from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root
        storage = validate_output_root(ROOT, Path(os.environ["RUNNER_TEMP"]))
        self.temporary = tempfile.TemporaryDirectory(prefix="native-null-unit-", dir=storage)
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def _compile_and_run(self, source, *, common=False, arguments=()):
        path = self.directory / "controlled-native-unit.c"
        path.write_text(source, encoding="utf-8")
        binary = self.directory / "controlled-native-unit"
        command = [*shlex.split(os.environ.get("CC", "cc")), "-std=c17", "-Wall", "-Wextra",
                   "-Werror", "-UNDEBUG", "-pthread", "-I", str(ROOT), "-I", str(source_path('common/include', root=ROOT)), str(path)]
        if common:
            command += [str(source_path('common/src', root=ROOT) / name) for name in COMMON]
        command += ["-o", str(binary)]
        built = subprocess.run(command, capture_output=True, text=True, timeout=60)
        self.assertEqual(built.returncode, 0, built.stderr)
        result = subprocess.run([str(binary), *arguments], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "controlled-native-unit:pass")
        return result

    def _lighttpd(self, operation, null_context, assertion):
        source = (ROOT / LIGHTTPD).read_text()
        definitions = "\n\n".join(function_definition(source, name) for name in LIGHTTPD_FUNCTIONS)
        main = r'''
int main(int argc, char **argv) {
    assert(argc == 3);
    msconnector_runtime runtime={.mode=MSCONNECTOR_PHASE4_MODE_SAFE};
    msconnector_runtime_transaction transaction={.marker=42U};
    handler_ctx ctx={.transaction=&transaction};
    plugin_data p={.runtime=&runtime,.request_body_hooks_enabled=1};
    connection con={.reqbody_read=&read_body};
    request_st r={.http_version=HTTP_VERSION_1_1,.http_status=200,.con=&con};
    handler_ctx *selected = strcmp(argv[2], "null") == 0 ? NULL : &ctx;
    int result;
    if (strcmp(argv[1], "finish-request") == 0)
        result = mod_msconnector_finish_request_body(&r, &p, selected);
    else if (strcmp(argv[1], "prepare-request") == 0)
        result = mod_msconnector_prepare_request_body(&r, &p, selected);
    else {
        assert(strcmp(argv[1], "finish-response") == 0);
        result = mod_msconnector_finish_response_body(&r, &p, selected);
    }
    __ASSERT__
    assert(host_calls == 0 && read_calls == 0 && header_calls == 0);
    assert(log_buffer[0] == '\0' && r.http_status == 200);
    puts("controlled-native-unit:pass"); return 0;
}
'''
        self._compile_and_run(LIGHTTPD_SEAMS + definitions + main.replace(
            "__ASSERT__", assertion), common=True,
            arguments=(operation, "null" if null_context else "normal"))

    def test_lighttpd_finish_request_rejects_null_context(self):
        self._lighttpd("finish-request", True,
                      "assert(result == HANDLER_ERROR && native_calls == 0 && commits == 0 && decision_calls == 0);")

    def test_lighttpd_finish_request_preserves_normal_completion(self):
        self._lighttpd("finish-request", False,
                      "assert(result == HANDLER_GO_ON && native_calls == 1 && commits == 0 && decision_calls == 1);"
                      "assert(ctx.request_body_finished == 1 && ctx.request_intervened == 0);")

    def test_lighttpd_prepare_request_rejects_null_context(self):
        self._lighttpd("prepare-request", True,
                      "assert(result == HANDLER_ERROR && native_calls == 0 && commits == 0 && decision_calls == 0);")

    def test_lighttpd_prepare_request_preserves_empty_body_completion(self):
        self._lighttpd("prepare-request", False,
                      "assert(result == HANDLER_GO_ON && native_calls == 1 && commits == 0 && decision_calls == 1);"
                      "assert(ctx.request_body_finished == 1 && ctx.request_body_gate_rejected == 0);")

    def test_lighttpd_finish_response_rejects_null_context(self):
        self._lighttpd("finish-response", True,
                      "assert(result == PLUGIN_BODY_HOOK_ERROR && native_calls == 0 && commits == 0 && decision_calls == 0);")

    def test_lighttpd_finish_response_preserves_normal_completion(self):
        self._lighttpd("finish-response", False,
                      "assert(result == PLUGIN_BODY_HOOK_CONTINUE && native_calls == 1 && commits == 1 && decision_calls == 0);"
                      "assert(ctx.response_body_finished == 1);")

    def _apr(self, *, missing_root):
        root = self.directory / "apr-files"
        root.mkdir(mode=0o700)
        target = root / "events"
        target.write_bytes(b"controlled unit bytes")
        target.chmod(0o600)
        marker = root / "marker"
        marker.write_text("I12_APACHE_SINK_FAULT_V1\n")
        marker.chmod(0o600)
        source = source_path(APR, root=ROOT).read_text()
        names = ("safe_root", "private_path", "admitted", "exact_path", "exact_fd", "remember", "observe",
                 "apply_fault", "apr_file_write_full")
        start = source.index("struct observation {")
        observation = source[start:source.index("};", start) + 2]
        definitions = "\n\n".join(function_definition(source, name) for name in names)
        main = r'''
#undef getenv
int main(int argc,char **argv) {
    assert(argc == 4);
    assert(setenv("I12_SINK_ROOT",argv[1],1) == 0);
    assert(setenv("I12_SINK_PATH",argv[2],1) == 0);
    assert(setenv("I12_SINK_MARKER",argv[3],1) == 0);
    assert(setenv("I12_SINK_FAULT","closed-descriptor",1) == 0);
    __ENVIRONMENT__
    apr_file_t file={.fd=open(argv[2],O_WRONLY|O_CLOEXEC)};
    assert(file.fd >= 0);
    const char payload[]="payload";
    expected_buffer=payload;
    apr_size_t written=0;
    errno=0;
    apr_status_t status=apr_file_write_full(&file,payload,7U,&written);
    assert(status == 37 && errno == EACCES && written == 3U && real_calls == 1);
    assert(atomic_load(&fired) == 0U && fcntl(file.fd,F_GETFD) >= 0);
    __READ_ASSERTION__
    assert(close(file.fd) == 0);
    puts("controlled-native-unit:pass"); return 0;
}
'''
        environment = 'assert(unsetenv("I12_SINK_ROOT") == 0);' if missing_root else "drop_mode=1;"
        read_assertion = "assert(mode_reads == 1);" if missing_root else "assert(mode_reads == 3);"
        result = self._compile_and_run(APR_SEAMS + observation + definitions + main.replace(
            "__ENVIRONMENT__", environment).replace("__READ_ASSERTION__", read_assertion),
            arguments=(str(root), str(target), str(marker)))
        observations = [json.loads(line.removeprefix("I12_APACHE_APR "))
                        for line in result.stderr.splitlines() if line.startswith("I12_APACHE_APR ")]
        if missing_root:
            self.assertEqual(observations, [])
        else:
            self.assertEqual(len(observations), 1)
            self.assertEqual(observations[0]["stage"], "apr_file_write_full")
            self.assertEqual(observations[0]["action"], "none")
            self.assertEqual(observations[0]["result"], 37)
            self.assertEqual(observations[0]["written_bytes"], 3)
            self.assertEqual(observations[0]["fd_valid_after"], 1)

    def test_apr_missing_root_preserves_real_write_passthrough(self):
        self._apr(missing_root=True)

    def test_apr_missing_mode_after_admission_preserves_real_write_passthrough(self):
        self._apr(missing_root=False)


if os.environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)


if __name__ == "__main__":
    unittest.main()
