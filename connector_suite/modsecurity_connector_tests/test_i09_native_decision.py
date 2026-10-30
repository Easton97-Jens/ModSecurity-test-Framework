"""Execute the Common libModSecurity collector with controlled native results."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from modsecurity_connector_tests.c_source_contract import function_definition
from modsecurity_connector_tests.test_i09_common_routes import SOURCES
from modsecurity_connector_tests.test_runtime_event_sink_failures import INCLUDES

ROOT = connector_root()


class NativeDecisionTests(unittest.TestCase):
    def test_connection_header_and_logging_native_results(self) -> None:
        source = (source_path('common/runtime/msconnector_runtime.c', root=ROOT)).read_text()
        types = source[source.index("#define RUNTIME_NAME_SIZE"):source.index("static void set_text_error")]
        includes = INCLUDES[:INCLUDES.index("static int audit_calls, cleanup_calls;")]
        fixture = includes + r'''
static int result, target, calls, decisions;
static int value(void) { return ++calls == target ? result : 1; }
static int msc_process_connection(Transaction *t, const char *a, int ap, const char *b, int bp) {
    (void)t; (void)a; (void)ap; (void)b; (void)bp; return value();
}
static int msc_process_uri(Transaction *t, const char *u, const char *m, const char *v) {
    (void)t; (void)u; (void)m; (void)v; return value();
}
static int msc_set_request_hostname(Transaction *t, const unsigned char *h) {
    (void)t; (void)h; return value();
}
static int msc_add_n_request_header(Transaction *t, const unsigned char *n, size_t ns,
        const unsigned char *v, size_t vs) {
    (void)t; (void)n; (void)ns; (void)v; (void)vs; return value();
}
static int msc_add_n_response_header(Transaction *t, const unsigned char *n, size_t ns,
        const unsigned char *v, size_t vs) {
    return msc_add_n_request_header(t,n,ns,v,vs);
}
static int msc_process_request_headers(Transaction *t) { (void)t; return value(); }
static int msc_process_response_headers(Transaction *t, int s, const char *v) {
    (void)t; (void)s; (void)v; return value();
}
static int msc_process_logging(Transaction *t) { (void)t; return value(); }
''' + types + r'''
static int native_decision(const msconnector_runtime *r, msconnector_native_transaction *t,
        enum msconnector_phase p, msconnector_decision *d, msconnector_error *e) {
    (void)r; (void)t; (void)e; ++decisions; msconnector_decision_set_allow(d); d->phase=p; return 1;
}
'''
        fixture += "\n".join(function_definition(source, name) for name in (
            "runtime_error", "string_is_empty", "http_version_without_prefix",
            "native_process_connection", "native_process_request_headers",
            "native_process_response_headers", "native_process_logging"))
        fixture += r'''
int main(void) {
    msconnector_runtime runtime = {0}; msconnector_native_transaction native = {0};
    msconnector_error error; msconnector_decision decision;
    msconnector_header header = {.name="x", .name_size=1, .value="y", .value_size=1};
    msconnector_request request = {.uri="/", .method="GET", .http_version="HTTP/1.1",
        .hostname="example.test", .headers=&header, .header_count=1};
    msconnector_response response = {.status=200, .http_version="HTTP/1.1",
        .headers=&header, .header_count=1};
    const int values[] = {-1,0,1,2,17};
    for (int operation=0; operation<4; ++operation) {
        int steps = operation == 0 ? 3 : operation == 3 ? 1 : 2;
        for (target=1; target<=steps; ++target) {
            for (size_t i=0; i<sizeof(values)/sizeof(values[0]); ++i) {
                result=values[i]; calls=decisions=0; msconnector_error_init(&error);
                int ok = operation==0 ? native_process_connection(&runtime,&native,&request,&decision,&error) :
                    operation==1 ? native_process_request_headers(&runtime,&native,&request,&decision,&error) :
                    operation==2 ? native_process_response_headers(&runtime,&native,&response,&decision,&error) :
                    native_process_logging(&runtime,&native,&error);
                if (ok != (result==1) || calls != (result==1 ? steps : target)) return 1;
                if (decisions != (operation!=3 && result==1)) return 2;
                if (error.code != (result==1 ? MSCONNECTOR_ERROR_NONE : MSCONNECTOR_ERROR_MODSECURITY_FAILURE)) return 3;
            }
        }
    }
    return 0;
}
'''
        self.compile_and_execute(fixture)

    def compile_and_execute(self, fixture: str) -> None:
        with tempfile.TemporaryDirectory(prefix="i09-native-", dir=os.environ.get("RUNNER_TEMP")) as tmp:
            directory = Path(tmp)
            path, binary = directory / "native.c", directory / "native"
            path.write_text(fixture)
            command = shlex.split(os.environ.get("CC", "cc")) + [
                "-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread",
                "-I", str(source_path('common/include', root=ROOT)), "-I", str(ROOT), str(path)]
            command += [str(source_path('common/src', root=ROOT) / name) for name in SOURCES]
            command += [str(source_path('connectors/profile_registry.c', root=ROOT)), "-o", str(binary)]
            compiled = subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            executed = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)

    def test_exact_intervention_results_and_stale_metadata(self) -> None:
        source = (source_path('common/runtime/msconnector_runtime.c', root=ROOT)).read_text()
        types = source[source.index("#define RUNTIME_NAME_SIZE"):source.index("static void set_text_error")]
        functions = "\n".join(function_definition(source, name) for name in (
            "runtime_error", "native_is_request_body_limit_rejection",
            "native_copy_redirect_target", "native_capture_rule_id", "native_decision"))
        # Only the libModSecurity call/cleanup seam is replaced. Collector,
        # decision normalization and rule-id parsing are production code.
        includes = INCLUDES[:INCLUDES.index("static int audit_calls, cleanup_calls;")]
        fixture = includes + r'''
#include "msconnector/native_result.h"
#include "msconnector/rule_id.h"
typedef struct { int status; char *url; char *log; int disruptive; } ModSecurityIntervention;
static int result, disruptive, cleanups;
static int msc_intervention(Transaction *tx, ModSecurityIntervention *value) {
    (void)tx; value->status = 403; value->log = "[id \"1001\"]";
    value->disruptive = disruptive; return result;
}
static void msc_intervention_cleanup(ModSecurityIntervention *value) {
    (void)value; ++cleanups;
}
''' + types + functions + r'''
int main(void) {
    msconnector_runtime runtime = {0};
    msconnector_native_transaction native = {0};
    msconnector_decision decision;
    msconnector_error error;
    const int values[] = {-1, 0, 1, 2, 17};
    runtime.config.default_block_status = 403;
    for (size_t i = 0; i < sizeof(values)/sizeof(values[0]); ++i) {
        for (disruptive = 0; disruptive <= 1; ++disruptive) {
            result = values[i]; cleanups = 0;
            strcpy(native.rule_id, "stale"); strcpy(native.reason, "stale");
            strcpy(native.redirect_url, "stale");
            msconnector_error_init(&error);
            msconnector_decision_set_allow(&decision);
            int ok = native_decision(&runtime, &native, MSCONNECTOR_PHASE_REQUEST_HEADERS,
                &decision, &error);
            if (cleanups != 1 || ok != (result == 0 || result == 1)) return 1;
            if (result != 0 && result != 1) {
                if (error.code != MSCONNECTOR_ERROR_MODSECURITY_FAILURE ||
                    decision.status != MSCONNECTOR_STATUS_OK) return 2;
            } else if (result == 0 || !disruptive) {
                if (decision.status != MSCONNECTOR_STATUS_OK || native.rule_id[0] ||
                    native.reason[0] || native.redirect_url[0]) return 3;
            } else {
                if (decision.status != MSCONNECTOR_STATUS_BLOCKED ||
                    strcmp(decision.rule_id, "1001") != 0 || decision.http_status != 403) return 4;
            }
        }
    }
    return 0;
}
'''
        self.compile_and_execute(fixture)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
