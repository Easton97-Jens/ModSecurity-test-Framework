"""Execute patched entity hooks with controlled Common failures, without a host."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = connector_root()

from modsecurity_connector_tests.c_source_contract import function_definition, matching_delimiter


class PatchedAPIResults(unittest.TestCase):
    def test_stock_strict_abort_requires_successful_shutdown(self):
        source = (source_path('connectors/lighttpd/stock_sidecar/stock_sidecar.c', root=ROOT)).read_text()
        start = source.index("if (action == MSCONNECTOR_LATE_INTERVENTION_ABORT_CONNECTION)", source.index("static int sidecar_exchange_response"))
        opening = source.index("{", start)
        branch = source[start:matching_delimiter(source, opening, "{", "}") + 1]
        helper = "\n".join(function_definition(source, name) for name in ("sidecar_shutdown_owned_socket", "sidecar_record_decision_delivery_failure", "sidecar_finish_strict_response"))
        harness = r'''
#include <assert.h>
#include <sys/socket.h>
#include "common/runtime/msconnector_runtime.h"
#include "msconnector/late_intervention.h"
typedef struct {int attempted,succeeded;} sidecar_owned_socket_stop;
typedef struct {sidecar_owned_socket_stop client_stop;int client,handled;msconnector_runtime_transaction *transaction;msconnector_decision decision;msconnector_error error;} state_t;
typedef state_t sidecar_exchange_state;
static int shutdown_result,actions,failures;
int shutdown(int fd,int how) {(void)fd;assert(how==SHUT_RDWR);return shutdown_result;}
int msconnector_runtime_transaction_record_host_action(msconnector_runtime_transaction *t,const msconnector_decision *d,msconnector_decision_action a,int h,const char *s,int b,msconnector_error *e) {(void)t;(void)d;(void)h;(void)s;(void)e;assert(a==MSCONNECTOR_DECISION_ACTION_ABORT_CONNECTION);assert(b==1);++actions;return 1;}
int msconnector_runtime_transaction_fail(msconnector_runtime_transaction *t,msconnector_transaction_error_class c,msconnector_error *e) {(void)t;(void)e;assert(c==MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR);++failures;return 1;}
__HELPER__
int msconnector_runtime_transaction_record_failure_host_action(msconnector_runtime_transaction *t,int h,int b,msconnector_error *e) {(void)t;(void)h;(void)b;(void)e;++actions;return 1;}
int msconnector_runtime_transaction_finish(msconnector_runtime_transaction *t,msconnector_error *e) {(void)t;(void)e;return 1;}
static int exercise(state_t *state,msconnector_late_intervention_action action) {__BRANCH__;return 1;}
int main(void) {state_t state={.transaction=(void*)1};assert(exercise(&state,MSCONNECTOR_LATE_INTERVENTION_ABORT_CONNECTION)==0);assert(actions==1);assert(failures==0);shutdown_result=-1;state.client_stop=(sidecar_owned_socket_stop){0};assert(exercise(&state,MSCONNECTOR_LATE_INTERVENTION_ABORT_CONNECTION)==0);assert(actions==1);assert(failures==1);return 0;}
'''.replace("__BRANCH__", branch).replace("__HELPER__", helper)
        self.compile_and_run(harness)

    def test_stock_failed_delivery_does_not_fabricate_abort(self):
        source = (source_path('connectors/lighttpd/stock_sidecar/stock_sidecar.c', root=ROOT)).read_text()
        functions = "\n".join(function_definition(source, name) for name in (
            "sidecar_shutdown_owned_socket", "sidecar_record_decision_delivery_failure", "sidecar_record_failure_action"))
        harness = r'''
#include <assert.h>
#include "common/runtime/msconnector_runtime.h"
#include <sys/socket.h>
typedef struct {int attempted,succeeded;} sidecar_owned_socket_stop;
static int actions,failures,shutdown_result=-1;
int shutdown(int fd,int how) {(void)fd;assert(how==SHUT_RDWR);return shutdown_result;}
int msconnector_runtime_transaction_record_host_action(msconnector_runtime_transaction *t,const msconnector_decision *d,msconnector_decision_action a,int h,const char *s,int b,msconnector_error *e) {(void)t;(void)d;(void)a;(void)h;(void)s;(void)b;(void)e;++actions;return 1;}
int msconnector_runtime_transaction_record_failure_host_action(msconnector_runtime_transaction *t,int h,int b,msconnector_error *e) {(void)t;(void)e;assert(h==500);assert(b==0);++actions;return 1;}
int msconnector_runtime_transaction_fail(msconnector_runtime_transaction *t,msconnector_transaction_error_class c,msconnector_error *e) {(void)t;(void)e;assert(c==MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR);++failures;return 1;}
__FUNCTIONS__
int main(void) {
 msconnector_runtime_transaction *t=(void*)1;msconnector_error e={0};msconnector_decision d={0};sidecar_owned_socket_stop stop={0};
 sidecar_record_failure_action(7,&stop,t,500,0,&e);assert(actions==0);
 sidecar_record_decision_delivery_failure(7,&stop,t,&d,&e);assert(actions==0);assert(failures==1);
 sidecar_record_failure_action(7,&stop,t,500,1,&e);assert(actions==1);return 0;
}
'''.replace("__FUNCTIONS__", functions)
        self.compile_and_run(harness)

    def test_stock_native_failed_begin_is_not_reopened_by_uri_reentry(self):
        source = (source_path('connectors/lighttpd/module/mod_msconnector.c', root=ROOT)).read_text()
        start = source.index("REQUEST_FUNC(mod_msconnector_handle_uri_clean) {")
        opening = source.index("{", start)
        body = source[opening:matching_delimiter(source, opening, "{", "}") + 1]
        helpers = "\n".join(function_definition(source, name) for name in (
            "mod_msconnector_error_response", "mod_msconnector_fail_request"))
        harness = r'''
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "common/runtime/msconnector_runtime.h"
typedef int handler_t;
enum {HANDLER_GO_ON=0,HANDLER_ERROR=-1,HANDLER_FINISHED=1};
typedef struct {void *plugin_ctx[1];struct {void *errh;} conf;struct {off_t bytes_out;} write_queue;size_t resp_header_len;int http_status;} request_st;
typedef struct {int id;struct {int enabled;} defaults;msconnector_runtime *runtime;size_t header_count_limit,total_header_limit;} plugin_data;
typedef struct {msconnector_runtime_transaction *transaction;msconnector_request request;int request_storage;char host_request_id[96];int request_intervened,api_failed,technical_failed,failure_response_selected,request_body_gate_rejected,host_response_attempted;} handler_ctx;
static handler_ctx mod_msconnector_failed_context={.technical_failed=1};
static int begins,cleanups;
#define log_error(...) ((void)0)
void msconnector_error_init(msconnector_error *e) {memset(e,0,sizeof(*e));}
void msconnector_decision_init(msconnector_decision *d) {memset(d,0,sizeof(*d));}
const char *msconnector_error_code_name(msconnector_error_code c) {(void)c;return "invalid-engine";}
void msconnector_runtime_request_contract(const msconnector_runtime *r,msconnector_request_mapper_contract *c) {(void)r;memset(c,0,sizeof(*c));}
static handler_ctx *handler_ctx_create(plugin_data *p) {(void)p;return calloc(1,sizeof(handler_ctx));}
static void handler_ctx_destroy(handler_ctx **p) {if (*p) {++cleanups;free(*p);*p=0;}}
static handler_t http_status_set_err(request_st *r,int status) {r->http_status=status;return HANDLER_ERROR;}
int msconnector_runtime_error_http_status(const msconnector_runtime *r,msconnector_error_code c) {(void)r;assert(c==MSCONNECTOR_ERROR_MODSECURITY_FAILURE);return 500;}
int msconnector_runtime_transaction_set_response_commit_state_checked(msconnector_runtime_transaction *t,int h,int b,msconnector_error *e) {(void)t;(void)h;(void)b;(void)e;return 1;}
int msconnector_runtime_transaction_fail(msconnector_runtime_transaction *t,msconnector_transaction_error_class c,msconnector_error *e) {(void)t;(void)c;(void)e;return 1;}
int msconnector_runtime_transaction_record_failure_host_action(msconnector_runtime_transaction *t,int h,int b,msconnector_error *e) {(void)t;(void)h;(void)b;(void)e;return 1;}
__HELPERS__
static int lighttpd_modsecurity_map_request(request_st *r,...) {(void)r;return 1;}
int msconnector_runtime_transaction_begin(msconnector_runtime *r,const msconnector_request *q,const char *id,msconnector_runtime_transaction **t,msconnector_decision *d,msconnector_error *e) {(void)r;(void)q;(void)id;(void)t;(void)d;e->code=MSCONNECTOR_ERROR_MODSECURITY_FAILURE;++begins;return 0;}
int msconnector_decision_is_disruptive(const msconnector_decision *d) {(void)d;return 0;}
static handler_t mod_msconnector_apply_decision(request_st *r,plugin_data *p,handler_ctx *c,const msconnector_decision *d) {(void)r;(void)p;(void)c;(void)d;return HANDLER_GO_ON;}
static handler_t uri_clean(request_st *r,void *p_d) __BODY__
int main(void) {
 request_st r={0};plugin_data p={.defaults={.enabled=1},.runtime=(void*)1};
 assert(uri_clean(&r,&p)==HANDLER_ERROR);assert(begins==1);assert(r.plugin_ctx[0]!=0);
 assert(uri_clean(&r,&p)==HANDLER_ERROR);assert(begins==1);
 handler_ctx_destroy((handler_ctx**)&r.plugin_ctx[0]);handler_ctx_destroy((handler_ctx**)&r.plugin_ctx[0]);assert(cleanups==1);return 0;
}
'''.replace("__BODY__", body).replace("__HELPERS__", helpers)
        self.compile_and_run(harness)

    def test_stock_safe_outcome_return_is_propagated(self):
        source = (source_path('connectors/lighttpd/stock_sidecar/stock_sidecar.c', root=ROOT)).read_text()
        start = source.index("if (action == MSCONNECTOR_LATE_INTERVENTION_LOG_ONLY)", source.index("static int sidecar_exchange_response"))
        branch = source[start:source.index("\n    }\n    return 1;", start)]
        harness = r'''
#include <assert.h>
#include "common/runtime/msconnector_runtime.h"
#include "msconnector/late_intervention.h"
typedef struct {msconnector_runtime_transaction *transaction;msconnector_decision decision;msconnector_error error;struct {struct {int status_code;} response_headers;} payload;} state_t;
static int result=1,calls;
int msconnector_runtime_transaction_record_host_action(msconnector_runtime_transaction *t,const msconnector_decision *d,msconnector_decision_action a,int h,const char *s,int b,msconnector_error *e) {(void)t;(void)d;(void)a;(void)h;(void)s;(void)b;(void)e;++calls;return result;}
static void sidecar_record_action(msconnector_runtime_transaction *t,const msconnector_decision *d,msconnector_error *e) {(void)t;(void)d;(void)e;}
static int exercise(state_t *state,msconnector_late_intervention_action action) {__BRANCH__;return 1;}
int main(void) {state_t state={0};assert(exercise(&state,MSCONNECTOR_LATE_INTERVENTION_LOG_ONLY)==1);result=0;assert(exercise(&state,MSCONNECTOR_LATE_INTERVENTION_LOG_ONLY)==0);assert(calls==2);return 0;}
'''
        self.compile_and_run(harness.replace("__BRANCH__", branch))
        mutation = branch.replace("&state->error) != 1) return 0;", "&state->error) == 123) return 0;")
        self.assertNotEqual(mutation, branch)
        self.compile_and_run(harness.replace("__BRANCH__", mutation), should_fail=True)

    def test_stock_declared_length_checks_representation_without_body_policy(self):
        source = (source_path('connectors/lighttpd/stock_sidecar/stock_sidecar.c', root=ROOT)).read_text()
        self.assertNotIn("phase4_effective_body_limit", source)
        self.assertNotIn("phase4_budget.h", source)
        self.assertNotIn("request_body_limit", source)
        parser = function_definition(source, "sidecar_decimal")
        harness = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
__PARSER__
int main(void) {
 char largest[32];size_t value=0;
 assert(snprintf(largest,sizeof(largest),"%zu",SIZE_MAX)>0);
 assert(sidecar_decimal(largest,&value));assert(value==SIZE_MAX);
 assert(!sidecar_decimal("18446744073709551616",&value));
 assert(!sidecar_decimal("42trailing",&value));
 return 0;
}
'''.replace("__PARSER__", parser)
        self.compile_and_run(harness)

    def compile_and_run(self, harness, should_fail=False):
        with tempfile.TemporaryDirectory(prefix="i09-lighttpd-") as tmp:
            path = Path(tmp)
            (path / "test.c").write_text(harness)
            result = subprocess.run([os.environ.get("CC", "cc"), "-std=c17", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT), "-I", str(source_path('common/include', root=ROOT)), str(path / "test.c"), "-o", str(path / "test")], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(path / "test")], cwd=path, capture_output=True, text=True)
            if should_fail:
                self.assertNotEqual(result.returncode, 0, "ignored-result mutation escaped the regression")
            else:
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_checked_commit_stops_append_eos_and_reentry(self):
        source = (source_path('connectors/lighttpd/module/mod_msconnector.c', root=ROOT)).read_text()
        functions = "\n".join(function_definition(source, name) for name in (
            "mod_msconnector_record_api_failure", "mod_msconnector_error_response", "mod_msconnector_fail_request", "mod_msconnector_apply_decision", "mod_msconnector_finish_response_body", "mod_msconnector_handle_response_body", "mod_msconnector_handle_response_abort"))
        harness = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "common/runtime/msconnector_runtime.h"
#include "msconnector/late_intervention.h"
typedef int handler_t;
typedef int plugin_body_hook_result;
typedef int plugin_response_abort_reason;
enum {PLUGIN_RESPONSE_ABORT_UPSTREAM_EOF=1};
enum {HANDLER_GO_ON=0,HANDLER_ERROR=-1,PLUGIN_BODY_HOOK_CONTINUE=0,PLUGIN_BODY_HOOK_ERROR=-1,PLUGIN_BODY_HOOK_ABORT=1};
typedef struct { void *plugin_ctx[1]; struct {void *errh;} conf; int http_status;struct {off_t bytes_out;} write_queue;size_t resp_header_len; } request_st;
typedef struct {int id,response_body_hooks_enabled; msconnector_runtime *runtime;} plugin_data;
typedef struct {msconnector_runtime_transaction *transaction; int request_intervened,response_body_finished,response_processed,api_failed,response_body_aborted,technical_failed,failure_response_selected,host_response_attempted; off_t response_body_next_offset;} handler_ctx;
static int commit_result=1,appends,finishes,commits,failures,disruptive,outcome_result=1,cancellations;
int msconnector_runtime_error_http_status(const msconnector_runtime *r,msconnector_error_code c) {(void)r;(void)c;return 500;}
int msconnector_runtime_transaction_record_failure_host_action(msconnector_runtime_transaction *t,int h,int b,msconnector_error *e) {(void)t;(void)e;assert(h==500 && b==0);return 1;}
static int mod_msconnector_response_headers_committed(const request_st *r) {(void)r;return 0;}
static int mod_msconnector_response_body_committed(const request_st *r) {(void)r;return 0;}
static handler_t mod_msconnector_handle_response_start(request_st *r,plugin_data *p) {(void)r;(void)p;return HANDLER_GO_ON;}
#define log_error(...) ((void)0)
void msconnector_error_init(msconnector_error *e) {memset(e,0,sizeof(*e));}
void msconnector_decision_init(msconnector_decision *d) {memset(d,0,sizeof(*d));}
const char *msconnector_error_code_name(msconnector_error_code c) {(void)c;return "host-api";}
enum msconnector_phase4_mode msconnector_runtime_phase4_mode(const msconnector_runtime *r) {(void)r;return MSCONNECTOR_PHASE4_MODE_OFF;}
int msconnector_runtime_transaction_set_response_commit_state_checked(msconnector_runtime_transaction *t,int h,int b,msconnector_error *e) {(void)t;(void)h;(void)b;++commits;e->code=MSCONNECTOR_ERROR_HOST_API_FAILURE;return commit_result;}
void msconnector_runtime_transaction_set_response_commit_state(msconnector_runtime_transaction *t,int h,int b) {msconnector_error e;(void)msconnector_runtime_transaction_set_response_commit_state_checked(t,h,b,&e);}
int msconnector_runtime_transaction_append_response_body_chunk(msconnector_runtime_transaction *t,const unsigned char *b,size_t n,msconnector_error *e) {(void)t;(void)b;(void)n;(void)e;++appends;return 1;}
int msconnector_runtime_transaction_finish_response_body(msconnector_runtime_transaction *t,msconnector_decision *d,msconnector_error *e) {(void)t;(void)d;(void)e;++finishes;return 1;}
int msconnector_decision_is_disruptive(const msconnector_decision *d) {(void)d;return disruptive;}
int msconnector_decision_http_status(const msconnector_decision *d) {(void)d;return 403;}
static handler_t http_status_set_err(request_st *r,int status) {r->http_status=status;return HANDLER_GO_ON;}
static handler_t http_status_set_err_fin(request_st *r,int status) {return http_status_set_err(r,status);}
static void http_response_reset(request_st *r) {r->http_status=0;}
static int mod_msconnector_emit_host_transaction_id(request_st *r,const plugin_data *p,const handler_ctx *c) {(void)r;(void)p;(void)c;return 1;}
void msconnector_late_intervention_policy_init(msconnector_late_intervention_policy *p) {memset(p,0,sizeof(*p));}
msconnector_late_intervention_action msconnector_late_intervention_resolve(const msconnector_late_intervention_policy *p,int h,int b,int s) {(void)p;(void)h;(void)b;(void)s;return MSCONNECTOR_LATE_INTERVENTION_LOG_ONLY;}
int msconnector_runtime_transaction_record_host_action(msconnector_runtime_transaction *t,const msconnector_decision *d,msconnector_decision_action a,int h,const char *s,int b,msconnector_error *e) {(void)t;(void)d;(void)a;(void)h;(void)s;(void)b;(void)e;return outcome_result;}
int msconnector_runtime_transaction_fail(msconnector_runtime_transaction *t,msconnector_transaction_error_class c,msconnector_error *e) {(void)t;(void)e;assert(c==MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR || c==MSCONNECTOR_TRANSACTION_ERROR_UPSTREAM_DISCONNECT);++failures;return 1;}
int msconnector_runtime_transaction_cancel(msconnector_runtime_transaction *t,int upstream,msconnector_error *e) {(void)t;(void)e;assert(upstream==1);++cancellations;return 1;}
__FUNCTIONS__
int main(void) {
 handler_ctx ctx={.transaction=(void*)1,.response_processed=1};
 request_st r={.plugin_ctx={&ctx},.http_status=200};plugin_data p={.response_body_hooks_enabled=1};
 const unsigned char bytes[]={42};
 assert(mod_msconnector_handle_response_body(&r,bytes,1,0,0,&p)==PLUGIN_BODY_HOOK_CONTINUE);assert(appends==1);assert(finishes==0);
 commit_result=0;
 assert(mod_msconnector_handle_response_body(&r,bytes,1,1,1,&p)==PLUGIN_BODY_HOOK_ERROR);assert(appends==1);assert(finishes==0);
 int before=commits;
 assert(mod_msconnector_handle_response_body(&r,bytes,1,1,1,&p)==PLUGIN_BODY_HOOK_ERROR);assert(commits==before);assert(appends==1);assert(failures==1);
 memset(&ctx,0,sizeof(ctx));ctx.transaction=(void*)1;ctx.response_processed=1;
 assert(mod_msconnector_finish_response_body(&r,&p,&ctx)==PLUGIN_BODY_HOOK_ERROR);assert(finishes==0);
 memset(&ctx,0,sizeof(ctx));ctx.transaction=(void*)1;disruptive=1;outcome_result=0;
 msconnector_decision d={0};assert(mod_msconnector_apply_decision(&r,&p,&ctx,&d)==HANDLER_ERROR);assert(ctx.technical_failed || ctx.api_failed);
 memset(&ctx,0,sizeof(ctx));ctx.transaction=(void*)1;
 assert(mod_msconnector_handle_response_abort(&r,PLUGIN_RESPONSE_ABORT_UPSTREAM_EOF,&p)==PLUGIN_BODY_HOOK_ERROR);assert(cancellations==1);assert(ctx.technical_failed || ctx.api_failed);
 assert(mod_msconnector_handle_response_abort(&r,PLUGIN_RESPONSE_ABORT_UPSTREAM_EOF,&p)==PLUGIN_BODY_HOOK_ERROR);assert(cancellations==1);
 memset(&ctx,0,sizeof(ctx));ctx.transaction=(void*)1;ctx.response_processed=1;ctx.response_body_next_offset=INT64_MAX;
 before=appends;int commits_before=commits;
 assert(mod_msconnector_handle_response_body(&r,bytes,1,INT64_MAX,0,&p)==PLUGIN_BODY_HOOK_ERROR);
 /* The first failure synchronizes host commitment once for typed cleanup;
  * terminal reentry must not perform another synchronization or append. */
 assert(ctx.technical_failed || ctx.api_failed);assert(appends==before);assert(commits==commits_before+1);
 assert(mod_msconnector_handle_response_body(&r,bytes,1,INT64_MAX,1,&p)==PLUGIN_BODY_HOOK_ERROR);
 assert(appends==before);assert(commits==commits_before+1);
 return 0;
}
'''.replace("__FUNCTIONS__", functions)
        self.compile_and_run(harness)


# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
