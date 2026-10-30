"""Compile actual host decision selection with stale backend framing and output guards."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = connector_root()
MODULE = source_path('connectors/lighttpd/module/mod_msconnector.c', root=ROOT)
PREAMBLE = r'''
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
typedef int handler_t;
enum {HANDLER_GO_ON,HANDLER_ERROR,HANDLER_FINISHED};
enum {MSCONNECTOR_ERROR_HOST_API_FAILURE,MSCONNECTOR_DECISION_ACTION_DENY};
typedef struct {int disruptive,status;} msconnector_decision;
typedef struct {int code;} msconnector_error;
typedef struct {void *runtime;} plugin_data;
typedef struct {int technical_failed,api_failed,host_response_attempted,response_processed;void *transaction;} handler_ctx;
typedef struct {int http_status;struct {off_t bytes_out;} write_queue;
 int stale_length,stale_location,queued_body,resp_body_started,resp_body_finished;struct {void *errh;} conf;} request_st;
static int resets,actions,failures,identity_headers;
static int mod_msconnector_emit_host_transaction_id(request_st *r,const plugin_data *p,const handler_ctx *c){(void)r;(void)p;(void)c;++identity_headers;return 1;}
static int msconnector_decision_is_disruptive(const msconnector_decision *d){return d->disruptive;}
static int msconnector_decision_http_status(const msconnector_decision *d){return d->status;}
static void msconnector_error_init(msconnector_error *e){e->code=0;}
static const char *msconnector_error_code_name(int code){(void)code;return "test";}
static handler_t http_status_set_err(request_st *r,int status){r->http_status=status;return HANDLER_FINISHED;}
static handler_t http_status_set_err_fin(request_st *r,int status){r->resp_body_finished=1;return http_status_set_err(r,status);}
static void http_response_reset(request_st *r){++resets;r->http_status=0;r->stale_length=0;r->stale_location=0;r->queued_body=0;r->resp_body_started=0;}
static handler_t mod_msconnector_fail_request(request_st *r,void *runtime,handler_ctx *c,int code){
 (void)r;(void)runtime;(void)c;(void)code;++failures;return HANDLER_ERROR;
}
static int msconnector_runtime_transaction_record_host_action(void *tx,const msconnector_decision *d,int action,int status,const char *transport,int aborted,msconnector_error *error){
 (void)tx;(void)d;(void)transport;(void)error;assert(action==MSCONNECTOR_DECISION_ACTION_DENY && !aborted && status==403);++actions;return 1;
}
static void log_error(void *errh,const char *file,int line,const char *message,...){(void)errh;(void)file;(void)line;(void)message;}
'''
MAIN = r'''
int main(int argc,char **argv){
 assert(argc==2);int mode=atoi(argv[1]);plugin_data p={0};handler_ctx c={.transaction=&c,.response_processed=1};
 request_st r={.http_status=200,.stale_length=33,.stale_location=1,.queued_body=7,.resp_body_started=1};
 msconnector_decision d={.disruptive=1,.status=mode==1?302:403};
 if(mode==2)r.write_queue.bytes_out=1;
 if(mode==3)c.response_processed=0;
 if(mode==4)d.disruptive=0;
 handler_t result=mod_msconnector_apply_decision(&r,&p,&c,&d);
 if(mode==2){assert(result==HANDLER_ERROR && failures==1 && resets==0 && actions==0 && r.http_status==200);}
 else if(mode==4){assert(result==HANDLER_GO_ON && resets==0 && actions==0);}
 else {assert(result==HANDLER_FINISHED && r.http_status==403 && actions==1 && c.host_response_attempted);
  assert(resets==(mode==3?0:1));
  assert(r.resp_body_finished==(mode==3?0:1));
  assert(identity_headers==(mode==3?0:1));
  if(mode!=3)assert(!r.stale_length && !r.stale_location && !r.queued_body && !r.resp_body_started);
 }
 return 0;
}
'''

class PrecommitResponseReplacementTests(unittest.TestCase):
    def compile_hook(self, directory, mutation=None):
        source = MODULE.read_text()
        hook = "static handler_t mod_msconnector_apply_decision(" + source.split(
            "static handler_t mod_msconnector_apply_decision(", 1)[1].split("\n/*", 1)[0]
        if mutation == "reset":
            hook = hook.replace("http_response_reset(r);", "(void)r;")
        if mutation == "finish":
            hook = hook.replace("http_status_set_err_fin(r, status)", "http_status_set_err(r, status)")
        if mutation == "commit":
            hook = hook.replace("if (r->write_queue.bytes_out > 0)", "if (0)")
        program = Path(directory) / (str(mutation) + ".c")
        program.write_text(PREAMBLE + hook + MAIN)
        binary = program.with_suffix("")
        result = subprocess.run(["cc", "-std=c17", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", str(program), "-o", str(binary)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return binary

    def test_real_decision_clears_backend_state_and_rejects_committed_replacement(self):
        parent = os.environ.get("TMP_ROOT") or os.environ.get("RUNNER_TEMP") or "/var/tmp/codex/ModSecurity-conector"
        with tempfile.TemporaryDirectory(prefix="lighttpd-precommit-", dir=parent) as directory:
            binary = self.compile_hook(directory)
            for mode in range(5):
                result = subprocess.run([str(binary), str(mode)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, f"mode={mode}: {result.stderr}")
            for mutation, mode in (("reset", 0), ("reset", 1), ("commit", 2), ("finish", 1)):
                binary = self.compile_hook(directory, mutation)
                result = subprocess.run([str(binary), str(mode)], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0, mutation)


# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
