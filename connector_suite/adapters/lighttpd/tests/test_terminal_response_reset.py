"""Compile the real reset hook and reject synthetic EOS after a P3 intervention."""
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
enum { HANDLER_GO_ON, HANDLER_ERROR };
typedef struct {int code;} msconnector_error;
typedef struct {int id,response_body_hooks_enabled;} plugin_data;
typedef struct {
 void *transaction;
 int technical_failed,api_failed,response_processed,response_body_finished;
 int response_body_aborted,request_body_gate_rejected,host_response_attempted;
} handler_ctx;
typedef struct {void *plugin_ctx[1];struct {void *errh;} conf;
 struct {off_t bytes_out;} write_queue;size_t resp_header_len;} request_st;
#define REQUEST_FUNC(name) handler_t name(request_st *r,void *p_d)
static int unobserved,finished,rejected,destroyed,diagnostics,fail_unobserved,commits;
static void msconnector_error_init(msconnector_error *e){e->code=0;}
static const char *msconnector_error_code_name(int code){(void)code;return "control";}
static int msconnector_runtime_transaction_set_response_commit_state_checked(void *t,int h,int b,msconnector_error *e){
 (void)t;(void)e;assert(h==0 && b==0);++commits;return 1;
}
static void log_error(void *h,const char *f,int l,const char *message,...){
 (void)h;(void)f;(void)l;(void)message;++diagnostics;
}
static handler_t mod_msconnector_finish_uninspected_response_body(request_st *r,handler_ctx *c){
 (void)r;++unobserved;
 /* Runtime forbids body completion after the already applied terminal decision. */
 return c->host_response_attempted || fail_unobserved ? HANDLER_ERROR : HANDLER_GO_ON;
}
static int msconnector_runtime_transaction_finish(void *t,msconnector_error *e){
 (void)t;(void)e;++finished;return 1;
}
static int msconnector_runtime_transaction_finish_host_rejected_request_body(void *t,msconnector_error *e){
 (void)t;(void)e;++rejected;return 1;
}
static void handler_ctx_destroy(handler_ctx **c){++destroyed;*c=NULL;}
'''
MAIN = r'''
int main(int argc,char **argv){
 assert(argc==2);int mode=atoi(argv[1]);
 handler_ctx c={.transaction=&c,.response_processed=1};plugin_data p={0};
 request_st r={.plugin_ctx={&c}};
 if(mode==1 || mode==3)c.host_response_attempted=1;
 if(mode==2 || mode==3)p.response_body_hooks_enabled=1;
 if(mode==4)c.technical_failed=1;
 if(mode==5)fail_unobserved=1;
 if(mode==6 || mode==7)c.response_processed=0;
 if(mode==7)c.request_body_gate_rejected=1;
 handler_t result=mod_msconnector_handle_request_reset(&r,&p);
 assert(destroyed==1 && r.plugin_ctx[0]==NULL);
 assert(commits==((mode==0 || mode==2 || mode==5)?1:0));
 assert(c.response_body_finished==0); /* reset never invents EOS in this hook */
 if(mode==2 || mode==4 || mode==5){assert(result==HANDLER_ERROR && finished==0);}
 else {assert(result==HANDLER_GO_ON && finished==(mode==7?0:1));}
 assert(rejected==(mode==7?1:0));
 assert(unobserved==(mode==0 || mode==5?1:0));
 assert(diagnostics==(mode==2 || mode==5?1:0));
 return 0;
}
'''


class TerminalResponseResetTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(
            prefix="lighttpd-terminal-reset-", dir=os.environ.get("RUNNER_TEMP"))
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)
        self.hook = MODULE.read_text().rsplit("REQUEST_FUNC(mod_msconnector_handle_request_reset)", 1)[1]
        self.hook = "REQUEST_FUNC(mod_msconnector_handle_request_reset)" + self.hook.split(
            "int mod_msconnector_plugin_init", 1)[0]

    def compile_hook(self, patched, *, mutation=False):
        hook = self.hook
        if mutation:
            hook = hook.replace("!ctx->host_response_attempted &&", "")
        source = self.work / ("patched.c" if patched else "stock.c")
        source.write_text(PREAMBLE + hook + MAIN)
        binary = source.with_suffix("")
        command = ["cc", "-std=c17", "-Wall", "-Wextra", "-Werror"]
        if patched:
            command.append("-DLIGHTTPD_MSCONNECTOR_STREAM_HOOK_ABI_VERSION=1")
        result = subprocess.run([*command, str(source), "-o", str(binary)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return binary

    def test_terminal_allow_missing_eos_and_failure_paths(self):
        for patched in (False, True):
            binary = self.compile_hook(patched)
            for mode in ((0, 1, 4, 5, 6, 7) if not patched else range(8)):
                with self.subTest(patched=patched, mode=mode):
                    result = subprocess.run([str(binary), str(mode)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_removing_terminal_guard_reproduces_the_regression(self):
        for patched in (False, True):
            binary = self.compile_hook(patched, mutation=True)
            result = subprocess.run([str(binary), "1"], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
