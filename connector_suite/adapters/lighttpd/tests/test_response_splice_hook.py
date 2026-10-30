"""Compile the actual core patch: a body consumer must observe every entity byte."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

CONNECTOR = source_path('connectors/lighttpd')
PATCH = CONNECTOR / "patches/0001-lighttpd-msconnector-stream-hooks.patch"
SPEC = importlib.util.spec_from_file_location("lighttpd_core_fragments", CONNECTOR / "tests/test_empty_response_eos.py")
FRAGMENTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FRAGMENTS)
UPSTREAM_SPLICE = 'static int http_response_append_splice(request_st * const r, http_response_opts * const opts, buffer * const b, const int fd, unsigned int toread) {\n    /* check if worthwhile to splice() to avoid copying through userspace */\n    /*assert(opts->simple_accum);*//*(checked in caller)*/\n    if (r->resp_body_scratchpad >= toread\n        && (toread > 32768\n            || (toread >= 8192 /*(!http_response_append_buffer_simple_accum())*/\n                && r->write_queue.last && r->write_queue.last->file.is_temp))) {\n\n        if (!buffer_is_blank(b)) {\n            /*(flush small reads previously accumulated in b)*/\n            int rc = http_response_append_buffer(r, b, 0); /*(0 to flush)*/\n            chunk_buffer_yield(b); /*(improve large buf reuse)*/\n            if (__builtin_expect( (0 != rc), 0)) return -1; /* error */\n        }\n\n        /*assert(opts->fdfmt == S_IFSOCK || opts->fdfmt == S_IFIFO);*/\n        ssize_t n = (opts->fdfmt == S_IFSOCK)\n          ? chunkqueue_append_splice_sock_tempfile(\n              &r->write_queue, fd, toread, r->conf.errh)\n          : chunkqueue_append_splice_pipe_tempfile(\n              &r->write_queue, fd, toread, r->conf.errh);\n        if (__builtin_expect( (n >= 0), 1)) {\n            if (0 == (r->resp_body_scratchpad -= n))\n                r->resp_body_finished = 1;\n            return 1; /* success */\n        }\n        else if (n != -EINVAL)\n            return -1; /* error */\n        /*(fall through; target filesystem w/o splice() support)*/\n    }\n    return 0; /* not handled */\n}'
PREAMBLE = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
enum {HTTP_VERSION_1_1=11,PLUGIN_BODY_HOOK_CONTINUE=0,S_IFSOCK=1,PLUGIN_FUNC_HANDLE_RESPONSE_BODY=0};
typedef int plugin_body_hook_result;
typedef struct {int is_temp;} file_info;
typedef struct {file_info file;} chunk;
typedef struct {chunk *last;} chunkqueue;
typedef struct {void *plugin_slots;} connection;
typedef struct {connection *con;chunkqueue write_queue;struct {void *errh;} conf;
 int http_version,resp_body_entity_hook_eos_sent,resp_body_entity_hook_suppressed,resp_body_finished;
 off_t resp_body_entity_hook_next_offset,resp_body_scratchpad;} request_st;
typedef struct {int fdfmt;} http_response_opts;
typedef struct {int blank;} buffer;
static int splices,body_calls,eos_calls,callback_error;
static size_t body_bytes;
static int buffer_is_blank(buffer *b){return b->blank;}
static int http_response_append_buffer(request_st *r,buffer *b,int eos){(void)r;(void)b;(void)eos;return 0;}
static void chunk_buffer_yield(buffer *b){(void)b;}
static ssize_t chunkqueue_append_splice_sock_tempfile(chunkqueue *q,int fd,unsigned int size,void *errh){(void)q;(void)fd;(void)errh;++splices;return size;}
static ssize_t chunkqueue_append_splice_pipe_tempfile(chunkqueue *q,int fd,unsigned int size,void *errh){return chunkqueue_append_splice_sock_tempfile(q,fd,size,errh);}
static plugin_body_hook_result plugins_call_handle_response_body(request_st *r,const unsigned char *data,size_t length,off_t offset,int eos){
 (void)r;(void)data;assert(offset==(off_t)body_bytes);++body_calls;body_bytes+=length;eos_calls+=eos;return callback_error;
}
'''
MAIN = r'''
int main(int argc,char **argv){
 assert(argc==2);int mode=argv[1][0]-'0';uint16_t slots[]={mode==1?0:16};connection con={.plugin_slots=slots};
 request_st r={.con=&con,.http_version=11,.resp_body_scratchpad=65536};http_response_opts opts={.fdfmt=S_IFSOCK};buffer b={.blank=1};
 int result=http_response_append_splice(&r,&opts,&b,3,65536);
 if(mode==1){assert(result==1 && splices==1 && r.resp_body_finished && body_calls==0);return 0;}
 assert(result==0 && splices==0 && !r.resp_body_finished);
 const unsigned char body[16]={0};
 if(mode==2){callback_error=-1;assert(http_chunk_msconnector_entity_body(&r,body,6,0)==-1);assert(!r.resp_body_entity_hook_eos_sent && eos_calls==0);return 0;}
 assert(http_chunk_msconnector_entity_body(&r,body,6,0)==0);
 assert(http_chunk_msconnector_entity_body(&r,body+6,10,0)==0);
 assert(http_chunk_msconnector_entity_close(&r)==0);
 assert(http_chunk_msconnector_entity_close(&r)==0);
 assert(body_bytes==16 && eos_calls==1 && body_calls==3 && r.resp_body_entity_hook_next_offset==16);
 return 0;
}
'''

class ResponseSpliceHookTests(unittest.TestCase):
    def compile_case(self, root, mutation=False):
        patch = PATCH.read_text()
        glue = FRAGMENTS.target_fragment(patch, "src/http-header-glue.c")
        splice = FRAGMENTS.function(glue, "http_response_append_splice") if "http_response_append_splice" in glue else UPSTREAM_SPLICE
        plugin = FRAGMENTS.target_fragment(patch, "src/plugin.c")
        query = FRAGMENTS.function(plugin, "plugins_response_body_hook_registered") if "plugins_response_body_hook_registered" in plugin else "int plugins_response_body_hook_registered(const request_st *r){return ((const uint16_t *)r->con->plugin_slots)[PLUGIN_FUNC_HANDLE_RESPONSE_BODY]!=0;}"
        if mutation:
            splice = splice.replace("if (plugins_response_body_hook_registered(r))", "if (0)")
        chunks = FRAGMENTS.target_fragment(patch, "src/http_chunk.c")
        body = FRAGMENTS.function(chunks, "http_chunk_msconnector_entity_body")
        close = FRAGMENTS.function(chunks, "http_chunk_msconnector_entity_close")
        program = root / ("mutant.c" if mutation else "actual.c")
        program.write_text(PREAMBLE + query + splice + body + close + MAIN)
        binary = program.with_suffix("")
        result = subprocess.run(["cc", "-std=c17", "-Wall", "-Wextra", "-Werror", str(program), "-o", str(binary)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return binary

    def test_consumer_uses_observed_ranges_and_no_consumer_preserves_splice(self):
        parent = Path(os.environ.get("TMP_ROOT") or os.environ.get("RUNNER_TEMP") or "/var/tmp/codex/ModSecurity-conector/tmp")
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="lighttpd-splice-", dir=parent) as directory:
            binary = self.compile_case(Path(directory))
            for mode in range(3):
                result = subprocess.run([str(binary), str(mode)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, f"mode={mode}: {result.stderr}")
            mutant = self.compile_case(Path(directory), mutation=True)
            result = subprocess.run([str(mutant), "0"], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)


# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
