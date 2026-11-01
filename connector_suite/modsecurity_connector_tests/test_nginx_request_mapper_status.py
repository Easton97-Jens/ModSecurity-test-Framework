"""Compile the real NGX mapper/caller and Common validator at host pool seams."""
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
MAPPER = source_path('connectors/nginx/src/ngx_http_modsecurity_mapper.c', root=ROOT)
ACCESS = source_path('connectors/nginx/src/ngx_http_modsecurity_access.c', root=ROOT)
PREAMBLE = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "msconnector/request_mapper_contract.h"
#include "msconnector/request_helpers.h"
#include "msconnector/headers.h"
typedef unsigned char u_char;
typedef int ngx_int_t;
typedef unsigned ngx_uint_t;
typedef struct { int unused; } ngx_pool_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct { ngx_str_t key, value; } ngx_table_elt_t;
typedef struct list_part_s { void *elts; unsigned nelts; struct list_part_s *next; } ngx_list_part_t;
typedef struct { ngx_list_part_t part; } ngx_list_t;
typedef struct { ngx_str_t addr_text; void *sockaddr, *local_sockaddr, *log; } ngx_connection_t;
typedef struct { ngx_pool_t *pool; struct { ngx_list_t headers; } headers_in;
                 ngx_str_t method_name, unparsed_uri, http_protocol;
                 ngx_connection_t *connection; unsigned http_version; } ngx_http_request_t;
enum { NGX_OK=0, NGX_LOG_ERR=4, NGX_HTTP_BAD_REQUEST=400, NGX_HTTP_INTERNAL_SERVER_ERROR=500,
       NGX_HTTP_VERSION_9=9, NGX_HTTP_VERSION_10=10, NGX_HTTP_VERSION_11=11, NGX_SOCKADDR_STRLEN=64 };
#define ngx_memcpy memcpy
#define ngx_strlen strlen
#define ngx_strncmp(left,right,size) strncmp((const char *)(left),(const char *)(right),size)
static int fault_mode, allocation_fail, allocations;
static size_t selected_header_limit = 1024;
static void *allocated[32];
static void *ngx_pnalloc(ngx_pool_t *pool, size_t size) {
    (void)pool; ++allocations;
    if (allocations == allocation_fail) return NULL;
    void *value=malloc(size); allocated[allocations-1]=value; return value;
}
static void *ngx_pcalloc(ngx_pool_t *pool, size_t size) {
    void *value=ngx_pnalloc(pool,size); if (value) memset(value,0,size); return value;
}
static int ngx_inet_get_port(void *address) { (void)address; return 1234; }
static int ngx_connection_local_sockaddr(ngx_connection_t *connection, ngx_str_t *local, int port) {
    (void)connection; (void)port; memcpy(local->data,"127.0.0.1",9); local->len=9; return NGX_OK;
}
static void ngx_log_error(int level, void *log, int error, const char *format, ...) {
    (void)level; (void)log; (void)error; (void)format;
}
int actual_mapper_validate(const msconnector_request_mapper_contract *,const msconnector_request *,char *,size_t);
void actual_contract_init(msconnector_request_mapper_contract *);
int msconnector_request_mapper_validate_output(const msconnector_request_mapper_contract *contract,
        const msconnector_request *request, char *error, size_t size) {
    msconnector_request injected=*request;
    if (fault_mode==1) { injected.body.size=1; injected.body.data=NULL; }
    if (fault_mode==2) { injected.header_count=1; injected.headers=NULL; }
    return actual_mapper_validate(contract,&injected,error,size);
}
void msconnector_request_mapper_contract_init(msconnector_request_mapper_contract *contract) {
    actual_contract_init(contract); contract->max_header_count=selected_header_limit;
}
'''
MAIN = r'''
int main(int argc, char **argv) {
    if (argc != 5) return 2;
    fault_mode=atoi(argv[1]); allocation_fail=atoi(argv[2]);
    unsigned header_count=(unsigned)atoi(argv[3]); selected_header_limit=(size_t)atoi(argv[4]);
    ngx_table_elt_t *headers=calloc(header_count ? header_count : 1,sizeof(*headers));
    if (headers==NULL) return 3;
    for (unsigned i=0;i<header_count;++i) {
        headers[i].key=i == 0 ? (ngx_str_t){4,(u_char *)"Host"} : (ngx_str_t){6,(u_char *)"X-Test"};
        headers[i].value=(ngx_str_t){9,(u_char *)"localhost"};
    }
    ngx_pool_t pool={0}; ngx_connection_t connection={{9,(u_char *)"127.0.0.1"},NULL,NULL,NULL};
    ngx_http_request_t request={&pool,{{{headers,header_count,NULL}}},
        {4,(u_char *)"POST"},{1,(u_char *)"/"},{8,(u_char *)"HTTP/1.1"},&connection,11};
    int result=ngx_http_modsecurity_validate_common_request_mapper(&request);
    printf("{\"result\":%d,\"allocations\":%d}\n",result,allocations);
    for (int i=0;i<allocations && i<32;++i) free(allocated[i]);
    free(headers); return 0;
}
'''


class NginxRequestMapperStatusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="ngx-mapper-status-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        compiler = shlex.split(os.environ.get("CC", "cc"))
        validator = directory / "validator.o"
        argv = compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror", "-I", str(source_path('common/include', root=ROOT)),
                           "-Dmsconnector_request_mapper_validate_output=actual_mapper_validate",
                           "-Dmsconnector_request_mapper_contract_init=actual_contract_init", "-c",
                           str(source_path('common/src/request_mapper_contract.c', root=ROOT)), "-o", str(validator)]
        compiled = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=30)
        if compiled.returncode:
            raise AssertionError(compiled.stderr)
        source = MAPPER.read_text()
        helpers = ("ngx_http_modsecurity_mapper_error", "ngx_http_modsecurity_pool_strndup",
                   "ngx_http_modsecurity_pool_cstrdup", "ngx_http_modsecurity_http_version",
                   "ngx_http_modsecurity_count_list_headers", "ngx_http_modsecurity_copy_headers",
                   "ngx_http_modsecurity_request_hostname", "ngx_http_modsecurity_map_request")
        # Keep the real signatures: the extractor starts at each function's own line.
        fragments = []
        for name in helpers:
            definition = function_definition(source, name)
            if definition.startswith(name + "("):
                definition = "int " + definition
            fragments.append(definition)
        request_init = function_definition((source_path('common/src/request_helpers.c', root=ROOT)).read_text(), "msconnector_request_init")
        caller = function_definition(ACCESS.read_text(), "ngx_http_modsecurity_validate_common_request_mapper")
        if caller.startswith("ngx_http_modsecurity_validate_common_request_mapper("):
            caller = "static ngx_int_t\n" + caller
        fixture = directory / "fixture.c"
        fixture.write_text(PREAMBLE + "\n" + request_init + "\n" + "\n".join(fragments) + "\n" + caller + "\n" + MAIN)
        cls.binary = directory / "mapper-status"
        argv = compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror", "-I", str(source_path('common/include', root=ROOT)),
                           str(fixture), str(validator), str(source_path('common/src/headers.c', root=ROOT)), "-o", str(cls.binary)]
        compiled = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=30)
        if compiled.returncode:
            raise AssertionError(compiled.stderr[-6000:])

    def probe(self, fault=0, allocation=0, headers=1, limit=1024):
        result = subprocess.run([str(self.binary), *map(str, (fault, allocation, headers, limit))],
                                check=True, capture_output=True, text=True, timeout=5)
        return json.loads(result.stdout)

    def test_valid_mapping_is_accepted(self):
        self.assertEqual(self.probe()["result"], 0)

    def test_internal_missing_body_and_header_pointers_are_server_errors(self):
        for fault in (1, 2):
            with self.subTest(fault=fault):
                self.assertEqual(self.probe(fault=fault)["result"], 500)

    def test_host_pool_allocation_failures_are_server_errors(self):
        for allocation in range(1, 9):
            with self.subTest(allocation=allocation):
                self.assertEqual(self.probe(allocation=allocation)["result"], 500)

    def test_client_header_count_limit_remains_bad_request(self):
        self.assertEqual(self.probe(headers=1025)["result"], 400)
        self.assertEqual(self.probe(headers=1024)["result"], 0)

    def test_zero_header_limit_preserves_existing_contract(self):
        self.assertEqual(self.probe(headers=1025, limit=0)["result"], 0)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
