"""Source-bound technical-event controls, not runtime or invented rule evidence."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from modsecurity_connector_tests.c_source_contract import function_definition

ROOT = connector_root()
PREAMBLE = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "msconnector/event_jsonl.h"
#include "msconnector/transaction_state.h"
#include "connectors/profile_registry.h"
typedef long ngx_int_t;
typedef struct { void *log; } connection_t;
typedef struct { unsigned status; } headers_t;
typedef struct { connection_t *connection; int header_sent; headers_t headers_out; } ngx_http_request_t;
typedef struct { int fd; } ngx_open_file_t;
typedef struct { ngx_open_file_t *phase4_log_file; } ngx_http_modsecurity_conf_t;
typedef struct { unsigned len; unsigned char *data; } ngx_str_t;
typedef struct { ngx_str_t event_transaction_id; } ngx_http_modsecurity_ctx_t;
typedef struct { const char *method,*uri,*content_type; } ngx_http_modsecurity_event_request_metadata_t;
enum { NGX_OK=0,NGX_ERROR=-1,NGX_INVALID_FILE=-1 };
static int ngx_http_modsecurity_module;
static ngx_http_modsecurity_conf_t config;
static ngx_http_modsecurity_conf_t *ngx_http_get_module_loc_conf(ngx_http_request_t *r,int module) {
    (void)r;(void)module;return &config;
}
static ngx_http_modsecurity_event_request_metadata_t ngx_http_modsecurity_event_request_metadata(ngx_http_request_t *r) {
    (void)r;return (ngx_http_modsecurity_event_request_metadata_t){"GET","/actual-fault", ""};
}
static ngx_int_t ngx_http_modsecurity_write_phase_event_jsonl(ngx_http_request_t *r,
    const ngx_http_modsecurity_conf_t *conf,const msconnector_event *event,const char *phase) {
    char line[4096];int truncated=0;
    (void)r;(void)conf;
    if (strcmp(phase,"technical") != 0) abort();
    if (!msconnector_event_write_jsonl_line(event,line,sizeof(line),&truncated) || truncated) return NGX_ERROR;
    fputs(line,stdout);return NGX_OK;
}
'''
MAIN = r'''
int main(int argc,char **argv) {
    connection_t connection={0};static ngx_open_file_t file={7};
    ngx_http_request_t request={&connection,0,{0}};
    ngx_http_modsecurity_ctx_t context={{9,(unsigned char *)"actual-tx"}};
    if (argc != 2) return 2;
    config.phase4_log_file=&file;
    switch (atoi(argv[1])) {
    case 1:
        context.event_transaction_id.len=0;
        return ngx_http_modsecurity_log_technical_failure(&request,&context,
            MSCONNECTOR_PHASE_REQUEST_HEADERS,MSCONNECTOR_TRANSACTION_ERROR_PROTOCOL,500) != NGX_OK;
    case 2:
        return ngx_http_modsecurity_log_technical_failure(&request,&context,
            MSCONNECTOR_PHASE_REQUEST_HEADERS,MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR,500) != NGX_OK;
    case 3:
        request.header_sent=1;request.headers_out.status=200;
        return ngx_http_modsecurity_log_technical_failure(&request,&context,
            MSCONNECTOR_PHASE_LOGGING,MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE,0) != NGX_OK;
    case 4: {
        msconnector_transaction_contract contract;
        request.header_sent=1;request.headers_out.status=200;
        if (msconnector_transaction_contract_init(&contract,
            msconnector_profile_registry_find("nginx"),"technical-control","nginx","actual-tx",
            MSCONNECTOR_TRANSACTION_MODE_SAFE,100U) != 0) return 4;
        for (enum msconnector_phase phase=MSCONNECTOR_PHASE_REQUEST_HEADERS;
             phase<=MSCONNECTOR_PHASE_REQUEST_BODY;++phase) {
            if (msconnector_transaction_contract_begin_phase(&contract,phase,0U) != 0 ||
                msconnector_transaction_contract_complete_phase(&contract,phase,0U) != 0) return 5;
        }
        if (msconnector_transaction_contract_finish(&contract,0U) !=
                MSCONNECTOR_TRANSACTION_TRANSITION_SKIPPED_PHASE ||
            contract.error_class != MSCONNECTOR_TRANSACTION_ERROR_PHASE_SEQUENCE ||
            contract.engine_decision != MSCONNECTOR_TRANSACTION_DECISION_PROTOCOL_ERROR) return 6;
        return ngx_http_modsecurity_log_technical_failure(&request,&context,
            MSCONNECTOR_PHASE_LOGGING,contract.error_class,0) != NGX_OK;
    }
    default:return 3;
    }
}
'''


class NativeTechnicalEventsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which(os.environ.get("CC", "cc"))
        if compiler is None:
            raise RuntimeError("real C17 compiler is required")
        temporary = tempfile.TemporaryDirectory(prefix="nginx-technical-events-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        path = Path(temporary.name)
        module = (source_path('connectors/nginx/src/ngx_http_modsecurity_module.c', root=ROOT)).read_text()
        source = path / "events.c"
        source.write_text(PREAMBLE + "ngx_int_t\n" + function_definition(module, "ngx_http_modsecurity_log_technical_failure") + MAIN)
        cls.binary = path / "events"
        command = [compiler, "-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread",
                   "-I", str(ROOT), "-I", str(source_path('common/include', root=ROOT)), str(source)]
        command.extend(str(source_path('common/src', root=ROOT) / name) for name in
                       ("transaction_state.c", "decision_action.c", "intervention.c", "block_statuses.c",
                        "late_intervention.c", "event.c", "event_jsonl.c", "json_escape.c", "status.c", "http_status.c"))
        command += [str(source_path('connectors/profile_registry.c', root=ROOT)), "-o", str(cls.binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
        if result.returncode:
            raise AssertionError(result.stderr[-5000:])

    def observe(self, mode):
        result = subprocess.run([str(self.binary), str(mode)], capture_output=True, text=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_unadmitted_invalid_identity_is_not_invented_transaction(self):
        event = self.observe(1)
        self.assertEqual(event["event"], "protocol_error")
        self.assertEqual(event["transaction_id"], "")
        self.assertEqual(event["phase"], "request_headers")
        self.assertEqual(event["http_status"], 500)
        self.assertEqual(event["rule_id"], "")

    def test_real_begin_failure_is_technical_not_rule_deny(self):
        event = self.observe(2)
        self.assertEqual(event["event"], "connector_error")
        self.assertEqual(event["transaction_id"], "actual-tx")
        self.assertEqual(event["status"], "error")
        self.assertEqual(event["rule_id"], "")

    def test_logging_failure_does_not_invent_post_response_http_500(self):
        event = self.observe(3)
        self.assertEqual(event["event"], "invalid_engine_response")
        self.assertEqual(event["phase"], "logging")
        self.assertEqual(event["http_status"], 0)
        self.assertEqual(event["visible_http_status"], 200)
        self.assertEqual(event["original_http_status"], 200)
        self.assertEqual(event["rule_id"], "")

    def test_actual_incomplete_common_finish_keeps_protocol_taxonomy(self):
        event = self.observe(4)
        self.assertEqual(event["event"], "protocol_error")
        self.assertEqual(event["message_id"], "MSCONN_EVENT_PROTOCOL_ERROR")
        self.assertEqual(event["phase"], "logging")
        self.assertEqual(event["http_status"], 0)
        self.assertEqual(event["visible_http_status"], 200)
        self.assertEqual(event["rule_id"], "")

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
