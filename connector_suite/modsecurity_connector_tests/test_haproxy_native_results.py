"""Compile production HAProxy transaction boundaries with native API seams."""
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
SOURCE = source_path('connectors/haproxy/src/haproxy_modsecurity_binding.c', root=ROOT)

PREAMBLE = r'''
#include "connectors/haproxy/src/haproxy_modsecurity_binding.h"
#include "connectors/profile_registry.h"
#include "msconnector/native_result.h"
#include "msconnector/intervention.h"
#include "msconnector/rule_id.h"
#include "msconnector/log_sanitize.h"
#include "msconnector/transaction_contract.h"
#include "msconnector/event_jsonl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
typedef struct {int dummy;} ModSecurity;
typedef struct {int dummy;} RulesSet;
typedef struct {int dummy;} Transaction;
typedef struct {int status,pause; char *url,*log; int disruptive;} ModSecurityIntervention;
#define HAPROXY_MODSECURITY_EXPECTED_STATUS 403
static int result=1, calls, cleaned, intervention_result, intervention_cleaned;
static int msc_process_connection(Transaction *t,const char *a,int b,const char *c,int d) {(void)t;(void)a;(void)b;(void)c;(void)d;calls++;return result;}
static int msc_process_uri(Transaction *t,const char *a,const char *b,const char *c) {(void)t;(void)a;(void)b;(void)c;calls++;return result;}
static int msc_add_request_header(Transaction *t,const unsigned char *a,const unsigned char *b) {(void)t;(void)a;(void)b;calls++;return result;}
static int msc_add_response_header(Transaction *t,const unsigned char *a,const unsigned char *b) {(void)t;(void)a;(void)b;calls++;return result;}
static int msc_process_response_headers(Transaction *t,int s,const char *p) {(void)t;(void)s;(void)p;calls++;return result;}
static int msc_append_request_body(Transaction *t,const unsigned char *p,size_t n) {(void)t;(void)p;(void)n;calls++;return result;}
static int msc_append_response_body(Transaction *t,const unsigned char *p,size_t n) {(void)t;(void)p;(void)n;calls++;return result;}
static int msc_process_request_body(Transaction *t) {(void)t;calls++;return result;}
static int msc_process_response_body(Transaction *t) {(void)t;calls++;return result;}
static int msc_process_request_headers(Transaction *t) {(void)t;calls++;return result;}
static int msc_process_logging(Transaction *t) {(void)t;calls++;return result;}
static void msc_transaction_cleanup(Transaction *t) {(void)t;cleaned++;}
static int msc_intervention(Transaction *t,ModSecurityIntervention *i) {(void)t;(void)i;return intervention_result;}
static void msc_intervention_cleanup(ModSecurityIntervention *i) {(void)i;intervention_cleaned++;}
'''

MAIN = r'''
#define CHECK(x) do {if(!(x)){fprintf(stderr,"failure line %d\n",__LINE__);return 1;}}while(0)
int main(int argc,char **argv) {
 Transaction native={0}; haproxy_modsecurity_engine engine={0};
 haproxy_modsecurity_header header={"Host","localhost"};
 haproxy_modsecurity_request request={.method="GET",.uri="/",.client_ip="192.0.2.1",.server_ip="192.0.2.2",.headers=&header,.header_count=1};
 haproxy_modsecurity_decision decision;
 haproxy_modsecurity_transaction *tx=calloc(1,sizeof(*tx));
 CHECK(argc==3);result=atoi(argv[2]);tx->engine=&engine;tx->transaction=&native;
 CHECK(msconnector_transaction_contract_init(&tx->contract,msconnector_profile_registry_find("haproxy-htx"),"test-id","haproxy","test",MSCONNECTOR_TRANSACTION_MODE_STRICT,1)==0);
 tx->contract_initialized=1;
 engine.common_config.phase4_mode=MSCONNECTOR_PHASE4_MODE_SAFE;
 if(strcmp(argv[1],"connection")==0) {
  init_decision(&decision,1);CHECK(process_request_connection(&native,&request,&decision)==-1);
  CHECK(strcmp(decision.action,"error")==0 && decision.rule_id==0);
 } else if(strcmp(argv[1],"p1")==0) {
  init_decision(&decision,1);CHECK(begin_transaction_protocol(tx,&request,&decision)==-1);
  CHECK(tx->contract.error_class==MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE);
  CHECK(tx->contract.completed_phase_mask==0);
 } else if(strcmp(argv[1],"header")==0) {
  init_decision(&decision,1);CHECK(process_request_headers(&native,&request,&decision)==-1);
  CHECK(strcmp(decision.action,"error")==0 && decision.rule_id==0);
 } else if(strcmp(argv[1],"logging")==0) {
  tx->contract.completed_phase_mask=MSCONNECTOR_TRANSACTION_PHASE_MASK_ALL;
  tx->contract.status=MSCONNECTOR_TRANSACTION_STATUS_WAITING_FOR_NEXT_PHASE;
  tx->contract.last_completed_phase=MSCONNECTOR_TRANSACTION_PHASE_P4;
  CHECK(haproxy_modsecurity_transaction_finish(tx)!=0);CHECK(cleaned==1 && calls==1);return 0;
 } else if(strcmp(argv[1],"intervention")==0) {
  intervention_result=result;CHECK(capture_intervention(&native,1,&decision)!=0);
  CHECK(strcmp(decision.action,"error")==0 && intervention_cleaned==1);
 } else if(strcmp(argv[1],"intervention_phase")==0) {
  intervention_result=result;result=1;init_decision(&decision,1);
  CHECK(begin_transaction_protocol(tx,&request,&decision)!=0);
  CHECK(tx->contract.completed_phase_mask==0 && intervention_cleaned==1);
 } else if(strcmp(argv[1],"success")==0) {
  intervention_result=result;result=1;init_decision(&decision,1);
  CHECK(begin_transaction_protocol(tx,&request,&decision)==0);
  CHECK(tx->contract.error_class==MSCONNECTOR_TRANSACTION_ERROR_NONE);
  CHECK(!msconnector_transaction_contract_is_terminal(&tx->contract));
 } else if(strcmp(argv[1],"event")==0) {
  char line[4096];init_decision(&decision,4);native_error_decision(&decision,"private");
  CHECK(haproxy_modsecurity_error_event_write(&decision,"test-id",line,sizeof(line)));fputs(line,stdout);
 } else if(strcmp(argv[1],"first_event")==0) {
  char line[4096];snprintf(tx->request_id,sizeof(tx->request_id),"test-id");
  init_decision(&decision,2);transaction_failure(tx,&decision,MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE,"first");
  init_decision(&decision,4);transaction_failure(tx,&decision,MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR,"second");
  CHECK(decision.error_class==MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE && decision.phase==2);
  CHECK(haproxy_modsecurity_transaction_error_event_write(tx,&decision,line,sizeof(line))==1);
  fputs(line,stdout);CHECK(haproxy_modsecurity_transaction_error_event_write(tx,&decision,line,sizeof(line))==0);
  msconnector_error error;msconnector_error_init(&error);
  CHECK(haproxy_modsecurity_transaction_error_event_write_checked(tx,&decision,line,sizeof(line),&error)==1 && line[0]=='\0');
  CHECK(error.code==MSCONNECTOR_ERROR_NONE);
  tx->error_event_emitted=0;
  CHECK(!haproxy_modsecurity_transaction_error_event_write_checked(tx,&decision,line,1,&error));
  CHECK(error.code==MSCONNECTOR_ERROR_EVENT_TOO_LARGE && !tx->error_event_emitted);
  msconnector_error_init(&error);
  CHECK(!haproxy_modsecurity_error_event_write_checked(&decision,"test-id",NULL,0,&error));
  CHECK(error.code==MSCONNECTOR_ERROR_INTERNAL);
  CHECK(haproxy_modsecurity_transaction_error_event_write_checked(tx,&decision,line,sizeof(line),NULL)==1 && line[0]!='\0');
 } else {
  const int response_phase=argv[1][0]=='r';
  enum msconnector_phase phase=response_phase?MSCONNECTOR_TRANSACTION_PHASE_P4:MSCONNECTOR_TRANSACTION_PHASE_P2;
  CHECK(msconnector_transaction_contract_begin_phase(&tx->contract,MSCONNECTOR_TRANSACTION_PHASE_P1,1)==0);
  CHECK(msconnector_transaction_contract_complete_phase(&tx->contract,MSCONNECTOR_TRANSACTION_PHASE_P1,1)==0);
  tx->request_headers_processed=1;
  if(response_phase || strcmp(argv[1],"p3")==0) {
   CHECK(msconnector_transaction_contract_begin_phase(&tx->contract,MSCONNECTOR_TRANSACTION_PHASE_P2,1)==0);
   CHECK(msconnector_transaction_contract_complete_phase(&tx->contract,MSCONNECTOR_TRANSACTION_PHASE_P2,1)==0);
   tx->request_body.processed=1;
   if(strcmp(argv[1],"p3")==0) {
    haproxy_modsecurity_response response={.status=200,.protocol="HTTP/1.1",.headers=&header,.header_count=1};
    CHECK(haproxy_modsecurity_transaction_process_response_headers(tx,&response,&decision)!=0);
    CHECK(tx->contract.error_class==MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE);
    int old=calls;CHECK(haproxy_modsecurity_transaction_process_response_headers(tx,&response,&decision)!=0);CHECK(calls==old);
    free(tx);return 0;
   }
   CHECK(msconnector_transaction_contract_begin_phase(&tx->contract,MSCONNECTOR_TRANSACTION_PHASE_P3,1)==0);
   CHECK(msconnector_transaction_contract_complete_phase(&tx->contract,MSCONNECTOR_TRANSACTION_PHASE_P3,1)==0);
   tx->response_headers_processed=1;
  }
  haproxy_modsecurity_body_phase state=response_phase?response_body_phase(tx):request_body_phase(tx);
  if(strstr(argv[1],"overflow")!=NULL) {
   unsigned char body[101]={0}; char line[4096];
   *state.body_bytes_seen=SIZE_MAX;
   int prior=strstr(argv[1],"prior")!=NULL;
   if(prior) CHECK(msconnector_transaction_contract_fail(&tx->contract,
       MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT,0U)==MSCONNECTOR_TRANSACTION_TRANSITION_OK);
   const msconnector_transaction_error_class expected=prior?
       MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT:MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR;
   snprintf(tx->request_id,sizeof(tx->request_id),"test-id");
   CHECK(append_body_chunk(tx,body,sizeof(body),&decision,&state)!=0);
   CHECK(calls==0 && tx->contract.error_class==expected);
   CHECK(!(tx->contract.completed_phase_mask & (response_phase?MSCONNECTOR_TRANSACTION_PHASE_MASK_P4:MSCONNECTOR_TRANSACTION_PHASE_MASK_P2)));
   CHECK(haproxy_modsecurity_transaction_error_event_write(tx,&decision,line,sizeof(line))==1);
   fputs(line,stdout);
   CHECK(append_body_chunk(tx,body,sizeof(body),&decision,&state)!=0);
   CHECK(calls==0 && tx->contract.error_class==expected);
   CHECK(haproxy_modsecurity_transaction_error_event_write(tx,&decision,line,sizeof(line))==0);
   transaction_cleanup(tx,0);CHECK(cleaned==1);return 0;
  }
  int append=strstr(argv[1],"append")!=NULL;
  int ok=append?(result==0 || result==1):(result==1);
  CHECK((append?append_body_chunk(tx,(const unsigned char *)"x",1,&decision,&state):finish_body(tx,&decision,&state))==(ok?0:1));
  if(!ok) {
   CHECK(decision.error_class==MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE);
   CHECK(!(tx->contract.completed_phase_mask & (phase==MSCONNECTOR_TRANSACTION_PHASE_P2?MSCONNECTOR_TRANSACTION_PHASE_MASK_P2:MSCONNECTOR_TRANSACTION_PHASE_MASK_P4)));
   int old=calls;CHECK(finish_body(tx,&decision,&state)!=0);CHECK(calls==old);
  }
 }
 free(tx);return 0;
}
'''


class HaproxyNativeResultsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="haproxy-native-", dir=os.environ.get("TMPDIR") or os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        cls.binary = directory / "fixture"
        source = SOURCE.read_text()
        declarations = source[source.index("struct haproxy_modsecurity_engine {"):source.index("msconnector_transaction_error_class haproxy_modsecurity_transaction_error(")]
        declarations += source[source.index("typedef int (*haproxy_modsecurity_body_append)"):source.index("static int haproxy_common_sdk_probe_semantics")]
        names = ["copy_message", "init_decision", "native_error_decision", "contract_phase_from_decision", "decision_phase_from_contract", "retain_transaction_failure", "transaction_failure", "haproxy_modsecurity_error_event_write_checked", "haproxy_modsecurity_error_event_write", "haproxy_modsecurity_transaction_error_event_write_checked", "haproxy_modsecurity_transaction_error_event_write", "init_intervention", "capture_log_rule_id", "capture_intervention_action", "capture_intervention", "record_contract_decision", "begin_contract_phase", "capture_pending_body_intervention", "validate_body_preconditions", "append_body_chunk", "finish_body", "request_body_phase", "response_body_phase", "request_text_or_default", "process_request_connection", "process_request_headers", "transaction_cleanup", "begin_transaction_protocol", "add_response_headers", "haproxy_modsecurity_transaction_process_response_headers", "process_transaction_logging", "haproxy_modsecurity_transaction_finish_with_decision", "haproxy_modsecurity_transaction_finish"]
        declarations += "static int map_response_for_transaction(haproxy_modsecurity_transaction *t,const haproxy_modsecurity_response *r,haproxy_modsecurity_decision *d){(void)t;(void)r;(void)d;return 1;}\n"
        fixture = PREAMBLE + declarations + "\n".join(function_definition(source, name) for name in names) + MAIN
        (directory / "fixture.c").write_text(fixture)
        common = ["error.c", "transaction_state.c", "decision.c", "decision_action.c", "rule_id.c", "log_sanitize.c", "intervention.c", "http_status.c", "event.c", "event_jsonl.c", "json_escape.c", "status.c"]
        args = shlex.split(os.environ.get("CC", "cc")) + ["-std=c17", "-Wall", "-Wextra", "-Werror", "-ffunction-sections", "-Wl,--gc-sections", "-I", str(ROOT), "-I", str(source_path('common/include', root=ROOT)), str(directory / "fixture.c")] + [str(source_path('common/src', root=ROOT) / name) for name in common] + [str(source_path('connectors/profile_registry.c', root=ROOT)), "-o", str(cls.binary)]
        result = subprocess.run(args, capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError(result.stderr)

    def test_native_errors_are_technical_and_terminal(self):
        for boundary in ("connection", "p1", "header", "logging", "intervention", "intervention_phase", "p3"):
            for result in (-1, 0, 2, 17):
                if boundary in ("intervention", "intervention_phase") and result == 0:
                    continue
                with self.subTest(boundary=boundary, result=result):
                    observed = subprocess.run([str(self.binary), boundary, str(result)], capture_output=True, text=True, timeout=10)
                    self.assertEqual(observed.returncode, 0, observed.stderr)

    def test_body_native_boundaries_and_reentry(self):
        for boundary in ("append", "finish", "response_append", "response_finish"):
            for result in (-1, 0, 1, 2, 17):
                with self.subTest(boundary=boundary, result=result):
                    observed = subprocess.run([str(self.binary), boundary, str(result)], capture_output=True, text=True, timeout=10)
                    self.assertEqual(observed.returncode, 0, observed.stderr)

    def test_first_overflowing_body_chunk_emits_technical_body_phase_once(self):
        for boundary, phase in (("overflow", "request_body"), ("response_overflow", "response_body"),
                                ("overflow_prior", "request_headers"), ("response_overflow_prior", "response_headers")):
            with self.subTest(boundary=boundary):
                observed = subprocess.run([str(self.binary), boundary, "1"], capture_output=True, text=True, timeout=10)
                self.assertEqual(observed.returncode, 0, observed.stderr)
                event = json.loads(observed.stdout)
                self.assertEqual(event["phase"], phase)
                prior = "prior" in boundary
                self.assertEqual(event["message_id"], "MSCONN_EVENT_ENGINE_TIMEOUT" if prior else "MSCONN_EVENT_CONNECTOR_ERROR")
                self.assertEqual(event["event"], "engine_timeout" if prior else "connector_error")
                self.assertEqual(event["status"], "error")
                self.assertEqual(event["rule_id"], "")
                self.assertEqual(event["actual_action"], "")

    def test_typed_error_is_metadata_only_and_has_no_actual_action(self):
        observed = subprocess.run([str(self.binary), "event", "1"], capture_output=True, text=True, timeout=10)
        self.assertEqual(observed.returncode, 0, observed.stderr)
        event = json.loads(observed.stdout)
        self.assertEqual(event["message_id"], "MSCONN_EVENT_INVALID_ENGINE_RESPONSE")
        self.assertEqual(event["status"], "error")
        self.assertEqual(event["rule_id"], "")
        self.assertEqual(event["actual_action"], "")
        self.assertNotIn("private", observed.stdout)

    def test_documented_success_with_no_or_nondisruptive_intervention(self):
        for intervention in (0, 1):
            observed = subprocess.run([str(self.binary), "success", str(intervention)], capture_output=True, text=True, timeout=10)
            self.assertEqual(observed.returncode, 0, observed.stderr)

    def test_first_cause_phase_and_single_terminal_event_survive_reentry(self):
        observed = subprocess.run([str(self.binary), "first_event", "1"], capture_output=True, text=True, timeout=10)
        self.assertEqual(observed.returncode, 0, observed.stderr)
        event = json.loads(observed.stdout)
        self.assertEqual(event["message_id"], "MSCONN_EVENT_INVALID_ENGINE_RESPONSE")
        self.assertEqual(event["actual_action"], "")

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
