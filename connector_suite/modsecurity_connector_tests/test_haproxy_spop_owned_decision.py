"""Actual Common decision ownership boundary followed by the HA SPOP copy."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
import tempfile
import unittest
from modsecurity_connector_tests.c_source_contract import function_definition

ROOT = connector_root()
RUNTIME = source_path('connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c', root=ROOT)
TRANSPORT = source_path('common/runtime/response_companion_transport.c', root=ROOT)

PROGRAM = r'''
#include "haproxy_spop_response_companion_backend.h"
#include "msconnector/limits.h"
#include <assert.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
/* DEFINITIONS */
static void check_owned(int redirect, int phase) {
  char reason[] = "native redacted reason";
  char location[] = "https://no-crs.invalid/phase3-redirect";
  msconnector_decision original, copied;
  if (redirect) msconnector_decision_set_redirect(&original,302,location,NULL,reason);
  else msconnector_decision_set_deny(&original,403,NULL,reason);
  original.phase = phase == 3 ? MSCONNECTOR_PHASE_RESPONSE_HEADERS : MSCONNECTOR_PHASE_RESPONSE_BODY;
  original.late_intervention = phase == 4;
  original.body_limit = phase == 4;
  response_companion_session_state snapshot = {0};
  haproxy_spop_response_companion_decision_storage storage = {0};
  msconnector_error error;
  msconnector_error_init(&error);
  assert(response_companion_store_latest_decision(&snapshot,&original,&error));
  assert(snapshot.latest_decision.reason != snapshot.latest_decision.intervention.log_message);
  assert(strcmp(snapshot.latest_decision.reason,snapshot.latest_decision.intervention.log_message)==0);
  if (redirect) assert(snapshot.latest_decision.redirect_url != snapshot.latest_decision.intervention.redirect_url);
  assert(copy_spop_bridge_decision(&copied,&storage,&snapshot.latest_decision,&error));
  memset(reason,'X',sizeof(reason)-1U); memset(location,'X',sizeof(location)-1U);
  memset(&snapshot,'X',sizeof(snapshot));
  assert(strcmp(copied.reason,"native redacted reason")==0);
  assert(copied.intervention.log_message == copied.reason);
  assert(copied.phase == original.phase && copied.kind == original.kind);
  assert(copied.http_status == original.http_status && copied.late_intervention == original.late_intervention);
  assert(copied.body_limit == original.body_limit);
  if (redirect) {
    assert(strcmp(copied.redirect_url,"https://no-crs.invalid/phase3-redirect")==0);
    assert(copied.intervention.redirect_url == copied.redirect_url);
  }
}
static void check_invalid(int fault) {
  char reason[] = "reason";
  char different[] = "DIFFERENT";
  char large[sizeof(((haproxy_spop_response_companion_decision_storage *)0)->log_message)+1U];
  char big_url[sizeof(((haproxy_spop_response_companion_decision_storage *)0)->redirect_url)+1U];
  memset(large,'A',sizeof(large));large[sizeof(large)-1U]=0;
  memset(big_url,'A',sizeof(big_url));big_url[sizeof(big_url)-1U]=0;
  msconnector_decision original,copied;
  msconnector_decision_set_deny(&original,403,NULL,reason);
  original.phase = MSCONNECTOR_PHASE_RESPONSE_BODY;
  switch(fault) {
    case 0: original.intervention.log_message = NULL; break;
    case 1: original.intervention.log_message = different; break;
    case 2: original.reason = original.intervention.log_message = large; break;
    case 3: original.reason = NULL; break;
    case 4: original.intervention.status = 404; break;
    case 5: original.kind = MSCONNECTOR_DECISION_KIND_ERROR; break;
    case 6: original.rule_id = "123"; break;
    case 7: original.log_message = reason; break;
    case 8: original.intervention.disruptive = 0; break;
    default:
      msconnector_decision_set_redirect(&original,302,"https://example.invalid/",NULL,reason);
      original.phase = MSCONNECTOR_PHASE_RESPONSE_HEADERS;
      if(fault==9) original.intervention.redirect_url = different;
      if(fault==10) original.intervention.redirect_url = NULL;
      if(fault==11) original.redirect_url = original.intervention.redirect_url = big_url;
      if(fault==12) original.redirect_url = NULL;
      break;
  }
  response_companion_session_state snapshot = {0};
  haproxy_spop_response_companion_decision_storage storage = {0};
  msconnector_error error;
  msconnector_error_init(&error);
  int stored = response_companion_store_latest_decision(&snapshot,&original,&error);
  if (stored) {
    assert(!copy_spop_bridge_decision(&copied,&storage,&snapshot.latest_decision,&error));
    assert(error.code == MSCONNECTOR_ERROR_INTERNAL);
  } else {
    assert(error.code == MSCONNECTOR_ERROR_MODSECURITY_FAILURE);
  }
}
static void *parallel_copy(void *value) {
  int phase = *(int *)value;
  for (int repeat=0;repeat<64;repeat++) check_owned(repeat%2,phase);
  return NULL;
}
int main(void) {
  for(int phase=3;phase<=4;phase++) for(int redirect=0;redirect<=1;redirect++) check_owned(redirect,phase);
  for(int fault=0;fault<=12;fault++) check_invalid(fault);
  msconnector_decision allow,copied;
  haproxy_spop_response_companion_decision_storage storage={0}; msconnector_error error;
  msconnector_error_init(&error);msconnector_decision_set_allow(&allow);allow.phase=MSCONNECTOR_PHASE_RESPONSE_BODY;
  assert(copy_spop_bridge_decision(&copied,&storage,&allow,&error));
  assert(copied.kind==MSCONNECTOR_DECISION_KIND_ALLOW && copied.phase==allow.phase);
  allow.kind=MSCONNECTOR_DECISION_KIND_DENY;
  assert(!copy_spop_bridge_decision(&copied,&storage,&allow,&error));
  pthread_t threads[2]; int phases[2]={3,4};
  for(int index=0;index<2;index++) assert(pthread_create(&threads[index],NULL,parallel_copy,&phases[index])==0);
  for(int index=0;index<2;index++) assert(pthread_join(threads[index],NULL)==0);
  puts("actual Common deep-copy -> HA owned decision: equal values accepted; mismatches rejected");
  return 0;
}
'''

def complete_function(source, name):
    body = function_definition(source, name)
    if body.startswith("static "):
        return body
    start = source.index(body)
    return source[:start].rstrip().splitlines()[-1] + "\n" + body

class SPOPDecisionOwnership(unittest.TestCase):
    def run_boundary(self, runtime=None, sanitizers=False):
        runtime = RUNTIME.read_text() if runtime is None else runtime
        transport = TRANSPORT.read_text()
        constants = "\n".join(re.findall(r"^#define RESPONSE_COMPANION_MAX_(?:RULE_ID|REDIRECT|DECISION_TEXT) .*", transport, re.M))
        fields = transport.split("    msconnector_decision latest_decision;",1)[1].split("    int claimed;",1)[0]
        declaration = "typedef struct { msconnector_decision latest_decision;" + fields + "} response_companion_session_state;"
        bodies = [complete_function(transport,n) for n in ("response_companion_error", "response_companion_bounded_text_size", "response_companion_copy_decision_text", "response_companion_store_latest_decision")]
        bodies += [complete_function(runtime,n) for n in ("copy_bridge_native_decision_text", "copy_spop_bridge_decision")]
        program = PROGRAM.replace("/* DEFINITIONS */", "\n".join([constants,declaration,*bodies]))
        temp_root=Path(os.environ.get("TMPDIR","/var/tmp/codex/ModSecurity-conector/tmp"))
        temp_root.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="ha-owned-decision-",dir=temp_root) as directory:
            work=Path(directory);source=work/"ownership.c";binary=work/"ownership"
            source.write_text(program)
            argv=["rtk","proxy","cc","-std=c17","-D_POSIX_C_SOURCE=200809L","-Wall","-Wextra","-Werror","-ffunction-sections","-Wl,--gc-sections","-pthread",
                "-I",str(source_path('common/include', root=ROOT)),"-I",str(source_path('common/runtime', root=ROOT)),"-I",str(source_path('connectors/haproxy/src', root=ROOT)),str(source),
                *(str(source_path('common/src', root=ROOT)/name) for name in ("decision.c","intervention.c","log_sanitize.c","block_statuses.c","http_status.c","decision_action.c","error.c")),"-o",str(binary)]
            if sanitizers: argv[3:3]=["-fsanitize=address,undefined","-fno-omit-frame-pointer"]
            compiled=subprocess.run(argv,capture_output=True,text=True)
            result=subprocess.run(["rtk","proxy",str(binary)],capture_output=True,text=True,timeout=30) if not compiled.returncode else None
            receipts=os.environ.get("HAPROXY_OWNED_DECISION_RECEIPTS")
            if receipts:
                target=Path(receipts);target.mkdir(parents=True,exist_ok=True)
                key=hashlib.sha256(program.encode()+str(sanitizers).encode()).hexdigest()[:16]
                (target/(key+".c")).write_text(program)
                (target/(key+".json")).write_text(json.dumps(dict(argv=argv,cwd=str(ROOT),compile_exit=compiled.returncode,compile_output=compiled.stdout+compiled.stderr,
                    exit=result.returncode if result else None,output=result.stdout+result.stderr if result else None,source_sha256=hashlib.sha256(program.encode()).hexdigest(),
                    binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest() if binary.exists() else None),indent=2)+"\n")
            self.assertEqual(compiled.returncode,0,compiled.stdout+compiled.stderr)
            return result

    def test_actual_common_copy_then_ha_copy(self):
        result=self.run_boundary()
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_owned_lifetime_asan_ubsan(self):
        result=self.run_boundary(sanitizers=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_value_and_ownership_mutations_are_detected(self):
        source=RUNTIME.read_text()
        mutations={
            "log-pointer-alias": ("source->intervention.log_message == NULL", "source->intervention.log_message != source->reason"),
            "url-pointer-alias": ("source->intervention.redirect_url == NULL ||", "source->intervention.redirect_url != source->redirect_url ||"),
            "log-mismatch-accepted": ("strncmp(source->intervention.log_message, storage->log_message,", "0 * strncmp(source->intervention.log_message, storage->log_message,"),
            "url-mismatch-accepted": ("strncmp(source->intervention.redirect_url, storage->redirect_url,", "0 * strncmp(source->intervention.redirect_url, storage->redirect_url,"),
            "borrowed-reason": ("storage->log_message);\n    } else {", "source->reason);\n    } else {"),
            "status-conflict": ("source->intervention.status != source->http_status ||", "0 ||"),
        }
        for name,(before,after) in mutations.items():
            with self.subTest(mutation=name):
                self.assertIn(before,source)
                result=self.run_boundary(source.replace(before,after,1))
                self.assertNotEqual(result.returncode,0,"decision metadata/ownership mutation survived")

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
