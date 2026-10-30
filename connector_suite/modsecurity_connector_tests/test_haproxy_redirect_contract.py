"""HAProxy native redirect ownership and header-safety contract; no host claim."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from modsecurity_connector_tests.c_source_contract import function_definition

ROOT = connector_root()
BINDING = source_path('connectors/haproxy/src/haproxy_modsecurity_binding.c', root=ROOT)

PREAMBLE = r'''
#define _POSIX_C_SOURCE 200809L
#include "haproxy_modsecurity_binding.h"
#include "msconnector/decision.h"
#include "msconnector/intervention.h"
#include "msconnector/log_sanitize.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct Transaction Transaction;
typedef struct {int status,pause;char *url,*log;int disruptive;} ModSecurityIntervention;
#define HAPROXY_MODSECURITY_EXPECTED_STATUS 403
static const char *input;
static unsigned int cleaned;
static int msc_intervention(Transaction *tx,ModSecurityIntervention *i) {
 (void)tx;i->url=strdup(input);i->log=strdup("[id \"1100202\"]");
 assert(i->url && i->log);i->disruptive=1;i->status=302;return 1;
}
static void msc_intervention_cleanup(ModSecurityIntervention *i) {
 free(i->url);free(i->log);i->url=i->log=NULL;cleaned++;
}
static void capture_log_rule_id(haproxy_modsecurity_decision *d,const char *log) {
 (void)log;d->rule_id=1100202;
}
'''
MAIN = r'''
static void run(const char *url,int valid) {
 input=url;haproxy_modsecurity_decision d;unsigned int before=cleaned;
 int result=capture_intervention((Transaction *)1,3,&d);
 assert(cleaned==before+1);
 if(valid) {
   assert(result==0 && d.disruptive && d.status==302 && d.phase==3);
   assert(strcmp(d.action,"redirect")==0 && strcmp(d.redirect_url,url)==0);
   assert(d.rule_id==1100202); /* Owned URL remains valid after native free. */
 } else {
   assert(result!=0 && d.error_class==MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE);
   assert(d.redirect_url[0]==0 && strcmp(d.action,"error")==0);
 }
}
int main(void) {
 run("https://no-crs.invalid/phase3-redirect",1);
 char edge[1025];memset(edge,'x',sizeof(edge));edge[1023]=0;run(edge,1);
 edge[1023]='x';edge[1024]=0;run(edge,0);
 run("https://no-crs.invalid/\r\nX-Injected: yes",0);
 run("https://no-crs.invalid/\tbad",0);
 run("https://no-crs.invalid/\177bad",0);
 return 0;
}
'''


class HAProxyRedirectCapture(unittest.TestCase):
    def run_capture(self, source, sanitizers=False, header_source=None):
        names = ("copy_message", "init_decision", "native_error_decision", "init_intervention", "capture_intervention_action", "capture_intervention")
        program = PREAMBLE + "\n".join(function_definition(source, name) for name in names) + MAIN
        parent = Path(os.environ.get("TMPDIR") or "/var/tmp/codex/ModSecurity-conector/tmp")
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="haproxy-redirect-", dir=parent) as name:
            directory = Path(name); fixture = directory / "redirect.c"; fixture.write_text(program)
            if header_source is not None:
                (directory / "haproxy_modsecurity_binding.h").write_text(header_source)
            binary = directory / "redirect"
            command = ["cc", "-std=c17", "-Wall", "-Wextra", "-Werror", "-ffunction-sections", "-Wl,--gc-sections",
                "-I", str(source_path('connectors/haproxy/src', root=ROOT)), "-I", str(source_path('common/include', root=ROOT)), str(fixture),
                *(str(source_path('common/src', root=ROOT) / f) for f in ("decision.c", "intervention.c", "log_sanitize.c", "block_statuses.c")), "-o", str(binary)]
            if sanitizers: command[1:1] = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            compiled = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            observed = subprocess.run([str(binary)], capture_output=True, text=True, cwd=directory, timeout=30)
            if os.environ.get("HAPROXY_REDIRECT_RECEIPTS"):
                receipt = Path(os.environ["HAPROXY_REDIRECT_RECEIPTS"]); receipt.mkdir(parents=True, exist_ok=True)
                key = hashlib.sha256(str(directory).encode()).hexdigest()[:16]
                (receipt / (key + ".c")).write_text(program)
                if header_source is not None: (receipt / (key + ".h")).write_text(header_source)
                (receipt / (key + ".json")).write_text(json.dumps(dict(argv=command,compile_exit=compiled.returncode,
                    exit=observed.returncode,stderr=observed.stderr,stdout=observed.stdout),indent=2)+"\n")
            return observed

    def test_owned_capture_rejects_truncation_and_controls(self):
        observed = self.run_capture(BINDING.read_text())
        self.assertEqual(observed.returncode, 0, observed.stderr)

    def test_url_validation_and_cleanup_mutations_are_detected(self):
        source = BINDING.read_text()
        header = (source_path('connectors/haproxy/src/haproxy_modsecurity_binding.h', root=ROOT)).read_text()
        for old,new in (("if (byte < 0x20U || byte == 0x7fU) { return 0; }", ""),
                        ("index < capacity;", "index <= capacity;")):
            with self.subTest(guard=old):
                self.assertIn(old,header)
                observed=self.run_capture(source,header_source=header.replace(old,new,1))
                self.assertNotEqual(observed.returncode,0,"unsafe URL mutation survived")
        cleanup = ('if (capture_intervention_action(&intervention, body_limit, decision) != 0) {\n'
                   '            msc_intervention_cleanup(&intervention);')
        self.assertIn(cleanup,source)
        observed=self.run_capture(source.replace(cleanup,
            'if (capture_intervention_action(&intervention, body_limit, decision) != 0) {',1))
        self.assertNotEqual(observed.returncode,0,"lost native cleanup mutation survived")

    def test_capture_asan_ubsan(self):
        observed = self.run_capture(BINDING.read_text(), sanitizers=True)
        self.assertEqual(observed.returncode, 0, observed.stderr)


NATIVE_PROGRAM = r"""
#include "haproxy_modsecurity_binding.h"
#include "msconnector/decision.h"
#include "msconnector/event.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc,char **argv) {
 assert(argc==4);int phase=atoi(argv[2]),companion=atoi(argv[3]);
 haproxy_modsecurity_engine_config cfg={0};cfg.rules_file=argv[1];
 msconnector_config_init(&cfg.common_config);msconnector_config_apply_defaults(&cfg.common_config);
 haproxy_modsecurity_engine *engine=NULL;haproxy_modsecurity_transaction *tx=NULL;
 haproxy_modsecurity_decision decision;
 haproxy_modsecurity_request request={0};haproxy_modsecurity_header header={"Host","localhost"};
 request.method="GET";request.uri="/phase3-redirect";request.http_version="1.1";
 request.client_ip="192.0.2.1";request.client_port=12345;request.server_ip="198.51.100.1";request.server_port=80;
 request.headers=&header;request.header_count=1;request.request_id="native-redirect";
 assert(haproxy_modsecurity_engine_create(&cfg,&engine,&decision)==0);
 if(companion) {
   assert(phase==3);
   assert(haproxy_modsecurity_transaction_begin(engine,&request,&decision,&tx)==0);
   assert(haproxy_modsecurity_transaction_handoff_response_companion(tx)==0);
   assert(haproxy_modsecurity_transaction_claim_response_companion(tx)==0);
 } else {
   assert(haproxy_modsecurity_transaction_begin_request_with_profile(engine,&request,"haproxy-htx",&decision,&tx)==0);
   if(phase>=2)assert(haproxy_modsecurity_transaction_finish_request_body(tx,&decision)==0);
 }
 if(phase==3) {
   haproxy_modsecurity_response response={0};haproxy_modsecurity_header rh={"Content-Type","text/plain"};
   response.status=200;response.protocol="HTTP/1.1";response.headers=&rh;response.header_count=1;
   assert(haproxy_modsecurity_transaction_process_response_headers(tx,&response,&decision)==0);
 }
 assert(decision.disruptive && decision.phase==phase && decision.status==302);
 assert(strcmp(decision.action,"redirect")==0);
 assert(strcmp(decision.redirect_url,"https://no-crs.invalid/phase3-redirect")==0);
 assert(decision.rule_id==(phase==3?1100202:1250940+phase));
 haproxy_modsecurity_decision captured=decision;
 if(companion) {
   msconnector_decision requested;msconnector_decision_set_redirect(&requested,302,captured.redirect_url,NULL,"native redirect");
   requested.phase=MSCONNECTOR_PHASE_RESPONSE_HEADERS;
   msconnector_event event;msconnector_error error;msconnector_error_init(&error);
   assert(!haproxy_modsecurity_transaction_response_event(tx,&requested,&event,&error));
   assert(haproxy_modsecurity_transaction_record_response_companion_outcome(tx,
     MSCONNECTOR_DECISION_ACTION_REDIRECT,"http_status",302,0)==0);
   msconnector_error_init(&error);
   assert(haproxy_modsecurity_transaction_response_event(tx,&requested,&event,&error)==1);
   assert(strcmp(event.decision.actual_action,"redirect")==0 && event.http.visible_http_status==302);
   assert(strcmp(event.decision.rule_id,"1100202")==0 && !event.flags.eos_seen && !event.flags.response_committed);
 }
 int finish=haproxy_modsecurity_transaction_finish_with_decision(tx,&decision);assert(finish==0);
 assert(strcmp(captured.redirect_url,"https://no-crs.invalid/phase3-redirect")==0);
 printf("{\"phase\":%d,\"rule_id\":%d,\"status\":%d,\"action\":\"%s\",\"location\":\"%s\",\"companion\":%d,\"finish_exit\":%d}\n",
   phase,captured.rule_id,captured.status,captured.action,captured.redirect_url,companion,finish);
 haproxy_modsecurity_engine_destroy(engine);return 0;
}
"""


class HAProxyNativeRedirect(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests import test_haproxy_engine_response_limits as native
        native.HaproxyRealEngineResponseLimitTests.setUpClass.__func__(cls)
        source = cls.runroot / "native-redirect.c"; source.write_text(NATIVE_PROGRAM)
        objroot = cls.build / "haproxy-modsecurity-binding"
        resolution = dict(line.split("=", 1) for line in (objroot / "paths.env").read_text().splitlines() if "=" in line)
        objects = [str(p) for p in objroot.glob("*.o") if p.name != "haproxy_modsecurity_binding_self_test.o" and not p.name.startswith("verify_")]
        cls.binary = cls.runroot / "native-redirect"
        command = ["rtk", "proxy", "cc", "-std=c17", "-D_POSIX_C_SOURCE=200809L", "-Wall", "-Wextra", "-Werror",
            "-I", str(source_path('connectors/haproxy/src', root=ROOT)), "-I", str(source_path('common/include', root=ROOT)), str(source), *objects,
            resolution["MODSECURITY_LIBRARY"], f'-Wl,-rpath,{resolution["MODSECURITY_LIB_DIR"]}', "-lstdc++", "-o", str(cls.binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        cls.receipt = Path(os.environ["HAPROXY_REDIRECT_RECEIPTS"]) if os.environ.get("HAPROXY_REDIRECT_RECEIPTS") else None
        if cls.receipt:
            cls.receipt.mkdir(parents=True, exist_ok=True)
            (cls.receipt / "native-compile.json").write_text(json.dumps(dict(argv=command,exit=result.returncode,stdout=result.stdout,stderr=result.stderr),indent=2)+"\n")
            (cls.receipt / "native-redirect.c").write_text(NATIVE_PROGRAM)
        if result.returncode: raise AssertionError(result.stdout + result.stderr)

    def test_real_native_p1_p2_and_canonical_p3_redirect(self):
        for phase, companion in ((1,0),(2,0),(3,0),(3,1)):
            rule_id = 1100202 if phase == 3 else 1250940 + phase
            rules = self.runroot / "redirect.conf"
            rules.write_text('SecRuleEngine On\nSecRequestBodyAccess On\nSecResponseBodyAccess On\nSecAuditEngine Off\n'
                f'SecAction "id:{rule_id},phase:{phase},redirect:https://no-crs.invalid/phase3-redirect,status:302,log"\n')
            command = ["rtk", "proxy", str(self.binary), str(rules), str(phase), str(companion)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            if self.receipt:
                key = f"native-p{phase}-companion{companion}"
                (self.receipt / (key + ".json")).write_text(json.dumps(dict(argv=command,exit=result.returncode,stdout=result.stdout,stderr=result.stderr),indent=2)+"\n")
                (self.receipt / (key + ".conf")).write_text(rules.read_text())
            self.assertEqual(result.returncode,0,result.stdout + result.stderr)
            observed = json.loads(result.stdout)
            self.assertEqual(observed["status"],302)
            self.assertEqual(observed["location"],"https://no-crs.invalid/phase3-redirect")
            self.assertEqual(observed["rule_id"],rule_id)
            print(result.stdout,end="")

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
