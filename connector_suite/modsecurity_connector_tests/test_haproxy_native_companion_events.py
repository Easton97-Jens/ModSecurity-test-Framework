"""Real engine P3/P4 event snapshot after OUTCOME, before native finish."""
from pathlib import Path
import json
import os
import subprocess
import unittest
from tests import test_haproxy_engine_response_limits as native

PROGRAM = r'''
#include "haproxy_modsecurity_binding.h"
#include "msconnector/event_jsonl.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
 assert(argc == 4); int phase = atoi(argv[2]);
 haproxy_modsecurity_engine_config cfg = {0};
 msconnector_config_init(&cfg.common_config);
 msconnector_config_apply_defaults(&cfg.common_config);
 cfg.common_config.phase4_mode = MSCONNECTOR_PHASE4_MODE_SAFE;
 cfg.rules_file = argv[1];
 haproxy_modsecurity_engine *engine = NULL;
 haproxy_modsecurity_transaction *tx = NULL;
 haproxy_modsecurity_decision d;
 haproxy_modsecurity_header h[] = {{"Host", "localhost"}};
 haproxy_modsecurity_request r = {0};
 r.method = "GET"; r.uri = "/events"; r.http_version = "2.0";
 r.client_ip = "192.0.2.1"; r.client_port = 1234;
 r.server_ip = "198.51.100.1"; r.server_port = 8080;
 r.headers = h; r.header_count = 1; r.request_id = "sdk-owner-events";
 assert(haproxy_modsecurity_engine_create(&cfg, &engine, &d) == 0);
 assert(haproxy_modsecurity_transaction_begin(engine, &r, &d, &tx) == 0);
 assert(haproxy_modsecurity_transaction_handoff_response_companion(tx) == 0);
 assert(haproxy_modsecurity_transaction_claim_response_companion(tx) == 0);
 haproxy_modsecurity_response response = {0};
 haproxy_modsecurity_header rh[] = {{"Content-Type", "text/plain"}};
 response.status = 200; response.protocol = "HTTP/1.1";
 response.headers = rh; response.header_count = 1;
 assert(haproxy_modsecurity_transaction_process_response_headers(tx, &response, &d) == 0);
 if (phase == 4) {
   assert(haproxy_modsecurity_transaction_set_response_commit_state(tx, 1, 1) == 0);
   assert(haproxy_modsecurity_transaction_append_response_body_chunk(tx, (const unsigned char *)"abc", 3, &d) == 0);
   assert(haproxy_modsecurity_transaction_finish_response_body(tx, &d) == 0);
 }
 assert(d.disruptive && d.rule_id == 1250931);
 msconnector_decision requested;
 msconnector_decision_set_deny(&requested, 403, NULL, "SECRET-MATCHED-INPUT");
 requested.phase = phase == 3 ? MSCONNECTOR_PHASE_RESPONSE_HEADERS : MSCONNECTOR_PHASE_RESPONSE_BODY;
 msconnector_event event;
 msconnector_error error;
 msconnector_error_init(&error);
 assert(!haproxy_modsecurity_transaction_response_event(tx, &requested, &event, &error));
 assert(haproxy_modsecurity_transaction_record_response_companion_outcome(tx,
   phase == 3 ? MSCONNECTOR_DECISION_ACTION_DENY : MSCONNECTOR_DECISION_ACTION_LOG_ONLY,
   phase == 3 ? "denied" : "log_only", phase == 3 ? 403 : 200, 0) == 0);
 msconnector_error_init(&error);
 assert(haproxy_modsecurity_transaction_response_event(tx, &requested, &event, &error));
 assert(strcmp(event.decision.rule_id, "1250931") == 0);
 assert(event.flags.response_committed == (phase == 4));
 assert(event.flags.eos_seen == (phase == 4));
 assert(event.body.bytes_seen == (phase == 4 ? 3U : 0U));
 int fd = -1; assert(msconnector_open_private_event_file(argv[3], &fd));
 FILE *file = fdopen(fd, "a"); assert(file != NULL);
 char json[8192];
 assert(msconnector_event_write_jsonl_stream(&event, file, json, sizeof(json), &error));
 assert(msconnector_event_file_close(&file, &error) && file == NULL);
 file = fopen(argv[3], "r"); assert(file != NULL);
 char physical[8192]; assert(fgets(physical, sizeof(physical), file));
 assert(strcmp(json, physical) == 0 && strstr(physical, "SECRET-MATCHED-INPUT") == NULL);
 assert(fclose(file) == 0); fputs(physical, stdout);
 assert(haproxy_modsecurity_transaction_finish_with_decision(tx, &d) == 0);
 haproxy_modsecurity_engine_destroy(engine);
 return 0;
}
'''


class NativeCompanionEvents(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        native.HaproxyRealEngineResponseLimitTests.setUpClass.__func__(cls)
        source = cls.runroot / "companion-events.c"
        source.write_text(PROGRAM)
        objroot = cls.build / "haproxy-modsecurity-binding"
        resolution = dict(line.split("=", 1) for line in (objroot / "paths.env").read_text().splitlines() if "=" in line)
        objects = [str(p) for p in objroot.glob("*.o") if p.name != "haproxy_modsecurity_binding_self_test.o" and not p.name.startswith("verify_")]
        command = ["rtk", "proxy", "cc", "-std=c17", "-D_POSIX_C_SOURCE=200809L", "-Wall", "-Wextra", "-Werror",
            "-I", str(native.ROOT / "connectors/haproxy/src"), "-I", str(native.ROOT / "common/include"),
            str(source), *objects, resolution["MODSECURITY_LIBRARY"],
            f'-Wl,-rpath,{resolution["MODSECURITY_LIB_DIR"]}', "-lstdc++", "-o", str(cls.binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        cls.receipt_root = Path(os.environ["HAPROXY_NATIVE_TEST_RECEIPTS"]) if os.environ.get("HAPROXY_NATIVE_TEST_RECEIPTS") else None
        if cls.receipt_root:
            cls.receipt_root.mkdir(parents=True, exist_ok=True)
            (cls.receipt_root / "compile.json").write_text(json.dumps(dict(argv=command, exit=result.returncode, stdout=result.stdout, stderr=result.stderr), indent=2))
            (cls.receipt_root / "companion-events.c").write_text(PROGRAM)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    def test_real_native_outcome_event_bytes(self):
        for phase in (3, 4):
            rules = self.runroot / "rules.conf"
            rules.write_text('SecRuleEngine On\nSecRequestBodyAccess On\nSecResponseBodyAccess On\n'
                'SecResponseBodyMimeType text/plain\nSecAuditEngine Off\n'
                f'SecAction "id:1250931,phase:{phase},deny,status:403,log"\n')
            command = ["rtk", "proxy", str(self.binary), str(rules), str(phase), str(self.runroot / f"p{phase}-events.jsonl")]
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            if self.receipt_root:
                (self.receipt_root / f"p{phase}.json").write_text(json.dumps(dict(argv=command, exit=result.returncode, stdout=result.stdout, stderr=result.stderr), indent=2))
                (self.receipt_root / f"p{phase}.conf").write_text(rules.read_text())
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            event = json.loads(result.stdout)
            self.assertNotIn("late_intervention_mode", event)
            self.assertEqual(event["rule_id"], "1250931")
            self.assertEqual(event["actual_action"], "deny" if phase == 3 else "log_only")
            self.assertEqual(event["response_committed"], phase == 4)
            print(result.stdout, end="")

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
