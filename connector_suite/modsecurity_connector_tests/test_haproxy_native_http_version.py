"""Real libModSecurity REQUEST_PROTOCOL and finite authorization finish.

This is native engine evidence, separate from a HAProxy hosted request.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import unittest
from tests import test_haproxy_engine_response_limits as native

PROGRAM = r"""
#include "haproxy_modsecurity_binding.h"
#include <modsecurity/modsecurity.h>
#include <modsecurity/transaction.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned int cleanups, logging_calls, p3_calls, p4_calls;
void __real_msc_transaction_cleanup(Transaction *t);
void __wrap_msc_transaction_cleanup(Transaction *t) { cleanups++; __real_msc_transaction_cleanup(t); }
int __real_msc_process_logging(Transaction *t);
int __wrap_msc_process_logging(Transaction *t) { logging_calls++; return __real_msc_process_logging(t); }
int __real_msc_process_response_headers(Transaction *t, int status, const char *protocol);
int __wrap_msc_process_response_headers(Transaction *t, int status, const char *protocol) {
    p3_calls++; return __real_msc_process_response_headers(t, status, protocol);
}
int __real_msc_process_response_body(Transaction *t);
int __wrap_msc_process_response_body(Transaction *t) { p4_calls++; return __real_msc_process_response_body(t); }
int main(int argc, char **argv) {
    assert(argc == 4);
    haproxy_modsecurity_engine_config config = {0};
    msconnector_config_init(&config.common_config);
    msconnector_config_apply_defaults(&config.common_config);
    config.rules_file = argv[1];
    haproxy_modsecurity_engine *engine = NULL;
    haproxy_modsecurity_transaction *tx = NULL;
    haproxy_modsecurity_decision d;
    haproxy_modsecurity_header headers[] = {{"Host", "localhost"}};
    haproxy_modsecurity_request r = {0};
    r.method = "GET"; r.uri = "/version"; r.http_version = argv[2];
    r.client_ip = "192.0.2.1"; r.client_port = 1234;
    r.server_ip = "198.51.100.1"; r.server_port = 8080;
    r.headers = headers; r.header_count = 1; r.request_id = "native-version";
    assert(haproxy_modsecurity_engine_create(&config, &engine, &d) == 0);
    assert(haproxy_modsecurity_transaction_begin_request_authorization(engine, &r, &d, &tx) == 0);
    int expected = atoi(argv[3]);
    assert(d.disruptive == (expected != 200));
    assert(d.status == expected);
    if (expected != 200) assert(d.phase == 1 && d.rule_id == 1250911);
    assert(haproxy_modsecurity_transaction_finish_with_decision(tx, &d) == 0);
    assert(logging_calls == 1 && cleanups == 1 && p3_calls == 0 && p4_calls == 0);
    printf("{\"http_version\":\"%s\",\"status\":%d,\"logging\":%u,\"cleanup\":%u,\"p3\":%u,\"p4\":%u}\n",
        r.http_version, expected, logging_calls, cleanups, p3_calls, p4_calls);
    haproxy_modsecurity_engine_destroy(engine);
    return 0;
}
"""

class NativeHTTPVersion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        native.HaproxyRealEngineResponseLimitTests.setUpClass.__func__(cls)
        source = cls.runroot / "http-version.c"
        source.write_text(PROGRAM)
        objroot = cls.build / "haproxy-modsecurity-binding"
        resolution = dict(line.split("=", 1) for line in (objroot / "paths.env").read_text().splitlines() if "=" in line)
        objects = [str(p) for p in objroot.glob("*.o") if p.name != "haproxy_modsecurity_binding_self_test.o" and not p.name.startswith("verify_")]
        command = ["rtk", "proxy", "cc", "-std=c17", "-Wall", "-Wextra", "-Werror",
            "-I", str(native.ROOT / "connectors/haproxy/src"), "-I", str(native.ROOT / "common/include"),
            "-I", resolution["MODSECURITY_INCLUDE_DIR"], str(source), *objects,
            resolution["MODSECURITY_LIBRARY"], f'-Wl,-rpath,{resolution["MODSECURITY_LIB_DIR"]}', "-lstdc++",
            "-Wl,--wrap=msc_transaction_cleanup", "-Wl,--wrap=msc_process_logging",
            "-Wl,--wrap=msc_process_response_headers", "-Wl,--wrap=msc_process_response_body", "-o", str(cls.binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        cls.receipt_root = Path(os.environ["HAPROXY_NATIVE_TEST_RECEIPTS"]) if os.environ.get("HAPROXY_NATIVE_TEST_RECEIPTS") else None
        if cls.receipt_root:
            cls.receipt_root.mkdir(parents=True, exist_ok=True)
            (cls.receipt_root / "native-http-version.c").write_text(PROGRAM)
            (cls.receipt_root / "compile.json").write_text(json.dumps(dict(argv=command, cwd=str(Path.cwd()),
                exit=result.returncode, stdout=result.stdout, stderr=result.stderr,
                engine_library=resolution["MODSECURITY_LIBRARY"],
                engine_sha256=hashlib.sha256(Path(resolution["MODSECURITY_LIBRARY"]).read_bytes()).hexdigest()), indent=2) + "\n")
        if result.returncode: raise AssertionError(result.stdout + result.stderr)

    def test_actual_request_protocol_and_request_only_finish(self):
        for version in ("1.0", "1.1", "2.0"):
            for match in (False, True):
                rules = self.runroot / "version.conf"
                expected = version if match else "9.9"
                rules.write_text('SecRuleEngine On\nSecRequestBodyAccess On\nSecAuditEngine Off\n'
                    f'SecRule REQUEST_PROTOCOL "@streq HTTP/{expected}" "id:1250911,phase:1,deny,status:409,log"\n')
                command = ["rtk", "proxy", str(self.binary), str(rules), version, "409" if match else "200"]
                result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                if self.receipt_root:
                    case = version.replace(".", "") + ("-match" if match else "-allow")
                    (self.receipt_root / (case + ".conf")).write_text(rules.read_text())
                    (self.receipt_root / (case + ".json")).write_text(json.dumps(dict(argv=command,
                        cwd=str(Path.cwd()), exit=result.returncode, stdout=result.stdout, stderr=result.stderr,
                        rules_sha256=hashlib.sha256(rules.read_bytes()).hexdigest()), indent=2) + "\n")
                print(result.stdout, end="")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
