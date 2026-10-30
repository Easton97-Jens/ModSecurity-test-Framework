"""Genuine engine request policy through the binding; no HAProxy host claim."""
from pathlib import Path
import subprocess
import unittest

from tests import test_haproxy_engine_response_limits as response_harness

PROGRAM = r"""
#include "haproxy_modsecurity_binding.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    haproxy_modsecurity_engine_config config = {0};
    haproxy_modsecurity_engine *engine = NULL;
    haproxy_modsecurity_transaction *transaction = NULL;
    haproxy_modsecurity_decision decision;
    haproxy_modsecurity_header headers[] = {{"Host", "localhost"},
        {"Content-Type", "application/x-www-form-urlencoded"}};
    haproxy_modsecurity_request request = {0};
    unsigned char chunk[32768];
    size_t length, sent = 0U, marker;
    int reject, match, rc;
    FILE *file = NULL;
    if (argc != 8) return 2;
    length = strtoul(argv[2], NULL, 10); marker = strtoul(argv[7], NULL, 10);
    reject = atoi(argv[3]); match = atoi(argv[4]);
    msconnector_config_init(&config.common_config);
    msconnector_config_apply_defaults(&config.common_config);
    config.rules_file = argv[1];
    request.request_id = "real-request-limit-binding";
    request.client_ip = "192.0.2.10"; request.client_port = 12345;
    request.server_ip = "198.51.100.20"; request.server_port = 8080;
    request.method = "POST";
    request.http_version = "1.1"; request.uri = "/engine-request-limit";
    request.headers = headers; request.header_count = 2U;
    if (haproxy_modsecurity_engine_create(&config, &engine, &decision) ||
        haproxy_modsecurity_transaction_begin_request_with_profile(engine, &request,
            "haproxy-htx", &decision, &transaction)) return 3;
    if (strcmp(argv[5], "file") == 0) {
        file = fopen(argv[6], "rb"); if (!file) return 4;
    }
    while (sent < length) {
        size_t amount = length - sent < sizeof(chunk) ? length - sent : sizeof(chunk);
        memset(chunk, 'a', sizeof(chunk));
        if (file && fread(chunk, 1U, amount, file) != amount) return 5;
        if (!file && marker >= sent && marker < sent + amount) chunk[marker - sent] = 'Z';
        rc = haproxy_modsecurity_transaction_append_request_body_chunk(transaction,
            chunk, (unsigned int)amount, &decision);
        if (rc) { fprintf(stderr, "append rc=%d log=%s\n", rc, decision.log_message); return 6; }
        sent += amount;
    }
    if (file) fclose(file);
    rc = haproxy_modsecurity_transaction_finish_request_body(transaction, &decision);
    if (rc || decision.phase != 2 || decision.disruptive != (reject || match) ||
        (reject && (!decision.body_limit || decision.status != 403 || decision.rule_id)) ||
        (!reject && decision.rule_id != (match ? 1250901 : 0))) {
        fprintf(stderr, "finish rc=%d phase=%d disruptive=%d limit=%d status=%d rule=%d log=%s\n",
            rc, decision.phase, decision.disruptive, decision.body_limit,
            decision.status, decision.rule_id, decision.log_message); return 7;
    }
    if (reject) {
        rc = haproxy_modsecurity_transaction_append_request_body_chunk(transaction,
            (const unsigned char *)"late", 4U, &decision);
        if (!rc || decision.status != 403 || !decision.body_limit ||
                decision.error_class != MSCONNECTOR_TRANSACTION_ERROR_BODY_LIMIT) {
            fprintf(stderr, "native Reject reentry lost status: rc=%d status=%d cause=%d\n",
                rc, decision.status, decision.error_class);
            return 9;
        }
    }
    haproxy_modsecurity_transaction_abort(transaction);
    haproxy_modsecurity_engine_destroy(engine); return 0;
}
"""


class HaproxyRealEngineRequestLimitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        response_harness.HaproxyRealEngineResponseLimitTests.setUpClass.__func__(cls)
        source = cls.runroot / "request-limits.c"
        source.write_text(PROGRAM)
        objroot = cls.build / "haproxy-modsecurity-binding"
        resolution = dict(line.split("=", 1) for line in (objroot / "paths.env").read_text().splitlines() if "=" in line)
        objects = [str(p) for p in objroot.glob("*.o") if p.name != "haproxy_modsecurity_binding_self_test.o" and not p.name.startswith("verify_")]
        result = subprocess.run(["rtk", "proxy", "cc", "-std=c17", "-Wall", "-Wextra", "-Werror",
            "-I", str(response_harness.ROOT / "connectors/haproxy/src"),
            "-I", str(response_harness.ROOT / "common/include"), str(source), *objects,
            resolution["MODSECURITY_LIBRARY"], f'-Wl,-rpath,{resolution["MODSECURITY_LIB_DIR"]}',
            "-lstdc++", "-o", str(cls.binary)], capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    def run_case(self, *, limit, no_files_limit, action, engine_mode, length,
                 reject, match, representation, marker):
        if limit <= 0 or no_files_limit <= 0 or action not in {"Reject", "ProcessPartial"}:
            raise ValueError("explicit positive native request limits and action required")
        rules = self.runroot / "request-case.conf"
        rules.write_text(f"SecRuleEngine {engine_mode}\nSecRequestBodyAccess On\n"
            f"SecRequestBodyLimit {limit}\nSecRequestBodyNoFilesLimit {no_files_limit}\n"
            f"SecRequestBodyLimitAction {action}\nSecAuditEngine Off\n"
            'SecRule REQUEST_BODY "@contains Z" "id:1250901,phase:2,deny,status:403,log"\n'
            'SecAction "id:1250902,phase:2,pass,nolog"\n')
        payload = self.runroot / "request.bin"
        if representation == "file":
            with payload.open("wb") as output:
                for start in range(0, length, 32768):
                    data = bytearray(b"a" * min(32768, length - start))
                    if start <= marker < start + len(data):
                        data[marker - start] = ord("Z")
                    output.write(data)
        result = subprocess.run(["rtk", "proxy", str(self.binary), str(rules), str(length),
            str(int(reject)), str(int(match)), representation, str(payload), str(marker)],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_explicit_boundaries_and_actions(self):
        for action in ("Reject", "ProcessPartial"):
            for length in (7, 8, 9):
                self.run_case(limit=8, no_files_limit=8, action=action, engine_mode="On",
                    length=length, reject=action == "Reject" and length > 8,
                    match=length <= 8, representation="memory", marker=length - 1)

    def test_multichunk_reject_survives_matching_pass_and_eos(self):
        for representation in ("memory", "file"):
            self.run_case(limit=65536, no_files_limit=65536, action="Reject", engine_mode="On",
                length=120000, reject=True, match=False, representation=representation, marker=119999)

    def test_partial_inspects_prefix_and_excludes_tail(self):
        for marker, match in ((3, True), (119999, False)):
            for representation in ("memory", "file"):
                self.run_case(limit=65536, no_files_limit=65536, action="ProcessPartial", engine_mode="On",
                    length=120000, reject=False, match=match, representation=representation, marker=marker)

    def test_detection_only_does_not_fabricate_reject(self):
        self.run_case(limit=65536, no_files_limit=65536, action="Reject", engine_mode="DetectionOnly",
            length=120000, reject=False, match=False, representation="memory", marker=119999)

    def test_tail_beyond_old_connector_limit_with_two_engine_limits(self):
        for representation in ("memory", "file"):
            for limit, reject, match in ((1048576, True, False), (2097152, False, True)):
                self.run_case(limit=limit, no_files_limit=limit, action="Reject", engine_mode="On",
                    length=1048600, reject=reject, match=match, representation=representation, marker=1048599)

    def test_no_files_limit_remains_engine_owned(self):
        self.run_case(limit=131072, no_files_limit=65536, action="Reject", engine_mode="On",
            length=120000, reject=False, match=True, representation="memory", marker=119999)

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
