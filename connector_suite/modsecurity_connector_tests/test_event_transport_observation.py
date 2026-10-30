"""Exercise missing versus observed transport metadata in the real Common writer.

These tests compile Common code, not native servers. Connector names are labels
in the fixture and must not be presented as six-host integration evidence.
"""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

from modsecurity_connector_tests.c_source_contract import function_definition

ROOT = connector_root()
FAMILIES = ("apache", "nginx", "haproxy", "envoy", "traefik", "lighttpd")
ABSENT = ("null", "", "not_observable")
NON_RULE_EVENTS = {
    "limit": ("body_limit", "MSCONN_EVENT_BODY_LIMIT"),
    "request-limit": ("body_limit", "MSCONN_EVENT_BODY_LIMIT"),
    "unsupported": ("unsupported_capability", "MSCONN_EVENT_UNSUPPORTED_CAPABILITY"),
    "cancel": ("client_cancel", "MSCONN_EVENT_CLIENT_CANCEL"),
    "disconnect": ("upstream_disconnect", "MSCONN_EVENT_UPSTREAM_DISCONNECT"),
}

FIXTURE = r'''
#include "msconnector/event_protocol.h"
#include "msconnector/event_jsonl.h"
#include "msconnector/integrity_event.h"
#include <stdio.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "fixture check at %d\n", __LINE__); return 1; } } while (0)
int main(int argc, char **argv) {
    msconnector_event source, view, twice;
    char json[8192], again[8192];
    int truncated = 0;
    CHECK(argc == 4);
    msconnector_event_init(&source);
    source.meta.connector = argv[3];
    source.meta.integration_mode = "common-compiled-fixture";
    source.meta.transaction_id = "tx-observation";
    source.meta.message_id = MSCONN_EVENT_PHASE4_HARD_ABORT_AFTER_200;
    source.meta.event = "phase4_intervention";
    source.decision.phase = MSCONNECTOR_PHASE_RESPONSE_BODY;
    source.decision.status = MSCONNECTOR_STATUS_BLOCKED;
    source.decision.action = "abort_connection";
    source.decision.requested_action = "deny";
    source.decision.actual_action = "abort_connection";
    source.decision.rule_id = "1001";
    source.http.http_status = 403;
    source.http.original_http_status = 201;
    source.http.visible_http_status = 201;
    source.http.transport_result = strcmp(argv[2], "null") == 0 ? NULL : argv[2];
    source.flags.response_committed = 1;
    source.flags.headers_sent = 1;
    source.flags.late_intervention_mode = "strict";
    source.flags.eos_seen = 0;
    source.body.bytes_seen = 4096;
    source.body.bytes_inspected = 1024;
    source.request.uri = "/public?token=secret-value";
    if (strcmp(argv[1], "error") == 0) {
        source.meta.message_id = MSCONN_EVENT_INVALID_ENGINE_RESPONSE;
        source.http.http_status = 500;
    } else if (strcmp(argv[1], "safe") == 0) {
        source.decision.actual_action = "log_only";
        source.flags.late_intervention_mode = "safe";
    } else if (strcmp(argv[1], "custom") == 0) {
        source.meta.message_id = "CUSTOM_APPLICATION";
        source.meta.event = "application_event";
        source.meta.message = "application-specific message";
    } else if (strcmp(argv[1], "limit") == 0 || strcmp(argv[1], "request-limit") == 0) {
        source.meta.message_id = MSCONN_EVENT_BODY_LIMIT;
        if (strcmp(argv[1], "request-limit") == 0) {
            source.decision.phase = MSCONNECTOR_PHASE_REQUEST_BODY;
        }
    } else if (strcmp(argv[1], "unsupported") == 0) {
        source.meta.message_id = MSCONN_EVENT_UNSUPPORTED_CAPABILITY;
    } else if (strcmp(argv[1], "cancel") == 0) {
        source.meta.message_id = MSCONN_EVENT_CLIENT_CANCEL;
        source.decision.status = MSCONNECTOR_STATUS_ERROR;
    } else if (strcmp(argv[1], "disconnect") == 0) {
        source.meta.message_id = MSCONN_EVENT_UPSTREAM_DISCONNECT;
        source.decision.status = MSCONNECTOR_STATUS_ERROR;
    }
    source.flags.connection_aborted = strcmp(argv[2], "connection_aborted") == 0;
    source.integrity.event_hash = msconnector_integrity_event_hash(&source, 7);
    CHECK(msconnector_event_protocol_view(&source, &view));
    CHECK(msconnector_event_protocol_view(&view, &twice));
    CHECK(msconnector_integrity_event_hash(&view, 7) == source.integrity.event_hash);
    CHECK(msconnector_integrity_event_hash(&twice, 7) == source.integrity.event_hash);
    CHECK(view.http.visible_http_status == source.http.visible_http_status);
    CHECK(view.flags.connection_aborted == source.flags.connection_aborted);
    CHECK(view.flags.eos_seen == source.flags.eos_seen);
    CHECK(view.body.bytes_seen == source.body.bytes_seen);
    CHECK(view.body.bytes_inspected == source.body.bytes_inspected);
    CHECK(msconnector_event_write_jsonl_line(&source, json, sizeof(json), &truncated));
    CHECK(msconnector_event_write_jsonl_line(&view, again, sizeof(again), &truncated));
    CHECK(strcmp(json, again) == 0);
    CHECK(strstr(json, "secret-value") == NULL);
    fputs(json, stdout);
    return 0;
}
'''


class EventTransportObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("a C compiler is required for observation tests")
        temporary = tempfile.TemporaryDirectory(prefix="event-observation-")
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        cls.directory = directory
        cls.compiler = compiler
        cls.binary = directory / "observation"
        (directory / "fixture.c").write_text(FIXTURE, encoding="utf-8")
        phase_source = (source_path('common/src/transaction_state.c', root=ROOT)).read_text(encoding="utf-8")
        phase = '#include "msconnector/transaction_state.h"\n' + function_definition(
            phase_source, "msconnector_phase_name"
        )
        (directory / "phase.c").write_text(phase, encoding="utf-8")
        sources = ("event.c", "event_jsonl.c", "integrity_event.c", "http_status.c", "json_escape.c", "status.c")
        command = compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror", "-I", str(source_path('common/include', root=ROOT))]
        command += [str(directory / "fixture.c"), str(directory / "phase.c")]
        command += [str(source_path('common/src', root=ROOT) / name) for name in sources]
        command += ["-o", str(cls.binary)]
        cls.build_command = command
        result = subprocess.run(command, capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError("observation fixture compilation failed:\n" + result.stderr)

    def event(self, scenario: str, transport: str, family: str = "common") -> dict:
        result = subprocess.run(
            [str(self.binary), scenario, transport, family],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_unobserved_rule_never_claims_an_executed_abort(self) -> None:
        for transport in ABSENT:
            with self.subTest(transport=transport):
                event = self.event("rule", transport)
                self.assertEqual(event["event"], "engine_decision")
                self.assertEqual(event["message_id"], "MSCONN_EVENT_ENGINE_DECISION")
                self.assertEqual(event["actual_action"], "")
                self.assertEqual(event["action"], "deny")
                self.assertEqual(event["requested_action"], "deny")
                self.assertIn("not observed", event["message"])
                self.assertFalse(event["connection_aborted"])
                self.assertFalse(event["eos_seen"])

    def test_unobserved_error_retains_technical_cause(self) -> None:
        for transport in ABSENT:
            with self.subTest(transport=transport):
                event = self.event("error", transport)
                self.assertEqual(event["event"], "invalid_engine_response")
                self.assertEqual(event["status"], "error")
                self.assertEqual(event["action"], "error")
                self.assertEqual(event["requested_action"], "error")
                self.assertEqual(event["actual_action"], "")
                self.assertEqual(event["rule_id"], "")
                self.assertEqual(event["visible_http_status"], 201)

    def test_observed_safe_and_abort_remain_distinct(self) -> None:
        safe = self.event("safe", "log_only")
        self.assertEqual(safe["actual_action"], "log_only")
        self.assertEqual(safe["event"], "phase4_intervention")
        self.assertFalse(safe["connection_aborted"])
        abort = self.event("rule", "connection_aborted")
        self.assertEqual(abort["actual_action"], "abort_connection")
        self.assertTrue(abort["connection_aborted"])
        self.assertEqual(abort["message_id"], "MSCONN_EVENT_PHASE4_HARD_ABORT")
        self.assertEqual(abort["visible_http_status"], 201)
        self.assertNotIn("HTTP 200", abort["message"])

    def test_observed_abort_does_not_reclassify_technical_error(self) -> None:
        event = self.event("error", "connection_aborted")
        self.assertEqual(event["status"], "error")
        self.assertEqual(event["requested_action"], "error")
        self.assertEqual(event["actual_action"], "abort_connection")
        self.assertEqual(event["rule_id"], "")

    def test_custom_event_is_not_reinterpreted(self) -> None:
        event = self.event("custom", "not_observable")
        self.assertEqual(event["event"], "application_event")
        self.assertEqual(event["message"], "application-specific message")
        self.assertEqual(event["actual_action"], "abort_connection")

    def test_missing_observation_contract_is_family_neutral(self) -> None:
        for scenario in ("rule", "error", *NON_RULE_EVENTS):
            expected = None
            for family in FAMILIES:
                with self.subTest(scenario=scenario, family=family):
                    event = self.event(scenario, "not_observable", family)
                    self.assertEqual(event.pop("connector"), family)
                    event.pop("event_hash")
                    if expected is None:
                        expected = event
                    self.assertEqual(event, expected)

    def test_unobserved_non_rule_events_do_not_claim_host_enforcement(self) -> None:
        for scenario, (name, message_id) in NON_RULE_EVENTS.items():
            for transport in ABSENT:
                with self.subTest(scenario=scenario, transport=transport):
                    event = self.event(scenario, transport)
                    self.assertEqual(event["event"], name)
                    self.assertEqual(event["message_id"], message_id)
                    self.assertEqual(event["actual_action"], "")
                    requested = "error" if scenario in ("cancel", "disconnect") else "deny"
                    self.assertEqual(event["action"], requested)
                    self.assertEqual(event["requested_action"], requested)
                    self.assertEqual(event["visible_http_status"], 201)
                    self.assertFalse(event["connection_aborted"])

    def test_observed_non_rule_events_preserve_the_actual_action(self) -> None:
        for scenario in NON_RULE_EVENTS:
            with self.subTest(scenario=scenario):
                event = self.event(scenario, "connection_aborted")
                self.assertEqual(event["actual_action"], "abort_connection")
                self.assertEqual(event["action"], "abort_connection")
                self.assertTrue(event["connection_aborted"])

    def test_limits_keep_their_phase_specific_cause(self) -> None:
        for scenario, cause in (("limit", "response_body_limit_exceeded"),
                                ("request-limit", "request_body_limit_exceeded")):
            with self.subTest(scenario=scenario):
                event = self.event(scenario, "not_observable")
                self.assertEqual(event["status"], "blocked")
                self.assertEqual(event["reason"], cause)
        self.assertEqual(self.event("unsupported", "not_observable")["status"], "unsupported")
        for scenario in ("cancel", "disconnect"):
            self.assertEqual(self.event(scenario, "not_observable")["status"], "error")

    def test_removing_the_shared_observation_guard_exposes_the_regression(self) -> None:
        header = (source_path('common/include/msconnector/event_protocol.h', root=ROOT)).read_text(encoding="utf-8")
        callsite = "    msconnector_event_protocol_observed_action_view(out);\n"
        self.assertEqual(header.count(callsite), 1)
        include = self.directory / "negative-control"
        target = include / "msconnector/event_protocol.h"
        target.parent.mkdir(parents=True)
        target.write_text(header.replace(callsite, "", 1), encoding="utf-8")
        binary = self.directory / "unguarded-observation"
        command = self.compiler + ["-I", str(include)]
        command += self.build_command[len(self.compiler):-2] + ["-o", str(binary)]
        compiled = subprocess.run(command, capture_output=True, text=True, timeout=90)
        self.assertEqual(compiled.returncode, 0, compiled.stderr[-4000:])
        result = subprocess.run([str(binary), "limit", "not_observable", "common"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        event = json.loads(result.stdout)
        self.assertEqual(event["actual_action"], "abort_connection")
        self.assertNotEqual(event["actual_action"], "")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
