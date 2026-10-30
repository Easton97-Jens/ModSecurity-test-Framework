"""Exercise actual Common lifecycle/error policy for each registered route.

This is compiled contract evidence. It neither launches ten hosts nor grants a
profile a new Strict/reset capability. Off uses the existing safe contract mode;
the separate off-mode body budget and native host dispatch are tested elsewhere.
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

ROOT = connector_root()
PROFILES = (
    "apache", "nginx", "haproxy-htx", "haproxy-spoe-spop", "envoy-ext-authz",
    "envoy-ext-proc", "traefik-forwardauth", "traefik-native-uds",
    "lighttpd-stock", "lighttpd-patched",
)
ERRORS = ("engine_timeout", "engine_unavailable", "invalid_engine_response",
          "connector_error", "protocol_error")
FIXTURE = r'''
#include "msconnector/transaction_state.h"
#include "connectors/profile_registry.h"
#include <stdio.h>
#include <string.h>

#define REQUIRE(condition) do { if (!(condition)) { return 2; } } while (0)

static int begin(msconnector_transaction_contract *contract,
        const msconnector_transaction_profile *profile, enum msconnector_phase phase) {
    return msconnector_transaction_profile_phase_route(profile, phase) ==
            MSCONNECTOR_TRANSACTION_PHASE_ROUTE_COMPANION_REQUIRED
        ? msconnector_transaction_contract_begin_companion_phase(contract, phase, 200U)
        : msconnector_transaction_contract_begin_phase(contract, phase, 200U);
}

static int prepare(msconnector_transaction_contract *contract,
        const msconnector_transaction_profile *profile, msconnector_transaction_mode mode,
        int committed) {
    REQUIRE(msconnector_transaction_contract_init(contract, profile, "profile-error",
        NULL, NULL, mode, 100U) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    for (enum msconnector_phase phase = MSCONNECTOR_PHASE_REQUEST_HEADERS;
            phase <= MSCONNECTOR_PHASE_RESPONSE_HEADERS; ++phase) {
        if (phase == MSCONNECTOR_PHASE_RESPONSE_HEADERS && profile->companion_phase_mask) {
            REQUIRE(msconnector_transaction_contract_handoff_response_companion(contract, 200U) ==
                MSCONNECTOR_TRANSACTION_TRANSITION_OK);
            REQUIRE(msconnector_transaction_contract_claim_response_companion(contract, 200U) ==
                MSCONNECTOR_TRANSACTION_TRANSITION_OK);
        }
        REQUIRE(begin(contract, profile, phase) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
        REQUIRE(msconnector_transaction_contract_complete_phase(contract, phase, 200U) ==
            MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    }
    REQUIRE(msconnector_transaction_contract_record_response_metadata(contract,
        201, "text/csv", 1U, 8U) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    REQUIRE(msconnector_transaction_contract_set_response_committed(contract, committed) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    REQUIRE(begin(contract, profile, MSCONNECTOR_PHASE_RESPONSE_BODY) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    REQUIRE(msconnector_transaction_contract_record_decision(contract,
        MSCONNECTOR_TRANSACTION_DECISION_LOG_ONLY, "previous-rule", 200U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    return 0;
}

static const struct {
    const char *name;
    msconnector_transaction_error_class error;
    msconnector_transaction_decision_kind kind;
} causes[] = {
    {"engine_timeout", MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT,
        MSCONNECTOR_TRANSACTION_DECISION_ENGINE_TIMEOUT},
    {"engine_unavailable", MSCONNECTOR_TRANSACTION_ERROR_ENGINE_UNAVAILABLE,
        MSCONNECTOR_TRANSACTION_DECISION_ENGINE_UNAVAILABLE},
    {"invalid_engine_response", MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE,
        MSCONNECTOR_TRANSACTION_DECISION_INVALID_ENGINE_RESPONSE},
    {"connector_error", MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR,
        MSCONNECTOR_TRANSACTION_DECISION_CONNECTOR_ERROR},
    {"protocol_error", MSCONNECTOR_TRANSACTION_ERROR_PROTOCOL,
        MSCONNECTOR_TRANSACTION_DECISION_PROTOCOL_ERROR}
};

int main(int argc, char **argv) {
    msconnector_transaction_contract contract;
    msconnector_transaction_decision_policy policy;
    const msconnector_transaction_profile *profile;
    msconnector_decision stale = {0};
    msconnector_transaction_mode mode;
    size_t selected = sizeof(causes) / sizeof(causes[0]);
    int committed;
    int second_failure;
    int first_cleanup;
    int second_cleanup;
    REQUIRE(argc == 5);
    profile = msconnector_profile_registry_find(argv[1]);
    REQUIRE(profile != NULL);
    REQUIRE(strcmp(argv[2], "safe") == 0 || strcmp(argv[2], "strict") == 0);
    mode = strcmp(argv[2], "strict") == 0 ?
        MSCONNECTOR_TRANSACTION_MODE_STRICT : MSCONNECTOR_TRANSACTION_MODE_SAFE;
    REQUIRE(strcmp(argv[3], "before") == 0 || strcmp(argv[3], "after") == 0);
    committed = strcmp(argv[3], "after") == 0;
    for (size_t index = 0U; index < sizeof(causes) / sizeof(causes[0]); ++index) {
        if (strcmp(argv[4], causes[index].name) == 0) { selected = index; break; }
    }
    REQUIRE(selected < sizeof(causes) / sizeof(causes[0]));
    REQUIRE(prepare(&contract, profile, mode, committed) == 0);
    REQUIRE(msconnector_transaction_contract_decision_policy(&contract,
        causes[selected].kind, &policy));
    REQUIRE(msconnector_transaction_contract_fail(&contract,
        causes[selected].error, 300U) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    second_failure = msconnector_transaction_contract_fail(&contract,
        MSCONNECTOR_TRANSACTION_ERROR_EVENT_LIMIT, 301U);
    REQUIRE(!msconnector_transaction_contract_can_append_body(&contract, 1));
    REQUIRE(begin(&contract, profile, MSCONNECTOR_PHASE_RESPONSE_BODY) !=
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    REQUIRE(msconnector_transaction_contract_complete_phase(&contract,
        MSCONNECTOR_PHASE_RESPONSE_BODY, 302U) != MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    REQUIRE(contract.completed_phase_mask == (MSCONNECTOR_TRANSACTION_PHASE_MASK_P1 |
        MSCONNECTOR_TRANSACTION_PHASE_MASK_P2 | MSCONNECTOR_TRANSACTION_PHASE_MASK_P3));
    stale.kind = MSCONNECTOR_DECISION_KIND_ALLOW;
    stale.status = MSCONNECTOR_STATUS_ERROR;
    REQUIRE(msconnector_transaction_decision_kind_from_engine(&stale) ==
        MSCONNECTOR_TRANSACTION_DECISION_CONNECTOR_ERROR);
    first_cleanup = msconnector_transaction_contract_cleanup(&contract, 303U);
    second_cleanup = msconnector_transaction_contract_cleanup(&contract, 304U);
    printf("{\"profile\":\"%s\",\"mode\":\"%s\",\"committed\":%d,"
        "\"cause\":\"%s\",\"action\":\"%s\",\"policy\":\"%s\","
        "\"rule_id\":\"%s\",\"event_type\":\"%s\",\"terminal\":%d,"
        "\"cleanup_required\":%d,\"second_failure\":%d,\"first_cleanup\":%d,"
        "\"second_cleanup\":%d,\"status\":%d,\"strict_capability\":%d}\n",
        profile->profile_name, argv[2], contract.response_committed,
        msconnector_transaction_error_class_name(contract.error_class),
        msconnector_decision_action_name(contract.action),
        msconnector_transaction_fail_policy_name(policy.fail_policy),
        contract.rule_id, policy.event_type, policy.terminal, policy.cleanup_required,
        second_failure, first_cleanup, second_cleanup, contract.response_status,
        contract.strict_post_commit_action);
    return 0;
}
'''


class ProfileErrorPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("a C compiler is required for profile error tests")
        temporary = tempfile.TemporaryDirectory(prefix="pr382-profile-errors-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        fixture = directory / "profiles.c"
        fixture.write_text(FIXTURE, encoding="utf-8")
        binary = directory / "profiles"
        command = compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread",
                              "-I", str(source_path('common/include', root=ROOT)), "-I", str(ROOT),
                              str(fixture), str(source_path('common/src/transaction_state.c', root=ROOT)),
                              str(source_path('common/src/decision_action.c', root=ROOT)),
                              str(source_path('connectors/profile_registry.c', root=ROOT)), "-o", str(binary)]
        compiled = subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)
        if compiled.returncode:
            raise AssertionError("profile fixture compilation failed:\n" + compiled.stderr[-6000:])
        cls.records = []
        for profile in PROFILES:
            for mode in ("safe", "strict"):
                for commitment in ("before", "after"):
                    for cause in ERRORS:
                        result = subprocess.run([str(binary), profile, mode, commitment, cause],
                                                capture_output=True, text=True, timeout=5, check=False)
                        if result.returncode:
                            raise AssertionError(f"profile case failed: {profile}/{mode}/{commitment}/{cause}: " + result.stderr[-2000:])
                        cls.records.append(json.loads(result.stdout))

    def test_every_profile_and_failure_is_exercised(self) -> None:
        self.assertEqual(len(self.records), 200)
        self.assertEqual({record["profile"] for record in self.records}, set(PROFILES))
        self.assertEqual({record["cause"] for record in self.records}, set(ERRORS))

    def test_technical_errors_never_become_log_only(self) -> None:
        for record in self.records:
            with self.subTest(profile=record["profile"], mode=record["mode"], cause=record["cause"], committed=record["committed"]):
                self.assertEqual(record["action"], "error" if record["committed"] else "deny")
                self.assertEqual(record["policy"], "stop_io" if record["committed"] else "fail_closed")
                self.assertEqual(record["terminal"], 1)
                self.assertEqual(record["cleanup_required"], 1)

    def test_first_cause_survives_reentry_without_stale_rule(self) -> None:
        for record in self.records:
            with self.subTest(profile=record["profile"], cause=record["cause"]):
                self.assertEqual(record["event_type"], record["cause"])
                self.assertEqual(record["rule_id"], "")
                self.assertNotEqual(record["second_failure"], 0)
                self.assertEqual(record["first_cleanup"], 0)
                self.assertNotEqual(record["second_cleanup"], 0)

    def test_policy_does_not_rewrite_http_or_invent_host_capability(self) -> None:
        for record in self.records:
            with self.subTest(profile=record["profile"], mode=record["mode"]):
                self.assertEqual(record["status"], 201)
                self.assertEqual(record["strict_capability"], int(record["profile"] == "lighttpd-stock"))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
