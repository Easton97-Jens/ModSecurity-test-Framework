"""Reject regressions in the actual Apache collector and its storage helper.

Reuse the existing isolated checker repository, rather than copying its setup.
These source mutations supplement the compiled APR/native lifecycle tests.
"""
from __future__ import annotations

from pathlib import Path
import unittest

from tests import test_apache_common_adoption as adoption

FLOW = "Apache validates the native intervention result and preserves both redirect and non-redirect enforcement sinks"
STORAGE = "Apache preserves redirect through the canonical decision mapper and native Location sink"


class ApacheNativeAdoptionTests(unittest.TestCase):
    def run_checker(self, old: str | None = None, new: str = ""):
        def mutate(filters: Path) -> None:
            adoption.replace_once(filters.parent / "mod_security3.c", old, new)

        fixture = adoption.ApacheCommonAdoptionCheckerTests(
            "test_current_helper_based_input_filter_is_accepted")
        return fixture._run_checker(None if old is None else mutate)

    def assert_rejected(self, old: str, new: str, message: str = FLOW) -> None:
        result = self.run_checker(old, new)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("FAIL: " + message, result.stdout.splitlines())

    def test_current_collector_and_request_owned_storage_pass(self):
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS: " + FLOW, result.stdout.splitlines())

    def test_zero_result_cannot_bypass_native_buffer_release(self):
        self.assert_rejected(
            "    } else if (native_result == 0 && !intervention.disruptive) {\n"
            "        result = N_INTERVENTION_STATUS;",
            "    } else if (native_result == 0 && !intervention.disruptive) {\n"
            "        return N_INTERVENTION_STATUS;")

    def test_unknown_positive_result_cannot_reach_storage(self):
        self.assert_rejected(
            "if (native_result != 0 && native_result != 1)",
            "if (native_result < 0)", STORAGE)

    def test_invalid_native_result_cannot_be_relabelled_as_host_error(self):
        self.assert_rejected(
            "    if (native_result != 0 && native_result != 1) {\n"
            "        result = apache_record_failure(msr, r,\n"
            "            MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE);",
            "    if (native_result != 0 && native_result != 1) {\n"
            "        result = apache_record_failure(msr, r,\n"
            "            MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR);")

    def test_collecting_flag_must_be_claimed_before_native_callback(self):
        self.assert_rejected("    msr->intervention.collecting = 1;",
                             "    msr->intervention.collecting = 0;")

    def test_collecting_flag_must_be_released_after_native_buffers(self):
        self.assert_rejected("    msr->intervention.collecting = 0;",
                             "    (void)msr->intervention.collecting;")

    def test_cleanup_call_cannot_be_removed(self):
        self.assert_rejected("    msc_release_intervention_buffers(&intervention);",
                             "    (void)intervention;", STORAGE)

    def test_late_redirect_cannot_mutate_committed_headers(self):
        self.assert_rejected(
            "if (redirect && !msr->response.committed && r->bytes_sent == 0)",
            "if (redirect)", STORAGE)

    def test_comment_cannot_supply_the_post_callback_error_guard(self):
        self.assert_rejected(
            "} else if (msr->contract.error_class != MSCONNECTOR_TRANSACTION_ERROR_NONE) {",
            "} else if (0) { /* msr->contract.error_class != MSCONNECTOR_TRANSACTION_ERROR_NONE */",
            STORAGE)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
