from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import re
import unittest


ROOT = connector_root()
HARNESS = source_path('connectors/nginx/harness/run_nginx_smoke.sh', root=ROOT)
MAKEFILE = source_path('Makefile', root=ROOT)


class NginxBoundedSoakContractTest(unittest.TestCase):
    def test_stage_uses_bounded_decimal_inputs_and_canonical_categories(self) -> None:
        source = HARNESS.read_text(encoding="utf-8")

        self.assertIn(
            'NGINX_SOAK_CASES="${NGINX_SOAK_CASES:-allow_without_marker ', source
        )
        self.assertIn("NGINX_SOAK_MAX_CASES=8", source)
        self.assertIn('NGINX_SOAK_DURATION_SECONDS="${NGINX_SOAK_DURATION_SECONDS:-30}"', source)
        self.assertIn('NGINX_SOAK_CONCURRENCY="${NGINX_SOAK_CONCURRENCY:-4}"', source)
        self.assertIn("require_bounded_positive_decimal()", source)
        self.assertIn("NGINX_SOAK_DURATION_SECONDS 300", source)
        self.assertIn("NGINX_SOAK_CONCURRENCY 16", source)

        for canonical_case in (
            "allow_without_marker",
            "phase2_body_limits",
            "phase2_args_block",
            "phase1_header_block",
            "request_body_urlencoded_block",
            "phase3_redirect_before_commit",
            "nginx_phase4_deny_after_commit_log_only",
            "nginx_phase4_deny_after_commit_abort",
        ):
            self.assertIn(canonical_case, source)

        self.assertIn("write_bounded_soak_category_selection()", source)
        self.assertIn("category=modern_transport status=not_applicable", source)
        self.assertIn("not_executable) soak_result=not_applicable", source)

    def test_workers_reuse_the_started_harness_and_propagate_failures(self) -> None:
        source = HARNESS.read_text(encoding="utf-8")
        worker_start = source.index("run_bounded_soak_worker()")
        worker_end = source.index("collect_bounded_soak_worker_summaries()")
        worker = source[worker_start:worker_end]

        self.assertIn("send_case_request", worker)
        self.assertIn("SEND_CASE_RESPONSE_BODY=/dev/null", worker)
        self.assertIn("SEND_CASE_CURL_ERROR_LOG=/dev/null", worker)
        self.assertIn("SEND_CASE_MAX_TIME_SECONDS=10", worker)
        self.assertIn("soak_request_matches_case", worker)
        self.assertIn("NGINX_SOAK_WORKER_PIDS", source)
        self.assertIn('wait "$soak_worker_pid"', source)
        self.assertIn('kill -0 "$NGINX_PID"', source)
        self.assertIn('fail "bounded soak worker failures detected"', source)
        self.assertIn('fail "NGINX did not remain alive after bounded soak"', source)

    def test_selected_cases_are_source_bounded_unique_and_canonical(self) -> None:
        source = HARNESS.read_text(encoding="utf-8")
        selection_start = source.index("prepare_bounded_soak_selection()")
        selection_end = source.index("run_all_cases()")
        selection = source[selection_start:selection_end]

        self.assertIn("for soak_case in $NGINX_SOAK_CASES; do", selection)
        self.assertIn(
            'if [ "$soak_case_count" -gt "$NGINX_SOAK_MAX_CASES" ]; then',
            selection,
        )
        self.assertIn(
            'fail "NGINX_SOAK_CASES permits at most $NGINX_SOAK_MAX_CASES canonical case ids"',
            selection,
        )
        self.assertIn(
            'fail "NGINX_SOAK_CASES may select only the bounded canonical case set"',
            selection,
        )
        self.assertIn(
            'fail "NGINX_SOAK_CASES must not repeat canonical case ids"',
            selection,
        )
        self.assertIn(
            'fail "NGINX_SOAK_CASES must select at least one canonical case id"',
            selection,
        )
        for canonical_case in (
            "allow_without_marker",
            "phase2_body_limits",
            "phase2_args_block",
            "phase1_header_block",
            "request_body_urlencoded_block",
            "phase3_redirect_before_commit",
            "nginx_phase4_deny_after_commit_log_only",
            "nginx_phase4_deny_after_commit_abort",
        ):
            self.assertIn(canonical_case, selection)

    def test_soak_output_is_a_count_only_summary_and_cleanup_traps_remain(self) -> None:
        source = HARNESS.read_text(encoding="utf-8")
        summary_start = source.index("write_bounded_soak_summary()")
        summary_end = source.index("run_bounded_soak()")
        summary = source[summary_start:summary_end]
        signal_cleanup_start = source.index("cleanup_on_signal()")
        signal_cleanup_end = source.index("cleanup_on_exit()")
        signal_cleanup = source[signal_cleanup_start:signal_cleanup_end]

        self.assertIn("nginx-bounded-soak-summary.txt", source)
        for field in (
            "requests_completed",
            "request_failures",
            "worker_summary_failures",
            "server_alive",
        ):
            self.assertIn(field, summary)
        self.assertNotIn("RESPONSE_BODY", summary)
        self.assertNotIn("curl-attack.err", summary)
        self.assertIn('trap - "$signal_name" EXIT', signal_cleanup)
        self.assertIn("trap cleanup_on_exit EXIT", source)
        self.assertIn("trap 'cleanup_on_signal INT 130' INT", source)
        self.assertIn("trap 'cleanup_on_signal TERM 143' TERM", source)

    def test_opt_in_make_target_uses_the_existing_framework_wrapper_only(self) -> None:
        makefile = MAKEFILE.read_text(encoding="utf-8")
        target = re.search(
            r"(?ms)^soak-nginx: check-framework prepare-runtime-components\n(?P<recipe>\t[^\n]+)$",
            makefile,
        )
        self.assertIsNotNone(target)
        recipe = target.group("recipe")
        for required in (
            "MSCONNECTOR_SMOKE_STAGE=bounded_soak",
            "MODSECURITY_TEST_VARIANT=no-crs",
            "NO_CRS_BASELINE=1",
            "FORCE_ALL_CASES=1",
            'MODSECURITY_RULE_PREAMBLE_FILE="$(NO_CRS_RULES_FILE)"',
            'sh "$(FRAMEWORK_ROOT)/ci/runtime/run-nginx-smoke.sh"',
        ):
            self.assertIn(required, recipe)
        self.assertNotRegex(makefile, r"(?m)^(?:test|smoke-nginx|quick-check):[^\n]*\bsoak-nginx\b")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
