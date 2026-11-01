#!/usr/bin/env python3
"""Guard the Parent-owned Apache Phase-4 response regression seam."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import subprocess
import unittest


ROOT = connector_root()
HARNESS = source_path('connectors/apache/harness/run_apache_smoke.sh', root=ROOT)
RUNNER = source_path('ci/runtime/lifecycle/run-apache-phase4-response-regression.sh', root=ROOT)
CASE_ROOT = source_path('ci/runtime/lifecycle/cases/apache-phase4-response', root=ROOT)
FILTERS = source_path('connectors/apache/src/msc_filters.c', root=ROOT)
UTILS = source_path('connectors/apache/src/msc_utils.c', root=ROOT)
ROGUE_HANDLER = source_path('connectors/apache/harness/mod_phase4_terminal_rogue.c', root=ROOT)
PHASE4_RESPONSE_BODY_MARKER = "no-crs-response-body-marker"
APACHE_EXAMPLE_README = source_path('examples/apache/README.md', root=ROOT)
APACHE_EXAMPLE_README_DE = source_path('examples/apache/README.de.md', root=ROOT)
APACHE_SAFE_CONFIGURATION = source_path('examples/apache/safe/httpd.conf', root=ROOT)
APACHE_CONFIGURATION_REFERENCE = source_path('examples/apache/configuration-reference.md', root=ROOT)
APACHE_CONFIGURATION_REFERENCE_DE = source_path('examples/apache/configuration-reference.de.md', root=ROOT)


class ApachePhase4ResponseRegressionWiringTest(unittest.TestCase):
    def test_harness_has_explicit_secure_and_vulnerable_barrier_expectations(self) -> None:
        source = HARNESS.read_text(encoding="utf-8")
        self.assertIn("MSCONNECTOR_PHASE4_SYNC_EXPECTATION", source)
        self.assertIn("bypass|precommit_deny|custom_mime_deny|allow|log_only|client_abort|engine_append_failure", source)
        self.assertIn("pre-commit deny released original response bytes before EOS", source)
        self.assertIn("custom-MIME pre-commit deny released original response bytes before EOS", source)
        self.assertIn("engine ProcessPartial failure", source)
        self.assertIn("bypass reproduction did not take the Safe log_only fallback", source)
        self.assertNotIn("APACHE_PHASE4_BODY_LIMIT", source)
        self.assertIn("assert_single_h1_status", source)
        self.assertIn("assert_text_response_headers", source)
        self.assertIn("--http1.1", source)

    def test_harness_extracts_repeated_phase4_grep_literals_without_relaxing_controls(self) -> None:
        harness = HARNESS.read_text(encoding="utf-8")

        self.assertEqual(
            harness.count("readonly PHASE4_FIRST_BYTE_PREFIX='first-byte-prefix'"),
            1,
        )
        self.assertEqual(harness.count("first-byte-prefix"), 3)
        self.assertNotIn("grep -F 'first-byte-prefix'", harness)
        self.assertNotIn("grep -F $PHASE4_FIRST_BYTE_PREFIX", harness)
        self.assertEqual(harness.count('grep -F "$PHASE4_FIRST_BYTE_PREFIX"'), 4)
        self.assertEqual(
            harness.count(
                "readonly PHASE4_RESPONSE_BODY_MARKER="
                f"'{PHASE4_RESPONSE_BODY_MARKER}'"
            ),
            1,
        )
        self.assertEqual(harness.count(PHASE4_RESPONSE_BODY_MARKER), 1)
        self.assertEqual(
            harness.count('expected_body="first-byte-prefix$PHASE4_RESPONSE_BODY_MARKER"'),
            2,
        )
        self.assertNotIn(f"grep -F '{PHASE4_RESPONSE_BODY_MARKER}'", harness)
        self.assertGreaterEqual(
            harness.count('grep -F "$PHASE4_RESPONSE_BODY_MARKER"'),
            8,
        )
        self.assertIn("pre-commit deny leaked original response bytes", harness)
        self.assertIn("custom-MIME pre-commit deny leaked original response bytes", harness)
        self.assertIn(
            "engine ProcessPartial failure released an uninspected original response byte",
            harness,
        )

        self.assertEqual(
            harness.count(
                "readonly PHASE4_TRANSACTION_REBIND_REFUSAL="
                "'request transaction cannot be safely rebound to the target URI'"
            ),
            1,
        )
        self.assertEqual(
            harness.count("request transaction cannot be safely rebound to the target URI"),
            1,
        )
        self.assertNotIn(
            "grep -F 'request transaction cannot be safely rebound to the target URI'",
            harness,
        )
        self.assertNotIn("grep -F $PHASE4_TRANSACTION_REBIND_REFUSAL", harness)
        self.assertEqual(
            harness.count('grep -F "$PHASE4_TRANSACTION_REBIND_REFUSAL"'),
            6,
        )
        self.assertIn(
            "Phase-4 internal redirect abort lacks the transaction-rebind refusal",
            harness,
        )
        self.assertIn(
            "nested ErrorDocument redirect lacks the transaction-rebind refusal",
            harness,
        )
        self.assertIn(
            "pre-output ErrorDocument redirect lacks the transaction-rebind refusal",
            harness,
        )

    def test_synchronized_upstream_cli_contract_selects_only_supported_arguments(self) -> None:
        source = HARNESS.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("APACHE_PHASE4_SYNCHRONIZED_UPSTREAM_CONTROL_ROOT", source)
        self.assertIn("APACHE_PHASE4_SYNCHRONIZED_UPSTREAM_CONTROL_ROOT", runner)
        self.assertIn('if [ "$APACHE_PHASE4_SYNCHRONIZED_UPSTREAM_CONTROL_ROOT" = "1" ]; then', source)
        self.assertIn('set -- "$PYTHON_BIN" "$SYNCHRONIZED_UPSTREAM" --serve', source)
        self.assertIn('--control-root "$SYNCHRONIZED_DIR"', source)
        self.assertIn("synchronized_upstream_control_root=1", runner)
        for argument in (
            "--ready-file",
            "--paused-file",
            "--release-file",
            "--server-evidence-file",
        ):
            self.assertIn(argument, source)

    def test_client_abort_forgets_the_reaped_synchronized_upstream_pid(self) -> None:
        source = HARNESS.read_text(encoding="utf-8")
        self.assertIn(
            'wait "$SYNCHRONIZED_UPSTREAM_PID"\n'
            "        upstream_rc=$?\n"
            "        SYNCHRONIZED_UPSTREAM_PID=\n",
            source,
        )
        cleanup = source.split("apache_profile_stop_tracked_process() {\n", 1)[1].split(
            "apache_profile_publish_cleanup_receipt() {\n", 1
        )[0]
        self.assertIn("process_pid=$2 SYNCHRONIZED_UPSTREAM_PID=", cleanup)
        self.assertIn("process_pid=$2 RESPONSE_HEADER_BACKEND_PID=", cleanup)

    def test_auxiliary_process_cleanup_consumes_each_pid_before_reentry(self) -> None:
        source = HARNESS.read_text(encoding="utf-8")
        cleanup = "apache_profile_stop_tracked_process() {\n" + source.split(
            "apache_profile_stop_tracked_process() {\n", 1
        )[1].split("apache_profile_publish_cleanup_receipt() {\n", 1)[0]
        script = "\n".join(
            (
                "set -eu",
                "alive_sync=1 kill_sync=0 wait_sync=0",
                "alive_backend=1 kill_backend=0 wait_backend=0",
                "kill() {",
                '  if [ "$1" = "-0" ]; then',
                '    case "$2" in 4242) [ "$alive_sync" -eq 1 ] ;; 5252) [ "$alive_backend" -eq 1 ] ;; esac',
                "    return",
                "  fi",
                '  case "$1" in',
                "    4242) alive_sync=0; kill_sync=$((kill_sync + 1)) ;;",
                "    5252) alive_backend=0; kill_backend=$((kill_backend + 1)) ;;",
                "  esac",
                "}",
                "wait() {",
                '  case "$1" in',
                "    4242) wait_sync=$((wait_sync + 1)) ;;",
                "    5252) wait_backend=$((wait_backend + 1)) ;;",
                "  esac",
                "}",
                cleanup,
                "SYNCHRONIZED_UPSTREAM_PID=4242",
                'apache_profile_stop_tracked_process synchronized-upstream "$SYNCHRONIZED_UPSTREAM_PID"',
                'apache_profile_stop_tracked_process synchronized-upstream "$SYNCHRONIZED_UPSTREAM_PID"',
                "RESPONSE_HEADER_BACKEND_PID=5252",
                'apache_profile_stop_tracked_process response-header-backend "$RESPONSE_HEADER_BACKEND_PID"',
                'apache_profile_stop_tracked_process response-header-backend "$RESPONSE_HEADER_BACKEND_PID"',
                'printf "%s %s %s %s %s %s\\n" "$SYNCHRONIZED_UPSTREAM_PID" "$RESPONSE_HEADER_BACKEND_PID" "$kill_sync" "$wait_sync" "$kill_backend" "$wait_backend"',
            )
        )
        completed = subprocess.run(
            ["sh", "-c", script],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.stdout, "  1 1 1 1\n")

    def test_parent_runner_keeps_framework_catalog_unchanged(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("EXTRA_CASE_ROOTS", source)
        self.assertIn("MODSECURITY_RULE_PREAMBLE_FILE=", source)
        self.assertIn("FORCE_ALL_CASES=1", source)
        for mode in (
            "bypass|deny|allow|log-only|client-abort|empty|empty-deny|limit|custom-mime-deny|engine-limit",
            "fragmented-buckets",
            "redirect-bypass-h1|redirect-abort-h1|redirect-bypass-h2|redirect-abort-h2",
            "redirect-target-config-bypass-h1|redirect-target-config-abort-h1",
            "redirect-uri-bypass-h1|redirect-uri-abort-h1",
            "redirect-target-handler-abort-h1|redirect-target-handler-abort-h2",
            "downstream-error-document-h1|downstream-error-document-h2|upstream-error-document-h1|upstream-error-document-h2",
            "nested-error-document-redirect-h1|preoutput-error-document-h1|preoutput-error-document-h2",
            "rogue-h1|rogue-allow-h1|rogue-p3-h1|rogue-p3-header-freeze-h1|rogue-p3-header-freeze-h2|rogue-error-document-h1|rogue-h2|rogue-error-document-h2",
        ):
            self.assertIn(mode, source)
        self.assertIn("apache_phase4_content_type_synchronized_upstream.py", source)
        self.assertIn("APACHE_PHASE4_ROGUE_TEST", source)
        self.assertNotIn("modules/ModSecurity-test-Framework/tests/cases", source)

    def test_regression_cases_cover_deny_allow_log_only_empty_and_limit(self) -> None:
        expected = {
            "precommit-deny.yaml": ("2190401", "deny,status:403", "SecAuditLog"),
            "allow.yaml": ("SecResponseBodyAccess On",),
            "log-only.yaml": ("2190402", "pass,log", "SecAuditLog"),
            "empty-allow.yaml": ('body: ""',),
            "empty-deny.yaml": ("2190403", "@rx ^$", "text/html", "deny,status:403", 'body: ""'),
            "limit-reject.yaml": ("body-exceeds-eight-byte-phase4-limit",),
            "custom-mime-deny.yaml": ("2190404", "application/vnd.apache-phase4+json", "deny,status:403"),
            "engine-limit-process-partial.yaml": ("2190405", "SecResponseBodyLimit 8", "SecResponseBodyLimitAction ProcessPartial"),
            "precommit-phase3-deny.yaml": ("2190406", "RESPONSE_HEADERS:Content-Type", "phase:3", "deny,status:403"),
            "precommit-phase3-header-freeze.yaml": ("2190407", "2190408", "RESPONSE_HEADERS:ETag", "phase:3", "deny,status:403"),
            "redirect-uri-policy.yaml": ("2190411", "REQUEST_URI", "RESPONSE_BODY", "deny,status:403"),
        }
        for name, markers in expected.items():
            with self.subTest(case=name):
                source = (CASE_ROOT / name).read_text(encoding="utf-8")
                for marker in markers:
                    self.assertIn(marker, source)

    def test_all_mime_phase4_path_streams_the_pre_eos_prefix_and_keeps_only_eos(self) -> None:
        filters = FILTERS.read_text(encoding="utf-8")
        utils = UTILS.read_text(encoding="utf-8")
        self.assertIn("apache_output_filter_prepare_response_brigade(msr, conf, f, &bb_in,", filters)
        self.assertIn("apr_brigade_split_ex(bb_in, eos_bucket, NULL)", filters)
        self.assertIn("apache_phase4_release_response_brigade", filters)
        self.assertIn("apache_phase4_normalize_response_brigade", filters)
        self.assertIn("APR_BUCKET_IS_FLUSH(bucket)", filters)
        self.assertNotIn("ap_save_brigade(", filters)
        self.assertNotIn("MSCONNECTOR_PHASE4_MAX_HELD_BUCKETS", filters)
        self.assertNotIn("response_brigade_bucket_count", filters)
        self.assertIn("pre-EOS prefix immediately", filters)
        self.assertIn("terminal EOS fragment", filters)
        self.assertIn("next-filter invocation is the Apache commitment boundary", filters)
        self.assertIn("(starts_response || terminal) && !msr->response.committed", filters)
        self.assertIn("A progressive downstream failure may already have exposed a body", filters)
        self.assertIn("apache_phase4_release_response_brigade(msr, f, bb_in, 0)", filters)
        self.assertIn("terminal_brigade,\n        1)", filters)
        self.assertIn("SIZE_MAX - msr->response_body_bytes_seen", filters)
        self.assertIn("response_brigade_bucket_count = 0U;", utils)
        self.assertIn("APACHE_PHASE4_FRAGMENTED_BUCKETS_TEST", HARNESS.read_text(encoding="utf-8"))
        self.assertIn("APACHE_PHASE4_FRAGMENTED_BUCKET_BOUNDARY_TEST", HARNESS.read_text(encoding="utf-8"))
        self.assertIn("fragmented-buckets", RUNNER.read_text(encoding="utf-8"))
        self.assertIn("fragmented-buckets-boundary", RUNNER.read_text(encoding="utf-8"))
        self.assertIn("phase4-fragmented-bucket", ROGUE_HANDLER.read_text(encoding="utf-8"))
        self.assertIn("PHASE4_FRAGMENTED_BUCKET_COUNT 4097U", ROGUE_HANDLER.read_text(encoding="utf-8"))
        self.assertIn("PHASE4_FRAGMENTED_BUCKET_BOUNDARY_COUNT 4095U", ROGUE_HANDLER.read_text(encoding="utf-8"))
        self.assertIn("PHASE4_FRAGMENTED_BUCKET_SPLIT_COUNT 2048U", ROGUE_HANDLER.read_text(encoding="utf-8"))
        self.assertNotIn("apache_phase4_in_scope", filters)
        self.assertNotIn("response_body_scope_decided", filters)
        self.assertIn("SecResponseBodyMimeType selection", filters)
        self.assertIn("msc_append_response_body(msr->t,", filters)
        self.assertIn("!msconnector_native_body_append_can_continue(msc_append_response_body(msr->t,", filters)
        self.assertIn("(const unsigned char *)data, len)))", filters)
        self.assertIn("!msconnector_native_phase_succeeded(msc_process_response_body(msr->t))", filters)
        self.assertIn("r->bytes_sent > 0", filters)
        self.assertIn("response_phase4_eos_released", filters)
        self.assertNotIn("|| r->eos_sent", filters)
        self.assertIn("missing progressive response brigade", filters)
        self.assertIn("response_phase4_gate_failed", filters)
        self.assertIn("if (msr->response_phase4_eos_released)", filters)
        self.assertIn("r->connection->aborted = 1", filters)
        self.assertIn("phase4_terminal_guard_filter", filters)
        self.assertIn("MSC_PHASE4_TERMINAL_OUTPUT_EMITTING", filters)
        self.assertIn("MSC_PHASE4_TERMINAL_OUTPUT_SEALED", filters)
        self.assertIn("ap_register_output_filter(\"MODSECURITY_PHASE4_GUARD\"", (source_path('connectors/apache/src/mod_security3.c', root=ROOT)).read_text(encoding="utf-8"))
        self.assertIn("ap_add_output_filter(\"MODSECURITY_PHASE4_GUARD\"", (source_path('connectors/apache/src/mod_security3.c', root=ROOT)).read_text(encoding="utf-8"))
        self.assertIn("mandatory Phase 4 content filter; aborting request", (source_path('connectors/apache/src/mod_security3.c', root=ROOT)).read_text(encoding="utf-8"))
        self.assertNotIn("ap_bucket_eoc_create", filters)
        self.assertNotIn("ap_flush_conn(r->connection)", filters)
        self.assertIn("msc_discard_response_brigade(msr);", utils)

    def test_example_guidance_matches_the_progressive_phase4_contract(self) -> None:
        english = APACHE_EXAMPLE_README.read_text(encoding="utf-8")
        german = APACHE_EXAMPLE_README_DE.read_text(encoding="utf-8")
        safe = APACHE_SAFE_CONFIGURATION.read_text(encoding="utf-8")
        reference = APACHE_CONFIGURATION_REFERENCE.read_text(encoding="utf-8")
        reference_de = APACHE_CONFIGURATION_REFERENCE_DE.read_text(encoding="utf-8")

        self.assertIn("[comprehensive reference](all/httpd.conf)", english)
        self.assertIn("[vollständige Referenz](all/httpd.conf)", german)
        self.assertIn("forwards that\nbucket to the next Apache filter without waiting for EOS", english)
        self.assertIn("leitet diesen\nBucket anschließend ohne Warten auf EOS an den nächsten Apache-Filter weiter", german)
        self.assertIn("No full response copy is\nkept by this filter.", english)
        self.assertIn("Dieser Filter hält keine vollständige Response-Kopie.", german)
        self.assertNotIn("retains every\nnormalized response brigade through first EOS", english)
        self.assertNotIn("Apache saves all normalized output\nbrigades through first EOS", english)
        self.assertNotIn("hält aber jede\nnormalisierte Response-Brigade bis zum ersten EOS zurück", german)
        self.assertNotIn("Apache speichert alle\nnormalisierten Output-Brigades bis zum ersten EOS", german)
        self.assertIn("forwards\n# non-terminal output without waiting for EOS", safe)
        self.assertNotIn("retains every normalized response through first EOS", safe)
        self.assertIn("forwards non-terminal output to the next filter without waiting for EOS", reference)
        self.assertIn("retains only the terminal EOS fragment", reference)
        self.assertNotIn("retains every normalized response brigade through first EOS", reference)
        self.assertNotIn("saved all-response brigade", reference)
        self.assertIn("leitet nichtterminale Ausgabe ohne Warten auf EOS an den nächsten Filter weiter", reference_de)
        self.assertIn("hält nur das terminale EOS-Fragment", reference_de)
        self.assertNotIn("hält jede normalisierte Response-Brigade bis zum ersten EOS zurück", reference_de)

    def test_rogue_handler_exercises_late_output_after_a_phase4_eos(self) -> None:
        harness = HARNESS.read_text(encoding="utf-8")
        handler = ROGUE_HANDLER.read_text(encoding="utf-8")
        self.assertIn("apr_bucket_immortal_create", handler)
        self.assertIn("phase4-rogue-prefix-", handler)
        self.assertIn("no-crs-response-body-marker", handler)
        self.assertIn("phase4-rogue-late-after-deny", handler)
        self.assertIn("phase4-rogue-suffix-after-eos", handler)
        self.assertIn("phase4_rogue_pass(r, \"phase4-rogue-late-after-deny\", 1, 1,", handler)
        self.assertIn("late_rc=0", harness)
        self.assertIn("--http2 --trace-ids", harness)
        self.assertIn("did not reuse the connection after denial", harness)
        self.assertIn("sole terminal Phase-4 response", harness)
        self.assertIn("APACHE_PHASE4_ROGUE_EXPECT", harness)
        self.assertIn("APACHE_PHASE4_ROGUE_PHASE", harness)
        self.assertIn("response_headers_before_commit", harness)
        self.assertIn("APACHE_PHASE4_ROGUE_HEADER_MUTATION", harness)
        self.assertIn("X-Phase3-Late", harness)
        self.assertIn("Phase-3 header-freeze H2", harness)
        self.assertIn("header_mutation=%d", handler)
        self.assertIn('"no-etag", "1"', handler)
        self.assertIn("phase3_etag[1] = 'X'", handler)
        self.assertIn("response_note_no_etag_snapshot", FILTERS.read_text(encoding="utf-8"))
        self.assertIn("response_env_force_no_vary_snapshot", FILTERS.read_text(encoding="utf-8"))
        self.assertIn("apr_table_clone", FILTERS.read_text(encoding="utf-8"))
        self.assertIn("apache_phase3_clone_content_languages", FILTERS.read_text(encoding="utf-8"))
        self.assertIn("response_header_only_snapshot", FILTERS.read_text(encoding="utf-8"))
        self.assertIn("r->header_only = 1", handler)

    def test_internal_redirect_regression_has_explicit_pre_fix_bypass_and_post_fix_abort_modes(self) -> None:
        harness = HARNESS.read_text(encoding="utf-8")
        handler = ROGUE_HANDLER.read_text(encoding="utf-8")
        self.assertIn("APACHE_PHASE4_INTERNAL_REDIRECT_TEST", harness)
        self.assertIn("APACHE_PHASE4_INTERNAL_REDIRECT_EXPECT", harness)
        self.assertIn("send_phase4_internal_redirect_request", harness)
        self.assertIn("response_not_committed", harness)
        self.assertIn("phase4-internal-redirect", harness)
        self.assertIn("redirect-bypass-h1", RUNNER.read_text(encoding="utf-8"))
        self.assertIn("redirect-abort-h1", RUNNER.read_text(encoding="utf-8"))
        self.assertIn("redirect-bypass-h2", RUNNER.read_text(encoding="utf-8"))
        self.assertIn("redirect-abort-h2", RUNNER.read_text(encoding="utf-8"))
        self.assertIn("redirect-target-config-bypass-h1", RUNNER.read_text(encoding="utf-8"))
        self.assertIn("redirect-target-config-abort-h1", RUNNER.read_text(encoding="utf-8"))
        self.assertIn("redirect-uri-bypass-h1", RUNNER.read_text(encoding="utf-8"))
        self.assertIn("redirect-uri-abort-h1", RUNNER.read_text(encoding="utf-8"))
        self.assertIn("ap_internal_redirect", handler)
        self.assertIn("/__phase4_internal_redirect_target.txt", handler)
        connector = (source_path('connectors/apache/src/mod_security3.c', root=ROOT)).read_text(encoding="utf-8")
        self.assertIn("apache_phase4_redirect_is_terminal_error_emission", connector)
        self.assertIn("apache_phase4_fail_normal_redirect", connector)
        self.assertIn("request transaction cannot be safely rebound to the target URI", connector)
        self.assertNotIn("apache_phase4_redirect_can_reattach", connector)
        self.assertNotIn("transaction_conf", connector)
        self.assertIn("apache_phase3_snapshot_response_state", FILTERS.read_text(encoding="utf-8"))
        self.assertIn("apache_phase3_restore_response_state", FILTERS.read_text(encoding="utf-8"))
        self.assertIn("assert_single_h2_status", harness)
        self.assertIn("phase4_terminal_test_uses_h2", harness)
        self.assertIn("APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_CONFIG_TEST", harness)
        self.assertIn("APACHE_PHASE4_INTERNAL_REDIRECT_URI_POLICY_TEST", harness)
        self.assertIn("phase4_redirect_direct_rule_event_count", harness)
        self.assertIn("2190410", harness)
        self.assertIn("2190411", (CASE_ROOT / "redirect-uri-policy.yaml").read_text(encoding="utf-8"))
        self.assertNotIn("effective ModSecurity configuration changed", harness)

    def test_normal_internal_redirect_refuses_the_target_handler_before_it_runs(self) -> None:
        harness = HARNESS.read_text(encoding="utf-8")
        handler = ROGUE_HANDLER.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("redirect-target-handler-abort-h1", runner)
        self.assertIn("redirect-target-handler-abort-h2", runner)
        self.assertIn("APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_HANDLER_TEST", harness)
        self.assertIn("target_handler_abort", harness)
        self.assertIn("assert_phase4_internal_redirect_target_handler_was_not_run", harness)
        self.assertIn("ModSecurity Phase4 redirect target handler executed", harness)
        self.assertIn("phase4-internal-redirect-target-handler-test", handler)
        self.assertIn("phase4-internal-redirect-target-handler-marker", handler)
        self.assertIn("/__phase4_internal_redirect_target_handler_target", handler)
        connector = (source_path('connectors/apache/src/mod_security3.c', root=ROOT)).read_text(encoding="utf-8")
        self.assertIn("hook_phase4_redirect_quick_handler", connector)
        self.assertIn("hook_phase4_redirect_handler", connector)
        self.assertIn("ap_hook_quick_handler(hook_phase4_redirect_quick_handler", connector)
        self.assertIn("ap_hook_handler(hook_phase4_redirect_handler", connector)
        self.assertIn("apache_phase4_terminal_error_redirect_note", connector)

    def test_downstream_apache_error_after_commit_is_a_bounded_abort_path(self) -> None:
        harness = HARNESS.read_text(encoding="utf-8")
        handler = ROGUE_HANDLER.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")
        downstream_start = harness.index("send_phase4_downstream_error_request() {")
        downstream_end = harness.index("send_phase4_upstream_error_request() {", downstream_start)
        downstream = harness[downstream_start:downstream_end]
        self.assertIn("APACHE_PHASE4_DOWNSTREAM_ERROR_TEST", harness)
        self.assertIn("APACHE_PHASE4_UPSTREAM_ERROR_TEST", harness)
        self.assertIn("send_phase4_downstream_error_request", harness)
        self.assertIn("send_phase4_upstream_error_request", harness)
        self.assertIn("phase4-downstream-error-document", harness)
        self.assertIn("downstream-error-document-h1", runner)
        self.assertIn("downstream-error-document-h2", runner)
        self.assertIn("upstream-error-document-h1", runner)
        self.assertIn("upstream-error-document-h2", runner)
        self.assertIn("phase4_downstream_error_filter", handler)
        self.assertIn("ap_bucket_error_create(HTTP_INTERNAL_SERVER_ERROR", handler)
        self.assertIn("PHASE4_DOWNSTREAM_ERROR", handler)
        self.assertIn("AP_FTYPE_CONTENT_SET - 2", handler)
        self.assertIn("no-crs-response-body-marker", handler)
        self.assertIn("phase4_upstream_error_pass", handler)
        self.assertIn("phase4-upstream-error", handler)
        self.assertIn("AP_BUCKET_IS_ERROR", FILTERS.read_text(encoding="utf-8"))
        self.assertIn("apache_phase4_error_bucket_status", FILTERS.read_text(encoding="utf-8"))
        filters = FILTERS.read_text(encoding="utf-8")
        self.assertIn("apache_emit_contract_failure_event_with_action", filters)
        self.assertIn('"abort_connection"', filters)
        self.assertIn(
            "Phase-4 downstream error must abort the post-commit response",
            downstream,
        )
        self.assertIn('"actual_action":"abort_connection"', downstream)
        self.assertIn('"connection_aborted":true', downstream)
        self.assertIn('"transport_result":"connection_aborted"', downstream)
        self.assertIn('grep -F "$HTTP2_PROTOCOL_LABEL"', downstream)
        self.assertIn('grep -E "$CURL_H2_ALPN_ACCEPT_PATTERN"', downstream)
        self.assertNotIn(
            "Phase-4 downstream error TLS client did not negotiate HTTP/2",
            downstream,
        )
        self.assertNotIn("assert_phase4_error_document_headers", downstream)
        self.assertNotIn(
            "sole configured ErrorDocument body", downstream
        )

    def test_downstream_output_failure_is_a_canonical_connector_error(self) -> None:
        filters = FILTERS.read_text(encoding="utf-8")
        start = filters.index("static apr_status_t apache_phase4_release_response_brigade")
        end = filters.index("apr_status_t phase4_terminal_guard_filter", start)
        release = filters[start:end]

        self.assertIn("rc = ap_pass_brigade(f->next, brigade);", release)
        self.assertIn("if (rc != APR_SUCCESS)", release)
        self.assertIn("msc_apache_contract_fail(msr,", release)
        self.assertIn("MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR", release)
        self.assertIn("response_phase4_terminal_output", release)

    def test_error_document_redirect_boundary_is_single_hop_and_preoutput_fail_closed(self) -> None:
        harness = HARNESS.read_text(encoding="utf-8")
        handler = ROGUE_HANDLER.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")
        connector = (source_path('connectors/apache/src/mod_security3.c', root=ROOT)).read_text(encoding="utf-8")
        self.assertIn("APACHE_PHASE4_NESTED_ERROR_REDIRECT_TEST", harness)
        self.assertIn("APACHE_PHASE4_PREOUTPUT_ERROR_DOCUMENT_TEST", harness)
        self.assertIn("send_phase4_nested_error_document_redirect_request", harness)
        self.assertIn("send_phase4_preoutput_error_document_request", harness)
        self.assertIn("nested-error-document-redirect-h1", runner)
        self.assertIn("preoutput-error-document-h1", runner)
        self.assertIn("preoutput-error-document-h2", runner)
        self.assertIn("phase4_nested_error_document_redirect_handler", handler)
        self.assertIn("phase4_preoutput_error_document_handler", handler)
        self.assertIn("HTTP_NOT_FOUND before any response brigade", handler)
        self.assertIn("no_local_copy", connector)
        self.assertIn("response_phase4_terminal_error_redirect_seen", connector)
        self.assertIn("request transaction cannot be safely rebound to the target URI", harness)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
