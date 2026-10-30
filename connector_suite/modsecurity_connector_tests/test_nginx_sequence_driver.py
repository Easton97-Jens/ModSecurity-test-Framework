"""Closed sequence configuration and native-fixture authority tests."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import argparse
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

DIRECTORY = connector_root() / "ci/runtime/lifecycle"

DRIVER = load_source(DIRECTORY / 'run-nginx-lifecycle-sequences.py')


class DriverTests(unittest.TestCase):
    def test_static_sequence_probes_do_not_create_internal_redirect_contexts(self):
        output = Path("/var/tmp/codex/sequence")
        projection = Path("/var/tmp/codex/projection/child")
        for case_id in sorted(set(DRIVER.SEQUENCES) - DRIVER.UPSTREAM_CASES):
            with self.subTest(case_id=case_id):
                config = DRIVER.sequence_config(
                    output,
                    19000,
                    projection,
                    case_id,
                    fault_transaction="a" * 32,
                )
                self.assertIn(b"location / { try_files /index.html =404; }", config)
                self.assertNotIn(b"try_files $uri /index.html;", config)

    def test_framing_configs_keep_static_and_actual_chunked_origin_separate(self):
        output = Path("/var/tmp/codex/sequence")
        projection = Path("/var/tmp/codex/projection/child")
        content_length = DRIVER.sequence_config(output, 19000, projection, "transport_http11_content_length",
                                                fault_transaction="a" * 32)
        chunked = DRIVER.sequence_config(output, 19000, projection, "transport_http11_chunked",
                                         fault_transaction="a" * 32, upstream_port=19001)
        self.assertIn(b"try_files /index.html =404;", content_length)
        self.assertNotIn(b"proxy_pass", content_length)
        self.assertIn(b"proxy_buffering off; proxy_http_version 1.1;", chunked)
        self.assertIn(b"proxy_pass http://127.0.0.1:19001;", chunked)
        for config in (content_length, chunked):
            self.assertIn(b"types { }", config)
            self.assertIn(b"default_type text/plain;", config)
            self.assertEqual(config.count(b"modsecurity_phase4_mode safe;"), 1)

    def test_deadline_config_sets_explicit_soft_budget_and_case_only_identity(self):
        config = DRIVER.sequence_config(Path("/var/tmp/codex/sequence"), 19000,
                                        Path("/var/tmp/codex/projection/child"),
                                        "engine_timeout_before_commit", fault_transaction="a" * 32)
        self.assertIn(b"modsecurity_engine_call_budget_ms 10;", config)
        self.assertIn(b"default $request_id;", config)

    def test_timeout_receipt_hash_matches_rules_after_deny_rule_removal(self):
        original = b'SecRuleEngine On\nSecRule RESPONSE_BODY "@contains marker" "id:1100301,phase:4,deny"\n'
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            path = output / "no-crs-baseline.conf"
            path.write_bytes(original)
            observed = DRIVER.configure_timeout_rules(output)
            effective = path.read_bytes()
        self.assertIn(b"SecRuleRemoveById 1100301", effective)
        self.assertEqual(observed, hashlib.sha256(effective).hexdigest())
        self.assertNotEqual(observed, hashlib.sha256(original).hexdigest())

    def test_postcommit_timeout_uses_actual_unbuffered_upstream_and_case_identity(self):
        config = DRIVER.sequence_config(Path("/var/tmp/codex/sequence"), 19000,
                                        Path("/var/tmp/codex/projection/child"),
                                        "engine_timeout_after_commit", fault_transaction="a" * 32,
                                        upstream_port=19001)
        self.assertIn(b"proxy_buffering off;", config)
        self.assertIn(b"proxy_pass http://127.0.0.1:19001;", config)
        self.assertIn(b"modsecurity_engine_call_budget_ms 10;", config)
        self.assertIn(b"default $request_id;", config)

    def test_budget_controls_remain_explicit_and_bounded(self):
        for budget in (0, 100):
            config = DRIVER.sequence_config(Path("/var/tmp/codex/sequence"), 19000,
                                            Path("/var/tmp/codex/projection/child"),
                                            "engine_timeout_before_commit", fault_transaction="a" * 32,
                                            engine_budget_ms=budget)
            self.assertIn(f"modsecurity_engine_call_budget_ms {budget};".encode(), config)
        with self.assertRaisesRegex(ValueError, "only disabled"):
            DRIVER.sequence_config(Path("/var/tmp/codex/sequence"), 19000,
                                   Path("/var/tmp/codex/projection/child"), "engine_timeout_before_commit",
                                   fault_transaction="a" * 32, engine_budget_ms=-1)

    def test_budget_controls_cannot_change_an_unrelated_case(self):
        args = argparse.Namespace(case_id="keepalive_allow_allow", fault_negative_control=False,
                                  engine_call_budget_ms=0)
        with mock.patch.object(DRIVER.BASE, "validate_inputs", return_value=(Path("/binary"), Path("/module"), Path("/output"))):
            with self.assertRaisesRegex(ValueError, "exact timeout fixture case"):
                DRIVER.run(args)

    def test_finish_fault_identity_does_not_capture_listener_probes(self):
        identity = "a" * 32
        config = DRIVER.sequence_config(Path("/var/tmp/codex/sequence"), 19000,
                                        Path("/var/tmp/codex/projection/child"),
                                        "finish_failure_propagation", fault_transaction=identity)
        self.assertIn(b"default $request_id;", config)
        self.assertIn(b'/no-crs/sequence/' + b'a' * 24 + b'/0', config)
        self.assertIn(b"modsecurity_transaction_id \"$sequence_transaction_id\";", config)

    def test_fault_controls_cannot_change_an_unrelated_sequence(self):
        args = argparse.Namespace(case_id="keepalive_allow_allow", fault_negative_control=True)
        with mock.patch.object(DRIVER.BASE, "validate_inputs", return_value=(Path("/binary"), Path("/module"), Path("/output"))):
            with self.assertRaisesRegex(ValueError, "exact native fixture case"):
                DRIVER.run(args)

    def test_late_modes_and_fault_identity_are_closed_configuration(self):
        output = Path("/var/tmp/codex/ModSecurity-conector/sequence")
        safe = DRIVER.sequence_config(output, 19000, Path("/var/tmp/codex/projection/child"),
                                      "keepalive_safe_followup", upstream_port=19001)
        strict = DRIVER.sequence_config(output, 19000, Path("/var/tmp/codex/projection/child"),
                                        "phase4_strict_http1_client_abort", upstream_port=19001)
        self.assertIn(b"modsecurity_phase4_mode safe;", safe)
        self.assertIn(b"modsecurity_phase4_mode strict;", strict)
        self.assertIn(b"proxy_buffering off;", strict)
        self.assertIn(b"connection_requests", strict)
        self.assertIn(b"$request_id", strict)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
