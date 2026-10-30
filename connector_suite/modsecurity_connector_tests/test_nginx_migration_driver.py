"""Controlled driver/fixture controls; not genuine NGINX runtime evidence."""
import hashlib
import json
from modsecurity_connector_tests.test_nginx_configtest_driver import NginxConfigtestDriverTest


class NginxMigrationDriverTest(NginxConfigtestDriverTest):
    def test_lexical_status_rejection_is_a_closed_quoted_engine_action(self):
        result = self.invoke(case_id="invalid_status",
                             diagnostic='"modsecurity_rules" directive Rules error Expecting an action, got:  status:not-a-number')
        self.assertEqual(result.returncode, 0, result.stderr)
        config = (self.root / "attempt/nginx.conf").read_text()
        self.assertIn('modsecurity_rules "SecRule REQUEST_URI \\"@unconditionalMatch\\"', config)
        self.assertIn('status:not-a-number\\"";', config)

    def test_removed_api_binds_exact_regular_fixture_and_config_error(self):
        for case_id, leaf, expected in (
            ("phase4_invalid_scope_file", "invalid-content-type-scope.txt", b"not a valid media type\n"),
            ("phase4_wildcard_scope_rejected", "wildcard-content-type-scope.txt", b"text/*\n"),
        ):
            with self.subTest(case_id=case_id):
                output = self.root / case_id
                diagnostic = f'unknown directive "modsecurity_phase4_content_types_file" in {output}/nginx.conf:6'
                result = self.invoke(case_id=case_id, output_name=case_id, diagnostic=diagnostic)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((output / leaf).read_bytes(), expected)
                self.assertEqual((output / leaf).stat().st_mode & 0o777, 0o600)
                receipt = json.loads((output / "source-result.json").read_text())["cases"][0]["configtest_receipt"]
                self.assertEqual(receipt["fixture_state"], "regular")
                self.assertEqual(receipt["fixture_sha256"], hashlib.sha256(expected).hexdigest())

    def test_removed_api_wrong_config_or_changed_fixture_cannot_pass(self):
        case_id = "phase4_wildcard_scope_rejected"
        diagnostic = 'unknown directive "modsecurity_phase4_content_types_file" in /foreign/nginx.conf:6'
        wrong_path = self.invoke(case_id=case_id, output_name="foreign", diagnostic=diagnostic)
        self.assertEqual(wrong_path.returncode, 1, wrong_path.stderr)
        output = self.root / "changed"
        mutation = 'printf changed > "${5%/*}/wildcard-content-type-scope.txt"'
        diagnostic = f'unknown directive "modsecurity_phase4_content_types_file" in {output}/nginx.conf:6'
        changed = self.invoke(case_id=case_id, output_name="changed", diagnostic=diagnostic, extra_script=mutation)
        self.assertEqual(changed.returncode, 1, changed.stderr)

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
