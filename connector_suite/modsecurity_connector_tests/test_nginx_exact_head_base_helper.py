"""Contracts for the trusted-base NGINX exact-head cell driver."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import re
import subprocess
import unittest


ROOT = connector_root()
DRIVER = source_path('ci/runtime/broker/run_nginx_exact_head_cells.sh', root=ROOT)
CANDIDATE_SCRIPT_REFERENCE = re.compile(r"\$CANDIDATE_ROOT/[^\" ]+\.(?:sh|py)\b")


class NginxExactHeadBaseHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = DRIVER.read_text(encoding="utf-8")

    def test_posix_shell_syntax(self) -> None:
        completed = subprocess.run(
            ["/bin/sh", "-n", str(DRIVER)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_driver_requires_prebuilt_root_owned_two_cell_topology(self) -> None:
        self.assertIn('[ "$#" -eq 3 ]', self.source)
        self.assertIn("write_mode on", self.source)
        self.assertIn("write_mode off", self.source)
        self.assertIn('[ -d "$SCRATCH_ROOT/on" ]', self.source)
        self.assertIn('[ -d "$SCRATCH_ROOT/off" ]', self.source)
        self.assertIn('config_root="$cell/config"', self.source)
        self.assertIn('control="$cell/control"', self.source)
        self.assertIn('runtime="$cell/runtime"', self.source)
        self.assertIn('logs="$cell/logs"', self.source)
        self.assertIn('release_path="$control/release"', self.source)
        self.assertIn('completion_path="$control/request-complete.json"', self.source)
        self.assertIn('[ ! -w "$control" ]', self.source)
        self.assertIn('request-complete.json', self.source)
        self.assertNotIn('mkdir "$cell"', self.source)
        self.assertNotIn('modsecurity_transaction_id "', self.source)
        self.assertNotIn('modsecurity_use_error_log', self.source)
        self.assertNotIn('include "', self.source)

    def test_candidate_checkout_is_not_executed_or_sourced(self) -> None:
        self.assertNotIn('source "$CANDIDATE', self.source)
        self.assertNotRegex(self.source, CANDIDATE_SCRIPT_REFERENCE)
        self.assertIn('"$NGINX_BINARY" -p "$cell" -c "$config"', self.source)
        self.assertIn('actual_tx=$(/usr/bin/sed -n', self.source)
        self.assertNotIn('result.json', self.source)

    def test_candidate_script_reference_pattern_detects_shell_and_python_paths(self) -> None:
        self.assertRegex("$CANDIDATE_ROOT/evil.sh", CANDIDATE_SCRIPT_REFERENCE)
        self.assertRegex("echo $CANDIDATE_ROOT/evil.py", CANDIDATE_SCRIPT_REFERENCE)

    def test_root_side_http_completion_and_fail_closed_shutdown_are_required(self) -> None:
        self.assertIn('[ "$completed" -eq 1 ] ||', self.source)
        self.assertIn('[ "$shutdown_status" -eq 0 ]', self.source)
        self.assertNotIn('http-status.txt', self.source)
        self.assertNotIn('/usr/bin/curl', self.source)
        self.assertNotIn("|| true", self.source)
        self.assertNotIn("continue-on-error", self.source)

    def test_identity_and_raw_log_observations_are_explicit(self) -> None:
        for field in (
            "master_pid",
            "worker_pid",
            "master_uid",
            "master_gid",
            "worker_uid",
            "worker_gid",
            "transaction_id",
            "binary_path",
            "config_path",
            "pid_path",
        ):
            self.assertIn(field, self.source)
        self.assertIn('[ "$worker_uid" != "$master_uid" ]', self.source)
        self.assertIn('[ "$worker_gid" != "$master_gid" ]', self.source)
        self.assertIn('grep -F "modsecurity_transaction_id=$actual_tx"', self.source)
        self.assertIn('[ "$mode" = off ] && [ "$callback" -eq 0 ]', self.source)
        self.assertIn('"$logs/events.jsonl"', self.source)

    def test_actual_callback_guard_truth_table(self) -> None:
        guard = next(line.strip() for line in self.source.splitlines()
                     if '[ "$mode" = on ]' in line)
        self.assertTrue(guard.endswith('|| die'), guard)
        for mode, callback, accepted in (
            ('on', '1', True), ('off', '0', True),
            ('on', '0', False), ('off', '1', False),
            ('on', '2', False), ('off', '2', False), ('unknown', '0', False),
        ):
            with self.subTest(mode=mode, callback=callback):
                completed = subprocess.run(
                    ['/bin/sh', '-c', 'die() { exit 19; }; mode=$1; callback=$2; '
                     + guard + '; exit 0', 'callback-guard', mode, callback],
                    check=False, capture_output=True, text=True,
                )
                self.assertEqual(completed.returncode, 0 if accepted else 19,
                                 completed.stderr)

    def test_paths_and_environment_are_allowlisted(self) -> None:
        self.assertIn("PATH=/usr/sbin:/usr/bin:/sbin:/bin", self.source)
        self.assertIn('case "${NGINX_BINARY:-}" in "$CANDIDATE_ROOT/nginx")', self.source)
        self.assertIn('case "${NGINX_MODULE:-}" in "$CANDIDATE_ROOT/ngx_http_modsecurity_module.so")', self.source)
        self.assertIn('case "${MODSECURITY_LIB_DIR:-}" in "$CANDIDATE_ROOT")', self.source)
        self.assertIn('case "${LD_LIBRARY_PATH:-}" in "$CANDIDATE_ROOT")', self.source)
        self.assertIn('[ -z "${LD_PRELOAD:-}" ] || die', self.source)
        self.assertIn('[ -z "${PYTHONPATH:-}" ] || die', self.source)
        self.assertIn('/usr/bin/find "$SCRATCH_ROOT" -mindepth 1 -maxdepth 1', self.source)

    def test_shell_cases_validate_parameters_and_have_default_pid_case(self) -> None:
        self.assertIn("path=$1", self.source)
        self.assertIn('case "$path" in', self.source)
        self.assertIn("''|*[!0-9]*) kill", self.source)
        self.assertIn('*) : ;;', self.source)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
