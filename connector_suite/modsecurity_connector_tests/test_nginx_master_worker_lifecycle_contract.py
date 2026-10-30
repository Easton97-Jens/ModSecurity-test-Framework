"""Static contract for the normal NGINX master/worker smoke lifecycle."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import unittest


ROOT = connector_root()
HARNESS = source_path('connectors/nginx/harness/run_nginx_smoke.sh', root=ROOT)
TEMPLATE = source_path('connectors/nginx/harness/nginx_smoke.conf', root=ROOT)


class NginxMasterWorkerLifecycleContractTest(unittest.TestCase):
    def setUp(self):
        self.source = HARNESS.read_text(encoding="utf-8")
        self.template = TEMPLATE.read_text(encoding="utf-8")

    def test_normal_template_keeps_master_worker_model_and_dynamic_module(self):
        self.assertIn('load_module "@@NGINX_MODULE@@";', self.template)
        self.assertNotIn("master_process off", self.template)
        self.assertIn("worker_processes 1;", self.template)
        self.assertIn("@@NGINX_WORKER_USER_DIRECTIVE@@", self.template)
        self.assertIn('pid "@@RUNTIME_ROOT@@/nginx.pid";', self.template)

    def test_normal_mode_rejects_disabled_lifecycle(self):
        self.assertIn('NGINX_LIFECYCLE_ENABLED="${NGINX_LIFECYCLE_ENABLED:-1}"', self.source)
        self.assertIn('fail "normal NGINX smoke requires lifecycle enabled"', self.source)

    def test_harness_records_exact_master_and_worker_identity(self):
        for required in (
            "record_nginx_master_worker_roles()",
            "worker_count=",
            "expected exactly one",
            "printf 'role=%s pid=%s ppid=%s uid=%s gid=%s command=%s",
            "NGINX_WORKER_RESOLVED_UID",
            'fail "NGINX worker pid=$worker_pid is running as root"',
            'NGINX_LIFECYCLE_ROLE_FILE="$LOG_DIR/nginx-process-roles.txt"',
        ):
            self.assertIn(required, self.source)

    def test_reload_is_real_and_followed_by_worker_replacement(self):
        for required in (
            "reload_nginx_master_worker()",
            '"$NGINX_BINARY" -p "$RUNTIME_ROOT" -c "$CONFIG_FILE" -s reload',
            "wait_for_nginx_worker_replacement()",
            "NGINX_LIFECYCLE_INITIAL_WORKER",
            "NGINX_LIFECYCLE_RELOADED_WORKER",
            'NGINX_LIFECYCLE_RELOAD=passed',
            "new_worker_count=",
        ):
            self.assertIn(required, self.source)

    def test_shutdown_uses_graceful_then_posix_fallback_signals(self):
        for required in (
            "shutdown_nginx_gracefully()",
            '"$NGINX_BINARY" -p "$RUNTIME_ROOT" -c "$CONFIG_FILE" -s quit',
            'kill -TERM "$NGINX_PID"',
            'kill -KILL "$NGINX_PID"',
            "NGINX_LIFECYCLE_SHUTDOWN=graceful_quit",
        ):
            self.assertIn(required, self.source)

    def test_cleanup_checks_children_listener_pid_uds_and_exit_status_fail_closed(self):
        for required in (
            "record_nginx_cleanup_state()",
            "master_pid=$NGINX_PID result=still_alive",
            "worker_pid=$nginx_tracked_worker_pid result=still_alive",
            "exit_status=$NGINX_LIFECYCLE_EXIT_STATUS result=failed",
            "children=none result=passed",
            'result=freed',
            'rm -f "$RUNTIME_PID_FILE"',
            'result=absent_after_cleanup',
            'find "$RUNTIME_ROOT" -type s',
            'uds=none result=passed',
            'temporary_file=$nginx_cleanup_path result=present_after_cleanup',
            'return "$nginx_cleanup_return"',
        ):
            self.assertIn(required, self.source)

    def test_signal_traps_preserve_nonzero_status_and_memcheck_is_separate(self):
        self.assertIn("cleanup_on_signal()", self.source)
        self.assertIn("cleanup_on_exit()", self.source)
        self.assertIn('if ! cleanup && [ "$nginx_exit_status" -eq 0 ]; then', self.source)
        self.assertIn('exit "$signal_status"', self.source)
        self.assertIn('[ "$NGINX_MEMCHECK" = "0" ] || return 0', self.source)
        self.assertIn("normal master/worker lifecycle proof disabled for opt-in Memcheck mode", self.source)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
