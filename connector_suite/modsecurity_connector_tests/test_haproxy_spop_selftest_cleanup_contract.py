"""Compiled regression for SPOP self-test metadata cleanup."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest


ROOT = connector_root()
SOURCE = source_path('connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c', root=ROOT)


class HAProxySPOPSelfTestCleanupContractTests(unittest.TestCase):
    def compile_and_run_harness(self, root: Path, harness: Path, binary: Path) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("requires a C compiler")

        compile_result = subprocess.run(
            [
                compiler,
                "-std=c17",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-ffunction-sections",
                "-fdata-sections",
                "-I",
                str(source_path('common/include', root=ROOT)),
                "-I",
                str(source_path('connectors/haproxy/src', root=ROOT)),
                str(harness),
                "-Wl,--gc-sections",
                "-o",
                str(binary),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
        run_result = subprocess.run(
            [str(binary)], cwd=ROOT, check=False, capture_output=True, text=True
        )
        self.assertEqual(run_result.returncode, 0, run_result.stderr)

    def test_runtime_owns_decision_log_lock_for_complete_records(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("pthread_mutex_t decision_log_lock;", source)
        self.assertIn("pthread_mutex_init(&state.decision_log_lock, 0)", source)
        self.assertIn("pthread_mutex_lock(&state->decision_log_lock)", source)
        self.assertIn("pthread_mutex_unlock(&state->decision_log_lock)", source)
        self.assertIn("pthread_mutex_destroy(&state->decision_log_lock)", source)
        decision_start = source.index("static int decision_log_write(")
        decision_end = source.index("static int production_config_has_safe_peer_limits", decision_start)
        decision_body = source[decision_start:decision_end]
        self.assertLess(
            decision_body.index("pthread_mutex_lock(&state->decision_log_lock)"),
            decision_body.index("phase4_common_event_write("),
        )
        self.assertLess(
            decision_body.index("phase4_common_event_write("),
            decision_body.index("pthread_mutex_unlock(&state->decision_log_lock)"),
        )

    def test_cache_miss_control_includes_both_endpoints(self) -> None:
        harness = (source_path('connectors/haproxy/harness/run_haproxy_spop_cache_miss.sh', root=ROOT)).read_text(encoding="utf-8")
        self.assertIn('("client_ip", typed_ipv4("127.0.0.1"))', harness)
        self.assertIn('("server_ip", typed_ipv4("127.0.0.1"))', harness)
        self.assertIn('("client_port", typed_uint(41000))', harness)
        self.assertIn('("server_port", typed_uint(8080))', harness)
        self.assertIn('headers = "Host: localhost\\r\\n"', harness)
        self.assertIn('args.append(("headers", typed_string(headers)))', harness)

    def test_compiled_cleanup_removes_pass_and_idempotent_error_metadata(self) -> None:
        harness_source = r'''
#define main haproxy_spop_diagnostic_runtime_program_main
#include "__SOURCE__"
#undef main

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    const char *ready = "__READY__";
    const char *pid = "__PID__";
    const char *port = "__PORT__";
    FILE *log = fopen("__LOG__", "w");
    assert(log != NULL);
    assert(close(creat(ready, 0600)) == 0);
    assert(close(creat(pid, 0600)) == 0);
    assert(close(creat(port, 0600)) == 0);
    assert(cleanup_self_test_metadata(ready, pid, port,
        SELF_TEST_METADATA_ALL, log) == 0);
    assert(access(ready, F_OK) != 0);
    assert(access(pid, F_OK) != 0);
    assert(access(port, F_OK) != 0);
    assert(cleanup_self_test_metadata(ready, pid, port,
        SELF_TEST_METADATA_ALL, log) == 0);
    assert(fclose(log) == 0);
    return 0;
}
'''

        with tempfile.TemporaryDirectory(
            prefix="haproxy-spop-selftest-cleanup-",
            dir=os.environ.get("TMPDIR"),
        ) as temporary_directory:
            root = Path(temporary_directory)
            paths = {
                "__SOURCE__": SOURCE.as_posix(),
                "__READY__": (root / "spop-diagnostic-runtime.ready").as_posix(),
                "__PID__": (root / "spop-diagnostic-runtime.pid").as_posix(),
                "__PORT__": (root / "spop-diagnostic-runtime.port").as_posix(),
                "__LOG__": (root / "self-test.log").as_posix(),
            }
            for marker, value in paths.items():
                harness_source = harness_source.replace(marker, value)
            harness = root / "cleanup_contract.c"
            binary = root / "cleanup_contract"
            harness.write_text(harness_source, encoding="utf-8")
            self.compile_and_run_harness(root, harness, binary)
            self.assertEqual(
                (root / "self-test.log").read_text(encoding="utf-8").count(
                    "self-test metadata cleanup PASS"
                ),
                2,
            )

    def test_metadata_claim_preserves_existing_paths_and_rejects_collision(self) -> None:
        harness_source = r'''
#define main haproxy_spop_diagnostic_runtime_program_main
#include "__SOURCE__"
#undef main

#include <assert.h>
static void write_sentinel(const char *path, const char *text) {
    FILE *file = fopen(path, "w");
    assert(file != NULL);
    assert(fputs(text, file) >= 0);
    assert(fclose(file) == 0);
}

static void assert_contents(const char *path, const char *expected) {
    char buffer[64];
    FILE *file = fopen(path, "r");
    assert(file != NULL);
    assert(fgets(buffer, sizeof(buffer), file) != NULL);
    assert(strcmp(buffer, expected) == 0);
    assert(fclose(file) == 0);
}

int main(void) {
    const char *root = "__ROOT__";
    char ready[4096];
    char pid_path[4096];
    char port[4096];
    pid_t child;
    int status;
    int ready_fd;

    assert(mkdir_p(root) == 0);
    snprintf(ready, sizeof(ready), "%s/spop-diagnostic-runtime.ready", root);
    snprintf(pid_path, sizeof(pid_path), "%s/spop-diagnostic-runtime.pid", root);
    snprintf(port, sizeof(port), "%s/spop-diagnostic-runtime.port", root);

    write_sentinel(pid_path, "caller-owned\n");
    ready_fd = claim_self_test_metadata_file(ready);
    assert(ready_fd >= 0);
    assert(claim_self_test_metadata_file(pid_path) < 0);
    assert(close(ready_fd) == 0);
    assert(cleanup_self_test_metadata(ready, pid_path, port,
        SELF_TEST_METADATA_READY, NULL) == 0);
    assert_contents(pid_path, "caller-owned\n");
    assert(access(ready, F_OK) != 0);
    assert(access(port, F_OK) != 0);
    assert(unlink(pid_path) == 0);

    ready_fd = claim_self_test_metadata_file(ready);
    assert(ready_fd >= 0);
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        exit(claim_self_test_metadata_file(ready) < 0 ? 0 : 1);
    }
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(close(ready_fd) == 0);
    assert(cleanup_self_test_metadata(ready, pid_path, port,
        SELF_TEST_METADATA_READY, NULL) == 0);
    assert(access(ready, F_OK) != 0);
    assert(access(pid_path, F_OK) != 0);
    assert(access(port, F_OK) != 0);
    return 0;
}
'''

        with tempfile.TemporaryDirectory(
            prefix="haproxy-spop-selftest-ownership-",
            dir=os.environ.get("TMPDIR"),
        ) as temporary_directory:
            root = Path(temporary_directory)
            paths = {
                "__SOURCE__": SOURCE.as_posix(),
                "__ROOT__": (root / "shared-tmp").as_posix(),
            }
            for marker, value in paths.items():
                harness_source = harness_source.replace(marker, value)
            harness = root / "selftest_ownership_contract.c"
            binary = root / "selftest_ownership_contract"
            harness.write_text(harness_source, encoding="utf-8")
            self.compile_and_run_harness(root, harness, binary)

    def test_cleanup_continues_after_eisdir_and_cannot_report_success(self) -> None:
        harness_source = r'''
#define main haproxy_spop_diagnostic_runtime_program_main
#include "__SOURCE__"
#undef main

#include <assert.h>
#include <sys/stat.h>

int main(void) {
    const char *root = "__ROOT__";
    char ready[4096];
    char pid_path[4096];
    char port[4096];
    FILE *log;

    assert(mkdir_p(root) == 0);
    snprintf(ready, sizeof(ready), "%s/ready", root);
    snprintf(pid_path, sizeof(pid_path), "%s/pid", root);
    snprintf(port, sizeof(port), "%s/port", root);
    assert(close(creat(ready, 0600)) == 0);
    assert(close(creat(pid_path, 0600)) == 0);
    assert(mkdir(port, 0700) == 0);
    log = fopen("__LOG__", "w");
    assert(log != NULL);
    assert(cleanup_self_test_metadata(ready, pid_path, port,
        SELF_TEST_METADATA_ALL, log) != 0);
    assert(access(ready, F_OK) != 0);
    assert(access(pid_path, F_OK) != 0);
    assert(access(port, F_OK) == 0);
    assert(fclose(log) == 0);
    log = fopen("__LOG__", "r");
    assert(log != NULL);
    {
        char contents[1024] = {0};
        assert(fread(contents, 1, sizeof(contents) - 1, log) > 0);
        assert(strstr(contents, "self-test metadata cleanup FAILED") != NULL);
        assert(strstr(contents, "self-test metadata cleanup PASS") == NULL);
    }
    assert(fclose(log) == 0);
    assert(rmdir(port) == 0);
    return 0;
}
'''

        with tempfile.TemporaryDirectory(
            prefix="haproxy-spop-selftest-eisdir-",
            dir=os.environ.get("TMPDIR"),
        ) as temporary_directory:
            root = Path(temporary_directory)
            log_path = root / "cleanup.log"
            paths = {
                "__SOURCE__": SOURCE.as_posix(),
                "__ROOT__": (root / "metadata").as_posix(),
                "__LOG__": log_path.as_posix(),
                "__LOG_TEXT__": "self-test metadata cleanup FAILED",
            }
            for marker, value in paths.items():
                harness_source = harness_source.replace(marker, value)
            harness = root / "eisdir_contract.c"
            binary = root / "eisdir_contract"
            harness.write_text(harness_source, encoding="utf-8")
            self.compile_and_run_harness(root, harness, binary)

    def test_run_self_test_has_cleanup_after_child_waits_on_success_and_errors(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        run_self_test = source.split("static int run_self_test", 1)[1].split(
            "typedef struct legacy_server_config", 1
        )[0]
        self.assertIn("self_test_cleanup_context cleanup_context", run_self_test)
        self.assertIn("&context.listen_fd, context.child_to_reap, &context.status", run_self_test)
        self.assertIn("context.terminate_child, &context.ready_fd, &context.pid_fd", run_self_test)
        self.assertIn("finish_self_test_resources(&cleanup_context)", run_self_test)
        self.assertIn("finish_self_test_resources", source)
        self.assertNotIn("(void)finish_self_test_resources", source)
        self.assertEqual(run_self_test.count("cleanup:\n"), 1)
        self.assertIn("pid_t child_to_reap;", source)
        self.assertIn("int terminate_child;", source)
        self.assertIn("int close_rc = 0;", source)
        self.assertIn("close_rc |= close_self_test_fd(&context->ready_fd);", source)
        self.assertIn("_exit(SPOP_RUNTIME_CLEANUP_FAILURE);", source)
        self.assertIn("errno == ECHILD", source)
        self.assertIn("context->child_to_reap = -1;", source)
        self.assertIn(
            "wait_self_test_child_bounded(context->child,\n"
            "            context->status, context->terminate)",
            source,
        )
        self.assertIn("wait_self_test_child_bounded(context->child,", source)
        self.assertIn("if (!WIFEXITED(context->status)", source)
        self.assertIn("context->ready_fd = claim_self_test_metadata_file(context->ready_path);", source)
        self.assertIn("context->pid_fd = claim_self_test_metadata_file(context->pid_path);", source)
        self.assertIn("context->port_fd = claim_self_test_metadata_file(context->port_path);", source)
        self.assertIn("context->owned_metadata |= SELF_TEST_METADATA_READY;", source)
        self.assertIn("context->owned_metadata |= SELF_TEST_METADATA_PID;", source)
        self.assertIn("context->owned_metadata |= SELF_TEST_METADATA_PORT;", source)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
