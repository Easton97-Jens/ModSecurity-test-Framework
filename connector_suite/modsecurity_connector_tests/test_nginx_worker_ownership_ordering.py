"""Root materialization must precede NGINX worker ownership handoff."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import grp
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = connector_root()
HARNESS = source_path('connectors/nginx/harness/run_nginx_smoke.sh', root=ROOT)
FRAMEWORK = Path(os.environ.get(
    "MSCONNECTOR_TEST_FRAMEWORK_ROOT", source_path('modules/ModSecurity-test-Framework', root=ROOT)
)).resolve()
CASE = FRAMEWORK / "tests/cases/no-crs-baseline/deny_header_marker_403.yaml"
CASE_CLI = FRAMEWORK / "tests/runners/case_cli.py"


def shell_function(source: str, name: str) -> str:
    start = source.index(f"{name}() {{\n")
    return source[start:source.index("\n}\n", start) + 3]


class NginxWorkerOwnershipOrderingTests(unittest.TestCase):
    def test_materialization_precedes_every_worker_handoff(self) -> None:
        source = HARNESS.read_text(encoding="utf-8")
        handoffs = [match.start() for match in re.finditer(
            r"(?m)^prepare_nginx_worker_paths$", source
        )]
        materialize = source.index('if ! "$PYTHON_BIN" "$CASE_CLI" materialize')
        successful_materialize = source.index("\nfi\n", materialize) + 4
        self.assertTrue(handoffs)
        self.assertGreater(min(handoffs), successful_materialize)
        self.assertLess(successful_materialize, source.index(
            "\nlock_private_runtime_paths\n", successful_materialize
        ))
        self.assertLess(handoffs[0], source.index("\nproject_nginx_worker_docroot\n"))
        self.assertLess(handoffs[-1], source.index("\npreflight_nginx_worker_docroot\n"))
        preparation = source[source.index('ensure_dir_755 "$NGINX_HARNESS_WORK_ROOT"'):
                             source.index(': > "$STATUS_FILE"')]
        self.assertIn('"$NGINX_SERVER_LOG_ROOT/audit"', preparation)
        worker_function = shell_function(source, "prepare_nginx_worker_paths")
        worker_paths = worker_function.split("    for path in \\\n", 1)[1].split("\n    do", 1)[0]
        self.assertEqual(re.findall(r'"([^"\n]+)"', worker_paths), [
            "$NGINX_WORKER_STATE_ROOT",
            *[f"$NGINX_WORKER_STATE_ROOT/{name}" for name in (
                "client_body_temp", "proxy_temp", "fastcgi_temp", "uwsgi_temp", "scgi_temp"
            )],
            "$NGINX_SERVER_LOG_ROOT", "$NGINX_SERVER_LOG_ROOT/audit",
        ])
        for private in ("RUNTIME_ROOT", "LOG_DIR", "RULES_FILE", "CONFIG_FILE",
                        "NGINX_MEMCHECK_EVIDENCE_DIR"):
            self.assertNotIn(f'"${private}"', worker_function)

    @unittest.skipUnless(os.geteuid() == 0, "requires real root/nobody ownership separation")
    def test_real_materializer_and_worker_access_preserve_private_paths(self) -> None:
        runuser = next((path for path in ("/usr/sbin/runuser", "/usr/bin/runuser")
                        if os.access(path, os.X_OK)), None)
        if runuser is None:
            self.skipTest("fixed runuser executable unavailable")
        try:
            worker = pwd.getpwnam("nobody")
            worker_group = grp.getgrnam("nogroup")
        except KeyError:
            self.skipTest("nobody/nogroup accounts unavailable")
        self.assertNotEqual(worker.pw_uid, os.geteuid())
        self.assertTrue(CASE.is_file(), CASE)
        self.assertTrue(CASE_CLI.is_file(), CASE_CLI)
        self.assertIn("@@AUDIT_LOG_DIR@@", CASE.read_text(encoding="utf-8"))
        source = HARNESS.read_text(encoding="utf-8")
        functions = "\n".join(shell_function(source, name) for name in (
            "ensure_dir_755", "ensure_private_dir", "nginx_worker_group",
            "prepare_nginx_worker_paths", "resolve_nginx_worker_identity",
            "nginx_worker_runuser",
            "write_permission_diagnostics", "lock_private_runtime_paths",
            "validate_nginx_generated_path_authority",
        ))
        preparation = source[source.index('ensure_dir_755 "$NGINX_HARNESS_WORK_ROOT"'):
                             source.index(': > "$STATUS_FILE"')]
        # Choose a task-owned ancestor the real worker can traverse. Never
        # change caller-owned ancestors or fall back to /tmp or /dev/shm.
        temporary_parent = Path(os.environ.get(
            "NGINX_OWNERSHIP_TEST_TEMP_ROOT", tempfile.gettempdir()
        ))
        if any(not stat.S_IMODE(path.stat().st_mode) & stat.S_IXOTH
               for path in (temporary_parent, *temporary_parent.parents)):
            self.skipTest("provide a worker-traversable external test temp root")
        with tempfile.TemporaryDirectory(prefix="nginx-owner-order-", dir=temporary_parent) as directory:
            base = Path(directory)
            base.chmod(0o711)
            verified = base / "verified"
            verified.mkdir(mode=0o711)
            verified.chmod(0o711)
            build = verified / "build"
            harness = build / "nginx-harness"
            runtime = harness / "runtime/deny_header_marker_403"
            logs = harness / "logs/deny_header_marker_403"
            server = harness / "server-logs/deny_header_marker_403"
            state = harness / "worker-state/deny_header_marker_403"
            environment = {
                "PATH": os.defpath, "CURRENT_UID": "0", "PYTHON_BIN": sys.executable,
                "PYTHONDONTWRITEBYTECODE": "1", "BUILD_ROOT": str(build),
                "VERIFIED_RUN_ROOT": str(verified), "NGINX_HARNESS_PARENT": str(build),
                "NGINX_HARNESS_WORK_ROOT": str(harness), "RUNTIME_BASE": str(harness / "runtime"),
                "RUNTIME_ROOT": str(runtime), "LOG_DIR": str(logs),
                "RESULTS_DIR": str(build / "results"), "RUNTIME_PID_FILE": str(runtime / "nginx.pid"),
                "NGINX_WORKER_STATE_ROOT": str(state), "NGINX_SERVER_LOG_ROOT": str(server),
                "NGINX_MEMCHECK_EVIDENCE_DIR": str(logs / "memcheck"),
                "STATUS_FILE": str(logs / "status.txt"), "PERMISSIONS_LOG": str(logs / "permissions.log"),
                "NGINX_WORKER_PREFLIGHT_FILE": str(logs / "preflight.jsonl"),
                "NGINX_PATH_AUTHORITY_VALIDATOR": str(source_path('ci/runtime/common/validate-nginx-harness-paths.py', root=ROOT)),
                "NGINX_WORKER_USER": "nobody", "NGINX_WORKER_GROUP": "nogroup",
                "NGINX_DOCROOT_PROJECTION": "1", "PRIVATE_DOCROOT": str(runtime / "htdocs"),
                "NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR": "", "FULL_LIFECYCLE_EVIDENCE_OUTPUT": "",
                "MSCONNECTOR_FULL_LIFECYCLE_SYNC": "0", "NGINX_PATHS_VALIDATED": "0",
            }

            def shell(commands: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ["sh", "-eu", "-c", 'umask 077\nblocked() { echo "$*" >&2; exit 77; }\n'
                     + functions + "\n" + commands],
                    env=environment, text=True, capture_output=True, check=False,
                )

            initial = shell("validate_nginx_generated_path_authority\n" + preparation)
            self.assertEqual(initial.returncode, 0, initial.stderr)
            for path in (server, server / "audit", runtime, runtime / "conf", logs):
                metadata = path.stat()
                self.assertEqual((metadata.st_uid, metadata.st_gid,
                                  stat.S_IMODE(metadata.st_mode)), (0, 0, 0o700), str(path))

            def materialize() -> subprocess.CompletedProcess[str]:
                return subprocess.run([
                    sys.executable, str(CASE_CLI), "materialize", "--case", str(CASE),
                    "--rules-file", str(runtime / "conf/rules.conf"),
                    "--env-file", str(runtime / "conf/case.env"),
                    "--headers-file", str(runtime / "conf/headers.txt"),
                    "--body-file", str(runtime / "conf/body.bin"),
                    "--docroot", str(runtime / "htdocs"),
                    "--audit-log-file", str(server / "audit.log"),
                    "--audit-log-dir", str(server / "audit"),
                    "--rules-preamble-file", str(FRAMEWORK / "tests/rules/no-crs-baseline.conf"),
                ], env=environment, text=True, capture_output=True, check=False)

            rendered = materialize()
            self.assertEqual(rendered.returncode, 0, rendered.stderr)
            rules = runtime / "conf/rules.conf"
            self.assertEqual(rules.stat().st_uid, 0)
            self.assertIn(str(server / "audit.log"), rules.read_text(encoding="utf-8"))
            handoff = shell("lock_private_runtime_paths\nprepare_nginx_worker_paths")
            self.assertEqual(handoff.returncode, 0, handoff.stderr)
            repeated = shell("lock_private_runtime_paths\nprepare_nginx_worker_paths")
            self.assertEqual(repeated.returncode, 0, repeated.stderr)
            for path in (server, server / "audit", state, *(state / name for name in (
                    "client_body_temp", "proxy_temp", "fastcgi_temp", "uwsgi_temp", "scgi_temp"))):
                metadata = path.stat()
                self.assertEqual((metadata.st_uid, metadata.st_gid,
                                  stat.S_IMODE(metadata.st_mode)),
                                 (worker.pw_uid, worker_group.gr_gid, 0o700), str(path))
            for path in (runtime, runtime / "conf", runtime / "htdocs", logs, logs / "memcheck"):
                metadata = path.stat()
                self.assertEqual((metadata.st_uid, stat.S_IMODE(metadata.st_mode)), (0, 0o700))

            def worker_command(*command: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run([runuser, "-u", "nobody", "-g", "nogroup", "--", *command],
                                      env={"PATH": os.defpath}, text=True, capture_output=True, check=False)

            for path in (server / "worker-write.log", server / "audit/worker-write.log"):
                written = worker_command("touch", str(path))
                self.assertEqual(written.returncode, 0, written.stderr)
                self.assertEqual(path.stat().st_uid, worker.pw_uid)
            for path, mode in ((rules, "-r"), (runtime / "conf/case.env", "-r"),
                               (runtime / "conf", "-x"), (runtime, "-x"), (logs, "-x")):
                self.assertNotEqual(worker_command("test", mode, str(path)).returncode, 0, str(path))
            # The real Framework guard must still refuse the old sequence.
            rejected = materialize()
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("audit log directory must be owned by the current user", rejected.stderr)


@unittest.skipUnless(os.geteuid() == 0, "requires root/nobody restricted-capability handoff")
class NginxRestrictedHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.setpriv = Path("/usr/bin/setpriv")
        if not self.setpriv.is_file() or not os.access(self.setpriv, os.X_OK):
            self.skipTest("fixed setpriv executable unavailable")
        if not any(os.access(path, os.X_OK) for path in ("/usr/sbin/runuser", "/usr/bin/runuser")):
            self.skipTest("fixed runuser executable unavailable")
        try:
            self.worker = pwd.getpwnam("nobody")
            self.group = grp.getgrnam("nogroup")
        except KeyError:
            self.skipTest("nobody/nogroup accounts unavailable")
        parent = Path(os.environ.get("NGINX_OWNERSHIP_TEST_TEMP_ROOT", tempfile.gettempdir()))
        if any(not stat.S_IMODE(path.stat().st_mode) & stat.S_IXOTH
               for path in (parent, *parent.parents)):
            self.skipTest("provide a worker-traversable external test temp root")
        self.temporary = tempfile.TemporaryDirectory(prefix="nginx-cap-handoff-", dir=parent)
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.base.chmod(0o711)
        self.state = self.base / "worker-state"
        self.server = self.base / "server-logs"
        self.logs = self.base / "private-logs"
        self.logs.mkdir(mode=0o700)
        self.paths = [self.state, *(self.state / name for name in (
            "client_body_temp", "proxy_temp", "fastcgi_temp", "uwsgi_temp", "scgi_temp"
        )), self.server, self.server / "audit"]
        self.environment = {
            "PATH": os.defpath, "CURRENT_UID": "0", "NGINX_WORKER_USER": "nobody",
            "NGINX_WORKER_GROUP": "nogroup", "NGINX_WORKER_STATE_ROOT": str(self.state),
            "NGINX_SERVER_LOG_ROOT": str(self.server), "LOG_DIR": str(self.logs),
        }
        source = HARNESS.read_text(encoding="utf-8")
        self.functions = "\n".join(shell_function(source, name) for name in (
            "nginx_worker_group", "nginx_worker_runuser", "resolve_nginx_worker_identity",
            "prepare_nginx_worker_paths", "create_fresh_phase4_regular_file",
            "prepare_phase4_log_target",
        ))

    def restricted_shell(self, commands: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([
            str(self.setpriv), "--bounding-set=-all,+chown,+setuid,+setgid",
            "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs",
            "/bin/sh", "-eu", "-c", 'umask 077\nblocked() { echo "$*" >&2; exit 77; }\n'
            'fail() { echo "$*" >&2; exit 1; }\n' + self.functions + "\n" + commands,
        ], env=self.environment, text=True, capture_output=True, check=False)

    def test_initial_and_repeated_handoff_with_only_chown_setuid_setgid(self) -> None:
        result = self.restricted_shell(
            "sed -n '/^CapEff:/p' /proc/self/status\n"
            "prepare_nginx_worker_paths"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(int(result.stdout.split(":", 1)[1].strip(), 16), 0xc1)
        for path in self.paths:
            metadata = path.stat()
            self.assertEqual((metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)),
                             (self.worker.pw_uid, self.group.gr_gid, 0o700), str(path))
        self.assertEqual((self.logs.stat().st_uid, stat.S_IMODE(self.logs.stat().st_mode)), (0, 0o700))
        before = [path.stat() for path in self.paths]
        repeated = self.restricted_shell("prepare_nginx_worker_paths")
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertEqual([(item.st_ino, item.st_ctime_ns) for item in before],
                         [(path.stat().st_ino, path.stat().st_ctime_ns) for path in self.paths])

    def test_repeated_handoff_rejects_mode_drift_without_repair(self) -> None:
        initial = self.restricted_shell("prepare_nginx_worker_paths")
        self.assertEqual(initial.returncode, 0, initial.stderr)
        (self.state / "proxy_temp").chmod(0o770)
        result = self.restricted_shell("prepare_nginx_worker_paths")
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertIn("failed ownership/mode validation", result.stderr)
        self.assertEqual(stat.S_IMODE((self.state / "proxy_temp").stat().st_mode), 0o770)

    def test_repeated_handoff_rejects_symlink_and_owner_drift(self) -> None:
        initial = self.restricted_shell("prepare_nginx_worker_paths")
        self.assertEqual(initial.returncode, 0, initial.stderr)
        child = self.state / "proxy_temp"
        child.rmdir()
        child.symlink_to(self.state / "fastcgi_temp", target_is_directory=True)
        symlinked = self.restricted_shell("prepare_nginx_worker_paths")
        self.assertEqual(symlinked.returncode, 77, symlinked.stderr)
        child.unlink()
        child.mkdir(mode=0o700)
        # An accidentally root-owned child must not be repaired or accepted.
        owner_drift = self.restricted_shell("prepare_nginx_worker_paths")
        self.assertEqual(owner_drift.returncode, 77, owner_drift.stderr)
        self.assertEqual(child.stat().st_uid, 0)

    def test_initial_handoff_rejects_symlink_without_touching_target(self) -> None:
        self.state.mkdir(mode=0o700)
        target = self.base / "unrelated-private"
        target.mkdir(mode=0o700)
        (self.state / "proxy_temp").symlink_to(target, target_is_directory=True)
        before = target.stat()
        result = self.restricted_shell("prepare_nginx_worker_paths")
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertIn("must not be a symlink", result.stderr)
        after = target.stat()
        self.assertEqual((before.st_uid, before.st_gid, before.st_mode),
                         (after.st_uid, after.st_gid, after.st_mode))

    def test_wrong_owner_phase4_fixture_keeps_private_mode_under_restricted_caps(self) -> None:
        self.environment["NGINX_PHASE4_LOG_TARGET_MODE"] = "unsafe_wrong_owner"
        result = self.restricted_shell("prepare_phase4_log_target")
        self.assertEqual(result.returncode, 0, result.stderr)
        metadata = (self.logs / "phase4.log").stat()
        self.assertEqual((metadata.st_uid, stat.S_IMODE(metadata.st_mode)),
                         (self.worker.pw_uid, 0o600))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
