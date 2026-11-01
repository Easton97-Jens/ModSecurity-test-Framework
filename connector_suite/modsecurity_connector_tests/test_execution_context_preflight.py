"""Small real-identity probes with all data below the caller's external root."""
import argparse
import hashlib
import json
import os
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from modsecurity_connector_ci.runtime.common import execution_context as context


class ExecutionContextTests(unittest.TestCase):
    def setUp(self):
        parent = Path(os.environ.get("EXECUTION_CONTEXT_TEST_ROOT",
                                     "/var/tmp/codex/ModSecurity-conector/execution-context-tests"))
        parent.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="case-", dir=parent)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def args(self, **values):
        defaults = dict(worker_user=None, worker_group=None, require_root_master=False,
                        require_chown=False, worker_read=[], worker_write=[], worker_deny=[],
                        uds_path=None, uds_root=None, port=[], timeout=3.0)
        defaults.update(values)
        return argparse.Namespace(**defaults)

    def test_actual_child_identity_file_write_and_uds(self):
        fixture = self.root / "fixture"
        fixture.write_text("fixture")
        metadata, checks = context.execution_context(self.args(
            worker_read=[str(fixture)], worker_write=[str(self.root)],
            uds_path=self.root / "s"), self.root)
        self.assertTrue(all(item["status"] == "PASS" for item in checks), checks)
        self.assertEqual(metadata["observed_worker"]["uid"], list(os.getresuid()))
        self.assertEqual(metadata["observed_worker"]["groups"], sorted(os.getgroups()))
        self.assertIn("uds_bind_connect_verified", [item["reason_code"] for item in checks])
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), ["fixture"])

    def test_mapping_failure_never_runs_child(self):
        metadata = context.snapshot()
        metadata["uid_map"] = ["1 1 1"]
        with mock.patch.object(context, "snapshot", return_value=metadata), mock.patch.object(context, "_fork_probe") as child:
            _, checks = context.execution_context(self.args(), self.root)
        self.assertIn("worker_identity_unmapped", [item["reason_code"] for item in checks])
        child.assert_not_called()

    def test_independent_private_uds_root_and_containment(self):
        with tempfile.TemporaryDirectory(prefix="socket-", dir=self.root.parent) as temporary:
            socket_root = Path(temporary)
            _, checks = context.execution_context(self.args(uds_root=socket_root,
                                                           uds_path=socket_root / "s"), self.root)
            self.assertEqual(checks[-1]["reason_code"], "uds_bind_connect_verified", checks)
            _, checks = context.execution_context(self.args(uds_root=socket_root,
                                                           uds_path=self.root / "s"), self.root)
            self.assertEqual(checks[-1]["reason_code"], "uds_path_untrusted", checks)

    def test_actual_worker_transition_traverse_only_and_private_denial(self):
        metadata = context.snapshot()
        caps = int(metadata["security"].get("CapEff", "0"), 16)
        worker = context.resolve_worker("65534", "65534")
        if os.geteuid() != 0 or caps & 0xc1 != 0xc1 or not context.mapped(worker[0], metadata["uid_map"]) or not all(
                context.mapped(gid, metadata["gid_map"]) for gid in [worker[1], *worker[2]]):
            self.skipTest("requires mapped worker and CAP_CHOWN/CAP_SETGID/CAP_SETUID")
        self.root.chmod(0o711)
        traverse = self.root / "traverse"
        traverse.mkdir(mode=0o711)
        fixture = traverse / "fixture"
        fixture.write_text("fixture")
        fixture.chmod(0o644)
        private = self.root / "private"
        private.mkdir(mode=0o700)
        writable = self.root / "writable"
        writable.mkdir(mode=0o730)
        os.chown(writable, 0, worker[1])
        writable.chmod(0o730)
        uds = self.root / "uds"
        uds.mkdir(mode=0o700)
        os.chown(uds, worker[0], worker[1])
        observed, checks = context.execution_context(self.args(
            worker_user="65534", worker_group="65534", require_root_master=True, require_chown=True,
            worker_read=[str(fixture)], worker_write=[str(writable)], worker_deny=[str(private)],
            uds_path=uds / "s"), self.root)
        self.assertTrue(all(item["status"] == "PASS" for item in checks), checks)
        self.assertEqual(observed["observed_worker"]["uid"], [worker[0]] * 3)
        self.assertEqual(observed["observed_worker"]["groups"], worker[2])
        self.assertEqual(list(writable.iterdir()), [])
        self.assertEqual(list(uds.iterdir()), [])
        private.chmod(0o711)
        _, checks = context.execution_context(self.args(worker_user="65534", worker_group="65534",
                                                       worker_deny=[str(private)]), self.root)
        self.assertEqual(checks[-1]["reason_code"], "worker_deny_unenforced", checks)
        self.assertEqual(checks[-1]["status"], "BLOCKED")

    def test_distinct_launcher_inherits_daemon_context_from_setpriv(self):
        metadata = context.snapshot()
        caps = int(metadata["security"].get("CapEff", "0"), 16)
        try:
            account = pwd.getpwnam("daemon")
        except KeyError:
            self.skipTest("daemon account unavailable")
        if (not Path("/usr/bin/setpriv").is_file() or os.geteuid() != 0
                or caps & 0xc1 != 0xc1 or account.pw_uid == os.geteuid()
                or not context.mapped(account.pw_uid, metadata["uid_map"])
                or not context.mapped(account.pw_gid, metadata["gid_map"])):
            self.skipTest("requires distinct mapped daemon and host credential capabilities")
        parent = self.root.parent
        artifact = Path(tempfile.mkdtemp(prefix="daemon-probe-", dir=parent))
        artifact.chmod(0o711)
        source_parent = artifact / "source"
        source_parent.mkdir(mode=0o711)
        stage = source_parent / "modules"
        stage.mkdir(mode=0o755)
        framework = Path(__file__).resolve().parents[2]
        sources = ["modsecurity_test_framework/__init__.py", "modsecurity_test_framework/connector_context.py",
                   "connector_suite/modsecurity_connector_ci/__init__.py",
                   "connector_suite/modsecurity_connector_ci/lib/runtime_path_utils.py",
                   "connector_suite/modsecurity_connector_ci/runtime/common/hostruntime_preflight.py",
                   "connector_suite/modsecurity_connector_ci/runtime/common/execution_context.py"]
        hashes = {}
        for relative in sources:
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(framework / relative, target)
            target.chmod(0o444)
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            self.assertEqual(digest, hashlib.sha256((framework / relative).read_bytes()).hexdigest())
            hashes[relative] = digest
        # FileFinder lists import directories; their enclosing source boundary
        # remains traverse-only, while source files themselves remain read-only.
        for directory, _, _ in os.walk(stage):
            Path(directory).chmod(0o755)
        fixture = artifact / "fixture"
        fixture.write_text("actual distinct launcher fixture\n")
        fixture.chmod(0o444)
        output = artifact / "out"
        output.mkdir(mode=0o700)
        os.chown(output, account.pw_uid, account.pw_gid)
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                       "PYTHONDONTWRITEBYTECODE": "1", "TEST_ROOT": str(stage),
                       "PYTHONPATH": str(stage) + os.pathsep + str(stage / "connector_suite")}
        command = ["/usr/bin/setpriv", "--reuid", str(account.pw_uid), "--regid", str(account.pw_gid),
                   "--clear-groups", sys.executable, "-m",
                   "modsecurity_connector_ci.runtime.common.hostruntime_preflight", "--execution-context-only",
                   "--profile", "distinct-daemon-launcher", "--runtime-root", str(output),
                   "--output-dir", str(output / "evidence"), "--worker-read", str(fixture),
                   "--worker-write", str(output), "--uds-path", str(output / "s")]
        completed = subprocess.run(command, cwd=stage, env=environment, capture_output=True,
                                   text=True, timeout=15, check=False)
        (artifact / "source-hashes.json").write_text(json.dumps(hashes, indent=2) + "\n")
        (artifact / "launcher-result.json").write_text(json.dumps({"returncode": completed.returncode,
                                                                   "stderr": completed.stderr[:2000]}, indent=2) + "\n")
        print("Distinct launcher evidence: " + str(artifact))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads((output / "evidence/status.json").read_text())
        self.assertEqual(result["runtime_status"], "NOT_RUN")
        self.assertEqual(result["execution_context"]["uid"], [account.pw_uid] * 3)
        self.assertEqual(result["execution_context"]["gid"], [account.pw_gid] * 3)
        self.assertEqual(result["execution_context"]["groups"], [])
        self.assertEqual(result["execution_context"]["observed_worker"]["uid"], [account.pw_uid] * 3)
        self.assertIn("uds_bind_connect_verified", [item["reason_code"] for item in result["checks"]])

    def test_missing_transition_capabilities_is_blocked(self):
        metadata = context.snapshot()
        metadata["security"]["CapEff"] = "0000000000000000"
        worker = (os.geteuid(), os.getegid(), sorted(os.getgroups()), True)
        with mock.patch.object(context, "snapshot", return_value=metadata), mock.patch.object(context, "resolve_worker", return_value=worker), mock.patch.object(context, "_fork_probe") as child:
            _, checks = context.execution_context(self.args(worker_user=str(os.geteuid()),
                                                          worker_group=str(os.getegid())), self.root)
        self.assertIn("worker_transition_capabilities_missing", [item["reason_code"] for item in checks])
        child.assert_not_called()

    def test_symlink_read_write_and_missing_deny_are_blocked(self):
        link = self.root / "link"
        link.symlink_to(self.root, target_is_directory=True)
        for kind, value in (("read", link), ("write", link), ("deny", self.root / "missing")):
            with self.subTest(kind=kind):
                _, checks = context.execution_context(self.args(**{"worker_" + kind: [str(value)]}), self.root)
                self.assertEqual(checks[-1]["status"], "BLOCKED", checks)
        self.assertTrue(link.is_symlink())

    def test_uds_length_and_existing_socket_are_blocked_without_removal(self):
        long_path = self.root / ("x" * 110)
        self.assertEqual(context._socket_probe(long_path, self.root, 1)["reason_code"], "uds_path_too_long")
        path = self.root / "s"
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(str(path))
            self.assertEqual(context._socket_probe(path, self.root, 1)["status"], "BLOCKED")
            self.assertTrue(path.exists())
        path.unlink()

    def test_unresponsive_child_is_bounded_and_reaped(self):
        started = time.monotonic()
        with mock.patch.object(context, "_child_probes", side_effect=lambda *_: time.sleep(5)):
            _, checks = context.execution_context(self.args(timeout=0.1), self.root)
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(checks[-1]["reason_code"], "worker_probe_timeout_or_invalid")
        self.assertEqual(checks[-1]["status"], "BLOCKED")

    def test_cli_context_only_preserves_not_run_runtime_without_binary(self):
        command = [sys.executable, "-m", "modsecurity_connector_ci.runtime.common.hostruntime_preflight",
                   "--execution-context-only", "--profile", "unit", "--runtime-root", str(self.root),
                   "--output-dir", str(self.root / "evidence")]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads((self.root / "evidence/status.json").read_text())
        self.assertEqual(result["runtime_status"], "NOT_RUN")
        self.assertEqual(result["status"], "PASS")
        self.assertIn("execution_context", result)
        self.assertNotIn("binary", [item["name"] for item in result["checks"]])
        base = [sys.executable, "-m", "modsecurity_connector_ci.runtime.common.hostruntime_preflight",
                "--profile", "unit", "--runtime-root", str(self.root),
                "--output-dir", str(self.root / "evidence")]
        for options in (["--worker-user", "1"], ["--worker-group", "1"], ["--require-root-master"],
                        ["--require-chown"], ["--worker-read", str(self.root)],
                        ["--worker-write", str(self.root)], ["--worker-deny", str(self.root)],
                        ["--uds-path", str(self.root / "s")], ["--uds-root", str(self.root)]):
            rejected = subprocess.run(base + options, capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(rejected.returncode, 2, rejected.stderr)
            self.assertIn("require --execution-context-only", rejected.stderr)
        rejected = subprocess.run(base + ["--execution-context-only", "--uds-root", str(self.root)],
                                  capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(rejected.returncode, 2, rejected.stderr)
        self.assertIn("--uds-root requires --uds-path", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
