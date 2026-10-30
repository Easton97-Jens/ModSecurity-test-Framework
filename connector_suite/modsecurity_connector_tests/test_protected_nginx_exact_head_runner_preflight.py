"""Focused contracts for the protected exact-head runner preflight."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import importlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock


ROOT = connector_root()
MODULE_PATH = source_path('ci/runtime/broker/protected_nginx_exact_head_runner_preflight.py', root=ROOT)
SHA = "a" * 40


def load_module() -> object:
    return importlib.import_module('modsecurity_connector_ci.runtime.broker.protected_nginx_exact_head_runner_preflight')


P = load_module()


class RunnerPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.runner_temp = self.root / "runner-temp"
        self.runner_temp.mkdir(mode=0o700)
        self.base = self.root / "base"
        self.base.mkdir(mode=0o755)
        self.environment = {
            "PATH": "/usr/bin:/bin",
            "HOME": "/nonexistent",
            "LANG": "C",
            "LC_ALL": "C",
            "RUNNER_TEMP": str(self.runner_temp),
            "GITHUB_WORKSPACE": str(self.base),
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_rejects_non_allowlisted_or_injected_environment(self) -> None:
        for key in (
            "PYTHONPATH",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "GITHUB_TOKEN",
            "GITHUB_SHA",
            "GITHUB_REPOSITORY",
            "GITHUB_RUN_ID",
        ):
            environment = dict(self.environment, **{key: "attacker"})
            with mock.patch.dict(os.environ, environment, clear=True):
                with self.assertRaisesRegex(P.PreflightError, "non-allowlisted"):
                    P.require_scrubbed_environment()

    def test_rejects_non_fixed_path_and_task_root_escape(self) -> None:
        environment = dict(self.environment, PATH="/attacker:/usr/bin:/bin")
        with mock.patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(P.PreflightError, "fixed PATH"):
                P.require_scrubbed_environment()
        with mock.patch.dict(os.environ, self.environment, clear=True):
            with mock.patch.object(
                P.argparse.ArgumentParser, "error", side_effect=SystemExit(2)
            ):
                with self.assertRaises(SystemExit):
                    P.parse_args(
                        [
                            "--role", "candidate-build", "--trusted-base-sha", SHA,
                            "--task-root", str(self.root / "outside"),
                        ]
                    )

    def test_rejects_symlinked_task_root_and_host_control_entry(self) -> None:
        target = self.root / "target"
        target.mkdir(mode=0o700)
        linked = self.runner_temp / P._CANDIDATE_TASK_ROOT_NAME
        linked.symlink_to(target, target_is_directory=True)
        with mock.patch.dict(os.environ, self.environment, clear=True):
            with self.assertRaisesRegex(P.PreflightError, "non-symlink"):
                P.require_private_task_root()
        with mock.patch.object(P, "HOST_CONTROL_PATHS", (self.root / "docker.sock",)):
            (self.root / "docker.sock").write_text("not a socket", encoding="utf-8")
            with self.assertRaisesRegex(P.PreflightError, "host-control"):
                P.reject_host_control_sockets()

    def test_rejects_every_fixed_host_control_location(self) -> None:
        for index, path in enumerate(P.HOST_CONTROL_PATHS):
            with self.subTest(path=path):
                sentinel = self.root / f"host-control-{index}"
                sentinel.write_text("present", encoding="utf-8")
                with mock.patch.object(P, "HOST_CONTROL_PATHS", (sentinel,)):
                    with self.assertRaisesRegex(P.PreflightError, "host-control"):
                        P.reject_host_control_sockets()

    def test_prepare_creates_only_private_directories_after_base_verification(self) -> None:
        task = self.runner_temp / P._CANDIDATE_TASK_ROOT_NAME
        with mock.patch.dict(os.environ, self.environment, clear=True), \
             mock.patch.object(P, "reject_host_control_sockets"), \
             mock.patch.object(P, "require_base_checkout", return_value=self.base) as base_check:
            result = P.prepare("candidate-build", SHA)
        self.assertEqual(result, task)
        self.assertEqual({entry.name for entry in task.iterdir()}, {"dispatcher"})
        base_check.assert_called_once_with(SHA)
        for child in task.iterdir():
            self.assertEqual(child.stat().st_mode & 0o777, 0o700)

    def test_prepare_precreates_the_privileged_artifact_parents(self) -> None:
        with mock.patch.dict(os.environ, self.environment, clear=True), \
             mock.patch.object(P, "reject_host_control_sockets"), \
             mock.patch.object(P, "require_base_checkout", return_value=self.base), \
             mock.patch.object(P, "require_host_gate"):
            task = P.prepare("privileged", SHA)
        self.assertEqual(
            {path.relative_to(task) for path in task.rglob("*") if path.is_dir()},
            {Path("inputs"), Path("inputs/dispatcher"), Path("inputs/candidate")},
        )
        for directory in task.rglob("*"):
            if directory.is_dir():
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700)

    def test_rejects_invalid_sha_before_checkout_is_accepted(self) -> None:
        with mock.patch.dict(os.environ, self.environment, clear=True), \
             mock.patch.object(P, "reject_host_control_sockets"), \
            mock.patch.object(P, "require_base_checkout") as base_check:
            with self.assertRaisesRegex(P.PreflightError, "lowercase 40-character"):
                P.prepare("privileged", "main")
        base_check.assert_not_called()

    def test_privileged_role_requires_root_owned_mode_755_host_gate(self) -> None:
        gate = mock.Mock()
        gate.lstat.return_value = types.SimpleNamespace(
            st_mode=stat.S_IFREG | 0o755, st_uid=0, st_gid=0
        )
        with mock.patch.object(P, "no_symlink_chain", return_value=gate):
            self.assertIs(P.require_host_gate(), gate)
        with mock.patch.dict(os.environ, self.environment, clear=True), \
             mock.patch.object(P, "reject_host_control_sockets"), \
            mock.patch.object(P, "require_base_checkout", return_value=self.base), \
            mock.patch.object(P, "require_host_gate") as require_gate:
            self.assertEqual(
                P.prepare("privileged", SHA),
                self.runner_temp / P._PRIVILEGED_TASK_ROOT_NAME,
            )
        require_gate.assert_called_once_with()

    def test_uses_only_fixed_task_leaf_and_descriptor_bound_git_cwd(self) -> None:
        with mock.patch.dict(os.environ, self.environment, clear=True):
            root = P.require_private_task_root()
        self.assertEqual(root, self.runner_temp / P._CANDIDATE_TASK_ROOT_NAME)

        completed = types.SimpleNamespace(returncode=0, stdout=SHA + "\n")
        with mock.patch.dict(os.environ, self.environment, clear=True), mock.patch.object(
            P.subprocess, "run", return_value=completed
        ) as run:
            self.assertEqual(P.require_base_checkout(SHA), self.base)
        self.assertEqual(run.call_args.args[0], ["/usr/bin/git", "rev-parse", "HEAD^{commit}"])
        self.assertFalse(run.call_args.kwargs["shell"])
        cwd = run.call_args.kwargs["cwd"]
        self.assertRegex(cwd, r"^/proc/self/fd/(?a:\d+)$")
        descriptor = int(cwd.rsplit("/", 1)[1])
        self.assertEqual(run.call_args.kwargs["pass_fds"], (descriptor,))

    def test_privileged_role_fails_closed_when_host_gate_is_missing_or_writable(self) -> None:
        missing = mock.Mock()
        missing.lstat.side_effect = FileNotFoundError()
        with mock.patch.object(P, "no_symlink_chain", return_value=missing):
            with self.assertRaisesRegex(P.PreflightError, "host gate"):
                P.require_host_gate()
        writable = mock.Mock()
        writable.lstat.return_value = types.SimpleNamespace(
            st_mode=stat.S_IFREG | 0o775, st_uid=0, st_gid=0
        )
        with mock.patch.object(P, "no_symlink_chain", return_value=writable):
            with self.assertRaisesRegex(P.PreflightError, "mode 0755"):
                P.require_host_gate()



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
