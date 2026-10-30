from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from tests import framework_test_trust as trust


class FrameworkTestTrustTest(unittest.TestCase):
    def test_git_resolution_ignores_fake_executable_earlier_in_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="framework-test-trust-") as temporary:
            fake_git = Path(temporary) / "git"
            fake_git.write_text("#!/bin/sh\nexit 97\n", encoding="utf-8")
            fake_git.chmod(0o755)
            completed = subprocess.CompletedProcess([], 0, "metadata\n", "")
            with mock.patch.dict(
                os.environ,
                {"PATH": f"{fake_git.parent}{os.pathsep}{os.environ.get('PATH', '')}"},
            ), mock.patch.object(
                trust.subprocess, "run", return_value=completed
            ) as run:
                output, error = trust._run_git(Path("/safe/root"), "rev-parse", "HEAD")

        self.assertEqual(output, "metadata\n")
        self.assertIsNone(error)
        executable = run.call_args.args[0][0]
        self.assertTrue(Path(executable).is_absolute())
        self.assertNotEqual(executable, str(fake_git))
        self.assertIn(Path(executable), trust.TRUSTED_GIT_PATHS)

    def test_git_metadata_queries_ignore_inherited_git_context(self) -> None:
        completed = subprocess.CompletedProcess([], 0, "metadata\n", "")
        with mock.patch.dict(
            os.environ,
            {"GIT_DIR": "/untrusted", "GIT_CONFIG_COUNT": "1"},
        ), mock.patch.object(trust.subprocess, "run", return_value=completed) as run:
            output, error = trust._run_git(Path("/safe/root"), "rev-parse", "HEAD")

        self.assertEqual(output, "metadata\n")
        self.assertIsNone(error)
        environment = run.call_args.kwargs["env"]
        self.assertNotIn("GIT_DIR", environment)
        self.assertNotIn("GIT_CONFIG_COUNT", environment)
        self.assertEqual(environment["GIT_OPTIONAL_LOCKS"], "0")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")

    def test_rejects_mismatched_head_before_common_sh_can_be_used(self) -> None:
        with tempfile.TemporaryDirectory(prefix="framework-test-trust-") as temporary:
            framework_root = Path(temporary) / "framework"
            common = framework_root / "ci" / "lib" / "common.sh"
            common.parent.mkdir(parents=True)
            common.write_text("exit 99\n", encoding="utf-8")
            with mock.patch.object(
                trust,
                "_run_git",
                side_effect=(
                    ("160000 commit expected modules/ModSecurity-test-Framework\n", None),
                    ("candidate\n", None),
                ),
            ) as run_git:
                root, error = trust.trusted_framework_root(Path("/parent"), framework_root)
        self.assertIsNone(root)
        self.assertEqual(
            error,
            "Framework test root HEAD candidate does not match Parent gitlink expected",
        )
        self.assertEqual(run_git.call_count, 2)

    def test_accepts_clean_regular_root_at_exact_parent_gitlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="framework-test-trust-") as temporary:
            framework_root = Path(temporary) / "framework"
            common = framework_root / "ci" / "lib" / "common.sh"
            common.parent.mkdir(parents=True)
            common.write_text("#!/bin/sh\n", encoding="utf-8")
            with mock.patch.object(
                trust,
                "_run_git",
                side_effect=(
                    ("160000 commit expected modules/ModSecurity-test-Framework\n", None),
                    ("expected\n", None),
                    ("", None),
                ),
            ):
                root, error = trust.trusted_framework_root(Path("/parent"), framework_root)
        self.assertEqual(root, framework_root)
        self.assertIsNone(error)

    def test_rejects_any_dirty_framework_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="framework-test-trust-") as temporary:
            framework_root = Path(temporary) / "framework"
            common = framework_root / "ci" / "lib" / "common.sh"
            common.parent.mkdir(parents=True)
            common.write_text("#!/bin/sh\n", encoding="utf-8")
            with mock.patch.object(
                trust,
                "_run_git",
                side_effect=(
                    ("160000 commit expected modules/ModSecurity-test-Framework\n", None),
                    ("expected\n", None),
                    (" M ci/checks/catalog/no_crs_baseline.py\n", None),
                ),
            ) as run_git:
                root, error = trust.trusted_framework_root(Path("/parent"), framework_root)
        self.assertIsNone(root)
        self.assertEqual(
            error,
            "Framework test root must be clean and contain a regular common.sh",
        )
        self.assertEqual(
            run_git.call_args_list[-1].args[1:],
            ("status", "--porcelain", "--untracked-files=all", "--ignore-submodules=none"),
        )

    def test_rejects_a_symlinked_common_sh(self) -> None:
        with tempfile.TemporaryDirectory(prefix="framework-test-trust-") as temporary:
            framework_root = Path(temporary) / "framework"
            common = framework_root / "ci" / "lib" / "common.sh"
            common.parent.mkdir(parents=True)
            target = framework_root / "common-target.sh"
            target.write_text("#!/bin/sh\n", encoding="utf-8")
            common.symlink_to(target)
            with mock.patch.object(
                trust,
                "_run_git",
                side_effect=(
                    ("160000 commit expected modules/ModSecurity-test-Framework\n", None),
                    ("expected\n", None),
                    ("", None),
                ),
            ):
                root, error = trust.trusted_framework_root(Path("/parent"), framework_root)
        self.assertIsNone(root)
        self.assertEqual(
            error,
            "Framework test root must be clean and contain a regular common.sh",
        )

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
