"""Unit coverage for the bounded Functional-A NGINX root launcher."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = connector_root()
LAUNCHER = source_path('connectors/nginx/harness/run_github_hosted_functional_a.py', root=ROOT)


def load_launcher_module():
    module = load_source(LAUNCHER)
    return module


LAUNCHER_MODULE = load_launcher_module()


class HostedFunctionalLauncherTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.framework = self.root / "modules" / "ModSecurity-test-Framework"
        connector = self.framework / "connector_suite/adapters/nginx/harness"
        framework_rules = self.framework / "tests" / "rules"
        connector.mkdir(parents=True)
        framework_rules.mkdir(parents=True)
        (framework_rules / "no-crs-baseline.conf").write_text("SecRuleEngine On\n", encoding="utf-8")
        exact = connector / "run_exact_head_use_error_log.sh"
        exact.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        exact.chmod(0o700)
        self.trusted_tmp = self.root / "trusted-tmp"
        self.trusted_tmp.mkdir()
        self.trusted_tmp.chmod(0o1777)
        self.job_root = self.trusted_tmp / (
            LAUNCHER_MODULE._FUNCTIONAL_JOB_ROOT_PREFIX + "fixture123"
        )
        self.job_root.mkdir(mode=0o700)
        self.job_root.chmod(0o711)
        self.verified = self.job_root / LAUNCHER_MODULE._VERIFIED_RUN_ROOT_NAME
        self.verified.mkdir(mode=0o700)
        self.verified.chmod(0o700)
        self.evidence = self.verified / LAUNCHER_MODULE._FUNCTIONAL_EVIDENCE_DIRECTORY_NAME
        self.evidence.mkdir(mode=0o700)
        self.evidence.chmod(0o700)
        self.functional_parent = self.job_root / "ModSecurity-conector-nginx-functional-parent"
        self.functional_parent.mkdir(mode=0o711)
        self.functional_parent.chmod(0o711)
        self.prefix = self.verified / "nginx-prefix"
        (self.prefix / "sbin").mkdir(parents=True)
        (self.prefix / "modules").mkdir()
        nginx = self.prefix / "sbin" / "nginx"
        nginx.write_text("binary\n", encoding="utf-8")
        nginx.chmod(0o700)
        (self.prefix / "modules" / "ngx_http_modsecurity_module.so").write_bytes(b"module")
        self.build = self.verified / "nginx-build"
        self.build.mkdir()
        self.lib = self.verified / "modsecurity-lib"
        self.lib.mkdir()
        (self.lib / "libmodsecurity.so.3").write_bytes(b"runtime library")
        (self.lib / "libmodsecurity.so").symlink_to("libmodsecurity.so.3")
        self.env = {
            "CONNECTOR_ROOT": str(self.root),
            "CONNECTOR_REVISION": "a" * 40,
            "TEST_ROOT": str(self.framework),
            "FRAMEWORK_ROOT": str(self.framework),
            "VERIFIED_RUN_ROOT": str(self.verified),
            "NGINX_FUNCTIONAL_A_PARENT_ROOT": str(self.functional_parent),
            "NGINX_FUNCTIONAL_A_EVIDENCE_ROOT": str(self.evidence),
            "EXPECTED_PARENT_SHA": "a" * 40,
            "NGINX_SHA256": "b" * 64,
            "NGINX_PREFIX": str(self.prefix),
            "NGINX_BUILD_DIR": str(self.build),
            "MODSECURITY_LIB_DIR": str(self.lib),
            "NGINX_FUNCTIONAL_WORKER_USER": "msconnector-nginx",
            "NGINX_FUNCTIONAL_WORKER_GROUP": "msconnector-nginx",
            "NGINX_PROTOCOL_PROFILE": "h1",
        }
        self.runner_uid = 4242
        original_lstat = Path.lstat

        def runner_owned_verified_root_lstat(path: Path) -> os.stat_result:
            metadata = original_lstat(path)
            if path in (self.job_root, self.functional_parent):
                fields = list(metadata)
                fields[4] = 0
                return os.stat_result(fields)
            if path in (self.verified, self.evidence):
                fields = list(metadata)
                fields[4] = self.runner_uid
                return os.stat_result(fields)
            return metadata

        self.repo_patch = mock.patch.object(LAUNCHER_MODULE, "repository_root", return_value=self.root)
        self.tmp_root_patch = mock.patch.object(
            LAUNCHER_MODULE,
            "_require_trusted_functional_tmp_root",
            return_value=self.trusted_tmp,
        )
        self.lstat_patch = mock.patch.object(
            Path,
            "lstat",
            new=runner_owned_verified_root_lstat,
        )
        self.euid_patch = mock.patch.object(
            LAUNCHER_MODULE.os,
            "geteuid",
            return_value=self.runner_uid,
        )
        self.repo_patch.start()
        self.tmp_root_patch.start()
        self.lstat_patch.start()
        self.euid_patch.start()

    def tearDown(self) -> None:
        self.euid_patch.stop()
        self.lstat_patch.stop()
        self.tmp_root_patch.stop()
        self.repo_patch.stop()
        self.tempdir.cleanup()

    def test_builds_deterministic_sudo_clean_environment_command(self) -> None:
        command = LAUNCHER_MODULE.build_root_command(self.env)
        self.assertEqual(command[:4], ["/usr/bin/sudo", "-n", "/usr/bin/env", "-i"])
        self.assertEqual(command[-2], "/bin/sh")
        self.assertEqual(command[-1], str(self.framework / "connector_suite/adapters/nginx/harness/run_exact_head_use_error_log.sh"))
        assignments = dict(item.split("=", 1) for item in command[4:-2])
        self.assertEqual(assignments["PATH"], "/usr/bin:/bin")
        self.assertEqual(assignments["HOME"], "/nonexistent")
        self.assertEqual(
            assignments["NGINX_FUNCTIONAL_A_PARENT_ROOT"], str(self.functional_parent)
        )
        self.assertEqual(
            assignments["VERIFIED_RUN_ROOT"],
            str(self.functional_parent / "nginx-hosted-functional-a"),
        )
        self.assertEqual(
            assignments["NGINX_WORKER_USER"], self.env["NGINX_FUNCTIONAL_WORKER_USER"]
        )
        self.assertEqual(
            assignments["NGINX_WORKER_GROUP"], self.env["NGINX_FUNCTIONAL_WORKER_GROUP"]
        )
        self.assertEqual(assignments["NGINX_HOSTED_FUNCTIONAL_A"], "1")
        self.assertEqual(
            assignments["NGINX_FUNCTIONAL_A_RUNTIME_LIBRARY"],
            str(self.lib / "libmodsecurity.so.3"),
        )
        self.assertEqual(assignments["NGINX_FUNCTIONAL_A_EVIDENCE_ROOT"], str(self.evidence))
        self.assertEqual(assignments["EXPECTED_PARENT_SHA"], "a" * 40)
        self.assertEqual(assignments["NGINX_SHA256"], "b" * 64)
        for forbidden in ("LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "BASH_ENV", "ENV"):
            self.assertNotIn(forbidden, assignments)
        self.assertEqual(command, LAUNCHER_MODULE.build_root_command(dict(self.env)))

    def test_rejects_paths_outside_verified_root(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        invalid = dict(self.env, NGINX_PREFIX=str(outside))
        with self.assertRaisesRegex(LAUNCHER_MODULE.FunctionalALaunchError, "below VERIFIED_RUN_ROOT"):
            LAUNCHER_MODULE.build_root_command(invalid)

    def test_rejects_unsafe_or_non_sibling_functional_parent(self) -> None:
        with self.assertRaisesRegex(
            LAUNCHER_MODULE.FunctionalALaunchError, "designated sibling"
        ):
            LAUNCHER_MODULE.build_root_command(
                dict(self.env, NGINX_FUNCTIONAL_A_PARENT_ROOT=str(self.verified / "nested"))
            )

        self.functional_parent.chmod(0o700)
        with self.assertRaisesRegex(LAUNCHER_MODULE.FunctionalALaunchError, "exactly non-enumerable mode 0711"):
            LAUNCHER_MODULE.build_root_command(self.env)
        self.functional_parent.chmod(0o711)

        self.job_root.chmod(0o700)
        try:
            with self.assertRaisesRegex(
                LAUNCHER_MODULE.FunctionalALaunchError,
                "job root must be exactly non-enumerable mode 0711",
            ):
                LAUNCHER_MODULE.build_root_command(self.env)
        finally:
            self.job_root.chmod(0o711)

    def test_rejects_correctly_bound_functional_parent_owned_by_another_user(self) -> None:
        original_lstat = Path.lstat

        def wrong_owner_lstat(path: Path) -> os.stat_result:
            metadata = original_lstat(path)
            if path == self.functional_parent:
                fields = list(metadata)
                fields[4] = self.runner_uid
                return os.stat_result(fields)
            return metadata

        with mock.patch.object(Path, "lstat", new=wrong_owner_lstat):
            with self.assertRaisesRegex(
                LAUNCHER_MODULE.FunctionalALaunchError,
                "NGINX_FUNCTIONAL_A_PARENT_ROOT must be owned by root",
            ):
                LAUNCHER_MODULE.build_root_command(self.env)

    def test_rejects_a_runner_owned_functional_job_root(self) -> None:
        original_lstat = Path.lstat

        def runner_owned_job_root_lstat(path: Path) -> os.stat_result:
            metadata = original_lstat(path)
            if path == self.job_root:
                fields = list(metadata)
                fields[4] = self.runner_uid
                return os.stat_result(fields)
            return metadata

        with mock.patch.object(Path, "lstat", new=runner_owned_job_root_lstat):
            with self.assertRaisesRegex(
                LAUNCHER_MODULE.FunctionalALaunchError,
                "Functional-A job root must be owned by root",
            ):
                LAUNCHER_MODULE.build_root_command(self.env)

    def test_trusted_temporary_root_and_job_owner_contracts(self) -> None:
        self.tmp_root_patch.stop()
        try:
            expected_root = LAUNCHER_MODULE._EXPECTED_FUNCTIONAL_TMP_ROOT
            self.assertEqual(expected_root, Path(os.sep) / "tmp")
            sticky_root = os.stat_result(
                (stat.S_IFDIR | 0o1777, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            )
            with (
                mock.patch.object(LAUNCHER_MODULE.tempfile, "gettempdir", return_value=str(expected_root)),
                mock.patch.object(LAUNCHER_MODULE, "_require_directory", return_value=expected_root),
                mock.patch.object(Path, "lstat", return_value=sticky_root),
            ):
                self.assertEqual(
                    LAUNCHER_MODULE._require_trusted_functional_tmp_root(), expected_root
                )

            unsafe_root = os.stat_result(
                (stat.S_IFDIR | 0o777, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            )
            with (
                mock.patch.object(LAUNCHER_MODULE.tempfile, "gettempdir", return_value=str(expected_root)),
                mock.patch.object(LAUNCHER_MODULE, "_require_directory", return_value=expected_root),
                mock.patch.object(Path, "lstat", return_value=unsafe_root),
                self.assertRaisesRegex(
                    LAUNCHER_MODULE.FunctionalALaunchError, "root-owned sticky mode 01777"
                ),
            ):
                LAUNCHER_MODULE._require_trusted_functional_tmp_root()

            with (
                mock.patch.object(LAUNCHER_MODULE.tempfile, "gettempdir", return_value="/var/tmp"),
                self.assertRaisesRegex(
                    LAUNCHER_MODULE.FunctionalALaunchError,
                    "must resolve to the fixed /tmp namespace",
                ),
            ):
                LAUNCHER_MODULE._require_trusted_functional_tmp_root()
        finally:
            self.tmp_root_patch.start()

        with mock.patch.object(LAUNCHER_MODULE.os, "geteuid", return_value=self.runner_uid + 1):
            with self.assertRaisesRegex(
                LAUNCHER_MODULE.FunctionalALaunchError,
                "VERIFIED_RUN_ROOT must be owned by the workflow runner",
            ):
                LAUNCHER_MODULE.build_root_command(self.env)

    def test_rejects_a_symlinked_functional_parent(self) -> None:
        self.functional_parent.rmdir()
        self.functional_parent.symlink_to("replacement", target_is_directory=True)
        with self.assertRaisesRegex(LAUNCHER_MODULE.FunctionalALaunchError, "symbolic link"):
            LAUNCHER_MODULE.build_root_command(self.env)

    def test_rejects_misbound_or_symlinked_functional_job_roots(self) -> None:
        misplaced_root = self.root / "misplaced-functional-job"
        misplaced_root.mkdir()
        misplaced_verified = misplaced_root / LAUNCHER_MODULE._VERIFIED_RUN_ROOT_NAME
        misplaced_verified.mkdir(mode=0o700)
        misplaced_verified.chmod(0o700)
        with self.assertRaisesRegex(
            LAUNCHER_MODULE.FunctionalALaunchError, "designated fresh /tmp job root"
        ):
            LAUNCHER_MODULE._require_private_verified_run_root(misplaced_verified)

        unexpected_verified = self.job_root / "unexpected-verified-root"
        unexpected_verified.mkdir(mode=0o700)
        unexpected_verified.chmod(0o700)
        with self.assertRaisesRegex(
            LAUNCHER_MODULE.FunctionalALaunchError, "designated private child"
        ):
            LAUNCHER_MODULE._require_private_verified_run_root(unexpected_verified)

        symlinked_root = self.trusted_tmp / (
            LAUNCHER_MODULE._FUNCTIONAL_JOB_ROOT_PREFIX + "symlink"
        )
        symlinked_root.symlink_to("replacement", target_is_directory=True)
        symlinked_verified = symlinked_root / LAUNCHER_MODULE._VERIFIED_RUN_ROOT_NAME
        with self.assertRaisesRegex(LAUNCHER_MODULE.FunctionalALaunchError, "symbolic link"):
            LAUNCHER_MODULE._require_private_verified_run_root(symlinked_verified)

    def test_rejects_symlinked_artifact_path(self) -> None:
        real = self.verified / "real-prefix"
        (real / "sbin").mkdir(parents=True)
        (real / "modules").mkdir()
        (real / "sbin" / "nginx").write_text("binary\n", encoding="utf-8")
        (real / "sbin" / "nginx").chmod(0o700)
        (real / "modules" / "ngx_http_modsecurity_module.so").write_bytes(b"module")
        symlink = self.verified / "symlink-prefix"
        symlink.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(LAUNCHER_MODULE.FunctionalALaunchError, "symbolic link"):
            LAUNCHER_MODULE.build_root_command(dict(self.env, NGINX_PREFIX=str(symlink)))

    def test_rejects_unbounded_worker_names_and_wrong_protocol(self) -> None:
        cases = [
            {"NGINX_FUNCTIONAL_WORKER_USER": "bad user"},
            {"NGINX_FUNCTIONAL_WORKER_GROUP": "-leading-dash"},
            {"NGINX_FUNCTIONAL_WORKER_USER": ""},
            {"NGINX_FUNCTIONAL_WORKER_GROUP": ""},
            {"NGINX_FUNCTIONAL_WORKER_USER": "x" * 65},
            {"NGINX_PROTOCOL_PROFILE": "h2"},
        ]
        for override in cases:
            with self.subTest(override=override):
                with self.assertRaises(LAUNCHER_MODULE.FunctionalALaunchError):
                    LAUNCHER_MODULE.build_root_command(dict(self.env, **override))

    def test_rejects_misbound_or_nonempty_functional_evidence_root(self) -> None:
        outside = self.root / "outside-evidence"
        outside.mkdir(mode=0o700)
        outside.chmod(0o700)
        with self.assertRaisesRegex(
            LAUNCHER_MODULE.FunctionalALaunchError, "designated verified-root child"
        ):
            LAUNCHER_MODULE.build_root_command(
                dict(self.env, NGINX_FUNCTIONAL_A_EVIDENCE_ROOT=str(outside))
            )

        self.evidence.chmod(0o755)
        try:
            with self.assertRaisesRegex(
                LAUNCHER_MODULE.FunctionalALaunchError, "runner-owned private mode 0700"
            ):
                LAUNCHER_MODULE.build_root_command(self.env)
        finally:
            self.evidence.chmod(0o700)

        (self.evidence / "result.json").write_text("stale\n", encoding="utf-8")
        with self.assertRaisesRegex(
            LAUNCHER_MODULE.FunctionalALaunchError, "fresh and empty"
        ):
            LAUNCHER_MODULE.build_root_command(self.env)

    def test_rejects_non_exact_expected_parent_sha(self) -> None:
        for value in ("", "A" * 40, "a" * 39, "g" * 40):
            with self.subTest(value=value), self.assertRaisesRegex(
                LAUNCHER_MODULE.FunctionalALaunchError, "exact lowercase commit SHA"
            ):
                LAUNCHER_MODULE.build_root_command(dict(self.env, EXPECTED_PARENT_SHA=value))

        for value in ("", "B" * 64, "b" * 63, "g" * 64):
            with self.subTest(value=value), self.assertRaisesRegex(
                LAUNCHER_MODULE.FunctionalALaunchError, "exact lowercase SHA-256"
            ):
                LAUNCHER_MODULE.build_root_command(dict(self.env, NGINX_SHA256=value))

    def test_rejects_missing_or_non_regular_artifacts(self) -> None:
        missing = dict(self.env, MODSECURITY_LIB_DIR=str(self.verified / "missing"))
        with self.assertRaises(LAUNCHER_MODULE.FunctionalALaunchError):
            LAUNCHER_MODULE.build_root_command(missing)
        module_path = self.prefix / "modules" / "ngx_http_modsecurity_module.so"
        module_path.unlink()
        module_path.mkdir()
        with self.assertRaisesRegex(LAUNCHER_MODULE.FunctionalALaunchError, "regular file"):
            LAUNCHER_MODULE.build_root_command(self.env)

    def test_rejects_a_symlinked_runtime_library_even_when_the_generic_alias_exists(self) -> None:
        runtime_library = self.lib / "libmodsecurity.so.3"
        runtime_library.unlink()
        runtime_library.symlink_to("libmodsecurity.so")
        with self.assertRaisesRegex(LAUNCHER_MODULE.FunctionalALaunchError, "symbolic link"):
            LAUNCHER_MODULE.build_root_command(self.env)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
