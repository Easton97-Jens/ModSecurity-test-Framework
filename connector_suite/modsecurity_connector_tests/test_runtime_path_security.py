from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import argparse
import contextlib
from functools import partial
import io
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = connector_root()
CI_LIB = source_path('ci/lib', root=ROOT)


from modsecurity_connector_ci.lib.runtime_path_utils import ensure_safe_runtime_directory, verified_runtime_paths
from modsecurity_connector_ci.lib.verified_run_id import VerifiedRunIdError, validate_verified_run_id
import modsecurity_connector_ci.lib.verified_full_matrix_receipt as RECEIPT
import modsecurity_connector_ci.lib.runtime_path_utils as RUNTIME_PATH_UTILS


def load_script(name: str, relative_path: str):
    module = load_source(ROOT / relative_path)
    return module


def fstat_with_directory_metadata(
    descriptor: int,
    *,
    original_fstat,
    target_device: int,
    target_inode: int,
    replacement_owner: int,
    replacement_mode: int,
) -> os.stat_result:
    details = original_fstat(descriptor)
    if (details.st_dev, details.st_ino) != (target_device, target_inode):
        return details
    replacement = list(details)
    replacement[0] = stat.S_IFDIR | replacement_mode
    replacement[4] = replacement_owner
    return os.stat_result(replacement)


VERIFIED_REPORT_RUN = load_script(
    "verified_report_run_runtime_path_security",
    "ci/runtime/lifecycle/run-verified-report-run.py",
)
FULL_MATRIX_JOB = load_script(
    "full_matrix_job_runtime_path_security",
    "ci/runtime/lifecycle/run-full-matrix-job.py",
)
FULL_MATRIX_RESUME = load_script(
    "full_matrix_resume_runtime_path_security",
    "ci/runtime/lifecycle/run-full-matrix-resume.py",
)
RUNTIME_PATH_PREFLIGHT = load_script(
    "runtime_path_preflight_security",
    "ci/runtime/lifecycle/prepare-verified-runtime-paths.py",
)
FULL_MATRIX_COMPLETENESS = load_script(
    "full_matrix_completeness_runtime_path_security",
    "ci/evidence/reports/generate-full-matrix-job-completeness.py",
)
CONNECTOR_ROADMAP = load_script(
    "connector_roadmap_temporary_output_security",
    "ci/evidence/reports/generate-connector-roadmap.py",
)
ORGANIZATION_INVENTORY = load_script(
    "organization_inventory_temporary_output_security",
    "scripts/generate_repository_organization_inventory.py",
)
NATIVE_CASE_RUNNER = load_script(
    "native_case_runner_runtime_path_security",
    "ci/runtime/lifecycle/run-native-case-comparison.py",
)
NGINX_HTTP500_ANALYSIS = load_script(
    "nginx_http500_runtime_path_security",
    "ci/evidence/reports/generate-nginx-mrts-http500-cluster-analysis.py",
)
VERIFIED_CASE_RUNNER = load_script(
    "verified_case_runner_runtime_path_security",
    "ci/runtime/lifecycle/run-verified-case.py",
)


class RuntimePathSecurityTest(unittest.TestCase):
    def test_case_runners_reject_symlinked_verified_roots_before_runtime_actions(self) -> None:
        framework_root = source_path('modules/ModSecurity-test-Framework', root=ROOT)
        with tempfile.TemporaryDirectory(prefix="runtime-case-runner-symlink-") as temporary:
            parent = Path(temporary)
            for variant in ("final", "parent"):
                for name, runner in (
                    ("native", NATIVE_CASE_RUNNER),
                    ("verified", VERIFIED_CASE_RUNNER),
                ):
                    with self.subTest(variant=variant, runner=name):
                        victim = parent / f"{variant}-{name}-victim"
                        victim.mkdir()
                        runner_parent = parent / f"{variant}-{name}-root"
                        if variant == "final":
                            runner_root = runner_parent
                            runner_root.symlink_to(victim, target_is_directory=True)
                        else:
                            runner_parent.symlink_to(victim, target_is_directory=True)
                            runner_root = runner_parent / "verified-root"
                        output_dir = parent / f"{variant}-{name}-output"
                        if name == "native":
                            arguments = [
                                "run-native-case-comparison.py",
                                "--case",
                                "allow_without_marker",
                                "--connector-root",
                                str(ROOT),
                                "--framework-root",
                                str(framework_root),
                                "--verified-run-root",
                                str(runner_root),
                                "--output-dir",
                                str(output_dir),
                                "--report-only",
                            ]
                        else:
                            arguments = [
                                "run-verified-case.py",
                                "--connector",
                                "apache",
                                "--case",
                                "allow_without_marker",
                                "--crs",
                                "no-crs",
                                "--mrts",
                                "no-mrts",
                                "--connector-root",
                                str(ROOT),
                                "--framework-root",
                                str(framework_root),
                                "--build-root",
                                str(parent / f"{variant}-{name}-build"),
                                "--verified-run-root",
                                str(runner_root),
                            ]

                        with mock.patch.object(sys, "argv", arguments):
                            with contextlib.redirect_stderr(io.StringIO()):
                                self.assertEqual(runner.main(), 77)

                        self.assertEqual(list(victim.iterdir()), [])
                        self.assertFalse(output_dir.exists())

    def test_verified_case_explain_does_not_materialize_a_runtime_root(self) -> None:
        framework_root = source_path('modules/ModSecurity-test-Framework', root=ROOT)
        with tempfile.TemporaryDirectory(prefix="runtime-case-explain-") as temporary:
            runtime_root = Path(temporary) / "uncreated-root"
            arguments = [
                "run-verified-case.py",
                "--connector",
                "apache",
                "--case",
                "allow_without_marker",
                "--crs",
                "no-crs",
                "--mrts",
                "no-mrts",
                "--connector-root",
                str(ROOT),
                "--framework-root",
                str(framework_root),
                "--build-root",
                str(Path(temporary) / "build"),
                "--verified-run-root",
                str(runtime_root),
                "--explain",
            ]

            with mock.patch.object(sys, "argv", arguments):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(VERIFIED_CASE_RUNNER.main(), 0)

            self.assertFalse(runtime_root.exists())

    def test_precreated_verified_runtime_root_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-path-symlink-") as temporary:
            parent = Path(temporary)
            victim = parent / "victim"
            victim.mkdir()
            run_root = parent / "verified-run"
            run_root.symlink_to(victim, target_is_directory=True)
            run_root_text = str(run_root)

            with self.assertRaisesRegex(ValueError, "symbolic links"):
                verified_runtime_paths({"VERIFIED_RUN_ROOT": run_root_text})
            with self.assertRaisesRegex(ValueError, "symbolic links"):
                ensure_safe_runtime_directory(run_root)

            self.assertFalse((victim / "state").exists())
            self.assertFalse((victim / "logs").exists())

    def test_private_runtime_root_control_creates_safe_directories(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-path-control-") as temporary:
            parent = Path(temporary)
            run_root = parent / "verified-run"
            build_root = parent / "build"
            paths = VERIFIED_REPORT_RUN.runtime_paths(
                {"VERIFIED_RUN_ROOT": str(run_root), "BUILD_ROOT": str(build_root)},
                build_root,
                "verified-run-20260721",
            )

            VERIFIED_REPORT_RUN.prepare_runtime_roots(paths)

            for key in (
                "VERIFIED_RUN_ROOT",
                "VERIFIED_RUNS_ROOT",
                "VERIFIED_RUN_INSTANCE_ROOT",
                "VERIFIED_RUN_INSTANCE_LOG_ROOT",
            ):
                path = Path(paths[key])
                with self.subTest(path=path):
                    self.assertTrue(path.is_dir())
                    self.assertFalse(path.is_symlink())
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o022, 0)

    def test_all_write_capable_configured_runtime_roots_are_prepared(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-path-all-roots-") as temporary:
            parent = Path(temporary)
            build_root = parent / "build"
            environment = {
                "VERIFIED_RUN_ROOT": str(parent / "verified-run"),
                "VERIFIED_STATE_ROOT": str(parent / "verified-state"),
                "VERIFIED_BUILD_ROOT": str(parent / "verified-build"),
                "VERIFIED_SOURCE_ROOT": str(parent / "verified-source"),
                "VERIFIED_TMP_ROOT": str(parent / "verified-tmp"),
                "VERIFIED_LOG_ROOT": str(parent / "verified-log"),
                "CACHE_ROOT": str(parent / "cache"),
                "VERIFIED_COMPONENT_CACHE": str(parent / "verified-cache"),
                "NGINX_HARNESS_PARENT": str(parent / "nginx-harness"),
                "BUILD_ROOT": str(build_root),
                "SOURCE_ROOT": str(parent / "source"),
                "TMP_ROOT": str(parent / "tmp"),
                "LOG_ROOT": str(parent / "log"),
                "CONNECTOR_COMPONENT_CACHE": str(parent / "connector-cache"),
                "MATRIX_ROOT": str(parent / "matrix"),
                "MRTS_BUILD_ROOT": str(parent / "mrts-build"),
                "MRTS_NATIVE_ROOT": str(parent / "mrts-native"),
            }
            paths = VERIFIED_REPORT_RUN.runtime_paths(
                environment,
                build_root,
                "verified-run-20260721",
            )

            VERIFIED_REPORT_RUN.prepare_runtime_roots(paths)

            for key, value in paths.items():
                path = Path(value)
                with self.subTest(key=key, path=path):
                    self.assertTrue(path.is_dir())
                    self.assertFalse(path.is_symlink())
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o022, 0)

    def test_canonical_source_root_remains_read_only_during_runtime_preparation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-path-read-only-source-") as temporary:
            parent = Path(temporary)
            build_root = parent / "build"
            paths = VERIFIED_REPORT_RUN.runtime_paths(
                {
                    "VERIFIED_RUN_ROOT": str(parent / "verified-run"),
                    "BUILD_ROOT": str(build_root),
                    "SOURCE_ROOT": str(ROOT),
                },
                build_root,
                "verified-run-20260721",
            )

            VERIFIED_REPORT_RUN.prepare_runtime_roots(paths)

            self.assertEqual(ROOT, Path(paths["SOURCE_ROOT"]))
            self.assertTrue(Path(paths["VERIFIED_RUN_INSTANCE_LOG_ROOT"]).is_dir())

    def test_configured_matrix_and_mrts_roots_reject_symlink_swap_before_child_creation(self) -> None:
        for key in ("MATRIX_ROOT", "MRTS_BUILD_ROOT", "MRTS_NATIVE_ROOT"):
            with self.subTest(key=key), tempfile.TemporaryDirectory(
                prefix=f"runtime-path-{key.lower()}-"
            ) as temporary:
                parent = Path(temporary)
                victim = parent / "victim"
                victim.mkdir()
                build_root = parent / "build"
                configured_root = parent / key.lower()
                paths = VERIFIED_REPORT_RUN.runtime_paths(
                    {
                        "VERIFIED_RUN_ROOT": str(parent / "verified-run"),
                        "BUILD_ROOT": str(build_root),
                        key: str(configured_root),
                    },
                    build_root,
                    "verified-run-20260721",
                )
                configured_root.symlink_to(victim, target_is_directory=True)

                with self.assertRaisesRegex(ValueError, "symbolic links"):
                    VERIFIED_REPORT_RUN.prepare_runtime_roots(paths)

                self.assertEqual(list(victim.iterdir()), [])
                self.assertFalse((victim / "no-crs").exists())

    def test_direct_full_matrix_job_rejects_matrix_swap_before_job_creation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-path-direct-job-") as temporary:
            parent = Path(temporary)
            victim = parent / "victim"
            victim.mkdir()
            build_root = parent / "build"
            matrix_root = parent / "matrix"
            environment = {
                "VERIFIED_RUN_ROOT": str(parent / "verified-run"),
                "BUILD_ROOT": str(build_root),
                "MATRIX_ROOT": str(matrix_root),
            }
            original_resolver = FULL_MATRIX_JOB.verified_runtime_paths

            def swap_matrix_root(*args, **kwargs):
                paths = original_resolver(*args, **kwargs)
                matrix_root.symlink_to(victim, target_is_directory=True)
                return paths

            arguments = [
                "run-full-matrix-job.py",
                "--connector",
                "apache",
                "--crs",
                "no-crs",
                "--mrts",
                "no-mrts",
                "--connector-root",
                str(ROOT),
                "--build-root",
                str(build_root),
            ]
            with mock.patch.dict(os.environ, environment, clear=False):
                with mock.patch.object(sys, "argv", arguments):
                    with mock.patch.object(
                        FULL_MATRIX_JOB,
                        "verified_runtime_paths",
                        side_effect=swap_matrix_root,
                    ):
                        with self.assertRaisesRegex(ValueError, "symbolic links"):
                            FULL_MATRIX_JOB.main()

            self.assertEqual(list(victim.iterdir()), [])
            self.assertFalse((victim / "no-crs").exists())

    def test_direct_full_matrix_resume_rejects_matrix_swap_before_subprocesses(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-path-direct-resume-") as temporary:
            parent = Path(temporary)
            victim = parent / "victim"
            victim.mkdir()
            build_root = parent / "build"
            matrix_root = parent / "matrix"
            environment = {
                "VERIFIED_RUN_ROOT": str(parent / "verified-run"),
                "BUILD_ROOT": str(build_root),
                "MATRIX_ROOT": str(matrix_root),
            }
            original_resolver = FULL_MATRIX_RESUME.verified_runtime_paths

            def swap_matrix_root(*args, **kwargs):
                paths = original_resolver(*args, **kwargs)
                matrix_root.symlink_to(victim, target_is_directory=True)
                return paths

            arguments = [
                "run-full-matrix-resume.py",
                "--connector-root",
                str(ROOT),
                "--build-root",
                str(build_root),
            ]
            with mock.patch.dict(os.environ, environment, clear=False):
                with mock.patch.object(sys, "argv", arguments):
                    with mock.patch.object(
                        FULL_MATRIX_RESUME,
                        "verified_runtime_paths",
                        side_effect=swap_matrix_root,
                    ):
                        with self.assertRaisesRegex(ValueError, "symbolic links"):
                            FULL_MATRIX_RESUME.main()

            self.assertEqual(list(victim.iterdir()), [])

    def test_shell_runtime_path_preflight_rejects_matrix_swap_before_shell_writes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-path-shell-preflight-") as temporary:
            parent = Path(temporary)
            victim = parent / "victim"
            victim.mkdir()
            build_root = parent / "build"
            matrix_root = parent / "matrix"
            environment = {
                "VERIFIED_RUN_ROOT": str(parent / "verified-run"),
                "BUILD_ROOT": str(build_root),
                "MATRIX_ROOT": str(matrix_root),
            }
            original_resolver = RUNTIME_PATH_PREFLIGHT.verified_runtime_paths

            def swap_matrix_root(*args, **kwargs):
                paths = original_resolver(*args, **kwargs)
                matrix_root.symlink_to(victim, target_is_directory=True)
                return paths

            with mock.patch.dict(os.environ, environment, clear=False):
                with mock.patch.object(
                    sys,
                    "argv",
                    ["prepare-verified-runtime-paths.py", "--build-root", str(build_root)],
                ):
                    with mock.patch.object(
                        RUNTIME_PATH_PREFLIGHT,
                        "verified_runtime_paths",
                        side_effect=swap_matrix_root,
                    ):
                        with contextlib.redirect_stderr(io.StringIO()):
                            self.assertEqual(RUNTIME_PATH_PREFLIGHT.main(), 77)

            self.assertEqual(list(victim.iterdir()), [])

    def test_direct_mrts_shell_entrypoints_preflight_before_first_directory_creation(self) -> None:
        for relative_path in (
            "ci/runtime/lifecycle/run-full-matrix-parallel.sh",
            "ci/runtime/lifecycle/run-full-mrts-runtime-matrix.sh",
            "ci/runtime/lifecycle/run-mrts-native-full.sh",
        ):
            script = (ROOT / relative_path).read_text(encoding="utf-8")
            with self.subTest(relative_path=relative_path):
                self.assertIn("prepare-verified-runtime-paths.py", script)
                self.assertLess(
                    script.index("prepare-verified-runtime-paths.py"),
                    script.index("mkdir -p"),
                )

    def test_precreated_group_writable_runtime_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-path-permissions-") as temporary:
            parent = Path(temporary)
            run_root = parent / "verified-run"
            build_root = parent / "build"
            run_root.mkdir(mode=0o777)
            run_root.chmod(0o777)
            paths = VERIFIED_REPORT_RUN.runtime_paths(
                {"VERIFIED_RUN_ROOT": str(run_root), "BUILD_ROOT": str(build_root)},
                build_root,
                "verified-run-20260721",
            )

            with self.assertRaisesRegex(ValueError, "group- or world-writable"):
                VERIFIED_REPORT_RUN.prepare_runtime_roots(paths)
            self.assertFalse((run_root / "state").exists())

    def test_root_owned_sticky_shared_root_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-shared-root-control-") as temporary:
            shared_root = Path(temporary)
            shared_details = shared_root.stat()
            runtime_root = shared_root / "runtime-root"
            original_fstat = RUNTIME_PATH_UTILS.os.fstat

            def trusted_shared_root_fstat(descriptor: int) -> os.stat_result:
                details = original_fstat(descriptor)
                if (details.st_dev, details.st_ino) != (
                    shared_details.st_dev,
                    shared_details.st_ino,
                ):
                    return details
                replacement = list(details)
                replacement[0] = stat.S_IFDIR | 0o1777
                replacement[4] = 0
                return os.stat_result(replacement)

            with mock.patch.object(
                RUNTIME_PATH_UTILS.os,
                "fstat",
                side_effect=trusted_shared_root_fstat,
            ):
                self.assertEqual(runtime_root, ensure_safe_runtime_directory(runtime_root))

            self.assertTrue(runtime_root.is_dir())
            self.assertEqual(stat.S_IMODE(runtime_root.stat().st_mode) & 0o022, 0)

    def test_nonsticky_or_nonroot_shared_root_is_rejected(self) -> None:
        variants = (
            ("root-owned non-sticky", 0, 0o777),
            ("non-root sticky", os.geteuid() + 1, 0o1777),
        )
        for label, owner, mode in variants:
            with self.subTest(label=label), tempfile.TemporaryDirectory(
                prefix="runtime-unsafe-shared-root-"
            ) as temporary:
                shared_root = Path(temporary)
                shared_details = shared_root.stat()
                runtime_root = shared_root / "runtime-root"
                original_fstat = RUNTIME_PATH_UTILS.os.fstat
                unsafe_shared_root_fstat = partial(
                    fstat_with_directory_metadata,
                    original_fstat=original_fstat,
                    target_device=shared_details.st_dev,
                    target_inode=shared_details.st_ino,
                    replacement_owner=owner,
                    replacement_mode=mode,
                )

                with mock.patch.object(
                    RUNTIME_PATH_UTILS.os,
                    "fstat",
                    side_effect=unsafe_shared_root_fstat,
                ):
                    with self.assertRaisesRegex(ValueError, "group- or world-writable"):
                        ensure_safe_runtime_directory(runtime_root)

                self.assertFalse(runtime_root.exists())

    def test_foreign_owned_component_below_shared_temp_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-foreign-owner-") as temporary:
            shared_root = Path(temporary)
            shared_details = shared_root.stat()
            foreign_parent = shared_root / "foreign-parent"
            foreign_parent.mkdir(mode=0o755)
            foreign_details = foreign_parent.stat()
            runtime_root = foreign_parent / "runtime-root"

            original_fstat = RUNTIME_PATH_UTILS.os.fstat

            def foreign_owner_fstat(descriptor: int) -> os.stat_result:
                details = original_fstat(descriptor)
                if (details.st_dev, details.st_ino) == (
                    shared_details.st_dev,
                    shared_details.st_ino,
                ):
                    replacement = list(details)
                    replacement[0] = stat.S_IFDIR | 0o1777
                    replacement[4] = 0
                    return os.stat_result(replacement)
                if (details.st_dev, details.st_ino) != (
                    foreign_details.st_dev,
                    foreign_details.st_ino,
                ):
                    return details
                replacement = list(details)
                replacement[4] = os.geteuid() + 1
                return os.stat_result(replacement)

            with mock.patch.object(RUNTIME_PATH_UTILS.os, "fstat", side_effect=foreign_owner_fstat):
                with self.assertRaisesRegex(ValueError, "untrusted owner below shared temporary root"):
                    ensure_safe_runtime_directory(runtime_root)

            self.assertFalse(runtime_root.exists())

    def test_verified_run_id_rejects_traversal_absolute_separator_and_dot_variants(self) -> None:
        invalid_values = (
            "../outside",
            "/absolute",
            "nested/run",
            "nested\\run",
            ".",
            "..",
            ".hidden",
            "run..suffix",
            " trailing",
        )
        for value in invalid_values:
            with self.subTest(value=value), self.assertRaises(VerifiedRunIdError):
                validate_verified_run_id(value)

        valid = "2026-07-21T02-35-59Z-deadbeef"
        self.assertEqual(validate_verified_run_id(valid), valid)

    def test_run_id_is_checked_before_lifecycle_and_report_path_joins(self) -> None:
        with tempfile.TemporaryDirectory(prefix="verified-run-id-") as temporary:
            parent = Path(temporary)
            run_root = parent / "runtime-root"
            build_root = parent / "build-root"
            environment = {"VERIFIED_RUN_ROOT": str(run_root), "BUILD_ROOT": str(build_root)}
            for value in ("../outside", "/absolute", "nested/run", ".", ".."):
                with self.subTest(value=value), self.assertRaises(VerifiedRunIdError):
                    VERIFIED_REPORT_RUN.runtime_paths(environment, build_root, value)

            arguments = argparse.Namespace(
                connector_root=str(ROOT),
                framework_root=None,
                build_root=str(build_root),
                output_dir=str(parent / "report-output"),
                verified_run_id="../outside",
                verified_commands_file="",
            )
            with mock.patch.dict(os.environ, environment, clear=False):
                with self.assertRaises(VerifiedRunIdError):
                    FULL_MATRIX_COMPLETENESS.resolve_generation_context(arguments)

            self.assertFalse((parent / "outside").exists())
            self.assertFalse((build_root / "verified-runs" / "outside").exists())
            with self.assertRaises(RECEIPT.AggregateReceiptError):
                RECEIPT.aggregate_receipt_path(build_root, "../outside")
            with self.assertRaises(VerifiedRunIdError):
                NGINX_HTTP500_ANALYSIS.build_payload(
                    ROOT,
                    build_root,
                    "../outside",
                )

            command = [
                sys.executable,
                str(source_path('ci/runtime/lifecycle/run-full-matrix-job.py', root=ROOT)),
                "--connector",
                "apache",
                "--crs",
                "no-crs",
                "--mrts",
                "no-mrts",
                "--connector-root",
                str(ROOT),
                "--build-root",
                str(build_root),
            ]
            process = subprocess.run(
                command,
                cwd=ROOT,
                env={**os.environ, **environment, "VERIFIED_RUN_ID": "../outside"},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(process.returncode, 0)
            self.assertIn("verified_run_id", process.stderr)
            self.assertFalse((build_root / "verified-runs").exists())

    def test_temporary_report_writers_ignore_precreated_default_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="temporary-report-writers-") as temporary:
            temporary_parent = Path(temporary)
            victim = temporary_parent / "victim"
            victim.mkdir()
            sentinel = victim / "sentinel.txt"
            sentinel.write_text("unchanged\n", encoding="utf-8")
            (temporary_parent / "modsecurity-doc-cleanup").symlink_to(
                victim,
                target_is_directory=True,
            )

            with mock.patch.dict(os.environ, {"TMP_ROOT": str(temporary_parent)}, clear=False):
                with mock.patch.object(
                    sys,
                    "argv",
                    ["generate-connector-roadmap.py", "--connector-root", str(ROOT)],
                ):
                    self.assertEqual(CONNECTOR_ROADMAP.main(), 0)
                with mock.patch.object(ORGANIZATION_INVENTORY, "tracked_files", return_value=[]):
                    ORGANIZATION_INVENTORY.main()

            roadmap_outputs = list(temporary_parent.glob("modsecurity-connector-roadmap-*"))
            inventory_outputs = list(temporary_parent.glob("modsecurity-doc-cleanup-*"))
            self.assertEqual(len(roadmap_outputs), 1)
            self.assertEqual(len(inventory_outputs), 1)
            self.assertTrue((roadmap_outputs[0] / "connector-roadmap.generated.json").is_file())
            self.assertTrue((roadmap_outputs[0] / "connector-roadmap.generated.md").is_file())
            self.assertTrue((roadmap_outputs[0] / "connector-roadmap.generated.de.md").is_file())
            self.assertTrue((inventory_outputs[0] / "repository-organization-inventory.json").is_file())
            self.assertTrue((inventory_outputs[0] / "repository-organization-plan.md").is_file())
            self.assertTrue((inventory_outputs[0] / "repository-organization-plan.de.md").is_file())
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged\n")
            self.assertEqual(stat.S_IMODE(roadmap_outputs[0].stat().st_mode) & 0o077, 0)
            self.assertEqual(stat.S_IMODE(inventory_outputs[0].stat().st_mode) & 0o077, 0)

    def test_native_report_output_normalizes_parent_traversal_before_authorization(self) -> None:
        with tempfile.TemporaryDirectory(prefix="native-report-output-") as temporary:
            parent = Path(temporary)
            runtime_root = ensure_safe_runtime_directory(parent / "runtime")
            escaped_report = (
                ROOT / "reports/testing/generated/manifest/../../outside-report"
            )
            with self.assertRaisesRegex(ValueError, "below the runtime root"):
                NATIVE_CASE_RUNNER.report_output_dir(
                    ROOT,
                    runtime_root,
                    str(escaped_report),
                )
            self.assertFalse((source_path('reports/testing/outside-report', root=ROOT)).exists())

    def test_native_report_output_accepts_only_safe_generated_components(self) -> None:
        with tempfile.TemporaryDirectory(prefix="native-report-output-components-") as temporary:
            parent = Path(temporary)
            connector_root = parent / "connector"
            connector_root.mkdir()
            runtime_root = ensure_safe_runtime_directory(parent / "runtime")
            output = NATIVE_CASE_RUNNER.report_output_dir(
                connector_root,
                runtime_root,
                "reports/testing/generated/manifest/unit-run",
            )
            self.assertEqual(
                output,
                connector_root / "reports/testing/generated/manifest/unit-run",
            )
            self.assertTrue(output.is_dir())
            with self.assertRaisesRegex(ValueError, "relative report output directory"):
                NATIVE_CASE_RUNNER.report_output_dir(
                    connector_root,
                    runtime_root,
                    "reports/testing/generated/manifest/../outside",
                )

    def test_full_matrix_resume_passes_only_decimal_timeout_to_child(self) -> None:
        arguments = argparse.Namespace(job_timeout_seconds=90, force=False)
        job = {"connector": "apache", "crs": "no-crs", "mrts": "no-mrts"}
        with tempfile.TemporaryDirectory(prefix="full-matrix-resume-command-") as temporary:
            with mock.patch.object(
                FULL_MATRIX_RESUME.subprocess,
                "run",
                return_value=mock.Mock(returncode=0),
            ) as run:
                self.assertEqual(
                    FULL_MATRIX_RESUME.run_missing_job(
                        job,
                        arguments,
                        ROOT,
                        source_path('modules/ModSecurity-test-Framework', root=ROOT),
                        Path(temporary),
                        30.5,
                    ),
                    0,
                )
            command = run.call_args.args[0]
            timeout_index = command.index("--timeout-seconds")
            self.assertEqual(command[timeout_index + 1], "30")
            self.assertFalse(run.call_args.kwargs["shell"])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
