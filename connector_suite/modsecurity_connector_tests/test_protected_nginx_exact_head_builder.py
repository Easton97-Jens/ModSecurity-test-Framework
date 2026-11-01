"""Regression tests for the unprivileged exact-head candidate artifact packer."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


ROOT = connector_root()
MODULE_PATH = source_path('ci/runtime/broker/protected_nginx_exact_head_builder.py', root=ROOT)
SHA = "a" * 40
BASE = "b" * 40


def load_module() -> object:
    return load_source(MODULE_PATH)

B = load_module()

C = load_source(source_path('ci/provisioning/components/prepare-runtime-components.py', root=ROOT))


class CandidateBuilderTests(unittest.TestCase):
    def test_build_pin_passes_authoritative_parent_provenance(self) -> None:
        environment = B.build_environment(argparse.Namespace(
            task_root=str(self.task_root), candidate_root=str(self.root / "candidate")
        ))
        provenance = C.nginx_pinned_provenance(environment)
        self.assertEqual(provenance["sha256"], B.EXPECTED_NGINX_SOURCE_SHA256)
        self.assertEqual(C.NGINX_PINNED_VERSION_READBACK, "nginx/" + B.EXPECTED_NGINX_VERSION)

    def test_cache_is_inside_admitted_build_root(self) -> None:
        environment = B.build_environment(argparse.Namespace(
            task_root=str(self.task_root), candidate_root=str(self.root / "candidate")
        ))
        self.assertEqual(Path(environment["CONNECTOR_COMPONENT_CACHE"]), self.build_root / "component-cache")

    def test_launcher_pins_match_authoritative_parent(self) -> None:
        tree = ast.parse((source_path('ci/runtime/broker/nginx_exact_head_root_launcher.py', root=ROOT)).read_text())
        constants = {
            node.targets[0].id: ast.literal_eval(node.value)
            for node in tree.body if isinstance(node, ast.Assign)
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id in {"EXPECTED_NGINX_VERSION", "EXPECTED_NGINX_SOURCE_DIGEST"}
        }
        self.assertEqual(constants["EXPECTED_NGINX_VERSION"],
                         C.NGINX_PINNED_VERSION_READBACK.removeprefix("nginx/"))
        self.assertEqual(constants["EXPECTED_NGINX_SOURCE_DIGEST"], C.NGINX_PINNED_RELEASE_ASSET_SHA256)

    def test_packages_snapshot_emitted_by_parent_for_managed_cache(self) -> None:
        cache = self.build_root / "component-cache"
        layout = C.connector_output_layout("nginx", cache / "builds/connectors/nginx" / SHA)
        binary = Path(layout["output_paths"]["binary"])
        module = Path(layout["output_paths"]["module"])
        library_dir = cache / "prefix/modsecurity" / BASE / "lib"
        archive_dir = cache / "archives/nginx"
        for path, content in (
            (binary, b"managed binary"), (module, b"managed module"),
            (archive_dir / C.NGINX_PINNED_RELEASE_ASSET_NAME, b"managed archive"),
        ):
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            path.write_bytes(content)
            path.chmod(0o755)
        source = self.build_root / "source/modsecurity"
        headers = source / "headers/modsecurity"
        headers.mkdir(parents=True)
        for name in ("modsecurity.h", "rules_set.h", "transaction.h"):
            (headers / name).write_text("header\n", encoding="utf-8")
        libs = source / "src/.libs"
        libs.mkdir(parents=True)
        (libs / "libmodsecurity.so.3.0.14").write_bytes(b"managed library")
        (libs / "libmodsecurity.so.3.0.14").chmod(0o755)
        (libs / "libmodsecurity.so.3").symlink_to("libmodsecurity.so.3.0.14")
        (libs / "libmodsecurity.so").symlink_to("libmodsecurity.so.3.0.14")
        C.copy_modsecurity_outputs(source, library_dir.parent)
        self.assertFalse((library_dir / "libmodsecurity.so.3").is_symlink())
        values = C.nginx_runtime_environment(ROOT, cache, {
            "status": "built", "nginx_bin": str(binary), "module_file": str(module),
            "module_dir": str(module.parent), "modsecurity_lib_dir": str(library_dir),
            "build_path": layout["build_root"], "nginx_prefix": layout["nginx_prefix"],
        })
        values["NGINX_DOWNLOAD_DIR"] = str(archive_dir)
        C.write_runtime_env_snapshot(values, snapshot_path=self.snapshot,
            output_root=self.task_root, target_connector="nginx", cache_root=cache)
        digest = hashlib.sha256(b"managed archive").hexdigest()
        with mock.patch.object(B, "EXPECTED_NGINX_SOURCE_SHA256", digest):
            manifest = json.loads(B.package(self.package_args()).read_text(encoding="utf-8"))
        self.assertEqual(manifest["artifacts"]["library"]["sha256"],
                         hashlib.sha256(b"managed library").hexdigest())

    def test_required_snapshot_fields_reject_empty_values(self) -> None:
        self.snapshot.write_text(self.snapshot.read_text().replace(
            "export NGINX_DOWNLOAD_DIR='" + str(self.archive.parent) + "'",
            "export NGINX_DOWNLOAD_DIR=''"), encoding="utf-8")
        arguments = self.package_args()
        with self.assertRaisesRegex(B.BuilderError, "lacks required"):
            B.package(arguments)

    def test_archive_directory_escape_is_rejected_before_hashing(self) -> None:
        self.snapshot.write_text(self.snapshot.read_text().replace(
            str(self.archive.parent), str(self.root)), encoding="utf-8")
        arguments = self.package_args()
        with mock.patch.object(B, "sha256_fd") as digest:
            with self.assertRaisesRegex(B.BuilderError, "escapes its approved root"):
                B.package(arguments)
        digest.assert_not_called()

    def test_duplicate_snapshot_fields_are_rejected(self) -> None:
        self.snapshot.write_text(self.snapshot.read_text() +
                                 "export NGINX_DOWNLOAD_DIR=''\n", encoding="utf-8")
        arguments = self.package_args()
        with self.assertRaisesRegex(B.BuilderError, "duplicate key"):
            B.package(arguments)

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.task_root = self.root / "task"
        self.task_root.mkdir(mode=0o700)
        self.build_root = self.task_root / "build"
        self.build_root.mkdir(mode=0o700)
        self.lib_dir = self.build_root / "lib"
        self.lib_dir.mkdir(mode=0o700)
        self.nginx_build = self.build_root / "nginx-build"
        (self.nginx_build / "verified-archives").mkdir(parents=True, mode=0o700)
        self.binary = self.build_root / "nginx-bin"
        self.module = self.build_root / "module.so"
        self.library = self.lib_dir / "libmodsecurity.so.3"
        self.archive = self.nginx_build / "verified-archives" / C.NGINX_PINNED_RELEASE_ASSET_NAME
        for path, content in (
            (self.binary, b"binary"),
            (self.module, b"module"),
            (self.library, b"library"),
            (self.archive, b"source archive"),
        ):
            path.write_bytes(content)
            path.chmod(0o600)
        self.binary.chmod(0o500)
        self.snapshot = self.task_root / "runtime.env"
        self.snapshot.write_text(
            "\n".join(
                (
                    "export RUNTIME_COMPONENT_ENV_SNAPSHOT_TARGET='nginx'",
                    "export MRTS_NATIVE_NGINX_BIN='" + str(self.binary) + "'",
                    "export MRTS_NATIVE_NGINX_MODULE_FILE='" + str(self.module) + "'",
                    "export MRTS_NATIVE_NGINX_MODSECURITY_LIB_DIR='" + str(self.lib_dir) + "'",
                    "export NGINX_BUILD_DIR='" + str(self.nginx_build) + "'",
                    "export NGINX_PREFIX='" + str(self.build_root / "prefix") + "'",
                    "export NGINX_DOWNLOAD_DIR='" + str(self.archive.parent) + "'",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        self.snapshot.chmod(0o600)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def package_args(self) -> argparse.Namespace:
        return argparse.Namespace(
            expected_pr_head=SHA,
            trusted_dispatcher_base_sha=BASE,
            run_id="run-1",
            task_root=str(self.task_root),
            build_root=str(self.build_root),
            runtime_snapshot=str(self.snapshot),
            output_root=str(self.task_root / "artifacts"),
        )

    def test_packages_only_fixed_files_with_independent_digests(self) -> None:
        archive_digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        with mock.patch.object(B, "EXPECTED_NGINX_SOURCE_SHA256", archive_digest):
            manifest_path = B.package(self.package_args())
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["tested_pr_head"], SHA)
        self.assertEqual(payload["trusted_dispatcher_base_sha"], BASE)
        self.assertEqual(payload["nginx_source_digest"], archive_digest)
        self.assertEqual(set(payload["artifacts"]), {"nginx", "module", "library"})
        self.assertEqual(
            {child.name for child in manifest_path.parent.iterdir()},
            {"nginx", "ngx_http_modsecurity_module.so", "libmodsecurity.so.3", "artifact-manifest.json"},
        )
        for record in payload["artifacts"].values():
            copied = manifest_path.parent / record["filename"]
            self.assertEqual(record["sha256"], hashlib.sha256(copied.read_bytes()).hexdigest())
            self.assertEqual(copied.stat().st_nlink, 1)
            self.assertEqual(
                stat.S_IMODE(copied.stat().st_mode),
                B.ARTIFACT_MODES[record["filename"]],
            )

    def test_package_rejects_non_executable_nginx_binary(self) -> None:
        self.binary.chmod(0o400)
        archive_digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        arguments = self.package_args()
        with mock.patch.object(B, "EXPECTED_NGINX_SOURCE_SHA256", archive_digest):
            with self.assertRaisesRegex(
                B.BuilderError, "NGINX binary must be owner-executable"
            ):
                B.package(arguments)

    def test_rejects_source_archive_digest_mismatch(self) -> None:
        arguments = self.package_args()
        with self.assertRaisesRegex(B.BuilderError, "source archive digest"):
            B.package(arguments)

    def test_rejects_previous_release_and_crossed_archive_pins(self) -> None:
        previous_digest = "e951607d534836624bd36b6b45a71dbfb055237deae3738da6bbf3270dada279"
        current_digest = "974ed5298a5e398e008704ed5db284e655fc270c596493dbccada452448fc9f1"
        self.archive.unlink()
        for index, (version, digest) in enumerate((
            ("1.31.5", previous_digest),
            ("1.31.6", previous_digest),
            ("1.31.5", current_digest),
        )):
            with self.subTest(version=version, digest=digest):
                archive = self.archive.parent / f"nginx-{version}.tar.gz"
                archive.write_bytes(b"source archive")
                archive.chmod(0o600)
                arguments = self.package_args()
                arguments.output_root = str(self.task_root / f"artifacts-{index}")
                try:
                    with mock.patch.object(B, "sha256_fd", return_value=digest):
                        with self.assertRaises(B.BuilderError):
                            B.package(arguments)
                    self.assertFalse((Path(arguments.output_root) / "artifact-manifest.json").exists())
                finally:
                    archive.unlink()

    def test_output_creation_does_not_follow_a_swapped_task_root(self) -> None:
        output_root = self.task_root / "artifacts"
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        moved_task_root = self.root / "moved-task"
        original_mkdir = os.mkdir
        swapped = False

        def swap_before_mkdir(path: str | Path, mode: int = 0o777, *,
                              dir_fd: int | None = None) -> None:
            nonlocal swapped
            if not swapped:
                swapped = True
                self.task_root.rename(moved_task_root)
                self.task_root.symlink_to(outside, target_is_directory=True)
            if dir_fd is None:
                original_mkdir(path, mode)
            else:
                original_mkdir(path, mode, dir_fd=dir_fd)

        with mock.patch.object(B.os, "mkdir", side_effect=swap_before_mkdir):
            try:
                B.create_private_directory(
                    output_root, self.task_root, "candidate artifact root"
                )
            except B.BuilderError:
                pass
        self.assertTrue(swapped)
        self.assertFalse((outside / "artifacts").exists())

    def test_package_output_and_manifest_stay_on_the_admitted_descriptor(self) -> None:
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        moved_task_root = self.root / "moved-task"
        original_open = os.open
        swapped = False

        def swap_before_output_open(path: str | Path, flags: int, mode: int = 0o777, *,
                                    dir_fd: int | None = None) -> int:
            nonlocal swapped
            if Path(path).name == B.ARTIFACTS["nginx"] and not swapped:
                swapped = True
                self.task_root.rename(moved_task_root)
                self.task_root.symlink_to(outside, target_is_directory=True)
            if dir_fd is None:
                return original_open(path, flags, mode)
            return original_open(path, flags, mode, dir_fd=dir_fd)

        archive_digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        arguments = self.package_args()
        with mock.patch.object(B.os, "open", side_effect=swap_before_output_open), mock.patch.object(
            B, "EXPECTED_NGINX_SOURCE_SHA256", archive_digest
        ):
            with self.assertRaisesRegex(B.BuilderError, "task root"):
                B.package(arguments)
        self.assertTrue(swapped)
        self.assertFalse((outside / "artifacts").exists())
        self.assertEqual(
            {child.name for child in (moved_task_root / "artifacts").iterdir()},
            {"nginx", "ngx_http_modsecurity_module.so", "libmodsecurity.so.3", "artifact-manifest.json"},
        )

    def test_package_rejects_output_directory_replacement_after_creation(self) -> None:
        replacement_parent = self.root / "outside"
        replacement_parent.mkdir(mode=0o700)
        replacement = replacement_parent / "replacement"
        replacement.mkdir(mode=0o700)
        moved_output = self.root / "moved-artifacts"
        original_create = B._create_private_relative_directory
        swapped = False

        def create_then_replace(task_descriptor: int, components: tuple[str, ...],
                                label: str) -> int:
            nonlocal swapped
            descriptor = original_create(task_descriptor, components, label)
            (self.task_root / "artifacts").rename(moved_output)
            replacement.rename(self.task_root / "artifacts")
            swapped = True
            return descriptor

        archive_digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        arguments = self.package_args()
        with mock.patch.object(
            B, "_create_private_relative_directory", side_effect=create_then_replace
        ), mock.patch.object(B, "EXPECTED_NGINX_SOURCE_SHA256", archive_digest):
            with self.assertRaisesRegex(B.BuilderError, "candidate artifact root"):
                B.package(arguments)
        self.assertTrue(swapped)
        self.assertEqual(list((self.task_root / "artifacts").iterdir()), [])
        self.assertEqual(
            {child.name for child in moved_output.iterdir()},
            {"nginx", "ngx_http_modsecurity_module.so", "libmodsecurity.so.3", "artifact-manifest.json"},
        )

    def test_packaging_reads_sources_from_the_admitted_build_descriptor(self) -> None:
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        (outside / "lib").mkdir(mode=0o700)
        (outside / "nginx-bin").write_bytes(b"outside binary")
        (outside / "module.so").write_bytes(b"outside module")
        (outside / "lib" / "libmodsecurity.so.3").write_bytes(b"outside library")
        moved_build_root = self.task_root / "moved-build"
        original_open = os.open
        swapped = False

        def swap_before_source_open(path: str | Path, flags: int, mode: int = 0o777, *,
                                    dir_fd: int | None = None) -> int:
            nonlocal swapped
            if Path(path).name == "nginx-bin" and not swapped:
                swapped = True
                self.build_root.rename(moved_build_root)
                self.build_root.symlink_to(outside, target_is_directory=True)
            if dir_fd is None:
                return original_open(path, flags, mode)
            return original_open(path, flags, mode, dir_fd=dir_fd)

        archive_digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        with mock.patch.object(B.os, "open", side_effect=swap_before_source_open), mock.patch.object(
            B, "EXPECTED_NGINX_SOURCE_SHA256", archive_digest
        ):
            manifest_path = B.package(self.package_args())
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertTrue(swapped)
        self.assertEqual(
            payload["artifacts"]["nginx"]["sha256"],
            hashlib.sha256(b"binary").hexdigest(),
        )
        self.assertNotEqual(
            payload["artifacts"]["nginx"]["sha256"],
            hashlib.sha256(b"outside binary").hexdigest(),
        )

    def test_rejects_hardlink_and_symlink_candidate_artifacts(self) -> None:
        linked = self.build_root / "hard-linked-module.so"
        os.link(self.module, linked)
        text = self.snapshot.read_text(encoding="utf-8").replace(str(self.module), str(linked))
        self.snapshot.write_text(text, encoding="utf-8")
        archive_digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        package_arguments = self.package_args()
        with mock.patch.object(B, "EXPECTED_NGINX_SOURCE_SHA256", archive_digest):
            with self.assertRaisesRegex(B.BuilderError, "single-link"):
                B.package(package_arguments)
        linked.unlink()
        self.snapshot.write_text(
            self.snapshot.read_text(encoding="utf-8").replace(str(linked), str(self.module)),
            encoding="utf-8",
        )
        self.snapshot.chmod(0o600)
        escaped = self.root / "escaped.so"
        escaped.write_bytes(b"escaped")
        self.module.unlink()
        self.module.symlink_to(escaped)
        arguments = self.package_args()
        arguments.output_root = str(self.task_root / "artifacts-second")
        with mock.patch.object(B, "EXPECTED_NGINX_SOURCE_SHA256", archive_digest):
            with self.assertRaisesRegex(B.BuilderError, "symbolic link"):
                B.package(arguments)

    def test_rejects_snapshot_path_escape_and_non_declarative_content(self) -> None:
        archive_digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.snapshot.write_text("export MRTS_NATIVE_NGINX_BIN='$(id)'\n", encoding="utf-8")
        self.snapshot.chmod(0o600)
        package_arguments = self.package_args()
        with mock.patch.object(B, "EXPECTED_NGINX_SOURCE_SHA256", archive_digest):
            with self.assertRaises(B.BuilderError):
                B.package(package_arguments)
        self.snapshot.write_text(
            self.snapshot.read_text(encoding="utf-8") + "echo unsafe\n", encoding="utf-8"
        )
        package_arguments = self.package_args()
        with mock.patch.object(B, "EXPECTED_NGINX_SOURCE_SHA256", archive_digest):
            with self.assertRaises(B.BuilderError):
                B.package(package_arguments)

    def test_clean_build_environment_has_no_inherited_token_or_loader_input(self) -> None:
        arguments = argparse.Namespace(task_root=str(self.task_root), candidate_root=str(self.root / "candidate"))
        environment = B.build_environment(arguments)
        self.assertEqual(environment["PATH"], "/usr/bin:/bin")
        self.assertNotIn("GITHUB_TOKEN", environment)
        self.assertNotIn("LD_PRELOAD", environment)
        self.assertNotIn("PYTHONPATH", environment)
        self.assertEqual(environment["NGINX_RELEASE_TAG"], C.NGINX_PINNED_RELEASE_TAG)

    def test_digest_patterns_are_ascii_and_cleanup_uses_no_base_exception(self) -> None:
        self.assertEqual(B.require_sha40(SHA, "SHA"), SHA)
        self.assertEqual(B.require_sha256("b" * 64, "digest"), "b" * 64)
        with self.assertRaises(B.BuilderError):
            B.require_sha40("١" * 40, "SHA")
        with self.assertRaises(B.BuilderError):
            B.require_sha256("١" * 64, "digest")
        self.assertNotIn("BaseException", MODULE_PATH.read_text(encoding="utf-8"))

    def test_build_invokes_only_fixed_unprivileged_make_vector(self) -> None:
        candidate = self.root / "candidate;literal"
        candidate.mkdir(mode=0o700)
        (candidate / "modules" / "ModSecurity-test-Framework").mkdir(parents=True, mode=0o700)
        arguments = argparse.Namespace(
            expected_pr_head=SHA,
            trusted_dispatcher_base_sha=BASE,
            run_id="run-1",
            task_root=str(self.task_root),
            candidate_root=str(candidate),
            output_root=str(self.task_root / "artifacts"),
        )
        reports = self.task_root / "runtime-component-reports"
        reports.mkdir(mode=0o700)
        snapshot = reports / "runtime-env-snapshot.one.sh"
        snapshot.write_text("export RUNTIME_COMPONENT_ENV_SNAPSHOT_TARGET='nginx'\n", encoding="utf-8")
        snapshot.chmod(0o600)
        with mock.patch.object(
            B, "require_unprivileged_identity", return_value=(os.geteuid(), os.getegid())
        ) as identity, mock.patch.object(B.subprocess, "run") as run, mock.patch.object(
            B, "package", return_value=Path("/safe/artifact-manifest.json")
        ) as package:
            output = B.run_candidate_build(arguments)
        self.assertEqual(output, Path("/safe/artifact-manifest.json"))
        identity.assert_called_once_with()
        command = run.call_args.args[0]
        self.assertEqual(command, ["/usr/bin/make", "fetch-deps"])
        self.assertNotIn("sudo", command)
        self.assertNotIn(str(candidate), command)
        cwd = run.call_args.kwargs["cwd"]
        self.assertRegex(cwd, r"^/proc/self/fd/[0-9]+$")
        candidate_fd = int(cwd.rsplit("/", 1)[-1])
        self.assertEqual(run.call_args.kwargs["pass_fds"], (candidate_fd,))
        self.assertNotEqual(candidate_fd, -1)
        self.assertFalse(run.call_args.kwargs["shell"])
        environment = run.call_args.kwargs["env"]
        self.assertEqual(environment["PATH"], "/usr/bin:/bin")
        self.assertNotIn("GITHUB_TOKEN", environment)
        package.assert_called_once()
        self.assertIsInstance(package.call_args.kwargs["task_descriptor"], int)

    def test_build_cwd_remains_admitted_when_candidate_path_is_replaced(self) -> None:
        candidate = self.root / "candidate"
        candidate.mkdir(mode=0o700)
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        (candidate / "marker").write_text("admitted", encoding="utf-8")
        arguments = argparse.Namespace(
            expected_pr_head=SHA,
            trusted_dispatcher_base_sha=BASE,
            run_id="run-1",
            task_root=str(self.task_root),
            candidate_root=str(candidate),
            output_root=str(self.task_root / "artifacts"),
        )
        reports = self.task_root / "runtime-component-reports"
        reports.mkdir(mode=0o700)
        (reports / "runtime-env-snapshot.one.sh").write_text(
            "export RUNTIME_COMPONENT_ENV_SNAPSHOT_TARGET='nginx'\n",
            encoding="utf-8",
        )
        observed: dict[str, str] = {}

        def replace_candidate_path(*_args: object, **kwargs: object) -> None:
            cwd = str(kwargs["cwd"])
            observed["cwd"] = cwd
            moved = self.root / "moved-candidate"
            candidate.rename(moved)
            candidate.symlink_to(outside, target_is_directory=True)
            observed["marker"] = Path(cwd, "marker").read_text(encoding="utf-8")

        with mock.patch.object(
            B, "require_unprivileged_identity", return_value=(os.geteuid(), os.getegid())
        ), mock.patch.object(B.subprocess, "run", side_effect=replace_candidate_path), mock.patch.object(
            B, "package", return_value=Path("/safe/artifact-manifest.json")
        ):
            B.run_candidate_build(arguments)
        self.assertRegex(observed["cwd"], r"^/proc/self/fd/[0-9]+$")
        self.assertEqual(observed["marker"], "admitted")

    def test_candidate_build_rejects_root_identity_before_make(self) -> None:
        arguments = argparse.Namespace(
            expected_pr_head=SHA,
            trusted_dispatcher_base_sha=BASE,
            run_id="run-1",
            task_root=str(self.task_root),
            candidate_root=str(self.root / "candidate"),
            output_root=str(self.task_root / "artifacts"),
        )
        with mock.patch.object(B.os, "getresuid", return_value=(0, 0, 0)), mock.patch.object(
            B.os, "getresgid", return_value=(0, 0, 0)
        ), mock.patch.object(B.subprocess, "run") as run, self.assertRaisesRegex(
            B.BuilderError, "must not run with a root UID or GID"
        ):
            B.run_candidate_build(arguments)
        run.assert_not_called()

    def test_unprivileged_identity_accepts_non_root_real_effective_and_saved_ids(self) -> None:
        with mock.patch.object(B.os, "getresuid", return_value=(1001, 1002, 1003)), mock.patch.object(
            B.os, "getresgid", return_value=(1004, 1005, 1006)
        ):
            self.assertEqual(B.require_unprivileged_identity(), (1002, 1005))

    def test_unprivileged_identity_rejects_saved_root_uid_or_gid(self) -> None:
        for user_ids, group_ids in (
            ((1001, 1002, 0), (1003, 1004, 1005)),
            ((1001, 1002, 1003), (1004, 1005, 0)),
        ):
            with self.subTest(user_ids=user_ids, group_ids=group_ids), mock.patch.object(
                B.os, "getresuid", return_value=user_ids
            ), mock.patch.object(B.os, "getresgid", return_value=group_ids), self.assertRaisesRegex(
                B.BuilderError, "must not run with a root UID or GID"
            ):
                B.require_unprivileged_identity()



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
