from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import hashlib
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = connector_root()
HELPER_PATH = source_path('ci/tools/prepare-readonly-submodule-validation-sandbox.py', root=ROOT)
HELPER = load_source(HELPER_PATH)

NAMESPACE_HELPER_PATH = source_path('ci/tools/run-readonly-submodule-validation-namespace.py', root=ROOT)
NAMESPACE_HELPER = load_source(NAMESPACE_HELPER_PATH)


class PrepareReadonlySubmoduleValidationSandboxTests(unittest.TestCase):
    @staticmethod
    def identity_is_mapped_in_current_namespace(identity: HELPER.ValidatorIdentity) -> bool:
        def mapped(identifier: int, map_name: str) -> bool:
            try:
                rows = Path(f"/proc/self/{map_name}").read_text(encoding="utf-8").splitlines()
            except OSError:
                return False
            for row in rows:
                inside, _outside, count = (int(value) for value in row.split())
                if inside <= identifier < inside + count:
                    return True
            return False

        return mapped(identity.uid, "uid_map") and mapped(identity.gid, "gid_map")

    def make_layout(self, temporary: Path) -> tuple[Path, Path, Path, Path]:
        source = temporary / "source"
        framework = source / "modules" / "framework"
        runner_temp = temporary / "runner-temp"
        write = runner_temp / f"{HELPER.WRITE_ROOT_PREFIX}fixture"
        framework.mkdir(parents=True)
        framework_git = framework / ".git"
        framework_git.write_text("gitdir: ../../.git/modules/framework\n", encoding="utf-8")
        (source / ".git" / "modules" / "framework").mkdir(parents=True)
        runner_temp.mkdir()
        write.mkdir(mode=0o711)
        if os.geteuid() == 0:
            os.chown(write, 0, 0)
        os.chmod(write, 0o711)
        return source, framework, runner_temp, write

    @staticmethod
    def sandbox_args(
        source: Path,
        framework: Path,
        runner_temp: Path,
        write: Path,
        *,
        validator_user: str = "unused",
        validator_group: str = "unused",
    ) -> object:
        return HELPER.parse_args(
            [
                "--source-root", str(source), "--framework-root", str(framework),
                "--write-root", str(write), "--runner-temp", str(runner_temp),
                "--validator-user", validator_user, "--validator-group", validator_group,
            ]
        )

    @staticmethod
    def cleanup_args(source: Path, framework: Path, runner_temp: Path, write: Path) -> object:
        return HELPER.parse_args(
            [
                "--cleanup",
                "--source-root", str(source),
                "--framework-root", str(framework),
                "--write-root", str(write),
                "--runner-temp", str(runner_temp),
            ]
        )

    @staticmethod
    def source_snapshot(root: Path) -> tuple[tuple[object, ...], ...]:
        """Independently record every user-visible source/Git property in scope."""
        records: list[tuple[object, ...]] = []

        def record(path: Path, relative: str) -> None:
            metadata = os.lstat(path)
            common: tuple[object, ...] = (
                relative,
                metadata.st_size,
                metadata.st_uid,
                metadata.st_gid,
                stat.S_IMODE(metadata.st_mode),
                metadata.st_nlink,
            )
            if stat.S_ISDIR(metadata.st_mode):
                records.append(("directory", *common))
                with os.scandir(path) as entries:
                    children = sorted(entries, key=lambda entry: entry.name)
                for entry in children:
                    child_relative = entry.name if relative == "." else f"{relative}/{entry.name}"
                    record(Path(entry.path), child_relative)
            elif stat.S_ISREG(metadata.st_mode):
                records.append(("regular", *common, hashlib.sha256(path.read_bytes()).hexdigest()))
            elif stat.S_ISLNK(metadata.st_mode):
                records.append(("symlink", *common, os.readlink(path)))
            else:
                records.append(("other", *common))

        record(root, ".")
        return tuple(records)

    @staticmethod
    def current_identity() -> HELPER.ValidatorIdentity:
        return HELPER.ValidatorIdentity("validator", "validator", os.getuid(), os.getgid())

    def sandbox_with_source_file(
        self,
        temporary: Path,
        *,
        filename: str = "input.txt",
        contents: str = "source",
        mode: int | None = None,
    ) -> tuple[Path, Path, Path, Path, Path, object, HELPER.ValidatorIdentity]:
        """Create a sandbox fixture with one explicit source file."""
        source, framework, runner_temp, write = self.make_layout(temporary)
        source_file = source / filename
        source_file.write_text(contents, encoding="utf-8")
        if mode is not None:
            source_file.chmod(mode)
        arguments = self.sandbox_args(source, framework, runner_temp, write)
        return source, framework, runner_temp, write, source_file, arguments, self.current_identity()

    def test_valid_control_preserves_complete_source_metadata_and_creates_only_external_root(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("locking control requires root")
        with tempfile.TemporaryDirectory(prefix="readonly-sandbox-") as raw:
            source, framework, runner_temp, write = self.make_layout(Path(raw))
            source_file = source / "input.txt"
            source_file.write_text("trusted", encoding="utf-8")
            source_file.chmod(0o664)
            git_module_file = source / ".git" / "modules" / "framework" / "config"
            git_module_file.parent.mkdir(parents=True, exist_ok=True)
            git_module_file.write_text("[core]", encoding="utf-8")
            git_module_file.chmod(0o660)
            framework_file = framework / "framework-source.c"
            framework_file.write_text("int framework_fixture;\n", encoding="utf-8")
            framework_file.chmod(0o751)
            restrictive_file = source / "restrictive.txt"
            restrictive_file.write_text("private", encoding="utf-8")
            restrictive_file.chmod(0o600)
            source_link = source / "internal-link"
            source_link.symlink_to("input.txt")
            before = self.source_snapshot(source)
            arguments = self.sandbox_args(source, framework, runner_temp, write)
            identity = self.current_identity()
            with mock.patch.object(HELPER, "resolve_validator_identity", return_value=identity):
                external, inventory_sha256 = HELPER.prepare_sandbox(arguments)
            self.assertEqual(external, write / "external")
            self.assertEqual(len(inventory_sha256), 64)
            self.assertEqual(stat.S_IMODE(write.stat().st_mode), 0o711)
            self.assertEqual(stat.S_IMODE(external.stat().st_mode), 0o700)
            self.assertEqual(external.stat().st_uid, identity.uid)
            inventory = write / HELPER.INVENTORY_FILENAME
            self.assertEqual(stat.S_IMODE(inventory.stat().st_mode), 0o600)
            self.assertEqual(self.source_snapshot(source), before)
            self.assertEqual(stat.S_IMODE(source_file.stat().st_mode), 0o664)
            self.assertEqual(stat.S_IMODE(framework_file.stat().st_mode), 0o751)
            self.assertEqual(stat.S_IMODE(restrictive_file.stat().st_mode), 0o600)
            self.assertEqual(os.readlink(source_link), "input.txt")
            with mock.patch.object(HELPER, "resolve_validator_identity", return_value=identity):
                verified_external, verified_sha256 = HELPER.verify_sandbox(arguments)
                repeated_external, repeated_sha256 = HELPER.verify_sandbox(arguments)
            self.assertEqual(verified_external, external)
            self.assertEqual(verified_sha256, inventory_sha256)
            self.assertEqual((repeated_external, repeated_sha256), (external, inventory_sha256))
            self.assertEqual(self.source_snapshot(source), before)
            self.assertEqual(HELPER.cleanup_sandbox(self.cleanup_args(source, framework, runner_temp, write)), write)
            self.assertFalse(write.exists())
            self.assertEqual(self.source_snapshot(source), before)

    def test_real_validator_can_write_only_external_root(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("privilege-drop control requires root")
        try:
            account = pwd.getpwnam("nobody")
            group = HELPER.grp.getgrgid(account.pw_gid)
        except KeyError:
            self.skipTest("the system has no nobody identity")
        identity = HELPER.resolve_validator_identity(account.pw_name, group.gr_name)
        if not self.identity_is_mapped_in_current_namespace(identity):
            self.skipTest("the nobody identity is unavailable in this user namespace")
        with tempfile.TemporaryDirectory(
            dir="/tmp", prefix="readonly-sandbox-"
        ) as raw:
            temporary = Path(raw)
            # The child needs traversal through the disposable fixture parent,
            # but no permission to list or change the guarded write root.
            os.chmod(temporary, 0o711)
            source, framework, runner_temp, write = self.make_layout(temporary)
            os.chmod(runner_temp, 0o755)
            (source / "input.txt").write_text("trusted", encoding="utf-8")
            before = self.source_snapshot(source)
            arguments = self.sandbox_args(
                source, framework, runner_temp, write,
                validator_user=identity.user, validator_group=identity.group,
            )
            external, _inventory_sha256 = HELPER.prepare_sandbox(arguments)

            def child_exit(script: str, target: Path) -> int:
                def drop_privileges() -> None:
                    os.setgroups([])
                    os.setgid(identity.gid)
                    os.setuid(identity.uid)

                return subprocess.run(
                    ["/bin/sh", "-ceu", script, "readonly-sandbox-probe", str(target)],
                    check=False,
                    preexec_fn=drop_privileges,
                ).returncode

            cannot_write = 'if touch -- "$1" 2>/dev/null; then exit 1; fi'
            cannot_list = 'if ls -A -- "$1" >/dev/null 2>&1; then exit 1; fi'
            cannot_remove = 'if rm -- "$1" 2>/dev/null; then exit 1; fi'
            cannot_chmod = 'if chmod 600 -- "$1" 2>/dev/null; then exit 1; fi'
            can_write = 'printf allowed > "$1"'

            self.assertEqual(child_exit(cannot_write, source / "candidate-write"), 0)
            self.assertEqual(child_exit(cannot_remove, source / "input.txt"), 0)
            self.assertEqual(child_exit(cannot_chmod, source / "input.txt"), 0)
            self.assertEqual(child_exit(cannot_write, source / ".git" / "index.lock"), 0)
            self.assertEqual(child_exit(cannot_write, write / "candidate-write"), 0)
            self.assertEqual(child_exit(cannot_list, write), 0)
            external_file = external / "candidate-write"
            self.assertEqual(child_exit(can_write, external_file), 0)
            self.assertEqual(external_file.read_text(encoding="utf-8"), "allowed")
            self.assertEqual(HELPER.verify_sandbox(arguments)[0], external)
            self.assertEqual(self.source_snapshot(source), before)
            HELPER.cleanup_sandbox(self.cleanup_args(source, framework, runner_temp, write))
            self.assertFalse(write.exists())
            self.assertEqual(self.source_snapshot(source), before)

    def test_prepare_candidate_verify_and_cleanup_preserve_source_metadata(self) -> None:
        """Exercise the real mount boundary when root namespaces and nobody are available."""
        if os.geteuid() != 0 or sys.platform != "linux":
            self.skipTest("mount/PID namespace capability is unavailable")
        try:
            account = pwd.getpwnam("nobody")
            group = HELPER.grp.getgrgid(account.pw_gid)
            identity = HELPER.resolve_validator_identity(account.pw_name, group.gr_name)
        except KeyError:
            self.skipTest("the system has no unprivileged nobody identity")
        if not self.identity_is_mapped_in_current_namespace(identity):
            self.skipTest("the nobody identity is unavailable in this user namespace")
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="readonly-sandbox-") as raw:
            temporary = Path(raw)
            os.chmod(temporary, 0o755)
            source, framework, runner_temp, write = self.make_layout(temporary)
            os.chmod(runner_temp, 0o755)
            source_file = source / "group-writable.txt"
            source_file.write_text("trusted", encoding="utf-8")
            source_file.chmod(0o664)
            framework_file = framework / "framework-input.txt"
            framework_file.write_text("framework", encoding="utf-8")
            framework_file.chmod(0o660)
            before = self.source_snapshot(source)
            arguments = self.sandbox_args(
                source,
                framework,
                runner_temp,
                write,
                validator_user=identity.user,
                validator_group=identity.group,
            )
            external, _inventory_sha256 = HELPER.prepare_sandbox(arguments)
            self.assertEqual(self.source_snapshot(source), before)
            namespace_parent = temporary / "namespace-parent"
            namespace_parent.mkdir(mode=0o750)
            os.chown(namespace_parent, 0, identity.gid)
            os.chmod(namespace_parent, 0o750)
            mount_root = NAMESPACE_HELPER._create_mount_layout(namespace_parent, identity.gid)

            def candidate(
                source_view: Path,
                framework_relative: Path,
                external_view: Path,
                _guard: Path,
                _python: Path,
                uid: int,
                gid: int,
            ) -> None:
                os.setgroups([])
                os.setgid(gid)
                os.setuid(uid)
                framework_view = source_view / framework_relative
                for operation in (
                    lambda: (source_view / "candidate-write").touch(),
                    lambda: (framework_view / "candidate-write").touch(),
                    lambda: (source_view / ".git" / "index.lock").touch(),
                    lambda: os.chmod(source_view / "group-writable.txt", 0o600),
                    lambda: os.chmod(framework_view / "framework-input.txt", 0o600),
                ):
                    try:
                        operation()
                    except OSError:
                        continue
                    os._exit(1)
                (external_view / "candidate-output").write_text("allowed", encoding="utf-8")
                os._exit(0)

            try:
                child = os.fork()
                if child == 0:
                    try:
                        os._exit(
                            NAMESPACE_HELPER._namespace_child(
                                source,
                                framework,
                                external,
                                mount_root,
                                Path(sys.executable).resolve(strict=True),
                                identity.uid,
                                identity.gid,
                                candidate,
                            )
                        )
                    except NAMESPACE_HELPER.NamespaceUnavailable:
                        os._exit(125)
                    except BaseException as error:
                        os.write(2, ("namespace test child failed: " + type(error).__name__ + ": " + ascii(str(error))[:500] + "\n").encode("ascii"))
                        os._exit(1)
                _pid, status = os.waitpid(child, 0)
                result = os.waitstatus_to_exitcode(status)
                if result == 125:
                    self.skipTest("mount/PID namespace capability is unavailable")
                self.assertEqual(result, 0)
                self.assertEqual((external / "candidate-output").read_text(encoding="utf-8"), "allowed")
                self.assertEqual(self.source_snapshot(source), before)
                self.assertEqual(HELPER.verify_sandbox(arguments)[0], external)
                self.assertEqual(self.source_snapshot(source), before)
                HELPER.cleanup_sandbox(self.cleanup_args(source, framework, runner_temp, write))
                self.assertFalse(write.exists())
                self.assertEqual(self.source_snapshot(source), before)
            finally:
                for path in (mount_root / "source", mount_root / "external", mount_root):
                    if path.exists():
                        os.rmdir(path)

    def test_namespace_setup_and_candidate_failures_preserve_source_metadata(self) -> None:
        """A namespace-stage failure must leave the prepared host tree untouched."""
        if os.geteuid() != 0 or sys.platform != "linux":
            self.skipTest("namespace failure controls require Linux root")
        with tempfile.TemporaryDirectory(prefix="readonly-sandbox-") as raw:
            temporary = Path(raw)
            source, framework, runner_temp, write = self.make_layout(temporary)
            source_file = source / "group-writable.txt"
            source_file.write_text("trusted", encoding="utf-8")
            source_file.chmod(0o664)
            before = self.source_snapshot(source)
            identity = self.current_identity()
            sandbox_arguments = self.sandbox_args(source, framework, runner_temp, write)
            with mock.patch.object(HELPER, "resolve_validator_identity", return_value=identity):
                external, _inventory_sha256 = HELPER.prepare_sandbox(sandbox_arguments)
            self.assertEqual(self.source_snapshot(source), before)

            # Mock the namespace-parent topology check here: it has dedicated
            # coverage in the namespace test module.  This keeps the failure
            # proof independent of a writable host /tmp while exercising the
            # real runner's setup, fork, and private-layout cleanup paths.
            namespace_parent = temporary / "namespace-parent"
            namespace_parent.mkdir(mode=0o750)
            os.chown(namespace_parent, 0, identity.gid)
            os.chmod(namespace_parent, 0o750)
            namespace_arguments = NAMESPACE_HELPER.parse_args(
                [
                    "--source-root",
                    str(source),
                    "--framework-root",
                    str(framework),
                    "--write-root",
                    str(write),
                    "--external-root",
                    str(external),
                    "--validator-user",
                    identity.user,
                    "--validator-group",
                    identity.group,
                    "--python",
                    sys.executable,
                    "--namespace-parent",
                    str(namespace_parent),
                ]
            )
            for label, child_behavior, expected_status in (
                ("setup", RuntimeError("injected namespace setup failure"), 126),
                ("candidate", lambda *_arguments: 47, 47),
            ):
                with self.subTest(stage=label), mock.patch.object(
                    NAMESPACE_HELPER, "_identity", return_value=(identity.uid, identity.gid)
                ), mock.patch.object(
                    NAMESPACE_HELPER, "_validate_namespace_parent"
                ), mock.patch.object(
                    NAMESPACE_HELPER, "_namespace_child", side_effect=child_behavior
                ):
                    self.assertEqual(NAMESPACE_HELPER.run(namespace_arguments), expected_status)
                self.assertEqual(self.source_snapshot(source), before)
                self.assertFalse((namespace_parent / "mount-root").exists())

            with mock.patch.object(HELPER, "resolve_validator_identity", return_value=identity):
                self.assertEqual(HELPER.verify_sandbox(sandbox_arguments)[0], external)
            self.assertEqual(self.source_snapshot(source), before)
            HELPER.cleanup_sandbox(self.cleanup_args(source, framework, runner_temp, write))
            self.assertFalse(write.exists())
            self.assertEqual(self.source_snapshot(source), before)

    def test_inventory_write_failure_does_not_mutate_source_or_framework(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("root-owned write-root control requires root")
        with tempfile.TemporaryDirectory(prefix="readonly-sandbox-") as raw:
            source, framework, runner_temp, write, _source_file, arguments, identity = (
                self.sandbox_with_source_file(
                    Path(raw), filename="group-writable.txt", contents="trusted", mode=0o664
                )
            )
            before = self.source_snapshot(source)
            with (
                mock.patch.object(HELPER, "resolve_validator_identity", return_value=identity),
                mock.patch.object(HELPER, "_write_exact_regular_file", side_effect=OSError("injected")),
            ):
                with self.assertRaisesRegex(OSError, "injected"):
                    HELPER.prepare_sandbox(arguments)
            self.assertEqual(self.source_snapshot(source), before)
            self.assertFalse((write / HELPER.INVENTORY_FILENAME).exists())
            self.assertFalse((write / HELPER.EXTERNAL_DIRNAME).exists())
            HELPER.cleanup_sandbox(self.cleanup_args(source, framework, runner_temp, write))
            self.assertEqual(self.source_snapshot(source), before)

    def test_external_root_failure_does_not_mutate_source_or_framework(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("root-owned write-root control requires root")
        with tempfile.TemporaryDirectory(prefix="readonly-sandbox-") as raw:
            source, framework, runner_temp, write, _source_file, arguments, identity = (
                self.sandbox_with_source_file(
                    Path(raw), filename="group-writable.txt", contents="trusted", mode=0o664
                )
            )
            before = self.source_snapshot(source)
            with (
                mock.patch.object(HELPER, "resolve_validator_identity", return_value=identity),
                mock.patch.object(HELPER, "_make_external_root", side_effect=OSError("injected")),
            ):
                with self.assertRaisesRegex(OSError, "injected"):
                    HELPER.prepare_sandbox(arguments)
            self.assertEqual(self.source_snapshot(source), before)
            self.assertTrue((write / HELPER.INVENTORY_FILENAME).is_file())
            self.assertFalse((write / HELPER.EXTERNAL_DIRNAME).exists())
            HELPER.cleanup_sandbox(self.cleanup_args(source, framework, runner_temp, write))
            self.assertEqual(self.source_snapshot(source), before)

    def test_verify_output_failure_does_not_mutate_source_or_framework(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("root-owned write-root control requires root")
        with tempfile.TemporaryDirectory(prefix="readonly-sandbox-") as raw:
            source, framework, runner_temp, write, _source_file, arguments, identity = (
                self.sandbox_with_source_file(
                    Path(raw), filename="group-writable.txt", contents="trusted", mode=0o664
                )
            )
            before = self.source_snapshot(source)
            with mock.patch.object(HELPER, "resolve_validator_identity", return_value=identity):
                external, _inventory_sha256 = HELPER.prepare_sandbox(arguments)
                unsafe_output = external / "group-writable-output"
                unsafe_output.write_text("unsafe", encoding="utf-8")
                unsafe_output.chmod(0o660)
                with self.assertRaisesRegex(ValueError, "unsafe permissions"):
                    HELPER.verify_sandbox(arguments)
            self.assertEqual(self.source_snapshot(source), before)
            HELPER.cleanup_sandbox(self.cleanup_args(source, framework, runner_temp, write))
            self.assertEqual(self.source_snapshot(source), before)

    def test_rejects_nested_source_mount_before_inventory_or_output_creation(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("root-owned write-root control requires root")
        with tempfile.TemporaryDirectory(prefix="readonly-sandbox-") as raw:
            source, framework, runner_temp, write, _source_file, arguments, identity = (
                self.sandbox_with_source_file(
                    Path(raw), filename="group-writable.txt", contents="trusted", mode=0o664
                )
            )
            before = self.source_snapshot(source)
            with (
                mock.patch.object(HELPER, "resolve_validator_identity", return_value=identity),
                mock.patch.object(
                    HELPER, "_mountinfo_mountpoints", return_value=iter([source / "foreign-mount"])
                ),
            ):
                with self.assertRaisesRegex(ValueError, "source root contains an unexpected active mount"):
                    HELPER.prepare_sandbox(arguments)
            self.assertEqual(self.source_snapshot(source), before)
            self.assertFalse((write / HELPER.INVENTORY_FILENAME).exists())
            self.assertFalse((write / HELPER.EXTERNAL_DIRNAME).exists())
            HELPER.cleanup_sandbox(self.cleanup_args(source, framework, runner_temp, write))
            self.assertEqual(self.source_snapshot(source), before)

    def test_cleanup_is_descriptor_safe_and_rejects_active_mounts(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("root-owned cleanup control requires root")
        with tempfile.TemporaryDirectory(prefix="readonly-sandbox-") as raw:
            temporary = Path(raw)
            source, framework, runner_temp, write = self.make_layout(temporary)
            source_file = source / "input.txt"
            source_file.write_text("trusted", encoding="utf-8")
            before = self.source_snapshot(source)
            outside = temporary / "outside.txt"
            outside.write_text("outside", encoding="utf-8")
            (write / "link-to-outside").symlink_to(outside)
            arguments = self.cleanup_args(source, framework, runner_temp, write)
            with mock.patch.object(
                HELPER, "_mountinfo_mountpoints", return_value=iter([write / "foreign-mount"])
            ):
                with self.assertRaisesRegex(ValueError, "cleanup write root contains an unexpected active mount"):
                    HELPER.cleanup_sandbox(arguments)
            self.assertTrue(write.exists())
            self.assertEqual(outside.read_text(encoding="utf-8"), "outside")
            self.assertEqual(self.source_snapshot(source), before)
            HELPER.cleanup_sandbox(arguments)
            self.assertFalse(write.exists())
            self.assertEqual(outside.read_text(encoding="utf-8"), "outside")
            self.assertEqual(self.source_snapshot(source), before)

    def test_cleanup_rejects_nonprivate_write_root_without_deleting_it(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("root-owned cleanup control requires root")
        with tempfile.TemporaryDirectory(prefix="readonly-sandbox-") as raw:
            temporary = Path(raw)
            source, framework, runner_temp, _write = self.make_layout(temporary)
            before = self.source_snapshot(source)
            unrelated = runner_temp / "unrelated"
            unrelated.mkdir(mode=0o711)
            os.chown(unrelated, 0, 0)
            os.chmod(unrelated, 0o711)
            cleanup_arguments = self.cleanup_args(source, framework, runner_temp, unrelated)
            with self.assertRaisesRegex(ValueError, "private validation prefix"):
                HELPER.cleanup_sandbox(cleanup_arguments)
            self.assertTrue(unrelated.exists())
            self.assertEqual(self.source_snapshot(source), before)

    def test_rejects_external_source_symlink_without_touching_its_target(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("no-follow source-link control requires root")
        with tempfile.TemporaryDirectory(prefix="readonly-sandbox-") as raw:
            temporary = Path(raw)
            source, framework, runner_temp, write = self.make_layout(temporary)
            outside = temporary / "outside.txt"
            outside.write_text("outside", encoding="utf-8")
            original = outside.stat()
            (source / "outside-link").symlink_to(outside)
            arguments = self.sandbox_args(source, framework, runner_temp, write)
            identity = self.current_identity()
            with mock.patch.object(HELPER, "resolve_validator_identity", return_value=identity):
                with self.assertRaisesRegex(ValueError, "symbolic link must remain inside source"):
                    HELPER.prepare_sandbox(arguments)
            current = outside.stat()
            self.assertEqual(outside.read_text(encoding="utf-8"), "outside")
            self.assertEqual((current.st_uid, current.st_gid, stat.S_IMODE(current.st_mode)), (
                original.st_uid, original.st_gid, stat.S_IMODE(original.st_mode),
            ))
            self.assertFalse((write / HELPER.EXTERNAL_DIRNAME).exists())

    def test_detects_source_inventory_mutation_after_preparation(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("source-inventory mutation control requires root")
        with tempfile.TemporaryDirectory(prefix="readonly-sandbox-") as raw:
            source, framework, runner_temp, write = self.make_layout(Path(raw))
            source_file = source / "input.txt"
            source_file.write_text("before", encoding="utf-8")
            arguments = self.sandbox_args(source, framework, runner_temp, write)
            identity = self.current_identity()
            with mock.patch.object(HELPER, "resolve_validator_identity", return_value=identity):
                HELPER.prepare_sandbox(arguments)
                source_file.write_text("after", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "source inventory changed"):
                    HELPER.verify_sandbox(arguments)

    def test_records_an_allowed_internal_source_symlink_without_following_it(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("internal source-link inventory control requires root")
        with tempfile.TemporaryDirectory(prefix="readonly-sandbox-") as raw:
            source, framework, runner_temp, write = self.make_layout(Path(raw))
            source_file = source / "input.txt"
            source_file.write_text("inside", encoding="utf-8")
            source_link = source / "inside-link"
            source_link.symlink_to("input.txt")
            arguments = self.sandbox_args(source, framework, runner_temp, write)
            identity = self.current_identity()
            with mock.patch.object(HELPER, "resolve_validator_identity", return_value=identity):
                external, _inventory_sha256 = HELPER.prepare_sandbox(arguments)
                inventory, _inventory_digest = HELPER._read_inventory(
                    write / HELPER.INVENTORY_FILENAME
                )
                self.assertIn(
                    {"path": "inside-link", "type": "symlink", "target": "input.txt"},
                    [
                        {
                            key: entry[key]
                            for key in ("path", "type", "target")
                            if key in entry
                        }
                        for entry in inventory
                    ],
                )
                self.assertTrue(source_link.is_symlink())
                self.assertEqual(source_file.read_text(encoding="utf-8"), "inside")
                self.assertEqual(HELPER.verify_sandbox(arguments)[0], external)

    def test_accepts_contained_relative_external_symlink(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("external-output controls require root")
        with tempfile.TemporaryDirectory(prefix="readonly-sandbox-") as raw:
            _source, _framework, _runner_temp, _write, _source_file, arguments, identity = (
                self.sandbox_with_source_file(Path(raw))
            )
            with mock.patch.object(HELPER, "resolve_validator_identity", return_value=identity):
                external, _inventory_sha256 = HELPER.prepare_sandbox(arguments)
                shared = external / "shared"
                checks = external / "reg-tests" / "checks"
                shared.mkdir()
                checks.mkdir(parents=True)
                (shared / "common.pem").write_text("contained", encoding="utf-8")
                (checks / "common.pem").symlink_to("../../shared/common.pem")
                self.assertEqual(HELPER.verify_sandbox(arguments)[0], external)

    def test_rejects_absolute_external_symlink_target(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("external-output controls require root")
        with tempfile.TemporaryDirectory(prefix="readonly-sandbox-") as raw:
            _source, _framework, _runner_temp, _write, _source_file, arguments, identity = (
                self.sandbox_with_source_file(Path(raw))
            )
            with mock.patch.object(HELPER, "resolve_validator_identity", return_value=identity):
                external, _inventory_sha256 = HELPER.prepare_sandbox(arguments)
                (external / "absolute-in-root").symlink_to(external / "target")
                with self.assertRaisesRegex(ValueError, "unsafe target"):
                    HELPER.verify_sandbox(arguments)

    def test_rejects_external_symlink_to_source_or_guard_by_relative_escape(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("external-output controls require root")
        with tempfile.TemporaryDirectory(prefix="readonly-sandbox-") as raw:
            _source, _framework, _runner_temp, _write, _source_file, arguments, identity = (
                self.sandbox_with_source_file(Path(raw))
            )
            with mock.patch.object(HELPER, "resolve_validator_identity", return_value=identity):
                external, _inventory_sha256 = HELPER.prepare_sandbox(arguments)
                (external / "source-escape").symlink_to("../../../source/input.txt")
                with self.assertRaisesRegex(ValueError, "escapes external root"):
                    HELPER.verify_sandbox(arguments)
                (external / "source-escape").unlink()
                (external / "guard-escape").symlink_to("../source-inventory.json")
                with self.assertRaisesRegex(ValueError, "escapes external root"):
                    HELPER.verify_sandbox(arguments)

    def test_rejects_external_symlink_chain_with_an_escaping_hop(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("external-output controls require root")
        with tempfile.TemporaryDirectory(prefix="readonly-sandbox-") as raw:
            _source, _framework, _runner_temp, _write, _source_file, arguments, identity = (
                self.sandbox_with_source_file(Path(raw))
            )
            with mock.patch.object(HELPER, "resolve_validator_identity", return_value=identity):
                external, _inventory_sha256 = HELPER.prepare_sandbox(arguments)
                links = external / "links"
                links.mkdir()
                (links / "first").symlink_to("second")
                (links / "second").symlink_to("../../../../source/input.txt")
                with self.assertRaisesRegex(ValueError, "escapes external root"):
                    HELPER.verify_sandbox(arguments)

    def test_rejects_foreign_owned_external_symlink_before_target_validation(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("external-output controls require root")
        with tempfile.TemporaryDirectory(prefix="readonly-sandbox-") as raw:
            source, _framework, _runner_temp, _write, _source_file, arguments, identity = (
                self.sandbox_with_source_file(Path(raw))
            )
            with mock.patch.object(HELPER, "resolve_validator_identity", return_value=identity):
                external, _inventory_sha256 = HELPER.prepare_sandbox(arguments)
                link = external / "foreign-link"
                link.symlink_to("target")
                real_walk = HELPER._walk_tree

                def walk_with_foreign_link(root: Path):
                    for path, relative, metadata in real_walk(root):
                        if root == external and path == link:
                            metadata = SimpleNamespace(
                                st_mode=metadata.st_mode,
                                st_uid=identity.uid + 1,
                                st_gid=metadata.st_gid,
                                st_dev=metadata.st_dev,
                                st_ino=metadata.st_ino,
                            )
                        yield path, relative, metadata

                with mock.patch.object(HELPER, "_walk_tree", side_effect=walk_with_foreign_link):
                    with self.assertRaisesRegex(ValueError, "foreign owner"):
                        HELPER._validate_external_tree(external, source, identity)

    def test_rejects_unsafe_external_output_objects(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("external-output controls require root")
        with tempfile.TemporaryDirectory(prefix="readonly-sandbox-") as raw:
            source, _framework, _runner_temp, _write, source_file, arguments, identity = (
                self.sandbox_with_source_file(Path(raw))
            )
            with mock.patch.object(HELPER, "resolve_validator_identity", return_value=identity):
                external, _inventory_sha256 = HELPER.prepare_sandbox(arguments)
                (external / "outside-link").symlink_to(source_file)
                with self.assertRaisesRegex(ValueError, "unsafe target"):
                    HELPER.verify_sandbox(arguments)
                (external / "outside-link").unlink()
                os.link(source_file, external / "source-hardlink")
                with self.assertRaisesRegex(ValueError, "hardlinks a source"):
                    HELPER._validate_external_tree(external, source, identity)
                (external / "source-hardlink").unlink()
                os.mkfifo(external / "writerless-fifo", 0o600)
                with self.assertRaisesRegex(ValueError, "unsupported file type"):
                    HELPER.verify_sandbox(arguments)
                (external / "writerless-fifo").unlink()
                unsafe_mode = external / "group-writable"
                unsafe_mode.write_text("unsafe", encoding="utf-8")
                unsafe_mode.chmod(0o660)
                with self.assertRaisesRegex(ValueError, "unsafe permissions"):
                    HELPER.verify_sandbox(arguments)

    def test_rejects_missing_write_root_without_materializing_it(self) -> None:
        with tempfile.TemporaryDirectory(prefix="readonly-sandbox-") as raw:
            temporary = Path(raw)
            source = temporary / "source"
            framework = source / "framework"
            runner_temp = temporary / "runner-temp"
            framework.mkdir(parents=True)
            runner_temp.mkdir()
            missing_write = runner_temp / f"{HELPER.WRITE_ROOT_PREFIX}missing"
            with self.assertRaisesRegex(ValueError, "write root must be an existing directory"):
                HELPER.validate_layout(
                    source_root=str(source), framework_root=str(framework),
                    write_root=str(missing_write), runner_temp=str(runner_temp),
                )
            self.assertFalse(missing_write.exists())

    def test_rejects_symlinked_write_root_without_creating_external_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="readonly-sandbox-") as raw:
            temporary = Path(raw)
            source, framework, runner_temp, write = self.make_layout(temporary)
            outside = temporary / "outside"
            outside.mkdir()
            write.rmdir()
            write.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symbolic links"):
                HELPER.validate_layout(
                    source_root=str(source), framework_root=str(framework),
                    write_root=str(write), runner_temp=str(runner_temp),
                )
            self.assertFalse((outside / "external").exists())

    def test_rejects_source_traversal_before_any_filesystem_change(self) -> None:
        with tempfile.TemporaryDirectory(prefix="readonly-sandbox-") as raw:
            source, framework, runner_temp, write = self.make_layout(Path(raw))
            traversal = f"{source}/../source"
            with self.assertRaisesRegex(ValueError, "traversal"):
                HELPER.validate_layout(
                    source_root=traversal, framework_root=str(framework),
                    write_root=str(write), runner_temp=str(runner_temp),
                )
            self.assertFalse((write / "external").exists())

    def test_rejects_write_root_inside_source_tree(self) -> None:
        with tempfile.TemporaryDirectory(prefix="readonly-sandbox-") as raw:
            temporary = Path(raw)
            source = temporary / "source"
            framework = source / "framework"
            runner_temp = source / "runner-temp"
            write = runner_temp / f"{HELPER.WRITE_ROOT_PREFIX}inside-source"
            source.mkdir()
            framework.mkdir()
            runner_temp.mkdir()
            write.mkdir(mode=0o711)
            if os.geteuid() == 0:
                os.chown(write, 0, 0)
            with self.assertRaisesRegex(ValueError, "disjoint"):
                HELPER.validate_layout(
                    source_root=str(source), framework_root=str(framework),
                    write_root=str(write), runner_temp=str(runner_temp),
                )

    def test_rejects_validator_in_administrative_group(self) -> None:
        account = SimpleNamespace(pw_uid=1001, pw_gid=1001)
        validator_group = SimpleNamespace(gr_gid=1001, gr_name="validator", gr_mem=[])
        sudo_group = SimpleNamespace(gr_gid=27, gr_name="sudo", gr_mem=["validator"])
        with (
            mock.patch.object(HELPER.pwd, "getpwnam", return_value=account),
            mock.patch.object(HELPER.grp, "getgrnam", return_value=validator_group),
            mock.patch.object(HELPER.grp, "getgrgid", return_value=validator_group),
            mock.patch.object(HELPER.grp, "getgrall", return_value=[sudo_group]),
        ):
            with self.assertRaisesRegex(ValueError, "must not belong"):
                HELPER.resolve_validator_identity("validator", "validator")

    def test_rejects_nonempty_write_root_without_creating_external_directory(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("root-owned write-root control requires root")
        with tempfile.TemporaryDirectory(prefix="readonly-sandbox-") as raw:
            source, framework, runner_temp, write = self.make_layout(Path(raw))
            marker = write / "already-present"
            marker.write_text("not fresh", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "newly created and empty"):
                HELPER.validate_layout(
                    source_root=str(source), framework_root=str(framework),
                    write_root=str(write), runner_temp=str(runner_temp),
                )
            self.assertFalse((write / "external").exists())



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
