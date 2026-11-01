from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import inspect
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = connector_root()
HELPER_PATH = source_path('ci/tools/run-readonly-submodule-validation-namespace.py', root=ROOT)
HELPER = load_source(HELPER_PATH)


class ReadonlySubmoduleValidationNamespaceTests(unittest.TestCase):
    @staticmethod
    def _jail_layout(root: Path = Path("/mount-root")) -> object:
        source = root / "source"
        external = root / "external"
        proc = root / "proc"
        return HELPER.JailLayout(root, source, external, proc, (root, source, external, proc))

    def test_procfs_target_is_the_exported_literal_target(self) -> None:
        self.assertEqual(HELPER.PROCFS_TARGET, Path("/proc"))

    def test_python_runtime_allowlist_binds_only_the_exact_hosted_toolcache_tree(self) -> None:
        hosted_python = Path("/opt/hostedtoolcache/Python/3.14.6/x64/bin/python")
        hosted_root = Path("/opt/hostedtoolcache/Python/3.14.6/x64")
        with mock.patch.object(HELPER, "_validate_hosted_python_runtime") as validated:
            self.assertEqual(HELPER._hosted_python_runtime_root(hosted_python), hosted_root)
        validated.assert_called_once_with(hosted_root)
        self.assertIsNone(HELPER._hosted_python_runtime_root(Path("/usr/bin/python3")))
        for invalid in (
            Path("/opt/hostedtoolcache/Python/3.14.6/bin/python"),
            Path("/opt/hostedtoolcache/Python/3.14.6/arm64/bin/python"),
            Path("/opt/hostedtoolcache/pip/bin/python"),
            Path("/home/runner/python"),
        ):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(RuntimeError, "python is outside"):
                HELPER._hosted_python_runtime_root(invalid)

    def test_hosted_python_runtime_must_be_a_real_nonsymlink_directory(self) -> None:
        runtime = Path("/opt/hostedtoolcache/Python/3.14.6/x64")
        directory = stat.S_IFDIR
        with mock.patch.object(HELPER.os, "lstat", return_value=SimpleNamespace(st_mode=directory | 0o777)):
            HELPER._validate_hosted_python_runtime(runtime)
        for metadata in (
            SimpleNamespace(st_mode=stat.S_IFREG | 0o755),
            SimpleNamespace(st_mode=stat.S_IFLNK | 0o777),
        ):
            with self.subTest(metadata=metadata), mock.patch.object(HELPER.os, "lstat", return_value=metadata):
                with self.assertRaisesRegex(RuntimeError, "unsafe hosted Python runtime"):
                    HELPER._validate_hosted_python_runtime(runtime)
        chain = [
            SimpleNamespace(st_mode=directory | 0o755),
            SimpleNamespace(st_mode=directory | 0o755),
            SimpleNamespace(st_mode=directory | 0o755),
            SimpleNamespace(st_mode=directory | 0o755),
            SimpleNamespace(st_mode=stat.S_IFLNK | 0o777),
        ]
        with mock.patch.object(HELPER.os, "lstat", side_effect=chain):
            with self.assertRaisesRegex(RuntimeError, "unsafe hosted Python runtime"):
                HELPER._validate_hosted_python_runtime(runtime)

    def test_jail_binds_an_exact_hosted_runtime_not_the_host_opt_directory(self) -> None:
        mount_root = Path("/jail")
        hosted_root = Path("/opt/hostedtoolcache/Python/3.14.6/x64")
        hosted_target = mount_root / "opt/hostedtoolcache/Python/3.14.6/x64"
        with mock.patch.object(HELPER, "_hosted_python_runtime_root", return_value=hosted_root), mock.patch.object(
            HELPER, "_mount"
        ), mock.patch.object(HELPER, "_secure_directory"), mock.patch.object(
            HELPER, "_create_jail_directory"
        ), mock.patch.object(HELPER, "_create_jail_file"), mock.patch.object(
            HELPER, "_create_jail_device"
        ), mock.patch.object(HELPER, "_verify_mount"), mock.patch.object(
            HELPER, "_trusted_runtime_source"
        ), mock.patch.object(HELPER, "_bind_readonly") as bind_readonly:
            layout = HELPER._build_jail_layout(
                mount_root,
                Path("/trusted/source"),
                Path("/trusted/external"),
                hosted_root / "bin/python",
            )
        self.assertIn(hosted_target, layout.mounts)
        self.assertIn(mock.call(hosted_root, hosted_target), bind_readonly.call_args_list)
        self.assertNotIn(mock.call(Path("/opt"), mount_root / "opt"), bind_readonly.call_args_list)

    def test_jail_file_creation_never_widens_permissions_after_open(self) -> None:
        self.assertNotIn("fchmod", inspect.getsource(HELPER._create_jail_file))

    def test_jail_etc_allowlist_excludes_optional_zoneinfo_symlinks(self) -> None:
        self.assertNotIn(Path("/etc/localtime"), HELPER.JAIL_RUNTIME_ETC_FILES)
        self.assertIn(Path("/etc/passwd"), HELPER.JAIL_RUNTIME_ETC_FILES)

    def test_fixed_compilers_resolve_only_within_the_readonly_runtime(self) -> None:
        executable = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        with mock.patch.object(HELPER.Path, "resolve", return_value=Path("/usr/bin/gcc-15")), mock.patch.object(
            HELPER.os, "stat", return_value=executable
        ):
            self.assertEqual(
                HELPER._fixed_runtime_executable(HELPER.JAIL_C_COMPILER, "C compiler"),
                Path("/usr/bin/gcc-15"),
            )
        for resolved, metadata in (
            (Path("/tmp/gcc"), executable),
            (Path("/bin/gcc-15"), executable),
            (Path("/usr/bin/gcc-15"), SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0)),
            (Path("/usr/bin/gcc-15"), SimpleNamespace(st_mode=stat.S_IFREG | 0o775, st_uid=0)),
            (Path("/usr/bin/gcc-15"), SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=1001)),
        ):
            with self.subTest(resolved=resolved), mock.patch.object(
                HELPER.Path, "resolve", return_value=resolved
            ), mock.patch.object(HELPER.os, "stat", return_value=metadata):
                with self.assertRaisesRegex(RuntimeError, "unsafe C compiler"):
                    HELPER._fixed_runtime_executable(HELPER.JAIL_C_COMPILER, "C compiler")

    def test_readonly_bind_remounts_the_exact_runtime_with_security_flags(self) -> None:
        source = Path("/opt/hostedtoolcache/Python/3.14.6/x64")
        target = Path("/jail/opt/hostedtoolcache/Python/3.14.6/x64")
        flags = HELPER.MS_BIND | HELPER.MS_REMOUNT | HELPER.MS_RDONLY | HELPER.MS_NOSUID | HELPER.MS_NODEV
        with mock.patch.object(HELPER, "_mount") as mount, mock.patch.object(HELPER, "_verify_mount") as verify:
            HELPER._bind_readonly(source, target)
        self.assertEqual(
            mount.call_args_list,
            [mock.call(str(source), target, HELPER.MS_BIND), mock.call(None, target, flags)],
        )
        verify.assert_called_once_with(target, readonly=True, require_noexec=False)

    def test_identity_rejects_privileged_or_missing_account_topologies(self) -> None:
        account = SimpleNamespace(pw_uid=1001, pw_gid=1001)
        validator = SimpleNamespace(gr_name="validator", gr_gid=1001, gr_mem=())
        primary = SimpleNamespace(gr_name="validator", gr_gid=1001, gr_mem=())
        cases = {
            "root uid": (SimpleNamespace(pw_uid=0, pw_gid=1001), validator, primary, [validator], True),
            "requested gid zero": (account, SimpleNamespace(gr_name="validator", gr_gid=0, gr_mem=()), primary, [validator], True),
            "primary gid zero": (SimpleNamespace(pw_uid=1001, pw_gid=0), validator, SimpleNamespace(gr_name="root", gr_gid=0, gr_mem=()), [validator], True),
            "primary root name": (account, validator, SimpleNamespace(gr_name="root", gr_gid=1001, gr_mem=()), [validator], True),
            "root membership": (account, validator, primary, [validator, SimpleNamespace(gr_name="root", gr_gid=100, gr_mem=("validator",))], True),
            "missing membership": (account, validator, SimpleNamespace(gr_name="other", gr_gid=1001, gr_mem=()), [SimpleNamespace(gr_name="other", gr_gid=1001, gr_mem=())], True),
            "sudo membership": (account, validator, primary, [validator, SimpleNamespace(gr_name="sudo", gr_gid=27, gr_mem=("validator",))], True),
            "wheel membership": (account, validator, primary, [validator, SimpleNamespace(gr_name="wheel", gr_gid=10, gr_mem=("validator",))], True),
            "admin membership": (account, validator, primary, [validator, SimpleNamespace(gr_name="admin", gr_gid=20, gr_mem=("validator",))], True),
        }
        for name, (case_account, requested, case_primary, groups, rejects) in cases.items():
            with self.subTest(name=name), mock.patch.object(HELPER.pwd, "getpwnam", return_value=case_account), mock.patch.object(HELPER.grp, "getgrnam", return_value=requested), mock.patch.object(HELPER.grp, "getgrgid", return_value=case_primary), mock.patch.object(HELPER.grp, "getgrall", return_value=groups):
                if rejects:
                    with self.assertRaises(ValueError):
                        HELPER._identity("validator", "validator")
        for missing in ("user", "group"):
            with self.subTest(missing=missing), mock.patch.object(HELPER.pwd, "getpwnam", side_effect=KeyError() if missing == "user" else lambda _name: account), mock.patch.object(HELPER.grp, "getgrnam", side_effect=KeyError() if missing == "group" else lambda _name: validator), mock.patch.object(HELPER.grp, "getgrgid", return_value=primary):
                with self.assertRaisesRegex(ValueError, "must already exist"):
                    HELPER._identity("validator", "validator")

    def test_no_new_privileges_fails_closed_when_prctl_is_rejected(self) -> None:
        with mock.patch.object(HELPER.LIBC, "prctl", return_value=0) as prctl:
            HELPER._set_no_new_privs()
        prctl.assert_called_once_with(HELPER.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        with mock.patch.object(HELPER.LIBC, "prctl", return_value=-1), mock.patch.object(HELPER.ctypes, "get_errno", return_value=1):
            with self.assertRaisesRegex(OSError, "no_new_privs"):
                HELPER._set_no_new_privs()

    def test_cli_requires_all_physical_roots_and_identity(self) -> None:
        required = [
            "--source-root", "/source", "--framework-root", "/source/modules/framework",
            "--write-root", "/write", "--external-root", "/write/external",
            "--validator-user", "validator", "--validator-group", "validator",
            "--python", "/usr/bin/python3",
        ]
        with self.assertRaises(SystemExit):
            HELPER.parse_args(required)
        arguments = HELPER.parse_args(
            required + ["--namespace-parent", "/tmp/modsecurity-readonly-namespace.test"]
        )
        self.assertEqual(arguments.namespace_parent, "/tmp/modsecurity-readonly-namespace.test")
        self.assertEqual(arguments.external_root, "/write/external")

    def test_nested_source_mounts_are_rejected_before_namespace_setup(self) -> None:
        source = Path("/workspace/source")
        source_mount = "37 25 0:32 / /workspace/source rw,relatime - ext4 /dev/sda rw"
        nested_mount = (
            "38 37 0:33 / /workspace/source/modules/framework rw,relatime "
            "- ext4 /dev/sdb rw"
        )
        with mock.patch.object(HELPER.Path, "read_text", return_value=source_mount):
            HELPER._reject_nested_source_mounts(source)
        with mock.patch.object(
            HELPER.Path, "read_text", return_value=f"{source_mount}\n{nested_mount}\n"
        ):
            with self.assertRaisesRegex(RuntimeError, "source root contains an unexpected active mount"):
                HELPER._reject_nested_source_mounts(source)

    def test_mountinfo_decoder_rejects_malformed_octal_escapes(self) -> None:
        self.assertEqual(HELPER._decode_mountinfo_path(r"/workspace/source\040tree"), "/workspace/source tree")
        for malformed in ("\\", r"\04", r"\0x0"):
            with self.subTest(malformed=malformed), self.assertRaisesRegex(ValueError, "invalid escaped"):
                HELPER._decode_mountinfo_path(malformed)

    def test_configuration_checks_nested_source_mounts_before_candidate_setup(self) -> None:
        source = Path("/workspace/source")
        framework = source / "modules/framework"
        write_root = Path("/runner-temp/modsecurity-readonly-validation.fixture")
        external = write_root / "external"
        arguments = SimpleNamespace(
            source_root=str(source),
            framework_root=str(framework),
            write_root=str(write_root),
            external_root=str(external),
            namespace_parent="/tmp/modsecurity-readonly-namespace.test",
            python=sys.executable,
            validator_user="validator",
            validator_group="validator",
        )
        with (
            mock.patch.object(
                HELPER,
                "_absolute_existing_directory",
                side_effect=(source, framework, write_root, external),
            ),
            mock.patch.object(HELPER, "_strict_child"),
            mock.patch.object(HELPER, "_disjoint"),
            mock.patch.object(
                HELPER,
                "_reject_nested_source_mounts",
                side_effect=RuntimeError("source root contains an unexpected active mount"),
            ) as reject_mounts,
        ):
            with self.assertRaisesRegex(RuntimeError, "unexpected active mount"):
                HELPER._validated_configuration(arguments)
        reject_mounts.assert_called_once_with(source)

    def test_namespace_parent_validation_rejects_untrusted_topologies(self) -> None:
        parent = Path("/tmp/modsecurity-readonly-namespace.test")
        directory = stat.S_IFDIR
        valid_tmp = SimpleNamespace(st_mode=directory | 0o1777, st_uid=0, st_gid=0)
        valid_parent = SimpleNamespace(st_mode=directory | 0o750, st_uid=0, st_gid=4242)
        with mock.patch.object(
            HELPER.os, "lstat", side_effect=(valid_tmp, valid_parent)
        ), mock.patch.object(HELPER.os, "scandir", return_value=[]):
            HELPER._validate_namespace_parent(parent, 4242)
        cases = {
            "bad tmp ancestor": (SimpleNamespace(st_mode=directory | 0o777, st_uid=0, st_gid=0), valid_parent, []),
            "wrong owner": (valid_tmp, SimpleNamespace(st_mode=directory | 0o750, st_uid=1, st_gid=4242), []),
            "wrong group": (valid_tmp, SimpleNamespace(st_mode=directory | 0o750, st_uid=0, st_gid=1), []),
            "wrong mode": (valid_tmp, SimpleNamespace(st_mode=directory | 0o755, st_uid=0, st_gid=4242), []),
            "nonempty": (valid_tmp, valid_parent, [SimpleNamespace(name="unexpected")]),
        }
        with self.assertRaisesRegex(ValueError, "sticky ancestor"):
            HELPER._validate_namespace_parent(Path("/tmp"), 4242)
        for name, (tmp_metadata, parent_metadata, contents) in cases.items():
            with self.subTest(name=name), mock.patch.object(
                HELPER.os, "lstat", side_effect=(tmp_metadata, parent_metadata)
            ), mock.patch.object(HELPER.os, "scandir", return_value=contents):
                with self.assertRaises(ValueError):
                    HELPER._validate_namespace_parent(parent, 4242)

    def test_main_blocks_runtime_errors_including_namespace_unavailability(self) -> None:
        for error in (RuntimeError("unsafe mount layout"), HELPER.NamespaceUnavailable("unshare denied")):
            with self.subTest(error=type(error).__name__), mock.patch.object(
                HELPER, "parse_args", return_value=SimpleNamespace()
            ), mock.patch.object(HELPER, "run", side_effect=error), mock.patch.object(
                HELPER.sys, "stderr"
            ) as stderr:
                self.assertEqual(HELPER.main([]), 2)
                self.assertIn(str(error), "".join(call.args[0] for call in stderr.write.call_args_list))

    def test_run_fails_closed_and_removes_mount_layout_after_unexpected_setup_errors(self) -> None:
        for error_type in (OSError, RuntimeError):
            with self.subTest(error_type=error_type.__name__), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                source = root / "source"
                framework = source / "modules" / "framework"
                write_root = root / "write"
                external = write_root / "external"
                namespace_parent = root / "namespace-parent"
                framework.mkdir(parents=True)
                external.mkdir(parents=True)
                namespace_parent.mkdir()
                mount_root = namespace_parent / "mount-root"
                (mount_root / "source").mkdir(parents=True)
                (mount_root / "external").mkdir()
                os.chmod(write_root, 0o711)
                os.chmod(external, 0o700)
                arguments = SimpleNamespace(
                    source_root=str(source), framework_root=str(framework),
                    write_root=str(write_root), external_root=str(external),
                    namespace_parent=str(namespace_parent), python=sys.executable,
                    validator_user="validator", validator_group="validator",
                )
                with mock.patch.object(HELPER.os, "geteuid", return_value=0), mock.patch.object(
                    HELPER,
                    "_validated_configuration",
                    return_value=(
                        source, framework, write_root, external, namespace_parent,
                        Path(sys.executable), os.getuid(), os.getgid(),
                    ),
                ), mock.patch.object(HELPER, "_create_mount_layout", return_value=mount_root
                ), mock.patch.object(HELPER, "_mountinfo_for", return_value=[]), mock.patch.object(
                    HELPER.os, "fork", return_value=1
                ), mock.patch.object(HELPER.os, "waitpid", side_effect=error_type("unexpected setup failure")):
                    with self.assertRaises(error_type):
                        HELPER.run(arguments)
                self.assertFalse(mount_root.exists())

    def test_run_removes_a_partial_mount_layout_when_creation_fails(self) -> None:
        """A failed layout creator cannot strand private mount placeholders."""
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "source"
            framework = source / "modules" / "framework"
            write_root = root / "write"
            external = write_root / "external"
            namespace_parent = root / "namespace-parent"
            framework.mkdir(parents=True)
            external.mkdir(parents=True)
            namespace_parent.mkdir()
            mount_root = namespace_parent / "mount-root"
            (mount_root / "source").mkdir(parents=True)
            arguments = SimpleNamespace(
                source_root=str(source),
                framework_root=str(framework),
                write_root=str(write_root),
                external_root=str(external),
                namespace_parent=str(namespace_parent),
                python=sys.executable,
                validator_user="validator",
                validator_group="validator",
            )
            with mock.patch.object(HELPER.os, "geteuid", return_value=0), mock.patch.object(
                HELPER,
                "_validated_configuration",
                return_value=(
                    source,
                    framework,
                    write_root,
                    external,
                    namespace_parent,
                    Path(sys.executable),
                    os.getuid(),
                    os.getgid(),
                ),
            ), mock.patch.object(
                HELPER,
                "_create_mount_layout",
                side_effect=OSError("injected partial layout failure"),
            ), mock.patch.object(HELPER, "_mountinfo_for", return_value=[]):
                with self.assertRaisesRegex(OSError, "injected partial layout failure"):
                    HELPER.run(arguments)
            self.assertFalse(mount_root.exists())

    def test_candidate_environment_uses_only_namespace_views_for_sources(self) -> None:
        source = Path("/tmp/task/source")
        external = Path("/tmp/task/external")
        environment = HELPER._candidate_environment(
            source, Path("modules/ModSecurity-test-Framework"), external, Path("/tmp/task"),
            Path("/usr/bin/python3"), Path("/usr/bin/gcc-15"), Path("/usr/bin/g++-15"),
        )
        self.assertEqual(environment["GITHUB_WORKSPACE"], str(source))
        self.assertEqual(
            environment["FRAMEWORK_ROOT"], "/tmp/task/source/modules/ModSecurity-test-Framework"
        )
        self.assertEqual(environment["PATH"], HELPER.SAFE_PATH)
        self.assertEqual(environment["CC"], "/usr/bin/gcc-15")
        self.assertEqual(environment["CXX"], "/usr/bin/g++-15")
        self.assertEqual(environment["GITHUB_ACTIONS"], "true")
        self.assertEqual(environment["BUILD_ROOT"], "/tmp/task/external/build")
        self.assertEqual(
            environment["APACHE_C_STANDARDS_OUT"],
            "/tmp/task/external/build/apache-c-standards",
        )
        self.assertEqual(environment["VALIDATION_WRITE_ROOT"], "/tmp/task")
        self.assertNotIn("SUDO", " ".join(environment))
        self.assertEqual(
            set(environment),
            {
                "PATH", "PYTHON", "CC", "CXX", "HOME", "TMPDIR", "TMP", "TEMP", "XDG_CACHE_HOME",
                "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "PIP_CACHE_DIR",
                "PYTHONPYCACHEPREFIX", "PYTHONUSERBASE", "PYTHONPATH", "PYTHONNOUSERSITE",
                "PYTHONDONTWRITEBYTECODE", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM",
                "GIT_OPTIONAL_LOCKS", "GITHUB_ACTIONS", "GITHUB_WORKSPACE", "FRAMEWORK_ROOT", "VALIDATOR_EXTERNAL_ROOT",
                "BUILD_ROOT", "APACHE_C_STANDARDS_OUT",
                "VALIDATION_WRITE_ROOT", "VERIFIED_RUN_ROOT", "VERIFIED_STATE_ROOT", "VERIFIED_BUILD_ROOT",
                "VERIFIED_SOURCE_ROOT", "VERIFIED_TMP_ROOT", "VERIFIED_LOG_ROOT", "CACHE_ROOT",
                "VERIFIED_COMPONENT_CACHE", "CONNECTOR_COMPONENT_CACHE", "VERIFIED_EVIDENCE_ROOT",
                "EVIDENCE_ROOT", "RUNTIME_EVIDENCE_ROOT", "RUNTIME_RUN_ROOT", "RUNTIME_LOG_ROOT",
                "SOURCE_ROOT", "TMP_ROOT", "LOG_ROOT", "MATRIX_ROOT",
            },
        )
        for key, value in environment.items():
            if key not in {
                "PATH", "PYTHON", "CC", "CXX", "GITHUB_ACTIONS", "GITHUB_WORKSPACE", "FRAMEWORK_ROOT", "PYTHONNOUSERSITE",
                "PYTHONDONTWRITEBYTECODE", "GIT_CONFIG_NOSYSTEM", "GIT_OPTIONAL_LOCKS", "VALIDATION_WRITE_ROOT",
            }:
                self.assertTrue(value.startswith(str(external)), key)

    def test_rejects_external_root_outside_the_physical_write_root(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "source"; framework = source / "modules" / "framework"
            source.mkdir(); framework.mkdir(parents=True)
            write = root / "write"; external = root / "outside"; write.mkdir(); external.mkdir()
            os.chmod(write, 0o711); os.chmod(external, 0o700)
            arguments = HELPER.parse_args(
                ["--source-root", str(source), "--framework-root", str(framework),
                 "--write-root", str(write), "--external-root", str(external),
                 "--validator-user", "nobody", "--validator-group", "nogroup", "--python", sys.executable,
                 "--namespace-parent", "/tmp/modsecurity-readonly-namespace.test"]
            )
            # The topology validation is intentionally tested independently
            # from the production root gate: hosted lint invokes this module
            # as an ordinary runner user.
            with mock.patch.object(HELPER.os, "geteuid", return_value=0):
                with self.assertRaisesRegex(ValueError, "exactly the write root external child"):
                    HELPER.run(arguments)

    def test_mount_verifier_rejects_missing_readonly_or_security_flags(self) -> None:
        target = Path("/tmp/namespace-test-target")
        with mock.patch.object(HELPER, "_mountinfo_for", return_value=["1 2 0:1 / /tmp/namespace-test-target rw - ext4 /dev/x rw"]):
            with self.assertRaisesRegex(RuntimeError, "unsafe mount flags"):
                HELPER._verify_mount(target, readonly=True)

    def test_procfs_verifier_requires_one_hardened_proc_mount_at_the_jail_target(self) -> None:
        hardened = "99 1 0:42 / /proc ro,nosuid,nodev,noexec - proc proc rw"
        inherited = "98 1 0:42 / /proc rw,nosuid,nodev,noexec - proc proc rw"
        with mock.patch.object(HELPER, "_mountinfo_for", return_value=[inherited, hardened]):
            HELPER._verify_procfs(HELPER.PROCFS_TARGET)
        for rows in (
            [inherited],
            ["99 1 0:42 / /proc ro,nosuid,nodev - proc proc rw"],
            ["99 1 0:42 / /proc ro,nosuid,nodev,noexec - sysfs sysfs rw"],
            [hardened, hardened],
        ):
            with self.subTest(rows=rows), mock.patch.object(HELPER, "_mountinfo_for", return_value=rows):
                with self.assertRaisesRegex(RuntimeError, "hardened procfs"):
                    HELPER._verify_procfs(HELPER.PROCFS_TARGET)
        with self.assertRaisesRegex(RuntimeError, "hardened procfs"):
            HELPER._verify_procfs(Path("/untrusted-proc"))

    def test_procfs_verification_failure_never_runs_candidate(self) -> None:
        class ChildExit(BaseException):
            pass

        source = Path("/source")
        framework = source / "modules/framework"
        external = Path("/external")
        mount_root = Path("/mount-root")
        layout = self._jail_layout(mount_root)
        candidate = mock.Mock()
        with mock.patch.object(HELPER, "_unshare"), mock.patch.object(
            HELPER, "_build_jail_layout", return_value=layout
        ), mock.patch.object(HELPER, "_mount") as mount, mock.patch.object(
            HELPER.os, "pipe", return_value=(30, 31)
        ), mock.patch.object(
            HELPER.os, "fork", return_value=0
        ), mock.patch.object(HELPER.os, "close"), mock.patch.object(
            HELPER.os, "_exit", side_effect=ChildExit
        ), mock.patch.object(HELPER, "_verify_procfs", side_effect=RuntimeError("proc verification failed")), mock.patch.object(
            HELPER, "_set_no_new_privs"
        ) as no_new_privs:
            with self.assertRaises(ChildExit):
                HELPER._namespace_child(source, framework, external, mount_root, Path("/python"), 1000, 1000, candidate)
        candidate.assert_not_called()
        no_new_privs.assert_not_called()
        mount.assert_any_call("proc", layout.proc, HELPER.MS_RDONLY | HELPER.MS_NOSUID | HELPER.MS_NODEV | HELPER.MS_NOEXEC, "proc")

    def test_parent_tears_down_the_complete_jail_only_after_waiting_for_pid_one(self) -> None:
        source = Path("/source")
        framework = source / "modules/framework"
        external = Path("/external")
        mount_root = Path("/mount-root")
        layout = self._jail_layout(mount_root)
        events: list[tuple[str, object]] = []

        def waitpid(pid: int, options: int) -> tuple[int, int]:
            events.append(("waitpid", pid))
            self.assertEqual(options, 0)
            return pid, 0

        with mock.patch.object(HELPER, "_unshare"), mock.patch.object(
            HELPER, "_mount"
        ), mock.patch.object(HELPER, "_build_jail_layout", return_value=layout
        ), mock.patch.object(HELPER.os, "pipe", return_value=(30, 31)), mock.patch.object(
            HELPER.os, "fork", return_value=4321
        ), mock.patch.object(HELPER.os, "close"), mock.patch.object(
            HELPER.os, "read", return_value=b"1"
        ), mock.patch.object(HELPER.os, "waitpid", side_effect=waitpid), mock.patch.object(
            HELPER, "_teardown_jail_layout", side_effect=lambda observed: events.append(("teardown", observed))
        ):
            result = HELPER._namespace_child(
                source, framework, external, mount_root, Path("/python"), 1000, 1000
            )

        self.assertEqual(result, 0)
        self.assertEqual(
            events,
            [
                ("waitpid", 4321),
                ("teardown", layout),
            ],
        )

    def test_post_ready_child_failure_transfers_jail_cleanup_to_parent(self) -> None:
        class ChildExit(BaseException):
            pass

        candidate_arguments = (
            Path("/source"),
            Path("modules/framework"),
            Path("/external"),
            Path("/guard"),
            Path("/usr/bin/python3"),
            1000,
            1000,
        )
        layout = self._jail_layout()
        readiness = bytearray()
        candidate = mock.Mock()

        def write(_descriptor: int, value: bytes) -> int:
            readiness.extend(value)
            return len(value)

        with mock.patch.object(HELPER, "_mount") as mount, mock.patch.object(
            HELPER, "_verify_procfs"
        ), mock.patch.object(HELPER, "_enter_jail"), mock.patch.object(
            HELPER, "_replace_standard_input"
        ), mock.patch.object(HELPER, "_close_unapproved_descriptors"), mock.patch.object(
            HELPER.os, "write", side_effect=write
        ) as child_write, mock.patch.object(HELPER.os, "close"), mock.patch.object(
            HELPER, "_set_no_new_privs", side_effect=RuntimeError("no_new_privs failed")
        ), mock.patch.object(HELPER.os, "_exit", side_effect=ChildExit):
            with self.assertRaises(ChildExit):
                HELPER._run_pid1_candidate(candidate_arguments, candidate, (30, 31), layout)

        child_write.assert_called_once_with(31, b"1")
        self.assertEqual(bytes(readiness), b"1")
        candidate.assert_not_called()
        mount.assert_any_call("proc", layout.proc, HELPER.MS_RDONLY | HELPER.MS_NOSUID | HELPER.MS_NODEV | HELPER.MS_NOEXEC, "proc")

        parent_teardown = mock.Mock()
        parent_read = mock.Mock(return_value=bytes(readiness))
        with mock.patch.object(HELPER, "_unshare"), mock.patch.object(
            HELPER, "_mount"
        ), mock.patch.object(HELPER, "_build_jail_layout", return_value=layout
        ), mock.patch.object(HELPER.os, "pipe", return_value=(30, 31)), mock.patch.object(
            HELPER.os, "fork", return_value=4321
        ), mock.patch.object(HELPER.os, "close"), mock.patch.object(
            HELPER.os, "read", parent_read
        ), mock.patch.object(HELPER.os, "waitpid", return_value=(4321, 127 << 8)), mock.patch.object(
            HELPER, "_teardown_jail_layout", parent_teardown
        ):
            result = HELPER._namespace_child(
                Path("/source"),
                Path("/source/modules/framework"),
                Path("/external"),
                Path("/mount-root"),
                Path("/usr/bin/python3"),
                1000,
                1000,
            )

        self.assertEqual(result, 127)
        parent_read.assert_called_once_with(30, 1)
        parent_teardown.assert_called_once_with(layout)

    def test_mount_layout_forces_traversable_root_validator_modes_despite_umask(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("root ownership verification is unavailable")
        with tempfile.TemporaryDirectory() as raw:
            validator_gid = os.getgid()
            previous_umask = os.umask(0o077)
            try:
                root = HELPER._create_mount_layout(Path(raw), validator_gid)
            finally:
                os.umask(previous_umask)
            try:
                self.assertEqual(root.parent, Path(raw))
                self.assertEqual(root.name, "mount-root")
                for path in (root, root / "source", root / "external"):
                    metadata = os.lstat(path)
                    self.assertEqual((metadata.st_uid, metadata.st_gid), (0, validator_gid))
                    self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o750)
                    self.assertTrue(stat.S_ISDIR(metadata.st_mode))
                    self.assertFalse(stat.S_ISLNK(metadata.st_mode))
            finally:
                os.rmdir(root / "source"); os.rmdir(root / "external"); os.rmdir(root)

    def test_launcher_never_uses_tempfile_or_python_chmod_for_mount_layout(self) -> None:
        launcher = HELPER_PATH.read_text(encoding="utf-8")
        self.assertNotIn("tempfile", launcher)
        self.assertNotIn("os.chmod(", launcher)

    def test_fixed_candidate_program_keeps_all_isolation_probes_and_pid1_exec(self) -> None:
        program = HELPER._candidate_script()
        for required in (
            "umask 077", "CapEff", "NoNewPrivs", "GITHUB_WORKSPACE/.git", "FRAMEWORK_ROOT/.git",
            "VALIDATION_WRITE_ROOT/.readonly-validator-guard-probe", "/dev/.readonly-validator-device-probe", "/usr/bin/sudo",
            "/usr/bin/mount -o remount,rw", "VALIDATOR_EXTERNAL_ROOT/write-probe",
            '"$PYTHON" -I -c "import yaml; assert not yaml.__with_libyaml__"',
            "exec make", "safe.directory", "expect_blocked mv",
            "expect_blocked rm", "expect_blocked chmod", "for target in /tmp /var /home /root /run /sys /dev/shm",
            "validator retained an inherited descriptor", 'test -e "$descriptor" || continue', "test -c /dev/null", "validator sees an unexpected device",
            "python_runtime_bin=$(dirname \"$PYTHON\")", "runtime-write-probe", "runtime-directory-probe",
            "runtime-rename-probe",
            "cap_eff=\"\"; no_new_privs=\"\"", "while IFS=$'\\t ' read -r label value",
            "done < /proc/self/status",
        ):
            self.assertIn(required, program)
        self.assertIn('exec make PYTHON="$PYTHON" quick-check', program)
        self.assertNotIn('exec make PYTHON="$PYTHON" BUILD_ROOT=', program)
        self.assertNotIn("eval ", program)
        self.assertNotIn("awk ", program)
        self.assertNotIn("-m pip install", program)
        self.assertNotIn("-m venv", program)
        syntax = subprocess.run(
            ["/bin/bash", "--noprofile", "--norc", "-n", "-c", program],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def test_dependency_preflight_failure_stops_make_and_preserves_selected_python(self) -> None:
        """Only a successful isolated import may reach make with the selected runtime."""
        program = HELPER._candidate_script()
        bootstrap = program[program.index('touch "$VALIDATOR_EXTERNAL_ROOT/write-probe"'):]
        boundary_program = "#!" + sys.executable + "\n" + '''
import json
import os
from pathlib import Path
import sys

phase = "make" if Path(sys.argv[0]).name == "make" else "preflight"
with Path(os.environ["BOOTSTRAP_TRACE"]).open("a") as output:
    output.write(json.dumps({"phase": phase, "argv": sys.argv,
                             "python": os.environ["PYTHON"]}) + "\\n")
if phase == "preflight":
    if sys.argv[1:] != ["-I", "-c", "import yaml; assert not yaml.__with_libyaml__"]:
        raise SystemExit(44)
    raise SystemExit(int(os.environ["IMPORT_STATUS"]))
'''
        cases = (("prepared dependency", 0, ["preflight", "make"]),
                 ("dependency import failure", 23, ["preflight"]))
        for name, status, phases in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                external = root / "external space"
                external.mkdir()
                binaries = root / "bin"
                binaries.mkdir()
                selected_python = binaries / "selected-python"
                for executable in (selected_python, binaries / "make"):
                    executable.write_text(boundary_program, encoding="utf-8")
                    executable.chmod(0o700)
                trace = root / "trace.jsonl"
                environment = {
                    "PATH": str(binaries) + os.pathsep + os.defpath,
                    "PYTHON": str(selected_python), "VALIDATOR_EXTERNAL_ROOT": str(external),
                    "GITHUB_WORKSPACE": str(root), "PYTHONPATH": str(external / "python-packages"),
                    "BOOTSTRAP_TRACE": str(trace), "IMPORT_STATUS": str(status),
                    "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
                }
                result = subprocess.run(
                    ["/bin/bash", "--noprofile", "--norc", "-ceu", bootstrap],
                    env=environment, capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, status, result.stderr)
                events = [json.loads(line) for line in trace.read_text().splitlines()]
                self.assertEqual([event["phase"] for event in events], phases)
                self.assertEqual(events[0]["argv"], [str(selected_python), "-I", "-c",
                                 "import yaml; assert not yaml.__with_libyaml__"])
                self.assertTrue(all(event["python"] == str(selected_python) for event in events))
                if "make" in phases:
                    self.assertEqual(events[1]["argv"][1:], ["PYTHON=" + str(selected_python), "quick-check"])

    def test_candidate_proc_status_parser_preserves_capability_and_no_new_privs_checks(self) -> None:
        program = HELPER._candidate_script()
        parser_start = program.index('cap_eff=""; no_new_privs=""')
        parser_end = program.index('for target in /tmp /var /home /root /run /sys /dev/shm')
        parser = program[parser_start:parser_end]
        cases = {
            "valid": ("0000000000000000", "1", 0),
            "capabilities retained": ("0000000000000001", "1", 1),
            "no new privs disabled": ("0000000000000000", "0", 1),
        }
        for name, (cap_eff, no_new_privs, expected) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as raw:
                status = Path(raw) / "status"
                status.write_text(
                    f"Name:\tvalidator\nCapEff:\t{cap_eff}\nNoNewPrivs:\t{no_new_privs}\n",
                    encoding="utf-8",
                )
                result = subprocess.run(
                    [
                        "/bin/bash", "--noprofile", "--norc", "-eu", "-c",
                        parser.replace("/proc/self/status", str(status)),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    env={"PATH": ""},
                )
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_jail_path_and_runtime_allowlist_are_fixed(self) -> None:
        root = Path("/mount-root")
        self.assertEqual(HELPER._jail_target(root, HELPER.JAIL_SOURCE), root / "source")
        self.assertEqual(HELPER._jail_target(root, HELPER.PROCFS_TARGET), root / "proc")
        for invalid in (Path("source"), Path("/")):
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                HELPER._jail_target(root, invalid)
        self.assertTrue(HELPER._runtime_path_is_exposed(Path("/usr/bin/python3")))
        self.assertFalse(HELPER._runtime_path_is_exposed(Path("/opt/hostedtoolcache/python/bin/python")))
        self.assertFalse(HELPER._runtime_path_is_exposed(Path("/tmp/python")))

    def test_unapproved_inherited_descriptors_are_closed(self) -> None:
        read_end, write_end = os.pipe()
        child = os.fork()
        if child == 0:
            try:
                HELPER._close_unapproved_descriptors({0, 1, 2})
                try:
                    os.fstat(read_end)
                except OSError:
                    os._exit(0)
                os._exit(1)
            except BaseException:
                os._exit(1)
        os.close(read_end); os.close(write_end)
        _pid, status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)

    def test_environment_build_root_does_not_override_nested_make_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fixture_build_root = root / "fixture-build"
            (root / "parent.mk").write_text(
                ".PHONY: check\n"
                "check:\n"
                "\t@$(MAKE) --no-print-directory -f child.mk verify\n",
                encoding="utf-8",
            )
            (root / "child.mk").write_text(
                f"BUILD_ROOT := {fixture_build_root}\n"
                ".PHONY: verify\n"
                "verify:\n"
                f"\t@test \"$(BUILD_ROOT)\" = \"{fixture_build_root}\"\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment["BUILD_ROOT"] = str(root / "candidate-external" / "build")

            environment_result = subprocess.run(
                ["make", "--no-print-directory", "-f", "parent.mk", "check"],
                cwd=root,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            command_line_result = subprocess.run(
                [
                    "make", "--no-print-directory", "-f", "parent.mk",
                    f"BUILD_ROOT={environment['BUILD_ROOT']}", "check",
                ],
                cwd=root,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(environment_result.returncode, 0, environment_result.stderr)
            self.assertNotEqual(command_line_result.returncode, 0)

    def test_privileged_namespace_mount_integration(self) -> None:
        """Exercise a real private read-only bind mount when the kernel permits it."""
        if os.geteuid() != 0 or sys.platform != "linux":
            self.skipTest("mount/PID namespace capability is unavailable")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); source = root / "source"; target = root / "target"
            source.mkdir(); target.mkdir()
            child = os.fork()
            if child == 0:
                try:
                    HELPER._unshare()
                    HELPER._mount(None, Path("/"), HELPER.MS_REC | HELPER.MS_PRIVATE)
                    HELPER._mount(str(source), target, HELPER.MS_BIND)
                    HELPER._mount(None, target, HELPER.MS_BIND | HELPER.MS_REMOUNT | HELPER.MS_RDONLY | HELPER.MS_NOSUID | HELPER.MS_NODEV)
                    HELPER._verify_mount(target, readonly=True)
                    before_proc = HELPER._mountinfo_for(Path("/proc"))
                    HELPER._mount("proc", Path("/proc"), HELPER.MS_RDONLY | HELPER.MS_NOSUID | HELPER.MS_NODEV | HELPER.MS_NOEXEC, "proc")
                    HELPER._verify_procfs(Path("/proc"))
                    HELPER._umount(Path("/proc"))
                    if HELPER._mountinfo_for(Path("/proc")) != before_proc:
                        os._exit(1)
                    HELPER._umount(target)
                except HELPER.NamespaceUnavailable:
                    os._exit(125)
                except BaseException:
                    os._exit(1)
                os._exit(0)
            _pid, status = os.waitpid(child, 0)
            code = os.waitstatus_to_exitcode(status)
            if code == 125:
                self.skipTest("mount/PID namespace capability is unavailable")
            self.assertEqual(code, 0)

    def test_privileged_world_writable_runtime_is_readonly_after_bind(self) -> None:
        """A 0777 hosted runtime source cannot stay writable through its RO bind."""
        if os.geteuid() != 0 or sys.platform != "linux":
            self.skipTest("mount/PID namespace capability is unavailable")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); runtime = root / "runtime"; target = root / "target"
            previous_umask = os.umask(0)
            try:
                runtime.mkdir(mode=stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
            finally:
                os.umask(previous_umask)
            target.mkdir()
            executable = runtime / "python"; executable.write_text("runtime", encoding="utf-8")
            child = os.fork()
            if child == 0:
                try:
                    HELPER._unshare()
                    HELPER._mount(None, Path("/"), HELPER.MS_REC | HELPER.MS_PRIVATE)
                    HELPER._bind_readonly(runtime, target)
                    if (target / "python").read_text(encoding="utf-8") != "runtime":
                        os._exit(1)
                    for operation in (
                        lambda: (target / "write-probe").touch(),
                        lambda: (target / "directory-probe").mkdir(),
                        lambda: os.rename(target / "python", target / "renamed"),
                        lambda: os.unlink(target / "python"),
                    ):
                        try:
                            operation()
                        except OSError:
                            continue
                        os._exit(1)
                    os._exit(0)
                except HELPER.NamespaceUnavailable:
                    os._exit(125)
                except BaseException:
                    os._exit(1)
            _pid, status = os.waitpid(child, 0)
            code = os.waitstatus_to_exitcode(status)
            if code == 125:
                self.skipTest("mount/PID namespace capability is unavailable")
            self.assertEqual(code, 0)
            self.assertEqual(executable.read_text(encoding="utf-8"), "runtime")

    def test_privileged_candidate_cannot_escape_the_chroot_or_outlive_pid1(self) -> None:
        """Exercise the real allowlist jail when mount/PID namespaces are available."""
        if os.geteuid() != 0 or sys.platform != "linux":
            self.skipTest("mount/PID namespace capability is unavailable")
        try:
            account = pwd.getpwnam("nobody")
            group = HELPER.grp.getgrgid(account.pw_gid)
        except KeyError:
            self.skipTest("dedicated unprivileged identity capability is unavailable")

        def mapped(identifier: int, map_name: str) -> bool:
            for row in Path(f"/proc/self/{map_name}").read_text(encoding="utf-8").splitlines():
                inside, _outside, count = (int(value) for value in row.split())
                if inside <= identifier < inside + count:
                    return True
            return False

        if not mapped(account.pw_uid, "uid_map") or not mapped(group.gr_gid, "gid_map"):
            self.skipTest("dedicated unprivileged identity capability is unavailable")
        # Honor the configured external task temporary root.  A jail that
        # merely bind-mounts /source would still leave the physical host path visible.
        with tempfile.TemporaryDirectory(prefix="readonly-namespace-") as raw:
            root = Path(raw); os.chmod(root, 0o755)
            source = root / "source"; framework = source / "modules" / "framework"
            framework.mkdir(parents=True); (source / ".git" / "modules").mkdir(parents=True)
            (framework / ".git").mkdir(); (source / "Makefile").write_text("parent", encoding="utf-8")
            (framework / "Makefile").write_text("framework", encoding="utf-8")
            external = root / "external"; external.mkdir(); os.chown(external, account.pw_uid, group.gr_gid); os.chmod(external, 0o700)
            mount_root = root / "mount-root"; mount_root.mkdir(mode=0o755)
            (mount_root / "source").mkdir(mode=0o755); (mount_root / "external").mkdir(mode=0o755)
            inherited_source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY)

            def candidate(source_view: Path, framework_relative: Path, external_view: Path, _guard: Path, _python: Path, uid: int, gid: int) -> None:
                if "NoNewPrivs:\t1" not in Path("/proc/self/status").read_text(encoding="utf-8"):
                    os._exit(1)
                local_pid = os.getpid()
                if local_pid != 1 or not Path(f"/proc/{local_pid}/task/{local_pid}").is_dir():
                    os._exit(1)
                if os.readlink("/proc/self/ns/pid") != os.readlink(f"/proc/{local_pid}/ns/pid"):
                    os._exit(1)
                os.setgroups([]); os.setgid(gid); os.setuid(uid); os.chdir(source_view)
                framework_view = source_view / framework_relative
                python_view = Path(_python)
                if source_view != HELPER.JAIL_SOURCE or external_view != HELPER.JAIL_EXTERNAL:
                    os._exit(1)
                for denied in (Path("/tmp"), Path("/var/tmp"), Path("/dev/shm"), Path("/home"), Path("/root"), Path("/run"), Path("/sys"), source, framework):
                    if denied.exists():
                        os._exit(1)
                with self.assertRaises(OSError):
                    os.fstat(inherited_source_fd)
                if not os.access(external_view, os.W_OK) or any(
                    os.access(path, os.W_OK)
                    for path in (Path("/"), Path("/dev"), source_view, framework_view, Path("/guard"))
                ):
                    os._exit(1)
                def blocked(operation: object) -> None:
                    with self.assertRaises(OSError):
                        operation()  # type: ignore[operator]
                blocked(lambda: (source_view / "create").touch())
                blocked(lambda: (framework_view / "create").touch())
                blocked(lambda: (source_view / ".git" / "index.lock").touch())
                blocked(lambda: (framework_view / ".git" / "index.lock").touch())
                blocked(lambda: (Path("/dev") / "create").touch())
                blocked(lambda: (Path("/dev/shm") / "create").touch())
                blocked(lambda: os.chmod(source_view / "Makefile", 0o600))
                blocked(lambda: os.chmod(framework_view / "Makefile", 0o600))
                blocked(lambda: os.chmod(source_view / ".git", 0o600))
                blocked(lambda: os.chmod(framework_view / ".git", 0o600))
                blocked(lambda: os.rename(source_view / "Makefile", source_view / "renamed"))
                blocked(lambda: os.rename(framework_view / "Makefile", framework_view / "renamed"))
                blocked(lambda: os.rename(source_view / ".git", source_view / "renamed-git"))
                blocked(lambda: os.rename(framework_view / ".git", framework_view / "renamed-git"))
                blocked(lambda: os.unlink(source_view / "Makefile"))
                blocked(lambda: os.unlink(framework_view / "Makefile"))
                blocked(lambda: (python_view.parent / "runtime-write-probe").touch())
                blocked(lambda: (python_view.parent / "runtime-directory-probe").mkdir())
                blocked(lambda: os.chmod(python_view, 0o600))
                blocked(lambda: os.rename(python_view, python_view.parent / "runtime-renamed"))
                if pwd.getpwuid(uid).pw_name != account.pw_name:
                    os._exit(1)
                identity = subprocess.run(["/usr/bin/id", "-un"], check=False, capture_output=True, text=True)
                if identity.returncode != 0 or identity.stdout.strip() != account.pw_name:
                    os._exit(1)
                interpreter = subprocess.run([str(python_view), "-c", "import sys; assert sys.executable"], check=False)
                if interpreter.returncode != 0:
                    os._exit(1)
                (external_view / "candidate-output").write_text("allowed", encoding="utf-8")
                background = os.fork()
                if background == 0:
                    time.sleep(0.2)
                    (external_view / "background-after-pid1").touch()
                    os._exit(0)
                os._exit(0)

            child = os.fork()
            if child == 0:
                try:
                    os._exit(HELPER._namespace_child(
                        source, framework, external, mount_root, Path(sys.executable).resolve(strict=True), account.pw_uid,
                        group.gr_gid, candidate,
                    ))
                except HELPER.NamespaceUnavailable:
                    os._exit(125)
                except BaseException as error:
                    os.write(2, ("namespace test child failed: " + type(error).__name__ + ": " + ascii(str(error))[:500] + "\n").encode("ascii"))
                    os._exit(1)
            os.close(inherited_source_fd)
            _pid, status = os.waitpid(child, 0)
            code = os.waitstatus_to_exitcode(status)
            if code == 125:
                self.skipTest("mount/PID namespace capability is unavailable")
            self.assertEqual(code, 0)
            self.assertEqual((external / "candidate-output").read_text(encoding="utf-8"), "allowed")
            self.assertEqual((source / "Makefile").read_text(encoding="utf-8"), "parent")
            self.assertFalse(HELPER._mountinfo_for(mount_root))
            time.sleep(0.3)
            self.assertFalse((external / "background-after-pid1").exists())
            os.rmdir(mount_root / "source"); os.rmdir(mount_root / "external"); os.rmdir(mount_root)


    def test_external_virtualenv_alias_resolves_to_existing_jail_runtime(self) -> None:
        """Resolve a venv alias without adding its writable parent to the jail."""
        if sys.platform != "linux":
            self.skipTest("Linux runtime layout is required")
        system_python = Path("/usr/bin/python3").resolve(strict=True)
        self.assertTrue(HELPER._runtime_path_is_exposed(system_python))
        with tempfile.TemporaryDirectory(prefix="external-python-alias-") as raw:
            alias = Path(raw) / "python"
            alias.symlink_to(system_python)
            with self.assertRaisesRegex(RuntimeError, "outside the jailed runtime allowlist"):
                HELPER._hosted_python_runtime_root(alias)
            resolved = alias.resolve(strict=True)
            self.assertEqual(resolved, system_python)
            self.assertIsNone(HELPER._hosted_python_runtime_root(resolved))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
