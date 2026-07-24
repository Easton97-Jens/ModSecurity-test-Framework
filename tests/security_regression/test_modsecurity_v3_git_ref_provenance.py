"""Regression coverage for the immutable ModSecurity v3 Git boundary.

The tests replace Git only where the provisioning and build scripts invoke it.
They never contact upstream or build a real ModSecurity checkout.
"""

import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


TEST_SUPPORT_ROOT = Path(__file__).resolve().parent
if str(TEST_SUPPORT_ROOT) not in sys.path:
    sys.path.insert(0, str(TEST_SUPPORT_ROOT))

from git_provenance_test_support import (
    create_approved_modsecurity_v3_topology,
    fake_git_script,
)


ROOT = Path(__file__).resolve().parents[2]
FETCH_V3 = ROOT / "ci/provisioning/fetch-smoke-sources.sh"
PREPARE_APACHE = ROOT / "ci/provisioning/prepare-apache-build.sh"
PREPARE_NGINX = ROOT / "ci/provisioning/prepare-nginx-build.sh"
BUILD_V3 = ROOT / "ci/provisioning/build-v3-under-src.sh"
APPROVED_REPO = "https://github.com/owasp-modsecurity/ModSecurity.git"
APPROVED_COMMIT = "0fb4aff98b4980cf6426697d5605c424e3d5bb60"
APPROVED_RELEASE_TAG = "v3.0.15"
ALTERNATE_COMMIT = "a" * 40
# A full valid graph invokes the hermetic fake Git once per verification step
# across the root and eight approved children.  Python 3.14 process startup
# exceeds the legacy 15-second bound while the real Git control remains fast.
PROVENANCE_COMMAND_TIMEOUT_SECONDS = 45


FAKE_GIT = fake_git_script(APPROVED_REPO, APPROVED_COMMIT)


BUILD_TRAP = """#!/bin/sh
printf '%s %s\\n' "$0" "$*" >> "$FAKE_BUILD_LOG"
exit 96
"""


FAKE_PROVISION_HARNESS = """#!/bin/sh
set -eu
. "$FRAMEWORK_ROOT/ci/lib/common.sh"
ci_modsecurity_v3_require_host_git() {
    ci_v3_host_git_bin=$FAKE_GIT_BIN
    return 0
}
ci_provision_approved_modsecurity_v3_checkout "$1"
"""


FAKE_DIRECT_CHECKOUT_HARNESS = """#!/bin/sh
set -eu
. "$FRAMEWORK_ROOT/ci/lib/common.sh"
ci_modsecurity_v3_require_host_git() {
    ci_v3_host_git_bin=$FAKE_GIT_BIN
    return 0
}
ci_require_approved_modsecurity_v3_checkout "$1"
"""


class ModSecurityV3ProvenanceTests(unittest.TestCase):
    maxDiff = None

    @staticmethod
    def git_verbs(commands):
        verbs = []
        for command_line in commands:
            arguments = shlex.split(command_line)
            while arguments:
                if arguments[0] == "--no-optional-locks":
                    arguments = arguments[1:]
                elif arguments[0].startswith("--git-dir=") or arguments[0].startswith("--work-tree="):
                    arguments = arguments[1:]
                elif len(arguments) >= 2 and arguments[0] in {"--git-dir", "--work-tree"}:
                    arguments = arguments[2:]
                elif len(arguments) >= 2 and arguments[0] in {"-c", "-C"}:
                    arguments = arguments[2:]
                else:
                    break
            if arguments:
                verbs.append(arguments[0])
        return verbs

    @staticmethod
    def write_executable(path, contents):
        path.write_text(contents, encoding="utf-8")
        path.chmod(0o755)

    @staticmethod
    def run_system_git(*arguments, cwd=None, capture_output=False):
        return subprocess.run(
            ["/usr/bin/git", *arguments],
            cwd=cwd,
            check=True,
            text=True,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
        )

    @staticmethod
    def run_common_function(environment, script, *arguments):
        direct_environment = environment.copy()
        direct_environment["PATH"] = os.defpath
        return subprocess.run(
            ["sh", "-c", script, "modsecurity-v3-common", *map(str, arguments)],
            cwd=ROOT,
            env=direct_environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=PROVENANCE_COMMAND_TIMEOUT_SECONDS,
        )

    def create_real_commit_origin(self, temporary_path, name, payload_name="payload.txt"):
        origin = temporary_path / f"{name}-origin.git"
        worktree = temporary_path / f"{name}-seed"
        self.run_system_git("init", "--bare", str(origin))
        self.run_system_git("init", str(worktree))
        self.run_system_git("-C", str(worktree), "config", "user.name", "Framework Test")
        self.run_system_git(
            "-C", str(worktree), "config", "user.email", "framework-test@example.invalid"
        )
        (worktree / payload_name).write_text(f"{name} payload\n", encoding="utf-8")
        self.run_system_git("-C", str(worktree), "add", payload_name)
        self.run_system_git("-C", str(worktree), "commit", "-m", f"{name} fixture")
        commit = self.run_system_git(
            "-C", str(worktree), "rev-parse", "HEAD", capture_output=True
        ).stdout.strip()
        self.run_system_git("-C", str(worktree), "remote", "add", "origin", str(origin))
        self.run_system_git("-C", str(worktree), "push", "origin", "HEAD:master")
        return origin, worktree, commit

    def initialize_real_checkout(self, destination, origin, commit):
        self.run_system_git("init", str(destination))
        self.run_system_git("-C", str(destination), "remote", "add", "origin", str(origin))
        self.run_system_git("-C", str(destination), "fetch", "origin", commit)

    def create_fixture(self, temporary_path, *, trap_build_commands=False):
        verified_root = temporary_path / "verified"
        source_root = verified_root / "src"
        source_root.mkdir(parents=True)
        source_dir = source_root / "ModSecurity_V3"
        adapter_source = temporary_path / "adapter"
        adapter_source.mkdir()

        fake_bin = temporary_path / "bin"
        fake_bin.mkdir()
        self.write_executable(fake_bin / "git", FAKE_GIT)
        self.write_executable(fake_bin / "provision-approved-v3", FAKE_PROVISION_HARNESS)
        self.write_executable(fake_bin / "require-approved-v3", FAKE_DIRECT_CHECKOUT_HARNESS)
        git_log = temporary_path / "git.log"
        git_log.touch()
        build_log = temporary_path / "build.log"
        build_log.touch()
        if trap_build_commands:
            for command in ("cp", "make", "cc"):
                self.write_executable(fake_bin / command, BUILD_TRAP)

        environment = os.environ.copy()
        environment.update(
            {
                "CI_ROOT": str(ROOT / "ci"),
                "FRAMEWORK_ROOT": str(ROOT),
                "CONNECTOR_ROOT": str(ROOT),
                "REPO_ROOT": str(ROOT),
                "VERIFIED_RUN_ROOT": str(verified_root),
                "VERIFIED_BUILD_ROOT": str(verified_root / "build"),
                "VERIFIED_SOURCE_ROOT": str(source_root),
                "VERIFIED_TMP_ROOT": str(verified_root / "tmp"),
                "VERIFIED_LOG_ROOT": str(verified_root / "logs"),
                "SOURCE_ROOT": str(source_root),
                "BUILD_ROOT": str(verified_root / "build"),
                "TMP_ROOT": str(verified_root / "tmp"),
                "LOG_ROOT": str(verified_root / "logs"),
                "MODSECURITY_SOURCE_DIR": str(source_dir),
                "MODSECURITY_V3_SOURCE_DIR": str(source_dir),
                "FAKE_GIT_LOG": str(git_log),
                "FAKE_GIT_ROOT": str(source_dir),
                "FAKE_GIT_BIN": str(fake_bin / "git"),
                "FAKE_PROVISION_HARNESS": str(fake_bin / "provision-approved-v3"),
                "FAKE_DIRECT_CHECKOUT_HARNESS": str(fake_bin / "require-approved-v3"),
                "FAKE_GIT_ORIGIN": APPROVED_REPO,
                "FAKE_BUILD_LOG": str(build_log),
                "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
            }
        )
        return environment, source_dir, adapter_source, git_log, build_log

    @staticmethod
    def read_commands(git_log):
        return [line.rstrip() for line in git_log.read_text(encoding="utf-8").splitlines() if line.strip()]

    def invoke_fetch(self, *, overrides=None, existing_source=False):
        with tempfile.TemporaryDirectory(prefix="modsecurity-v3-provenance-") as temporary:
            temporary_path = Path(temporary)
            environment, source_dir, _, git_log, _ = self.create_fixture(temporary_path)
            sentinel = source_dir / "untrusted-source-marker"
            if existing_source:
                (source_dir / ".git").mkdir(parents=True)
                sentinel.write_text("existing source must not be reused", encoding="utf-8")
            environment.update(overrides or {})
            result = subprocess.run(
                [environment["FAKE_PROVISION_HARNESS"], str(source_dir)],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=PROVENANCE_COMMAND_TIMEOUT_SECONDS,
            )
            return result, self.read_commands(git_log), sentinel.exists()

    def assert_blocked_before_git(self, overrides):
        result, commands, _ = self.invoke_fetch(overrides=overrides)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(commands, [], result.stdout + result.stderr)

    def test_rejects_mutable_refs_and_origin_overrides_before_git(self):
        for variable, rejected_value in (
            ("MODSECURITY_GIT_REF", "v3/master"),
            ("MODSECURITY_V3_GIT_REF", "main"),
            ("MODSECURITY_GIT_REF", APPROVED_COMMIT),
            ("MODSECURITY_REPO_URL", "https://github.com/attacker/ModSecurity.git"),
            ("MODSECURITY_V3_GIT_URL", "https://github.com/attacker/ModSecurity.git"),
        ):
            with self.subTest(variable=variable, value=rejected_value):
                self.assert_blocked_before_git({variable: rejected_value})

    def test_empty_legacy_aliases_normalize_to_reviewed_metadata(self):
        result, commands, _ = self.invoke_fetch(
            overrides={
                "MODSECURITY_REPO_URL": "",
                "MODSECURITY_GIT_REF": "",
                "MODSECURITY_V3_GIT_URL": "",
                "MODSECURITY_V3_GIT_REF": "",
            }
        )
        command_text = "\n".join(commands)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"fetch --depth 1 --no-tags origin {APPROVED_COMMIT}", command_text)
        self.assertNotIn(APPROVED_RELEASE_TAG, command_text)

    def test_fresh_control_fetches_only_the_reviewed_commit_then_initializes_the_static_topology(self):
        result, commands, _ = self.invoke_fetch()
        command_text = "\n".join(commands)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("init ", command_text)
        self.assertIn(f"remote add origin {APPROVED_REPO}", command_text)
        self.assertIn(f"fetch --depth 1 --no-tags origin {APPROVED_COMMIT}", command_text)
        self.assertIn(f"checkout --detach {APPROVED_COMMIT}", command_text)
        self.assertIn("submodule update --init --recursive --checkout", command_text)
        self.assertLess(
            command_text.index(f"checkout --detach {APPROVED_COMMIT}"),
            command_text.index("submodule update --init --recursive --checkout"),
        )
        self.assertIn("--no-optional-locks", command_text)
        self.assertIn("-c core.fsmonitor=false", command_text)
        self.assertIn("-c core.useBuiltinFSMonitor=false", command_text)
        self.assertNotIn(APPROVED_RELEASE_TAG, command_text)

    def test_fetch_script_delegates_v3_provisioning_to_the_hardened_framework_api(self):
        fetch_source = FETCH_V3.read_text(encoding="utf-8")
        start = fetch_source.index("provision_fresh_modsecurity_v3()")
        end = fetch_source.index('require_absolute_path "$SOURCE_ROOT"')
        provision_function = fetch_source[start:end]
        self.assertIn(
            'ci_provision_approved_modsecurity_v3_checkout "$MODSECURITY_V3_SOURCE_DIR"',
            provision_function,
        )
        self.assertNotIn("ci_modsecurity_v3_git", provision_function)

    def test_ignores_a_fake_git_earlier_in_path_and_uses_the_verified_system_binary(self):
        with tempfile.TemporaryDirectory(prefix="modsecurity-v3-host-git-") as temporary:
            temporary_path = Path(temporary)
            environment, _, _, git_log, _ = self.create_fixture(temporary_path)
            attacker_bin = temporary_path / "attacker-bin"
            attacker_bin.mkdir()
            attacker_marker = temporary_path / "attacker-git-ran"
            self.write_executable(
                attacker_bin / "git",
                f"#!/bin/sh\n: > {shlex.quote(str(attacker_marker))}\nexit 96\n",
            )
            environment["PATH"] = f"{attacker_bin}{os.pathsep}{environment['PATH']}"
            result = subprocess.run(
                [
                    "sh",
                    "-c",
                    '. "$FRAMEWORK_ROOT/ci/lib/common.sh"\nci_modsecurity_v3_git --version',
                ],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=PROVENANCE_COMMAND_TIMEOUT_SECONDS,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("git version", result.stdout)
            self.assertFalse(attacker_marker.exists(), result.stdout + result.stderr)
            self.assertEqual(self.read_commands(git_log), [])

    def test_public_provisioning_scrubs_dynamic_loader_state_before_processes(self):
        with tempfile.TemporaryDirectory(prefix="modsecurity-v3-loader-environment-") as temporary:
            temporary_path = Path(temporary)
            environment, source_dir, _, git_log, _ = self.create_fixture(temporary_path)
            result = self.run_common_function(
                environment,
                'export LD_TRACE_LOADED_OBJECTS=1\n'
                '. "$FRAMEWORK_ROOT/ci/lib/common.sh"\n'
                'ci_modsecurity_v3_require_host_git() {\n'
                '    ci_v3_host_git_bin=$FAKE_GIT_BIN\n'
                '    return 0\n'
                '}\n'
                'ci_provision_approved_modsecurity_v3_checkout "$1"',
                source_dir,
            )
            commands = self.read_commands(git_log)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("init", self.git_verbs(commands))
            self.assertIn("checkout", self.git_verbs(commands))

    def test_rejects_a_symlinked_fresh_destination_parent_before_git(self):
        with tempfile.TemporaryDirectory(prefix="modsecurity-v3-parent-symlink-") as temporary:
            temporary_path = Path(temporary)
            environment, _, _, git_log, _ = self.create_fixture(temporary_path)
            real_parent = temporary_path / "real-parent"
            real_parent.mkdir()
            symlinked_parent = temporary_path / "symlinked-parent"
            os.symlink(real_parent, symlinked_parent, target_is_directory=True)
            destination = symlinked_parent / "ModSecurity_V3"
            result = subprocess.run(
                [environment["FAKE_PROVISION_HARNESS"], str(destination)],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=PROVENANCE_COMMAND_TIMEOUT_SECONDS,
            )
            self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
            self.assertEqual(self.read_commands(git_log), [])
            self.assertFalse((real_parent / "ModSecurity_V3").exists())

    def test_fresh_root_checkout_contains_worktree_and_suppresses_attributes(self):
        with tempfile.TemporaryDirectory(prefix="modsecurity-v3-fresh-root-") as temporary:
            temporary_path = Path(temporary)
            environment, _, _, _, _ = self.create_fixture(temporary_path)
            origin, _, commit = self.create_real_commit_origin(temporary_path, "root")
            destination = temporary_path / "fresh-checkout"
            redirected_worktree = temporary_path / "redirected-worktree"
            attributes = temporary_path / "attacker.attributes"
            attributes.write_text("payload.txt filter=evil\n", encoding="utf-8")
            marker = temporary_path / "smudge-ran"
            smudge = temporary_path / "smudge.sh"
            self.write_executable(smudge, f"#!/bin/sh\n: > {shlex.quote(str(marker))}\ncat\n")
            self.initialize_real_checkout(destination, origin, commit)
            git_dir = destination / ".git"
            self.run_system_git(
                f"--git-dir={git_dir}",
                "config",
                "--local",
                "core.worktree",
                str(redirected_worktree),
            )
            self.run_system_git(
                f"--git-dir={git_dir}",
                "config",
                "--local",
                "core.attributesfile",
                str(attributes),
            )
            self.run_system_git(
                f"--git-dir={git_dir}",
                "config",
                "--local",
                "filter.evil.smudge",
                str(smudge),
            )
            result = self.run_common_function(
                environment,
                '. "$FRAMEWORK_ROOT/ci/lib/common.sh"\n'
                'ci_modsecurity_v3_fresh_root_git "$1" checkout --detach "$2"',
                destination,
                commit,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((destination / "payload.txt").read_text(encoding="utf-8"), "root payload\n")
            self.assertFalse((redirected_worktree / "payload.txt").exists())
            self.assertFalse(marker.exists(), result.stdout + result.stderr)

    def test_scrubs_local_custom_submodule_update_and_executes_real_fresh_submodule_helper(self):
        with tempfile.TemporaryDirectory(prefix="modsecurity-v3-submodule-config-") as temporary:
            temporary_path = Path(temporary)
            environment, _, _, _, _ = self.create_fixture(temporary_path)
            child_origin, _, _ = self.create_real_commit_origin(temporary_path, "child")
            root_origin, root_worktree, _ = self.create_real_commit_origin(temporary_path, "parent")
            self.run_system_git(
                "-C",
                str(root_worktree),
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                str(child_origin),
                "vendor/child",
            )
            self.run_system_git("-C", str(root_worktree), "add", ".gitmodules", "vendor/child")
            self.run_system_git("-C", str(root_worktree), "commit", "-m", "add child fixture")
            root_commit = self.run_system_git(
                "-C", str(root_worktree), "rev-parse", "HEAD", capture_output=True
            ).stdout.strip()
            self.run_system_git("-C", str(root_worktree), "push", "origin", "HEAD:main")
            destination = temporary_path / "fresh-parent-checkout"
            self.initialize_real_checkout(destination, root_origin, root_commit)
            self.run_system_git("-C", str(destination), "checkout", "--detach", root_commit)
            preinitialized = subprocess.run(
                [
                    "/usr/bin/git",
                    "-C",
                    str(destination),
                    "-c",
                    "protocol.file.allow=always",
                    "submodule",
                    "update",
                    "--init",
                    "--recursive",
                    "--checkout",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=PROVENANCE_COMMAND_TIMEOUT_SECONDS,
            )
            self.assertEqual(preinitialized.returncode, 0, preinitialized.stdout + preinitialized.stderr)
            marker = temporary_path / "custom-update-ran"
            custom_update = temporary_path / "custom-update.sh"
            self.write_executable(
                custom_update,
                f"#!/bin/sh\n: > {shlex.quote(str(marker))}\nexit 0\n",
            )
            git_dir = destination / ".git"
            self.run_system_git(
                f"--git-dir={git_dir}",
                "config",
                "--local",
                "submodule.vendor/child.update",
                f"!{custom_update}",
            )
            result = self.run_common_function(
                environment,
                '. "$FRAMEWORK_ROOT/ci/lib/common.sh"\n'
                'ci_modsecurity_v3_scrub_fresh_recursive_config "$1" &&\n'
                'ci_modsecurity_v3_fresh_root_git "$1" submodule update --init --recursive --checkout',
                destination,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            configured_update = subprocess.run(
                [
                    "/usr/bin/git",
                    f"--git-dir={git_dir}",
                    "config",
                    "--local",
                    "--get-all",
                    "submodule.vendor/child.update",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(configured_update.returncode, 1, configured_update.stdout + configured_update.stderr)
            self.assertTrue((destination / "vendor/child/payload.txt").is_file())
            self.assertFalse(marker.exists(), result.stdout + result.stderr)

    def test_sanitizes_untrusted_git_environment(self):
        result, commands, _ = self.invoke_fetch(
            overrides={
                "GIT_DIR": "untrusted-git-dir",
                "GIT_CONFIG_PARAMETERS": "'core.hooksPath=untrusted-hooks'",
                "GIT_SSL_NO_VERIFY": "1",
                "GIT_ASKPASS": "/bin/false",
            }
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("fetch", self.git_verbs(commands))

    def test_rejects_preexisting_source_before_git_or_consumption(self):
        result, commands, sentinel_exists = self.invoke_fetch(existing_source=True)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(commands, [], result.stdout + result.stderr)
        self.assertTrue(sentinel_exists)

    def test_rejects_unexpected_origin_before_fetch(self):
        result, commands, _ = self.invoke_fetch(
            overrides={"FAKE_GIT_ORIGIN": "https://github.com/attacker/ModSecurity.git"}
        )
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertIn("config", self.git_verbs(commands))
        self.assertNotIn("fetch", self.git_verbs(commands))

    def test_rejects_fetched_resolved_or_checked_out_commit_mismatch(self):
        for variable in (
            "FAKE_GIT_FETCH_HEAD_COMMIT",
            "FAKE_GIT_RESOLVED_COMMIT",
            "FAKE_GIT_HEAD_COMMIT",
        ):
            with self.subTest(variable=variable):
                result, commands, _ = self.invoke_fetch(overrides={variable: ALTERNATE_COMMIT})
                self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
                self.assertIn("fetch", self.git_verbs(commands))
                self.assertNotIn("submodule", self.git_verbs(commands))

    def test_rejects_recursive_topology_bypass_variants(self):
        for overrides in (
            {"FAKE_GIT_TOPOLOGY_MISSING": "bindings/python"},
            {"FAKE_GIT_TOPOLOGY_EXTRA": "1"},
            {"FAKE_GIT_CHILD_ORIGIN_MISMATCH": "1"},
            {"FAKE_GIT_CHILD_COMMIT_MISMATCH": "1"},
            {"FAKE_GIT_TOPOLOGY_SYMLINK": "others/libinjection"},
            {"FAKE_GIT_GITDIR_ESCAPE": "1"},
            {"FAKE_GIT_WORKTREE_REDIRECT": "1"},
            {"FAKE_GIT_EXTRA_REMOTE": "1"},
            {"FAKE_GIT_ATTACHED_HEAD": "1"},
            {"FAKE_GIT_DIRTY": "1"},
            {"FAKE_GIT_INDEX_FLAG": "1"},
        ):
            with self.subTest(overrides=overrides):
                result, commands, _ = self.invoke_fetch(overrides=overrides)
                self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
                self.assertIn("checkout", self.git_verbs(commands))

    def test_rejects_missing_root_manifest_before_recursive_initialization(self):
        result, commands, _ = self.invoke_fetch(
            overrides={"FAKE_GIT_ROOT_GITMODULES_MISSING": "1"}
        )
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertIn("checkout", self.git_verbs(commands))
        self.assertNotIn("submodule", self.git_verbs(commands))

    def invoke_existing_source_consumer(self, script):
        with tempfile.TemporaryDirectory(prefix="modsecurity-v3-consumer-") as temporary:
            temporary_path = Path(temporary)
            environment, source_dir, adapter_source, git_log, build_log = self.create_fixture(
                temporary_path, trap_build_commands=True
            )
            (source_dir / ".git").mkdir(parents=True)
            (source_dir / "untrusted-source-marker").write_text("unapproved", encoding="utf-8")
            environment.update(
                {
                    "FAKE_GIT_ORIGIN": "https://github.com/attacker/ModSecurity.git",
                    "MODSECURITY_APACHE_SOURCE_DIR": str(adapter_source),
                    "MODSECURITY_NGINX_SOURCE_DIR": str(adapter_source),
                    "BUILD_NGINX_FROM_SOURCE": "0",
                    "MODSECURITY_V3_DIR": str(temporary_path / "verified" / "build" / "v3-copy"),
                }
            )
            result = subprocess.run(
                ["sh", str(script)],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=PROVENANCE_COMMAND_TIMEOUT_SECONDS,
            )
            return result, self.read_commands(git_log), build_log.read_text(encoding="utf-8")

    def test_unapproved_existing_checkout_is_rejected_by_all_v3_build_paths_before_build(self):
        for script in (PREPARE_APACHE, PREPARE_NGINX, BUILD_V3):
            with self.subTest(script=script.name):
                result, commands, build_commands = self.invoke_existing_source_consumer(script)
                self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
                self.assertNotIn("fetch", self.git_verbs(commands))
                self.assertNotIn("submodule", self.git_verbs(commands))
                self.assertEqual(build_commands, "", result.stdout + result.stderr)

    def test_direct_build_path_requires_the_full_provenance_guard_before_copy(self):
        build_source = BUILD_V3.read_text(encoding="utf-8")
        guard = 'ci_require_approved_modsecurity_v3_checkout "$MODSECURITY_V3_SOURCE_DIR" || exit 77'
        self.assertIn(guard, build_source)
        self.assertLess(build_source.index(guard), build_source.index("run_logged copy-source"))

    def test_approved_fake_checkout_is_a_legitimate_direct_guard_control(self):
        with tempfile.TemporaryDirectory(prefix="modsecurity-v3-approved-build-") as temporary:
            temporary_path = Path(temporary)
            environment, source_dir, _, git_log, _ = self.create_fixture(temporary_path)
            create_approved_modsecurity_v3_topology(source_dir)
            result = subprocess.run(
                [environment["FAKE_DIRECT_CHECKOUT_HARNESS"], str(source_dir)],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=PROVENANCE_COMMAND_TIMEOUT_SECONDS,
            )
            commands = self.read_commands(git_log)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("config", self.git_verbs(commands))
            self.assertNotIn("fetch", self.git_verbs(commands))
            self.assertNotIn("submodule", self.git_verbs(commands))


if __name__ == "__main__":
    unittest.main()
