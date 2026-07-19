"""Regression coverage for the immutable ModSecurity v3 Git boundary.

The tests replace Git only where the provisioning and build scripts invoke it.
They never contact upstream or build a real ModSecurity checkout.
"""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FETCH_V3 = ROOT / "ci/provisioning/fetch-smoke-sources.sh"
PREPARE_APACHE = ROOT / "ci/provisioning/prepare-apache-build.sh"
PREPARE_NGINX = ROOT / "ci/provisioning/prepare-nginx-build.sh"
BUILD_V3 = ROOT / "ci/provisioning/build-v3-under-src.sh"
APPROVED_REPO = "https://github.com/owasp-modsecurity/ModSecurity.git"
APPROVED_COMMIT = "0fb4aff98b4980cf6426697d5605c424e3d5bb60"
APPROVED_RELEASE_TAG = "v3.0.15"
ALTERNATE_COMMIT = "a" * 40


FAKE_GIT = """#!/usr/bin/env python3
import os
from pathlib import Path
import sys

approved_repo = "https://github.com/owasp-modsecurity/ModSecurity.git"
approved_commit = "0fb4aff98b4980cf6426697d5605c424e3d5bb60"
log = Path(os.environ["FAKE_GIT_LOG"])
with log.open("a", encoding="utf-8") as handle:
    handle.write(" ".join(sys.argv[1:]) + "\\n")

for untrusted_environment_name in (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_CONFIG_PARAMETERS",
    "GIT_SSL_NO_VERIFY",
    "GIT_ASKPASS",
):
    if untrusted_environment_name in os.environ:
        sys.exit(91)

arguments = sys.argv[1:]
repository = None
while arguments:
    if arguments[0] == "-c":
        arguments = arguments[2:]
    elif arguments[0] == "-C":
        repository = arguments[1]
        arguments = arguments[2:]
    else:
        break

command = arguments[0] if arguments else ""
arguments = arguments[1:]
if command == "init":
    Path(arguments[-1], ".git").mkdir(parents=True, exist_ok=True)
elif command == "config":
    print(os.environ.get("FAKE_GIT_ORIGIN", approved_repo))
elif command == "fetch":
    sys.exit(int(os.environ.get("FAKE_GIT_FETCH_RC", "0")))
elif command == "checkout":
    if os.environ.get("FAKE_GIT_CREATE_GITMODULES") == "1" and repository:
        Path(repository, ".gitmodules").touch()
elif command == "rev-parse":
    if any(argument.startswith("FETCH_HEAD") for argument in arguments):
        print(os.environ.get("FAKE_GIT_FETCH_HEAD_COMMIT", approved_commit))
    elif any(argument.startswith("HEAD") for argument in arguments):
        print(os.environ.get("FAKE_GIT_HEAD_COMMIT", approved_commit))
    else:
        print(os.environ.get("FAKE_GIT_RESOLVED_COMMIT", approved_commit))
elif command == "ls-files":
    if os.environ.get("FAKE_GIT_GITLINK") == "1":
        print("160000 " + ("f" * 40) + " 0\\tthird-party")
"""


BUILD_TRAP = """#!/bin/sh
printf '%s %s\\n' "$0" "$*" >> "$FAKE_BUILD_LOG"
exit 96
"""


class ModSecurityV3ProvenanceTests(unittest.TestCase):
    maxDiff = None

    @staticmethod
    def git_verbs(commands):
        verbs = []
        for command_line in commands:
            arguments = shlex.split(command_line)
            while len(arguments) >= 2 and arguments[0] in {"-c", "-C"}:
                arguments = arguments[2:]
            if arguments:
                verbs.append(arguments[0])
        return verbs

    @staticmethod
    def write_executable(path, contents):
        path.write_text(contents, encoding="utf-8")
        path.chmod(0o755)

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
                ["sh", str(FETCH_V3), "v3"],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15,
            )
            return result, self.read_commands(git_log), sentinel.exists()

    def assert_blocked_before_git(self, overrides):
        result, commands, _ = self.invoke_fetch(overrides=overrides)
        self.assertEqual(77, result.returncode, result.stdout + result.stderr)
        self.assertEqual([], commands, result.stdout + result.stderr)

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
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn(f"fetch --depth 1 --no-tags origin {APPROVED_COMMIT}", command_text)
        self.assertNotIn(APPROVED_RELEASE_TAG, command_text)

    def test_fresh_control_fetches_only_the_reviewed_commit_without_submodules(self):
        result, commands, _ = self.invoke_fetch()
        command_text = "\n".join(commands)

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("init ", command_text)
        self.assertIn(f"remote add origin {APPROVED_REPO}", command_text)
        self.assertIn("config --get remote.origin.url", command_text)
        self.assertIn(f"fetch --depth 1 --no-tags origin {APPROVED_COMMIT}", command_text)
        self.assertIn("rev-parse --verify FETCH_HEAD^{commit}", command_text)
        self.assertIn(f"rev-parse --verify {APPROVED_COMMIT}^{{commit}}", command_text)
        self.assertIn(f"checkout --detach {APPROVED_COMMIT}", command_text)
        self.assertIn("rev-parse --verify HEAD^{commit}", command_text)
        self.assertNotIn("clone", self.git_verbs(commands))
        self.assertNotIn("submodule", self.git_verbs(commands))
        self.assertIn("-c core.hooksPath=/dev/null", command_text)
        self.assertIn("-c protocol.file.allow=never", command_text)
        self.assertIn("-c fetch.recurseSubmodules=false", command_text)
        self.assertIn("-c submodule.recurse=false", command_text)
        self.assertIn("-c http.sslVerify=true", command_text)
        self.assertNotIn(APPROVED_RELEASE_TAG, command_text)

    def test_sanitizes_untrusted_git_environment(self):
        result, commands, _ = self.invoke_fetch(
            overrides={
                "GIT_DIR": "untrusted-git-dir",
                "GIT_CONFIG_PARAMETERS": "'core.hooksPath=untrusted-hooks'",
                "GIT_SSL_NO_VERIFY": "1",
                "GIT_ASKPASS": "/bin/false",
            }
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("fetch", self.git_verbs(commands))

    def test_rejects_preexisting_source_before_git_or_consumption(self):
        result, commands, sentinel_exists = self.invoke_fetch(existing_source=True)
        self.assertEqual(77, result.returncode, result.stdout + result.stderr)
        self.assertEqual([], commands, result.stdout + result.stderr)
        self.assertTrue(sentinel_exists)

    def test_rejects_unexpected_origin_before_fetch(self):
        result, commands, _ = self.invoke_fetch(
            overrides={"FAKE_GIT_ORIGIN": "https://github.com/attacker/ModSecurity.git"}
        )
        self.assertEqual(77, result.returncode, result.stdout + result.stderr)
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
                self.assertEqual(77, result.returncode, result.stdout + result.stderr)
                self.assertIn("fetch", self.git_verbs(commands))
                self.assertNotIn("submodule", self.git_verbs(commands))

    def test_rejects_submodule_manifest_and_gitlinks(self):
        for overrides in (
            {"FAKE_GIT_CREATE_GITMODULES": "1"},
            {"FAKE_GIT_GITLINK": "1"},
        ):
            with self.subTest(overrides=overrides):
                result, commands, _ = self.invoke_fetch(overrides=overrides)
                self.assertEqual(77, result.returncode, result.stdout + result.stderr)
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
                timeout=15,
            )
            return result, self.read_commands(git_log), build_log.read_text(encoding="utf-8")

    def test_unapproved_existing_checkout_is_rejected_by_all_v3_build_paths_before_build(self):
        for script in (PREPARE_APACHE, PREPARE_NGINX, BUILD_V3):
            with self.subTest(script=script.name):
                result, commands, build_commands = self.invoke_existing_source_consumer(script)
                self.assertEqual(77, result.returncode, result.stdout + result.stderr)
                self.assertIn("config", self.git_verbs(commands))
                self.assertNotIn("fetch", self.git_verbs(commands))
                self.assertNotIn("submodule", self.git_verbs(commands))
                self.assertEqual("", build_commands, result.stdout + result.stderr)

    def test_approved_fake_checkout_is_a_legitimate_direct_build_control(self):
        with tempfile.TemporaryDirectory(prefix="modsecurity-v3-approved-build-") as temporary:
            temporary_path = Path(temporary)
            environment, source_dir, _, git_log, _ = self.create_fixture(temporary_path)
            (source_dir / ".git").mkdir(parents=True)
            self.write_executable(source_dir / "build.sh", "#!/bin/sh\nexit 0\n")
            self.write_executable(source_dir / "configure", "#!/bin/sh\nexit 0\n")
            (source_dir / "Makefile").write_text(
                "all:\n\tmkdir -p src/.libs\n\t: > src/.libs/libmodsecurity.so\n",
                encoding="utf-8",
            )
            destination = temporary_path / "verified" / "build" / "v3-build"
            environment["MODSECURITY_V3_DIR"] = str(destination)
            result = subprocess.run(
                ["sh", str(BUILD_V3)],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15,
            )
            commands = self.read_commands(git_log)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertTrue((destination / "src/.libs/libmodsecurity.so").is_file())
            self.assertIn("config", self.git_verbs(commands))
            self.assertNotIn("fetch", self.git_verbs(commands))
            self.assertNotIn("submodule", self.git_verbs(commands))


if __name__ == "__main__":
    unittest.main()
