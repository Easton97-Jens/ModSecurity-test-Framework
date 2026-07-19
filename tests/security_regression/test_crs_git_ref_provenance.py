"""Regression coverage for the CRS Git provenance boundary.

The fixture replaces Git only at the process boundary used by fetch-crs.sh.
It never contacts a remote or creates a real CRS checkout.
"""

import importlib.util
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FETCH_CRS = ROOT / "ci/provisioning/fetch-crs.sh"
CHECK_COMMON_VERSIONS = ROOT / "ci/tools/check-common-versions.py"
APPROVED_REPO = "https://github.com/coreruleset/coreruleset.git"
APPROVED_COMMIT = "55b09f5acfd16413e7b31041100711ceb7adc89c"
APPROVED_RELEASE_TAG = "v4.28.0"
ALTERNATE_COMMIT = "a" * 40
ANNOTATED_TAG_OBJECT = "5d2bd9a1ad7e607813f9e19cc73fa44dd5dd2ceb"


def load_common_version_checker():
    spec = importlib.util.spec_from_file_location("check_common_versions", CHECK_COMMON_VERSIONS)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the common-version checker")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


COMMON_VERSION_CHECKER = load_common_version_checker()


FAKE_GIT = """#!/usr/bin/env python3
import os
from pathlib import Path
import sys

approved_repo = "https://github.com/coreruleset/coreruleset.git"
approved_commit = "55b09f5acfd16413e7b31041100711ceb7adc89c"
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
elif command == "clone":
    Path(arguments[-1], ".git").mkdir(parents=True, exist_ok=True)
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
elif command == "submodule":
    sys.exit(int(os.environ.get("FAKE_GIT_SUBMODULE_RC", "0")))
"""


class FetchCrsProvenanceTests(unittest.TestCase):
    maxDiff = None

    @staticmethod
    def git_verbs(commands):
        verbs = []
        for command_line in commands:
            arguments = shlex.split(command_line)
            while arguments and arguments[0] in {"-c", "-C"}:
                arguments = arguments[2:]
            if arguments:
                verbs.append(arguments[0])
        return verbs

    def invoke_fetch(self, *, overrides=None, existing_source=False):
        """Run the real fetch script with only its Git executable mocked."""
        with tempfile.TemporaryDirectory(prefix="crs-provenance-") as temporary:
            temporary_path = Path(temporary)
            verified_root = temporary_path / "verified"
            source_root = verified_root / "src"
            source_root.mkdir(parents=True)
            source_dir = source_root / "coreruleset"
            sentinel = source_dir / "untrusted-rules.conf"
            if existing_source:
                (source_dir / ".git").mkdir(parents=True)
                sentinel.write_text("untrusted existing checkout", encoding="utf-8")

            fake_bin = temporary_path / "bin"
            fake_bin.mkdir()
            fake_git = fake_bin / "git"
            fake_git.write_text(FAKE_GIT, encoding="utf-8")
            fake_git.chmod(0o755)
            git_log = temporary_path / "git.log"
            git_log.touch()

            environment = os.environ.copy()
            environment.update(
                {
                    "CI_ROOT": str(ROOT / "ci"),
                    "FRAMEWORK_ROOT": str(ROOT),
                    "CONNECTOR_ROOT": str(ROOT),
                    "REPO_ROOT": str(ROOT),
                    "VERIFIED_RUN_ROOT": str(verified_root),
                    "SOURCE_ROOT": str(source_root),
                    "BUILD_ROOT": str(verified_root / "build"),
                    "TMP_ROOT": str(verified_root / "tmp"),
                    "LOG_ROOT": str(verified_root / "logs"),
                    "CRS_SOURCE_DIR": str(source_dir),
                    "CRS_RUNTIME_DIR": str(verified_root / "build" / "crs"),
                    "FAKE_GIT_LOG": str(git_log),
                    "FAKE_GIT_ORIGIN": APPROVED_REPO,
                    "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
                }
            )
            environment.update(overrides or {})
            result = subprocess.run(
                ["sh", str(FETCH_CRS)],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15,
            )
            commands = [line.rstrip() for line in git_log.read_text(encoding="utf-8").splitlines() if line.strip()]
            return result, commands, sentinel.exists()

    def assert_blocked_before_git(self, overrides):
        result, commands, _ = self.invoke_fetch(overrides=overrides)
        self.assertEqual(77, result.returncode, result.stdout + result.stderr)
        self.assertEqual([], commands, result.stdout + result.stderr)

    def test_rejects_mutable_ref_forms_before_git(self):
        for rejected_ref in (
            "v4.27.0",
            "main",
            "refs/tags/v4.28.0",
            "refs/heads/main",
            "refs/remotes/origin/main",
            "55b09f5",
            ANNOTATED_TAG_OBJECT,
        ):
            with self.subTest(ref=rejected_ref):
                self.assert_blocked_before_git({"CRS_GIT_REF": rejected_ref})

    def test_default_release_tag_is_metadata_not_a_git_selector(self):
        result, commands, _ = self.invoke_fetch(overrides={"CRS_GIT_REF": APPROVED_RELEASE_TAG})
        command_text = "\n".join(commands)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn(f"fetch --depth 1 --no-tags origin {APPROVED_COMMIT}", command_text)
        self.assertNotIn(APPROVED_RELEASE_TAG, command_text)
        self.assertNotIn("--branch", command_text)
        self.assertNotIn("checkout --detach FETCH_HEAD", command_text)

    def test_rejects_runtime_url_and_ref_overrides_or_ignores_approved_commit_override(self):
        self.assert_blocked_before_git({"CRS_REPO_URL": "https://github.com/attacker/crs.git"})
        self.assert_blocked_before_git({"CRS_GIT_REF": "main"})

        result, commands, _ = self.invoke_fetch(overrides={"CRS_APPROVED_COMMIT": ALTERNATE_COMMIT})
        command_text = "\n".join(commands)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn(APPROVED_COMMIT, command_text)
        self.assertNotIn(ALTERNATE_COMMIT, command_text)

        alternate_repo = "https://github.com/attacker/approved-crs.git"
        result, commands, _ = self.invoke_fetch(overrides={"CRS_APPROVED_REPO_URL": alternate_repo})
        command_text = "\n".join(commands)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn(APPROVED_REPO, command_text)
        self.assertNotIn(alternate_repo, command_text)

    def test_crs_git_sanitizes_untrusted_git_environment(self):
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

    def test_fresh_control_checks_origin_commit_object_and_head(self):
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

    def test_rejects_unexpected_origin_before_fetch(self):
        result, commands, _ = self.invoke_fetch(overrides={"FAKE_GIT_ORIGIN": "https://github.com/attacker/crs.git"})
        command_text = "\n".join(commands)
        self.assertEqual(77, result.returncode, result.stdout + result.stderr)
        self.assertIn("config --get remote.origin.url", command_text)
        self.assertNotIn("fetch", self.git_verbs(commands))

    def test_rejects_preexisting_source_before_git_or_crs_consumption(self):
        result, commands, sentinel_exists = self.invoke_fetch(existing_source=True)
        self.assertEqual(77, result.returncode, result.stdout + result.stderr)
        self.assertEqual([], commands, result.stdout + result.stderr)
        self.assertTrue(sentinel_exists)

    def test_rejects_resolved_commit_or_final_head_mismatch_before_submodules(self):
        result, commands, _ = self.invoke_fetch(overrides={"FAKE_GIT_FETCH_HEAD_COMMIT": ALTERNATE_COMMIT})
        command_text = "\n".join(commands)
        self.assertEqual(77, result.returncode, result.stdout + result.stderr)
        self.assertIn("rev-parse --verify FETCH_HEAD^{commit}", command_text)
        self.assertNotIn("checkout", self.git_verbs(commands))
        self.assertNotIn("submodule", self.git_verbs(commands))

        result, commands, _ = self.invoke_fetch(overrides={"FAKE_GIT_RESOLVED_COMMIT": ALTERNATE_COMMIT})
        command_text = "\n".join(commands)
        self.assertEqual(77, result.returncode, result.stdout + result.stderr)
        self.assertIn("rev-parse --verify", command_text)
        self.assertNotIn("checkout", self.git_verbs(commands))
        self.assertNotIn("submodule", self.git_verbs(commands))

        result, commands, _ = self.invoke_fetch(overrides={"FAKE_GIT_HEAD_COMMIT": ALTERNATE_COMMIT})
        command_text = "\n".join(commands)
        self.assertEqual(77, result.returncode, result.stdout + result.stderr)
        self.assertIn(f"checkout --detach {APPROVED_COMMIT}", command_text)
        self.assertIn("rev-parse --verify HEAD^{commit}", command_text)
        self.assertNotIn("submodule", self.git_verbs(commands))

    def test_rejects_submodule_manifest_after_parent_verification(self):
        result, commands, _ = self.invoke_fetch(overrides={"FAKE_GIT_CREATE_GITMODULES": "1"})
        command_text = "\n".join(commands)
        self.assertEqual(77, result.returncode, result.stdout + result.stderr)
        self.assertIn("rev-parse --verify HEAD^{commit}", command_text)
        self.assertNotIn("submodule", self.git_verbs(commands))

    def test_version_checker_requires_reviewed_release_tag_and_commit_pair(self):
        class FakeGithubClient:
            def __init__(self):
                self.urls = []

            def get_json(self, url):
                self.urls.append(url)
                return {"tag_name": "v4.29.0"}

        _, entries = COMMON_VERSION_CHECKER.parse_common(ROOT / "ci/lib/common.sh")
        client = FakeGithubClient()
        result = COMMON_VERSION_CHECKER.check_crs_release_provenance(entries, client)

        self.assertEqual(APPROVED_REPO, COMMON_VERSION_CHECKER.value(entries, "CRS_APPROVED_REPO_URL"))
        self.assertEqual(APPROVED_COMMIT, COMMON_VERSION_CHECKER.value(entries, "CRS_APPROVED_COMMIT"))
        self.assertEqual(APPROVED_RELEASE_TAG, COMMON_VERSION_CHECKER.value(entries, "CRS_RELEASE_TAG"))
        self.assertEqual(COMMON_VERSION_CHECKER.STATUS_UNKNOWN, result.status)
        self.assertEqual([], result.updates)
        self.assertEqual(
            ["CRS_APPROVED_REPO_URL", "CRS_RELEASE_TAG", "CRS_APPROVED_COMMIT"],
            result.variables,
        )
        self.assertEqual(
            "update CRS_RELEASE_TAG and CRS_APPROVED_COMMIT together after commit provenance review",
            result.details["reason"],
        )
        self.assertEqual(
            ["https://api.github.com/repos/coreruleset/coreruleset/releases/latest"],
            client.urls,
        )


if __name__ == "__main__":
    unittest.main()
