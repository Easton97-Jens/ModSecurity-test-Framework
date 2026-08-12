"""Regression coverage for the CRS Git provenance boundary.

The fixture replaces Git only at the process boundary used by fetch-crs.sh.
It never contacts a remote or creates a real CRS checkout.
"""

import importlib.util
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


from tests.security_regression.common_version_fixture_support import (
    write_common_fixture,
)
from tests.security_regression.git_provenance_test_support import (
    assert_immutable_commit_fetch_control,
)


ROOT = Path(__file__).resolve().parents[2]
FETCH_CRS = ROOT / "ci/provisioning/fetch-crs.sh"
CHECK_COMMON_VERSIONS = ROOT / "ci/tools/check-common-versions.py"
APPROVED_REPO = "https://github.com/coreruleset/coreruleset.git"
APPROVED_COMMIT = "c" * 40
APPROVED_RELEASE_TAG = "v4.900.0"
ALTERNATE_COMMIT = "a" * 40
ANNOTATED_TAG_OBJECT = "5d2bd9a1ad7e607813f9e19cc73fa44dd5dd2ceb"
EMPTY_GIT_BLOB = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
NONEMPTY_GIT_BLOB = "f" * 40
GITLINK_OBJECT = "d" * 40


def load_common_version_checker():
    spec = importlib.util.spec_from_file_location(
        "check_common_versions", CHECK_COMMON_VERSIONS
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the common-version checker")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


COMMON_VERSION_CHECKER = load_common_version_checker()


FAKE_GIT = (
    """#!/usr/bin/env python3
import os
from pathlib import Path
import sys

approved_repo = __APPROVED_REPO__
approved_commit = __APPROVED_COMMIT__
empty_blob = __EMPTY_GIT_BLOB__
nonempty_blob = __NONEMPTY_GIT_BLOB__
gitlink_object = __GITLINK_OBJECT__
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

gitmodules_case = os.environ.get("FAKE_GIT_GITMODULES_CASE", "absent")
failure = os.environ.get("FAKE_GIT_FAIL")


def is_scoped_gitmodules_query():
    return ".gitmodules" in arguments


def should_fail():
    if failure == command:
        return True
    if failure == "rev-parse-gitmodules":
        return command == "rev-parse" and any(
            ":.gitmodules" in argument for argument in arguments
        )
    if failure == "ls-files-index":
        return command == "ls-files" and not is_scoped_gitmodules_query()
    if failure == "ls-files-scoped":
        return command == "ls-files" and is_scoped_gitmodules_query()
    if failure == "config-submodule":
        return command == "config" and "--get-regexp" in arguments
    if failure == "ls-files-untracked":
        return command == "ls-files" and "--others" in arguments
    if failure == "diff-gitmodules":
        return command == "diff" and ".gitmodules" in arguments
    if failure == "diff-worktree":
        return command == "diff" and "--cached" not in arguments and ".gitmodules" not in arguments
    if failure == "diff-index":
        return command == "diff" and "--cached" in arguments
    return False


if should_fail():
    sys.exit(2)


def gitmodules_content(case):
    return {
        "empty": b"",
        "newline": b"\\n",
        "whitespace": b" \\t\\n",
        "comment": b"# not empty\\n",
        "declaration": b"[submodule \\\"attacker\\\"]\\npath = attacker\\n",
        "worktree-mismatch": b"",
        "symlink": b"",
        "special": b"",
        "wrong-mode": b"",
    }.get(case, b"")


def gitmodules_blob(case):
    if case in {"newline", "whitespace", "comment", "declaration"}:
        return nonempty_blob
    return empty_blob


def has_checkout_gitmodules(case):
    return case != "absent"


def has_tree_gitmodules(case):
    return case not in {"absent", "untracked"}


def tree_entry(case):
    if not has_tree_gitmodules(case):
        return ""
    mode = "100755" if case == "wrong-mode" else "100644"
    return f"{mode} blob {gitmodules_blob(case)}\\t.gitmodules"


def write_gitmodules_checkout(path, case):
    gitmodules = path / ".gitmodules"
    if not has_checkout_gitmodules(case):
        return
    if case == "symlink":
        target = path.parent / "gitmodules-target"
        target.write_bytes(b"")
        os.symlink(target, gitmodules)
        return
    if case == "special":
        gitmodules.mkdir()
        return
    content = gitmodules_content(case)
    if case == "worktree-mismatch":
        content = b"tampered"
    gitmodules.write_bytes(content)
    if case == "wrong-mode":
        gitmodules.chmod(0o755)
    if case == "worktree-wrong-mode":
        gitmodules.chmod(0o755)


def gitmodules_checkout_matches_tree(path, case):
    gitmodules = path / ".gitmodules"
    if not has_tree_gitmodules(case):
        return not os.path.lexists(gitmodules)
    if gitmodules.is_symlink() or not gitmodules.is_file():
        return False
    if gitmodules.read_bytes() != gitmodules_content(case):
        return False
    expected_mode = 0o755 if case == "wrong-mode" else 0o644
    return gitmodules.stat().st_mode & 0o777 == expected_mode


def tree_lines(recursive):
    lines = []
    entry = tree_entry(gitmodules_case)
    if entry:
        lines.append(entry)
    if recursive and os.environ.get("FAKE_GIT_TREE_GITLINK") == "1":
        lines.append(f"160000 commit {gitlink_object}\\tmodules/real")
    if recursive and os.environ.get("FAKE_GIT_NESTED_GITMODULES") == "1":
        lines.append(f"100644 blob {empty_blob}\\tnested/.gitmodules")
    if recursive and os.environ.get("FAKE_GIT_TRAVERSAL_GITMODULES") == "1":
        lines.append(f"100644 blob {empty_blob}\\t../.gitmodules")
    return lines


if command == "init":
    Path(arguments[-1], ".git").mkdir(parents=True, exist_ok=True)
elif command == "config":
    if "--get-regexp" in arguments:
        if os.environ.get("FAKE_GIT_SUBMODULE_CONFIG") == "1":
            print("submodule.attacker.path attacker")
        else:
            sys.exit(1)
    else:
        print(os.environ.get("FAKE_GIT_ORIGIN", approved_repo))
elif command == "clone":
    Path(arguments[-1], ".git").mkdir(parents=True, exist_ok=True)
elif command == "fetch":
    if any(argument.startswith("refs/tags/") for argument in arguments):
        sys.exit(int(os.environ.get("FAKE_GIT_TAG_FETCH_RC", "0")))
    sys.exit(int(os.environ.get("FAKE_GIT_FETCH_RC", "0")))
elif command == "checkout":
    if repository:
        checkout = Path(repository)
        write_gitmodules_checkout(checkout, gitmodules_case)
        if os.environ.get("FAKE_GIT_MODULES_REGISTRY") == "1":
            (checkout / ".git" / "modules").mkdir(parents=True, exist_ok=True)
elif command == "rev-parse":
    if any(":.gitmodules" in argument for argument in arguments):
        print(gitmodules_blob(gitmodules_case))
    elif any(argument.startswith("FETCH_HEAD") for argument in arguments):
        print(os.environ.get("FAKE_GIT_FETCH_HEAD_COMMIT", approved_commit))
    elif any(argument.startswith("refs/tags/") for argument in arguments):
        print(os.environ.get("FAKE_GIT_TAG_COMMIT", approved_commit))
    elif any(argument.startswith("HEAD") for argument in arguments):
        print(os.environ.get("FAKE_GIT_HEAD_COMMIT", approved_commit))
    else:
        print(os.environ.get("FAKE_GIT_RESOLVED_COMMIT", approved_commit))
elif command == "ls-tree":
    recursive = "-r" in arguments
    for line in tree_lines(recursive):
        print(line)
elif command == "cat-file":
    if "-s" in arguments:
        print(len(gitmodules_content(gitmodules_case)))
elif command == "show":
    sys.stdout.buffer.write(gitmodules_content(gitmodules_case))
elif command == "hash-object":
    if gitmodules_case == "worktree-mismatch":
        print(nonempty_blob)
    else:
        print(gitmodules_blob(gitmodules_case))
elif command == "ls-files":
    if "--others" in arguments:
        if os.environ.get("FAKE_GIT_UNTRACKED") == "1":
            print("rules/untrusted.conf")
    else:
        if (
            has_tree_gitmodules(gitmodules_case)
            or os.environ.get("FAKE_GIT_INDEX_UNTRACKED") == "1"
        ):
            blob = (
                nonempty_blob
                if os.environ.get("FAKE_GIT_INDEX_MISMATCH") == "1"
                else gitmodules_blob(gitmodules_case)
            )
            print(f"100644 {blob} 0\\t.gitmodules")
            if os.environ.get("FAKE_GIT_INDEX_DUPLICATE") == "1":
                print(f"100644 {blob} 1\\t.gitmodules")
        if (
            not is_scoped_gitmodules_query()
            and os.environ.get("FAKE_GIT_INDEX_GITLINK") == "1"
        ):
            print(f"160000 {gitlink_object} 0\\tmodules/real")
elif command == "diff":
    if repository and not gitmodules_checkout_matches_tree(
        Path(repository), gitmodules_case
    ):
        sys.exit(1)
elif command == "submodule":
    sys.exit(int(os.environ.get("FAKE_GIT_SUBMODULE_RC", "0")))
""".replace("__APPROVED_REPO__", repr(APPROVED_REPO))
    .replace("__APPROVED_COMMIT__", repr(APPROVED_COMMIT))
    .replace("__EMPTY_GIT_BLOB__", repr(EMPTY_GIT_BLOB))
    .replace("__NONEMPTY_GIT_BLOB__", repr(NONEMPTY_GIT_BLOB))
    .replace("__GITLINK_OBJECT__", repr(GITLINK_OBJECT))
)


class FetchCrsProvenanceTests(unittest.TestCase):
    maxDiff = None

    @staticmethod
    def create_framework_fixture(root: Path) -> Path:
        """Copy the entrypoint boundary so bootstrap derives fixture-local paths."""

        (root / "ci/lib").mkdir(parents=True)
        (root / "ci/provisioning").mkdir(parents=True)
        (root / "tests").mkdir()
        (root / "Makefile").write_text("# test-only framework root\n", encoding="utf-8")
        shutil.copy2(ROOT / "ci/lib/path.sh", root / "ci/lib/path.sh")
        shutil.copy2(
            ROOT / "ci/lib/path-bootstrap.sh", root / "ci/lib/path-bootstrap.sh"
        )
        shutil.copy2(FETCH_CRS, root / "ci/provisioning/fetch-crs.sh")
        shutil.copy2(
            ROOT / "ci/provisioning/crs-provenance.sh",
            root / "ci/provisioning/crs-provenance.sh",
        )
        shutil.copy2(
            ROOT / "ci/provisioning/prepare-crs.sh",
            root / "ci/provisioning/prepare-crs.sh",
        )
        source = (ROOT / "ci/lib/common.sh").read_text(encoding="utf-8")
        write_common_fixture(
            root,
            source,
            {
                "CRS_APPROVED_COMMIT": APPROVED_COMMIT,
                "CRS_RELEASE_TAG": APPROVED_RELEASE_TAG,
            },
        )
        return root / "ci/provisioning/fetch-crs.sh"

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

    def invoke_fetch(
        self,
        *,
        overrides=None,
        existing_source=False,
        source_location="source",
        after_fetch=None,
    ):
        """Run the real fetch script with only its Git executable mocked."""
        with tempfile.TemporaryDirectory(prefix="crs-provenance-") as temporary:
            temporary_path = Path(temporary)
            fixture_script = self.create_framework_fixture(
                temporary_path / "framework-fixture"
            )
            verified_root = temporary_path / "verified"
            source_root = verified_root / "src"
            source_root.mkdir(parents=True)
            if source_location == "source":
                source_dir = source_root / "coreruleset"
            elif source_location == "cache":
                source_dir = verified_root / "component-cache" / "coreruleset"
            elif source_location == "outside":
                source_dir = temporary_path / "outside" / "coreruleset"
            else:
                raise AssertionError(f"unsupported source location: {source_location}")
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
                    "CI_ROOT": str(fixture_script.parents[1]),
                    "FRAMEWORK_ROOT": str(fixture_script.parents[2]),
                    "CONNECTOR_ROOT": str(ROOT),
                    "REPO_ROOT": str(ROOT),
                    "VERIFIED_RUN_ROOT": str(verified_root),
                    "SOURCE_ROOT": str(source_root),
                    "BUILD_ROOT": str(verified_root / "build"),
                    "TMP_ROOT": str(verified_root / "tmp"),
                    "LOG_ROOT": str(verified_root / "logs"),
                    "CRS_SOURCE_DIR": str(source_dir),
                    "CRS_RUNTIME_DIR": str(verified_root / "build" / "crs"),
                    "CONNECTOR_COMPONENT_CACHE": str(verified_root / "component-cache"),
                    "FAKE_GIT_LOG": str(git_log),
                    "FAKE_GIT_ORIGIN": APPROVED_REPO,
                    "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
                }
            )
            environment.update(overrides or {})
            result = subprocess.run(
                ["sh", str(fixture_script)],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15,
            )
            after_fetch_result = None
            if after_fetch is not None:
                after_fetch_result = after_fetch(
                    source_dir,
                    Path(environment["CRS_RUNTIME_DIR"]),
                    fixture_script.with_name("prepare-crs.sh"),
                    environment,
                )
            commands = [
                line.rstrip()
                for line in git_log.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            if after_fetch is not None:
                return result, commands, sentinel.exists(), after_fetch_result
            return result, commands, sentinel.exists()

    def assert_blocked_before_git(self, overrides):
        result, commands, _ = self.invoke_fetch(overrides=overrides)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(commands, [], result.stdout + result.stderr)

    def test_rejects_mutable_ref_forms_before_git(self):
        for rejected_ref in (
            "v4.8999",
            "main",
            "refs/tags/v4.900.0",
            "refs/heads/main",
            "refs/remotes/origin/main",
            "55b09f5",
            ANNOTATED_TAG_OBJECT,
        ):
            with self.subTest(ref=rejected_ref):
                self.assert_blocked_before_git({"CRS_GIT_REF": rejected_ref})

    def test_default_release_tag_is_fetched_and_peeled_to_the_approved_commit(self):
        result, commands, _ = self.invoke_fetch(
            overrides={"CRS_GIT_REF": APPROVED_RELEASE_TAG}
        )
        command_text = "\n".join(commands)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            f"fetch --depth 1 --no-tags origin {APPROVED_COMMIT}", command_text
        )
        self.assertIn(
            "fetch --depth 1 --no-tags origin "
            f"refs/tags/{APPROVED_RELEASE_TAG}:refs/tags/{APPROVED_RELEASE_TAG}",
            command_text,
        )
        self.assertIn(
            f"rev-parse --verify refs/tags/{APPROVED_RELEASE_TAG}^{{}}",
            command_text,
        )
        self.assertNotIn("--branch", command_text)
        self.assertNotIn("checkout --detach FETCH_HEAD", command_text)

    def test_rejects_missing_or_moved_reviewed_release_tag(self):
        for overrides in (
            {"FAKE_GIT_TAG_FETCH_RC": "2"},
            {"FAKE_GIT_TAG_COMMIT": ALTERNATE_COMMIT},
        ):
            with self.subTest(overrides=overrides):
                result, commands, _ = self.invoke_fetch(overrides=overrides)
                command_text = "\n".join(commands)
                self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
                self.assertIn(
                    f"refs/tags/{APPROVED_RELEASE_TAG}:refs/tags/{APPROVED_RELEASE_TAG}",
                    command_text,
                )
                if "FAKE_GIT_TAG_COMMIT" in overrides:
                    self.assertIn(
                        f"rev-parse --verify refs/tags/{APPROVED_RELEASE_TAG}^{{}}",
                        command_text,
                    )
                self.assertNotIn("checkout", self.git_verbs(commands))

    def test_rejects_runtime_url_and_ref_overrides_or_ignores_approved_commit_override(
        self,
    ):
        self.assert_blocked_before_git(
            {"CRS_REPO_URL": "https://github.com/attacker/crs.git"}
        )
        self.assert_blocked_before_git({"CRS_GIT_REF": "main"})

        result, commands, _ = self.invoke_fetch(
            overrides={"CRS_APPROVED_COMMIT": ALTERNATE_COMMIT}
        )
        command_text = "\n".join(commands)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(APPROVED_COMMIT, command_text)
        self.assertNotIn(ALTERNATE_COMMIT, command_text)

        alternate_repo = "https://github.com/attacker/approved-crs.git"
        result, commands, _ = self.invoke_fetch(
            overrides={"CRS_APPROVED_REPO_URL": alternate_repo}
        )
        command_text = "\n".join(commands)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
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
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("fetch", self.git_verbs(commands))

    def test_fresh_control_checks_origin_commit_object_and_head(self):
        result, commands, _ = self.invoke_fetch()
        assert_immutable_commit_fetch_control(
            self, result, commands, self.git_verbs, APPROVED_REPO, APPROVED_COMMIT
        )

    def test_rejects_unexpected_origin_before_fetch(self):
        result, commands, _ = self.invoke_fetch(
            overrides={"FAKE_GIT_ORIGIN": "https://github.com/attacker/crs.git"}
        )
        command_text = "\n".join(commands)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertIn("config --get remote.origin.url", command_text)
        self.assertNotIn("fetch", self.git_verbs(commands))

    def test_rejects_preexisting_source_before_git_or_crs_consumption(self):
        result, commands, sentinel_exists = self.invoke_fetch(existing_source=True)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(commands, [], result.stdout + result.stderr)
        self.assertTrue(sentinel_exists)

    def test_rejects_a_cache_or_outside_source_before_git(self):
        for source_location in ("cache", "outside"):
            with self.subTest(source_location=source_location):
                result, commands, _ = self.invoke_fetch(source_location=source_location)
                self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
                self.assertEqual(commands, [], result.stdout + result.stderr)

    def test_rejects_resolved_commit_or_final_head_mismatch_before_submodules(self):
        result, commands, _ = self.invoke_fetch(
            overrides={"FAKE_GIT_FETCH_HEAD_COMMIT": ALTERNATE_COMMIT}
        )
        command_text = "\n".join(commands)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertIn("rev-parse --verify FETCH_HEAD^{commit}", command_text)
        self.assertNotIn("checkout", self.git_verbs(commands))
        self.assertNotIn("submodule", self.git_verbs(commands))

        result, commands, _ = self.invoke_fetch(
            overrides={"FAKE_GIT_RESOLVED_COMMIT": ALTERNATE_COMMIT}
        )
        command_text = "\n".join(commands)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertIn("rev-parse --verify", command_text)
        self.assertNotIn("checkout", self.git_verbs(commands))
        self.assertNotIn("submodule", self.git_verbs(commands))

        result, commands, _ = self.invoke_fetch(
            overrides={"FAKE_GIT_HEAD_COMMIT": ALTERNATE_COMMIT}
        )
        command_text = "\n".join(commands)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertIn(f"checkout --detach {APPROVED_COMMIT}", command_text)
        self.assertIn("rev-parse --verify HEAD^{commit}", command_text)
        self.assertNotIn("submodule", self.git_verbs(commands))

    def test_accepts_an_exactly_empty_regular_gitmodules_without_gitlinks(self):
        result, commands, _ = self.invoke_fetch(
            overrides={"FAKE_GIT_GITMODULES_CASE": "empty"}
        )
        command_text = "\n".join(commands)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"ls-tree -r {APPROVED_COMMIT}", command_text)
        self.assertIn("ls-files --stage", command_text)
        self.assertIn("ls-files --stage -- .gitmodules", command_text)
        self.assertIn(f"rev-parse --verify {APPROVED_COMMIT}:.gitmodules", command_text)
        self.assertIn(f"cat-file -s {APPROVED_COMMIT}:.gitmodules", command_text)
        self.assertIn("hash-object --no-filters -- ", command_text)
        self.assertIn(
            "diff --quiet --no-ext-diff --no-textconv -- .gitmodules", command_text
        )
        self.assertIn("config --local --get-regexp ^submodule\\.", command_text)
        self.assertIn("rev-parse --verify HEAD^{commit}", command_text)
        self.assertNotIn("submodule", self.git_verbs(commands))

    def test_prepare_rejects_a_post_fetch_gitmodules_replacement_before_runtime_writes(
        self,
    ):
        def replace_then_prepare(source_dir, runtime_dir, prepare_script, environment):
            (source_dir / ".gitmodules").write_text(
                '[submodule \\"attacker\\"]\\npath = attacker\\n',
                encoding="utf-8",
            )
            result = subprocess.run(
                ["sh", str(prepare_script)],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15,
            )
            entries = (
                sorted(path.name for path in runtime_dir.iterdir())
                if runtime_dir.exists()
                else []
            )
            return result, entries

        fetch_result, commands, _, prepare_state = self.invoke_fetch(
            overrides={"FAKE_GIT_GITMODULES_CASE": "empty"},
            after_fetch=replace_then_prepare,
        )
        prepare_result, runtime_entries = prepare_state
        self.assertEqual(
            fetch_result.returncode, 0, fetch_result.stdout + fetch_result.stderr
        )
        self.assertEqual(
            prepare_result.returncode, 77, prepare_result.stdout + prepare_result.stderr
        )
        self.assertIn(
            "prepare_crs checked-out .gitmodules is not an empty regular file",
            prepare_result.stdout + prepare_result.stderr,
        )
        self.assertEqual(runtime_entries, [])
        self.assertNotIn("submodule", self.git_verbs(commands))

    def assert_gitmodules_case_blocked(self, overrides):
        result, commands, _ = self.invoke_fetch(overrides=overrides)
        command_text = "\n".join(commands)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertIn("rev-parse --verify HEAD^{commit}", command_text)
        self.assertNotIn("submodule", self.git_verbs(commands))

    def test_rejects_empty_gitmodules_when_the_tree_or_index_has_a_gitlink(self):
        for override in (
            {"FAKE_GIT_GITMODULES_CASE": "empty", "FAKE_GIT_TREE_GITLINK": "1"},
            {"FAKE_GIT_GITMODULES_CASE": "empty", "FAKE_GIT_INDEX_GITLINK": "1"},
        ):
            with self.subTest(override=override):
                self.assert_gitmodules_case_blocked(override)

    def test_rejects_nonempty_gitmodules_forms(self):
        for gitmodules_case in ("newline", "whitespace", "comment", "declaration"):
            with self.subTest(gitmodules_case=gitmodules_case):
                self.assert_gitmodules_case_blocked(
                    {"FAKE_GIT_GITMODULES_CASE": gitmodules_case}
                )

    def test_rejects_gitmodules_symlink_special_or_wrong_tree_mode(self):
        for gitmodules_case in ("symlink", "special", "wrong-mode"):
            with self.subTest(gitmodules_case=gitmodules_case):
                self.assert_gitmodules_case_blocked(
                    {"FAKE_GIT_GITMODULES_CASE": gitmodules_case}
                )

    def test_rejects_gitmodules_checkout_or_index_mismatch(self):
        for override in (
            {"FAKE_GIT_GITMODULES_CASE": "worktree-mismatch"},
            {"FAKE_GIT_GITMODULES_CASE": "worktree-wrong-mode"},
            {"FAKE_GIT_GITMODULES_CASE": "empty", "FAKE_GIT_INDEX_MISMATCH": "1"},
            {"FAKE_GIT_GITMODULES_CASE": "empty", "FAKE_GIT_INDEX_DUPLICATE": "1"},
            {"FAKE_GIT_GITMODULES_CASE": "untracked"},
            {"FAKE_GIT_INDEX_UNTRACKED": "1"},
        ):
            with self.subTest(override=override):
                self.assert_gitmodules_case_blocked(override)

    def test_rejects_submodule_configuration_registry_or_extra_gitmodules_path(self):
        for override in (
            {"FAKE_GIT_GITMODULES_CASE": "empty", "FAKE_GIT_SUBMODULE_CONFIG": "1"},
            {"FAKE_GIT_GITMODULES_CASE": "empty", "FAKE_GIT_MODULES_REGISTRY": "1"},
            {"FAKE_GIT_GITMODULES_CASE": "empty", "FAKE_GIT_NESTED_GITMODULES": "1"},
            {"FAKE_GIT_TRAVERSAL_GITMODULES": "1"},
            {"FAKE_GIT_UNTRACKED": "1"},
        ):
            with self.subTest(override=override):
                self.assert_gitmodules_case_blocked(override)

    def test_rejects_git_inspection_errors_after_the_approved_checkout(self):
        for failure in (
            "ls-tree",
            "ls-files-index",
            "config-submodule",
            "ls-files-scoped",
            "rev-parse-gitmodules",
            "cat-file",
            "hash-object",
            "diff-gitmodules",
            "diff-worktree",
            "diff-index",
            "ls-files-untracked",
        ):
            with self.subTest(failure=failure):
                self.assert_gitmodules_case_blocked(
                    {"FAKE_GIT_GITMODULES_CASE": "empty", "FAKE_GIT_FAIL": failure}
                )

    def test_version_checker_requires_reviewed_release_tag_and_commit_pair(self):
        class FakeGithubClient:
            def __init__(self):
                self.urls = []

            def get_json(self, url):
                self.urls.append(url)
                responses = {
                    "https://api.github.com/repos/coreruleset/coreruleset/git/ref/tags/"
                    + APPROVED_RELEASE_TAG: {
                        "object": {"type": "commit", "sha": APPROVED_COMMIT}
                    },
                    "https://api.github.com/repos/coreruleset/coreruleset/releases/latest": {
                        "tag_name": "v4.900.1",
                        "draft": False,
                        "prerelease": False,
                    },
                    "https://api.github.com/repos/coreruleset/coreruleset/git/ref/tags/v4.900.1": {
                        "object": {"type": "commit", "sha": "d" * 40}
                    },
                }
                return responses[url]

        with tempfile.TemporaryDirectory(prefix="crs-provenance-") as temporary:
            fixture = (
                self.create_framework_fixture(
                    Path(temporary) / "framework-fixture"
                ).parents[1]
                / "lib/common.sh"
            )
            _, entries = COMMON_VERSION_CHECKER.parse_common(fixture)
            client = FakeGithubClient()
            result = COMMON_VERSION_CHECKER.check_crs_release_provenance(
                entries, client
            )

        self.assertEqual(
            COMMON_VERSION_CHECKER.value(entries, "CRS_APPROVED_REPO_URL"),
            APPROVED_REPO,
        )
        self.assertEqual(
            COMMON_VERSION_CHECKER.value(entries, "CRS_APPROVED_COMMIT"),
            APPROVED_COMMIT,
        )
        self.assertEqual(
            COMMON_VERSION_CHECKER.value(entries, "CRS_RELEASE_TAG"),
            APPROVED_RELEASE_TAG,
        )
        self.assertEqual(COMMON_VERSION_CHECKER.STATUS_REVIEW_REQUIRED, result.status)
        self.assertEqual(result.updates, [])
        self.assertEqual(
            result.variables,
            [
                "CRS_APPROVED_REPO_URL",
                "CRS_RELEASE_TAG",
                "CRS_APPROVED_COMMIT",
                "CRS_REPO_URL",
                "CRS_GIT_REF",
            ],
        )
        self.assertEqual(
            result.details["reason"],
            "update CRS_RELEASE_TAG and CRS_APPROVED_COMMIT together after peeled-commit provenance review",
        )
        self.assertEqual(
            result.details["manual_variables"],
            list(COMMON_VERSION_CHECKER.MANUAL_REVIEW_VARIABLES["OWASP Core Rule Set"]),
        )
        self.assertEqual(COMMON_VERSION_CHECKER.exit_code([result]), 2)
        self.assertEqual(
            COMMON_VERSION_CHECKER.exit_code(
                [result],
                entries,
                defer_reviewed_provenance=True,
            ),
            0,
        )
        self.assertEqual(
            client.urls,
            [
                "https://api.github.com/repos/coreruleset/coreruleset/git/ref/tags/v4.900.0",
                "https://api.github.com/repos/coreruleset/coreruleset/releases/latest",
                "https://api.github.com/repos/coreruleset/coreruleset/git/ref/tags/v4.900.1",
            ],
        )


if __name__ == "__main__":
    unittest.main()
