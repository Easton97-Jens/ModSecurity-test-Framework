"""Exercise strict revision data and independent provenance using local Git objects."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = connector_root()

from framework_revision_pins import (  # noqa: E402
    FRAMEWORK_PATH,
    LOCK_RELATIVE_PATH,
    MAX_LOCK_BYTES,
    MRTS_PATH,
    FrameworkRevisionPinsError,
    load_framework_revision_pins,
    load_project_version_pins,
    parse_framework_revision_pins,
    read_framework_mrts_gitlink,
    verify_framework_revision_pins,
)


class RevisionFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.lock = self.root / LOCK_RELATIVE_PATH
        self.lock.parent.mkdir(parents=True)
        self.pins = {
            "schema_version": 1, "framework_sha": "a" * 40, "mrts_sha": "b" * 40,
            "python_version": "3.15.7", "go_version": "1.27.1",
        }
        self.write_lock()

    def write_lock(self) -> None:
        self.lock.write_text(json.dumps(self.pins) + "\n", encoding="utf-8")


class RevisionLockTests(RevisionFixture):
    def test_offline_loader_requires_no_git_repository(self) -> None:
        self.assertEqual(load_framework_revision_pins(self.root), self.pins)
        self.assertEqual(load_project_version_pins(self.root), self.pins)

    def test_toolchain_versions_reject_prereleases_flags_and_unsupported_python_minor(self) -> None:
        for field in ("python_version", "go_version"):
            for value in (None, 1.27, "latest", "--help", "3.15.7; id", "1.27.1-rc1", "1.27.01", "1.２７.1"):
                data = json.dumps({**self.pins, field: value}).encode()
                with self.subTest(field=field, value=value), self.assertRaises(FrameworkRevisionPinsError):
                    parse_framework_revision_pins(data)
        for value in ("3.13.12", "3.14.9", "3.16.0", "3.15.07"):
            data = json.dumps({**self.pins, "python_version": value}).encode()
            with self.subTest(value=value), self.assertRaises(FrameworkRevisionPinsError):
                parse_framework_revision_pins(data)

    def test_go_stable_release_contract_includes_zero_minor_and_future_major(self) -> None:
        for value in ("1.0.0", "2.0.1"):
            with self.subTest(value=value):
                actual = parse_framework_revision_pins(json.dumps({**self.pins, "go_version": value}).encode())
                self.assertEqual(actual["go_version"], value)

    def test_invalid_schema_and_revision_values_are_rejected(self) -> None:
        invalid = [[], {}, {**self.pins, "unexpected": 1}]
        invalid += [{**self.pins, "schema_version": value} for value in (True, 1.0, "1", 2)]
        invalid += [{**self.pins, field: value} for field in ("framework_sha", "mrts_sha")
                    for value in (None, 123, "A" * 40, "a" * 39, "a" * 40 + "\n", "ａ" * 40)]
        for value in invalid:
            data = json.dumps(value).encode()
            with self.subTest(value=value), self.assertRaises(FrameworkRevisionPinsError):
                parse_framework_revision_pins(data)

    def test_duplicate_keys_bad_encoding_and_unbounded_data_are_rejected(self) -> None:
        duplicate = json.dumps(self.pins)[:-1] + ', "schema_version": 1}'
        for data in (duplicate.encode(), b"\xff", b"{", b" " * (MAX_LOCK_BYTES + 1)):
            with self.subTest(data=data[:40]), self.assertRaises(FrameworkRevisionPinsError):
                parse_framework_revision_pins(data)

    def test_nonregular_symlink_and_oversized_locks_are_rejected(self) -> None:
        self.lock.unlink()
        self.lock.symlink_to(ROOT / LOCK_RELATIVE_PATH)
        with self.assertRaises(FrameworkRevisionPinsError):
            load_framework_revision_pins(self.root)
        self.lock.unlink()
        os.mkfifo(self.lock)
        with self.assertRaises(FrameworkRevisionPinsError):
            load_framework_revision_pins(self.root)
        self.lock.unlink()
        self.lock.write_bytes(b" " * (MAX_LOCK_BYTES + 1))
        with self.assertRaises(FrameworkRevisionPinsError):
            load_framework_revision_pins(self.root)

    def test_symlink_lock_directory_is_rejected(self) -> None:
        self.lock.unlink()
        self.lock.parent.rmdir()
        self.lock.parent.symlink_to(source_path('ci/tooling', root=ROOT), target_is_directory=True)
        with self.assertRaises(FrameworkRevisionPinsError):
            load_framework_revision_pins(self.root)


class RevisionProvenanceTests(RevisionFixture):
    @staticmethod
    def git(root: Path, *arguments: str) -> str:
        return subprocess.run(
            ["git", "-C", str(root), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
             "-c", "commit.gpgsign=false", *arguments],
            check=True, capture_output=True, text=True,
        ).stdout.strip()

    def initialize(self, root: Path) -> str:
        root.mkdir(parents=True, exist_ok=True)
        self.git(root, "init", "-q")
        self.git(root, "commit", "--allow-empty", "-qm", "initial")
        return self.git(root, "rev-parse", "HEAD")

    def setUp(self) -> None:
        super().setUp()
        self.framework = self.root / FRAMEWORK_PATH
        self.mrts = self.framework / MRTS_PATH
        self.mrts_sha = self.initialize(self.mrts)
        self.initialize(self.framework)
        self.git(self.framework, "update-index", "--add", "--cacheinfo", f"160000,{self.mrts_sha},{MRTS_PATH}")
        self.git(self.framework, "commit", "-qm", "record MRTS")
        self.framework_sha = self.git(self.framework, "rev-parse", "HEAD")
        self.initialize(self.root)
        self.pins = {
            "schema_version": 1, "framework_sha": self.framework_sha, "mrts_sha": self.mrts_sha,
            "python_version": "3.15.7", "go_version": "1.27.1",
        }
        self.write_lock()
        self.git(self.root, "add", LOCK_RELATIVE_PATH)
        self.git(self.root, "update-index", "--add", "--cacheinfo", f"160000,{self.framework_sha},{FRAMEWORK_PATH}")
        self.git(self.root, "commit", "-qm", "record Framework lock")
        self.parent_sha = self.git(self.root, "rev-parse", "HEAD")

    def commit_lock(self) -> None:
        self.write_lock()
        self.git(self.root, "add", LOCK_RELATIVE_PATH)
        self.git(self.root, "commit", "-qm", "change lock")
        self.parent_sha = self.git(self.root, "rev-parse", "HEAD")

    def test_exact_repository_chain_is_accepted(self) -> None:
        self.assertEqual(verify_framework_revision_pins(self.root, self.parent_sha), self.pins)

    def test_candidate_gitlink_reader_uses_exact_object_not_current_head(self) -> None:
        self.git(self.framework, "update-index", "--cacheinfo", f"160000,{'a' * 40},{MRTS_PATH}")
        self.git(self.framework, "commit", "-qm", "new candidate MRTS")
        self.assertEqual(read_framework_mrts_gitlink(self.framework, self.framework_sha), self.mrts_sha)
        latest = self.git(self.framework, "rev-parse", "HEAD")
        self.assertEqual(read_framework_mrts_gitlink(self.framework, latest), "a" * 40)
        with self.assertRaises(FrameworkRevisionPinsError):
            read_framework_mrts_gitlink(self.framework, "HEAD")
        empty = self.git(self.framework, "rev-parse", f"{self.framework_sha}^")
        with self.assertRaises(FrameworkRevisionPinsError):
            read_framework_mrts_gitlink(self.framework, empty)

    def test_parent_sha_must_be_literal_and_exact_head(self) -> None:
        previous = self.git(self.root, "rev-parse", "HEAD^")
        for value in ("HEAD", "--help", self.parent_sha.upper(), previous):
            with self.subTest(value=value), self.assertRaises(FrameworkRevisionPinsError):
                verify_framework_revision_pins(self.root, value)

    def test_uncommitted_lock_rewrite_is_rejected_even_when_semantically_identical(self) -> None:
        self.lock.write_text(json.dumps(self.pins, indent=2), encoding="utf-8")
        with self.assertRaisesRegex(FrameworkRevisionPinsError, "exact Parent commit blob"):
            verify_framework_revision_pins(self.root, self.parent_sha)

    def test_recorded_symlink_lock_is_rejected(self) -> None:
        blob = self.git(self.root, "rev-parse", f"HEAD:{LOCK_RELATIVE_PATH}")
        self.git(self.root, "update-index", "--cacheinfo", f"120000,{blob},{LOCK_RELATIVE_PATH}")
        self.git(self.root, "commit", "-qm", "symlink mode")
        head = self.git(self.root, "rev-parse", "HEAD")
        with self.assertRaisesRegex(FrameworkRevisionPinsError, "regular non-executable blob"):
            verify_framework_revision_pins(self.root, head)

    def test_lock_cannot_override_parent_framework_gitlink(self) -> None:
        self.pins["framework_sha"] = self.git(self.framework, "rev-parse", "HEAD^")
        self.commit_lock()
        with self.assertRaisesRegex(FrameworkRevisionPinsError, "Framework recorded gitlink"):
            verify_framework_revision_pins(self.root, self.parent_sha)

    def test_git_replace_cannot_substitute_reviewed_parent_objects(self) -> None:
        previous = self.git(self.framework, "rev-parse", "HEAD^")
        self.git(self.root, "update-index", "--cacheinfo", f"160000,{previous},{FRAMEWORK_PATH}")
        self.git(self.root, "commit", "-qm", "wrong recorded Framework")
        wrong = self.git(self.root, "rev-parse", "HEAD")
        self.git(self.root, "replace", wrong, self.parent_sha)
        with self.assertRaisesRegex(FrameworkRevisionPinsError, "Framework recorded gitlink"):
            verify_framework_revision_pins(self.root, wrong)

    def test_lock_cannot_override_framework_mrts_gitlink(self) -> None:
        self.pins["mrts_sha"] = "a" * 40
        self.commit_lock()
        with self.assertRaisesRegex(FrameworkRevisionPinsError, "MRTS recorded gitlink"):
            verify_framework_revision_pins(self.root, self.parent_sha)

    def test_framework_and_mrts_materialized_head_mismatches_are_rejected(self) -> None:
        for root, name in ((self.mrts, "MRTS"), (self.framework, "Framework")):
            expected = self.git(root, "rev-parse", "HEAD")
            self.git(root, "commit", "--allow-empty", "-qm", "unselected checkout")
            with self.subTest(name=name), self.assertRaisesRegex(FrameworkRevisionPinsError, f"{name} HEAD"):
                verify_framework_revision_pins(self.root, self.parent_sha)
            self.git(root, "checkout", "-q", expected)

    def test_absent_independent_nested_repository_is_rejected(self) -> None:
        shutil.rmtree(self.mrts / ".git")
        with self.assertRaisesRegex(FrameworkRevisionPinsError, "initialized independent repository"):
            verify_framework_revision_pins(self.root, self.parent_sha)

    def test_regular_tree_entry_cannot_replace_gitlink(self) -> None:
        self.git(self.root, "update-index", "--force-remove", FRAMEWORK_PATH)
        marker = self.framework / "marker"
        marker.write_text("ordinary directory", encoding="utf-8")
        self.git(self.root, "add", f"{FRAMEWORK_PATH}/marker")
        self.git(self.root, "commit", "-qm", "wrong mode")
        head = self.git(self.root, "rev-parse", "HEAD")
        with self.assertRaisesRegex(FrameworkRevisionPinsError, "Framework recorded gitlink"):
            verify_framework_revision_pins(self.root, head)

    def test_fixed_root_cli_emits_only_validated_github_outputs(self) -> None:
        for path in ("ci/tools/read-framework-revisions.py", "ci/lib/framework_revision_pins.py"):
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, target)
        command = [sys.executable, "-I", str(self.root / "ci/tools/read-framework-revisions.py"),
                   "--parent-sha", self.parent_sha, "--format", "github-output"]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout, f"framework_sha={self.framework_sha}\nmrts_sha={self.mrts_sha}\n")
        json_result = subprocess.run(command[:-2], capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(json_result.stdout), self.pins)
        arbitrary = subprocess.run(command + ["--root", str(ROOT)], capture_output=True, text=True)
        self.assertEqual(arbitrary.returncode, 2)
        self.assertEqual(arbitrary.stdout, "")
        self.lock.write_text("{}", encoding="utf-8")
        failed = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(failed.returncode, 1)
        self.assertEqual(failed.stdout, "")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
