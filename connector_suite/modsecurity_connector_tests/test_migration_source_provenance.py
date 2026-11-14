"""Explicit on-demand migration provenance controls with real Git histories."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "migration_source_provenance_subject",
    ROOT / "connector_suite/modsecurity_connector_ci/tools/build-migration-map.py",
)
SUBJECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUBJECT)


class MigrationSourceProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.product, cls.framework = cls.root / "product", cls.root / "framework"
        cls.logical = "tests/fixture.yml.fixture"
        cls.physical = "connector_suite/fixtures/fixture.yml.fixture"
        for directory in (cls.product, cls.framework):
            directory.mkdir()
            cls.git(directory, "init", "-q")
        (cls.product / "legacy.fixture").write_text("original legacy bytes\n")
        cls.parent_base = cls.commit(cls.product)
        product_fixture = cls.product / cls.logical
        product_fixture.parent.mkdir(parents=True)
        product_fixture.write_text("later Product bytes\n")
        cls.parent_with_fixture = cls.commit(cls.product)
        product_fixture.unlink()
        cls.commit(cls.product)
        (cls.framework / "framework.txt").write_text("Framework baseline\n")
        cls.framework_base = cls.commit(cls.framework)
        cls.file = cls.framework / cls.physical
        cls.file.parent.mkdir(parents=True)
        cls.file.write_text("Framework-only fixture\n")
        cls.introduction = cls.commit(cls.framework)
        cls.blob = cls.git(
            cls.framework, "rev-parse", cls.introduction + ":" + cls.physical
        ).strip()
        (cls.framework / "later.txt").write_text("later revision\n")
        cls.later_revision = cls.commit(cls.framework)

    @staticmethod
    def git(root, *arguments):
        return subprocess.check_output(["git", "-C", str(root), *arguments], text=True)

    @classmethod
    def commit(cls, root):
        cls.git(root, "add", "--all")
        cls.git(
            root,
            "-c",
            "user.name=Migration Fixture",
            "-c",
            "user.email=migration-fixture@example.invalid",
            "commit",
            "-q",
            "-m",
            "fixture",
        )
        return cls.git(root, "rev-parse", "HEAD").strip()

    def setUp(self):
        self.mapping = {
            "legacy.fixture": "retained/legacy.fixture",
            self.logical: self.physical,
        }
        self.registration = {
            self.logical: {
                "framework_path": self.physical,
                "introduced_revision": self.introduction,
                "introduced_blob": self.blob,
            }
        }
        for name, value in (
            ("POST_MIGRATION_SOURCES", frozenset()),
            ("POST_MIGRATION_PROVENANCE", self.registration),
            ("INITIAL_BASE", self.parent_base),
            ("UPDATED_BASE", self.parent_base),
            ("FRAMEWORK_BASE", self.framework_base),
        ):
            context = patch.object(SUBJECT, name, value)
            context.start()
            self.addCleanup(context.stop)

    def classify(self):
        return SUBJECT.historical_source_mapping(
            self.mapping, self.framework, self.product
        )

    def test_registered_fixture_and_real_legacy_blob(self):
        historical = self.classify()
        self.assertEqual(historical, {"legacy.fixture": "retained/legacy.fixture"})
        self.assertEqual(
            SUBJECT.original_sources(self.product, self.parent_base, historical),
            {"legacy.fixture": b"original legacy bytes\n"},
        )
        records = SUBJECT.post_migration_file_records(
            self.mapping, self.framework, self.product
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(
            set(records[0]),
            {
                "logical_path",
                "framework_path",
                "sha256_framework_source",
                "migration_source",
            },
        )
        self.assertFalse(records[0]["migration_source"])

    def test_unknown_missing_source_stays_strict(self):
        self.mapping["unknown.fixture"] = "retained/unknown.fixture"
        historical = self.classify()
        self.assertIn("unknown.fixture", historical)
        with self.assertRaisesRegex(ValueError, "original source is not a Git blob"):
            SUBJECT.original_sources(self.product, self.parent_base, historical)

    def test_mapping_typo_and_missing_registration_reject(self):
        for mapping in ({self.logical: "wrong/fixture"}, {}):
            with self.subTest(mapping=mapping):
                self.mapping = mapping
                with self.assertRaisesRegex(ValueError, "mapping differs"):
                    self.classify()

    def test_wrong_introduction_or_blob_reject(self):
        for key, value in (
            ("introduced_revision", self.framework_base),
            ("introduced_blob", "0" * 40),
        ):
            with self.subTest(key=key):
                original = self.registration[self.logical][key]
                self.registration[self.logical][key] = value
                try:
                    with self.assertRaisesRegex(
                        ValueError, "introduction blob differs"
                    ):
                        self.classify()
                finally:
                    self.registration[self.logical][key] = original

    def test_later_existing_blob_is_not_an_introduction(self):
        self.registration[self.logical]["introduced_revision"] = self.later_revision
        with self.assertRaisesRegex(ValueError, "not added at introduction"):
            self.classify()

    def test_git_error_rejects(self):
        self.registration[self.logical]["introduced_revision"] = "e" * 40
        with self.assertRaises(subprocess.CalledProcessError):
            self.classify()

    def test_presence_in_either_product_baseline_rejects(self):
        for key in ("INITIAL_BASE", "UPDATED_BASE"):
            with (
                self.subTest(key=key),
                patch.object(SUBJECT, key, self.parent_with_fixture),
            ):
                with self.assertRaisesRegex(ValueError, "exists in Product baseline"):
                    self.classify()

    def test_current_missing_or_symlink_source_rejects(self):
        raw = self.file.read_bytes()
        self.file.unlink()
        try:
            with self.assertRaisesRegex(ValueError, "not regular"):
                self.classify()
            self.file.symlink_to(self.framework / "framework.txt")
            with self.assertRaisesRegex(ValueError, "not regular"):
                self.classify()
        finally:
            if self.file.is_symlink():
                self.file.unlink()
            self.file.write_bytes(raw)

    def test_symlink_ancestor_and_root_escape_reject_before_records(self):
        directory = self.file.parent
        for target in (
            self.root / "external-fixtures",
            self.framework / "held-fixtures",
        ):
            with self.subTest(target=target):
                directory.rename(target)
                directory.symlink_to(target, target_is_directory=True)
                try:
                    with self.assertRaisesRegex(
                        ValueError, "outside its root|symlink ancestor"
                    ):
                        self.classify()
                    with self.assertRaisesRegex(
                        ValueError, "outside its root|symlink ancestor"
                    ):
                        SUBJECT.post_migration_file_records(
                            self.mapping, self.framework, self.product
                        )
                finally:
                    directory.unlink()
                    target.rename(directory)


if __name__ == "__main__":
    unittest.main()
