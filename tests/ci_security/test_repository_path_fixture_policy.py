"""Focused closed-policy controls; these do not select Connector cases."""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "framework_path_fixture_policy",
    ROOT / "ci/checks/documentation/check-repository-path-references.py",
)
assert SPEC is not None
assert SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class RepositoryPathFixturePolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory(prefix="path-fixture-policy-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root_patch = patch.object(CHECKER, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def scan(self, relative, raw):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        scanned, errors = CHECKER.scan_path_references(path)
        return errors

    def negative_line(self, relative):
        digest, count = CHECKER.NEGATIVE_FIXTURE_LINE_SHA256[relative]
        lines = [
            line
            for line in (ROOT / relative).read_bytes().splitlines(keepends=True)
            if hashlib.sha256(line).hexdigest() == digest
        ]
        self.assertEqual(len(lines), count)
        return lines[0]

    def test_only_two_exact_historical_data_files_are_recognized(self):
        self.assertEqual(len(CHECKER.HISTORICAL_DATA_SHA256), 2)
        for relative, digest in CHECKER.HISTORICAL_DATA_SHA256.items():
            with self.subTest(path=relative):
                raw = (ROOT / relative).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
                self.assertEqual(self.scan(relative, raw), [])

    def test_changed_or_non_utf8_historical_data_fails_closed(self):
        for relative in CHECKER.HISTORICAL_DATA_SHA256:
            raw = (ROOT / relative).read_bytes()
            for mutation in (raw + b"\n", raw + b"\xff"):
                with self.subTest(path=relative, non_utf8=mutation.endswith(b"\xff")):
                    self.assertIn(
                        "immutable historical data SHA256 differs",
                        "\n".join(self.scan(relative, mutation)),
                    )

    def test_historical_bytes_at_another_path_are_not_exempt(self):
        for index, relative in enumerate(CHECKER.HISTORICAL_DATA_SHA256):
            with self.subTest(path=relative):
                self.assertIn(
                    "contains a local developer path",
                    "\n".join(
                        self.scan(
                            f"fixtures/foreign-{index}.json",
                            (ROOT / relative).read_bytes(),
                        )
                    ),
                )

    def test_exact_negative_fixture_lines_remain_visible_as_test_inputs(self):
        self.assertEqual(len(CHECKER.NEGATIVE_FIXTURE_LINE_SHA256), 2)
        for relative in CHECKER.NEGATIVE_FIXTURE_LINE_SHA256:
            with self.subTest(path=relative):
                line = self.negative_line(relative)
                self.assertIsNotNone(CHECKER.LOCAL_PATH_RE.search(line.decode()))
                self.assertEqual(self.scan(relative, line), [])

    def test_changed_missing_or_repeated_negative_lines_fail_closed(self):
        for relative in CHECKER.NEGATIVE_FIXTURE_LINE_SHA256:
            line = self.negative_line(relative)
            for mutation in (
                line.rstrip(b"\n") + b" \n",
                b"no negative vector\n",
                line + line,
                line + b"\xff",
            ):
                with self.subTest(
                    path=relative, mutation_sha=hashlib.sha256(mutation).hexdigest()
                ):
                    self.assertIn(
                        "reviewed negative-fixture line count differs",
                        "\n".join(self.scan(relative, mutation)),
                    )

    def test_added_local_path_outside_the_known_line_is_rejected(self):
        for relative in CHECKER.NEGATIVE_FIXTURE_LINE_SHA256:
            line = self.negative_line(relative)
            vector = CHECKER.LOCAL_PATH_RE.search(line.decode()).group(0)
            with self.subTest(path=relative):
                self.assertIn(
                    "contains a local developer path",
                    "\n".join(
                        self.scan(relative, line + vector.encode() + b"active\n")
                    ),
                )

    def test_negative_line_cannot_authorize_another_file_or_runtime_source(self):
        for relative in CHECKER.NEGATIVE_FIXTURE_LINE_SHA256:
            line = self.negative_line(relative)
            for foreign in ("tests/new-negative.py", "ci/runtime/active.py"):
                with self.subTest(path=relative, foreign=foreign):
                    self.assertIn(
                        "contains a local developer path",
                        "\n".join(self.scan(foreign, line)),
                    )

    def test_obsolete_flat_ci_paths_remain_checked_for_both_exception_kinds(self):
        obsolete = ("ci/" + sorted(CHECKER.OLD_CI_FILENAMES)[0]).encode()
        for relative in CHECKER.HISTORICAL_DATA_SHA256:
            with self.subTest(path=relative):
                errors = self.scan(relative, (ROOT / relative).read_bytes() + obsolete)
                self.assertIn("obsolete flat CI path", "\n".join(errors))
        for relative in CHECKER.NEGATIVE_FIXTURE_LINE_SHA256:
            with self.subTest(path=relative):
                errors = self.scan(relative, self.negative_line(relative) + obsolete)
                self.assertIn("obsolete flat CI path", "\n".join(errors))

    def test_missing_or_symlinked_reviewed_inputs_fail_closed(self):
        kinds = (
            ("HISTORICAL_DATA_SHA256", CHECKER.HISTORICAL_DATA_SHA256),
            ("NEGATIVE_FIXTURE_LINE_SHA256", CHECKER.NEGATIVE_FIXTURE_LINE_SHA256),
        )
        for kind, entries in kinds:
            for relative, policy in entries.items():
                with self.subTest(kind=kind, path=relative):
                    raw = (ROOT / relative).read_bytes()
                    path = self.root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(raw)
                    with (
                        patch.dict(CHECKER.HISTORICAL_DATA_SHA256, {}, clear=True),
                        patch.dict(
                            CHECKER.NEGATIVE_FIXTURE_LINE_SHA256, {}, clear=True
                        ),
                    ):
                        getattr(CHECKER, kind)[relative] = policy
                        self.assertEqual(CHECKER.fixture_policy_path_errors(), [])
                        path.unlink()
                        self.assertIn(
                            "regular non-symlink file",
                            "\n".join(CHECKER.fixture_policy_path_errors()),
                        )
                        foreign = path.with_name(path.name + ".foreign")
                        foreign.write_bytes(raw)
                        path.symlink_to(foreign)
                        self.assertIn(
                            "regular non-symlink file",
                            "\n".join(CHECKER.fixture_policy_path_errors()),
                        )
                        path.unlink()
                        foreign.unlink()


# New controls are explicit on demand; moving files does not expand selection.
if os.environ.get("ON_DEMAND_TESTS") != "1":

    def load_tests(loader, standard_tests, pattern):
        return unittest.TestSuite()
