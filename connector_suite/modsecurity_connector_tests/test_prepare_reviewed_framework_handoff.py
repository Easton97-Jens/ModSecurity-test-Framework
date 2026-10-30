"""Offline unit tests for the one-time, non-applying repair patch generator."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = connector_root()
SCRIPT = source_path('ci/tools/prepare-reviewed-framework-handoff.py', root=ROOT)
REPAIR = load_source(SCRIPT)


def common_fixture() -> str:
    generic = "".join(f'{name}="fixture"\n' for name in REPAIR.MUTABLE_SOURCE_FIELDS)
    pins = "".join(f'{name}="{old}"\n' for name, old, _new in REPAIR.PIN_UPDATES)
    return generic + pins


def candidate_fixture(previous: str) -> str:
    for name, old, new in REPAIR.PIN_UPDATES:
        previous = previous.replace(f'{name}="{old}"\n', f'{name}="{new}"\n')
    return previous


def parent_fixtures() -> dict[str, str]:
    originals = {
        path: 'NGINX_VERSION = "1.31.5"\nNGINX_DIGEST = "' + REPAIR.OLD_NGINX_SHA256 + '"\n'
        for path in REPAIR.NGINX_PATHS
    }
    originals[REPAIR.VERIFIER_PATH] = (
        'APPROVED_FRAMEWORK_COMMON_STRUCTURE_SHA256 = "' + REPAIR.OLD_STRUCTURE_SHA256 + '"\n'
    )
    for path in REPAIR.SHA_PATHS:
        originals[path] = 'FRAMEWORK_SHA = "' + REPAIR.OLD_FRAMEWORK_SHA + '"\n'
    originals[REPAIR.VERIFIER_TEST_PATH] = (
        'REVIEWED_FRAMEWORK_COMMON_STRUCTURE_SHA256 = "' + REPAIR.OLD_STRUCTURE_SHA256 + '"\n'
        'CANDIDATE_COMMON = "release-1.31.5"\n'
        'RUFF_COMMIT = "' + REPAIR.OLD_RUFF_COMMIT + '"\n'
        'NGINX_DIGEST = "' + REPAIR.OLD_NGINX_SHA256 + '"\n'
        'class CandidateTests:\n'
        '    def test_negative(self):\n'
        '        CANDIDATE_COMMON.replace("release-1.31.5", "release-1.31.6")\n'
        '    def test_production_review_digest_matches_the_reviewed_candidate(self) -> None:\n'
        '        pass\n'
    )
    return originals


class PrepareReviewedFrameworkHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.previous = common_fixture()
        self.candidate = candidate_fixture(self.previous)
        # Never relax the production baseline: only this synthetic unit fixture.
        self.digest_patch = mock.patch.object(
            REPAIR, "OLD_STRUCTURE_SHA256", REPAIR.structure_digest(self.previous)
        )
        self.digest_patch.start()
        self.addCleanup(self.digest_patch.stop)

    def test_exact_reviewed_delta_is_accepted(self) -> None:
        digest = REPAIR.reviewed_candidate_digest(self.previous, self.candidate)
        self.assertEqual(digest, REPAIR.structure_digest(self.candidate))
        self.assertNotEqual(digest, REPAIR.OLD_STRUCTURE_SHA256)
        self.assertEqual(len(REPAIR.PIN_UPDATES), 12)

    def test_unreviewed_shell_change_is_rejected(self) -> None:
        with self.assertRaisesRegex(REPAIR.RepairError, "beyond the 12"):
            REPAIR.reviewed_candidate_digest(self.previous, self.candidate + "echo changed\n")

    def test_extra_mutable_data_change_is_rejected_for_this_exact_repair(self) -> None:
        changed = self.candidate.replace('ENVOY_VERSION="fixture"', 'ENVOY_VERSION="other"')
        with self.assertRaisesRegex(REPAIR.RepairError, "beyond the 12"):
            REPAIR.reviewed_candidate_digest(self.previous, changed)

    def test_wrong_baseline_is_rejected(self) -> None:
        with self.assertRaisesRegex(REPAIR.RepairError, "Baseline"):
            REPAIR.reviewed_candidate_digest(self.previous + "# drift\n", self.candidate)

    def test_missing_reviewed_assignment_is_rejected(self) -> None:
        previous = self.previous.replace('AWS_LC_TAG="v5.5.0"\n', "")
        with mock.patch.object(REPAIR, "OLD_STRUCTURE_SHA256", REPAIR.structure_digest(previous)):
            with self.assertRaisesRegex(REPAIR.RepairError, "AWS_LC_TAG"):
                REPAIR.reviewed_candidate_digest(previous, self.candidate)

    def test_duplicate_reviewed_assignment_is_rejected(self) -> None:
        previous = self.previous + 'AWS_LC_TAG="v5.5.0"\n'
        with mock.patch.object(REPAIR, "OLD_STRUCTURE_SHA256", REPAIR.structure_digest(previous)):
            with self.assertRaisesRegex(REPAIR.RepairError, "AWS_LC_TAG"):
                REPAIR.reviewed_candidate_digest(previous, self.candidate)

    def test_duplicate_generic_field_is_rejected(self) -> None:
        with self.assertRaisesRegex(REPAIR.RepairError, "Duplicate"):
            REPAIR.structure_digest(self.previous + 'ENVOY_VERSION="fixture"\n')

    def test_missing_generic_field_is_rejected(self) -> None:
        previous = self.previous.replace('ENVOY_VERSION="fixture"\n', "")
        with self.assertRaisesRegex(REPAIR.RepairError, "Incomplete"):
            REPAIR.structure_digest(previous)

    def test_missing_replacement_is_rejected(self) -> None:
        with self.assertRaises(REPAIR.RepairError):
            REPAIR.replace_required("unchanged", "absent", "new", "fixture")

    def test_duplicate_single_replacement_is_rejected(self) -> None:
        with self.assertRaises(REPAIR.RepairError):
            REPAIR.replace_required("old old", "old", "new", "fixture", count=1)

    def test_patch_keeps_negative_control_distinct_and_does_not_mutate_input(self) -> None:
        originals = parent_fixtures()
        before = dict(originals)
        changed = REPAIR.build_changes(originals, "a" * 64)
        self.assertEqual(originals, before)
        self.assertIn(
            'CANDIDATE_COMMON.replace("release-1.31.6", "release-1.31.7")',
            changed[REPAIR.VERIFIER_TEST_PATH],
        )
        self.assertIn(
            "def test_checked_out_framework_common_matches_production_review",
            changed[REPAIR.VERIFIER_TEST_PATH],
        )
        for path in REPAIR.SHA_PATHS:
            self.assertNotIn(REPAIR.OLD_FRAMEWORK_SHA, changed[path])
            self.assertIn(REPAIR.NEW_FRAMEWORK_SHA, changed[path])

    def test_target_inventory_cannot_be_widened(self) -> None:
        originals = parent_fixtures()
        originals["ci/runtime/broker/nginx_root_broker.py"] = "unchanged\n"
        with self.assertRaisesRegex(REPAIR.RepairError, "inventory"):
            REPAIR.build_changes(originals, "a" * 64)

    def test_stale_target_precondition_is_rejected(self) -> None:
        originals = parent_fixtures()
        originals[REPAIR.NGINX_PATHS[0]] = "NGINX_VERSION = 'different'\n"
        with self.assertRaises(REPAIR.RepairError):
            REPAIR.build_changes(originals, "a" * 64)

    def test_changed_python_must_parse(self) -> None:
        originals = parent_fixtures()
        path = "tests/test_nginx_body_buffer_fixture.py"
        originals[path] = 'NGINX_VERSION = "1.31.5"\ninvalid python syntax\n'
        with self.assertRaises(SyntaxError):
            REPAIR.build_changes(originals, "a" * 64)

    def test_patch_contains_exact_gitlink_and_no_protected_paths(self) -> None:
        originals = parent_fixtures()
        changed = REPAIR.build_changes(originals, "a" * 64)
        patch = REPAIR.render_patch(originals, changed)
        self.assertEqual(patch, REPAIR.render_patch(originals, changed))
        self.assertIn(
            f"index {REPAIR.OLD_FRAMEWORK_SHA}..{REPAIR.NEW_FRAMEWORK_SHA} 160000\n",
            patch,
        )
        self.assertIn(f"-Subproject commit {REPAIR.OLD_FRAMEWORK_SHA}\n", patch)
        self.assertIn(f"+Subproject commit {REPAIR.NEW_FRAMEWORK_SHA}\n", patch)
        self.assertNotIn("ci/runtime/broker/", patch)
        self.assertNotIn("nginx-root-broker.yml", patch)
        self.assertNotIn("sync-framework-component-versions.py", patch)

    def test_patch_preserves_missing_final_newlines(self) -> None:
        patch = REPAIR.render_patch({"a.py": "OLD = 1"}, {"a.py": "OLD = 2"})
        self.assertIn("-OLD = 1\n\\ No newline at end of file\n", patch)
        self.assertIn("+OLD = 2\n\\ No newline at end of file\n", patch)

    def test_worktree_reader_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "actual.py").write_text("value = 1\n", encoding="utf-8")
            (root / "link.py").symlink_to(root / "actual.py")
            with self.assertRaisesRegex(REPAIR.RepairError, "Symlink"):
                REPAIR.read_worktree_file(root, "link.py")

    def test_cli_writes_only_new_patch_and_never_overwrites_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "repair.patch"
            with mock.patch.object(REPAIR, "prepare_patch", return_value=("patch\n", "a" * 64)):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(REPAIR.main(["--output", str(output)]), 0)
                self.assertEqual(output.read_text(encoding="utf-8"), "patch\n")
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(REPAIR.main(["--output", str(output)]), 2)
                self.assertEqual(output.read_text(encoding="utf-8"), "patch\n")

    def test_cli_does_not_write_when_preflight_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "repair.patch"
            with mock.patch.object(REPAIR, "prepare_patch", side_effect=REPAIR.RepairError("drift")):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(REPAIR.main(["--output", str(output)]), 2)
            self.assertFalse(output.exists())



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
