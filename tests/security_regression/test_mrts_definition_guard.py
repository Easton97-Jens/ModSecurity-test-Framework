"""B03 tests for the Framework launcher, not for direct MRTS invocation."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[2]
GUARD = ROOT / "ci/provisioning/mrts_definition_guard.py"
SPEC = importlib.util.spec_from_file_location("mrts_definition_guard", GUARD)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Framework MRTS guard module could not be loaded")
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)

# Harmless subprocess fixture: observes only task-owned temporary inputs.
# Use YAML for the observation as well as the input, so integer mapping keys
# cannot be silently converted to strings by a JSON round trip in the test.
GENERATOR = r"""
import argparse
import os
from pathlib import Path
import stat
import sys
import yaml

parser = argparse.ArgumentParser()
parser.add_argument("-r", nargs="+")
parser.add_argument("-e")
parser.add_argument("-t")
args = parser.parse_args()
original = os.environ.get("GUARD_TEST_ORIGINAL")
if original:
    Path(original).write_text("global:\n  content: changed-after-validation\n")
paths = [Path(value) for value in args.r]
observed = {
    "documents": [yaml.safe_load(path.read_text()) for path in paths],
    "paths": [str(path) for path in paths],
    "file_modes": [stat.S_IMODE(path.stat().st_mode) for path in paths],
    "directory_modes": [stat.S_IMODE(path.parent.stat().st_mode) for path in paths],
    "rules_out": args.e,
    "tests_out": args.t,
}
(Path(args.e) / "observed.yaml").write_text(
    yaml.safe_dump(observed, sort_keys=False), encoding="utf-8"
)
sys.exit(int(os.environ.get("GUARD_TEST_EXIT", "0")))
"""


class MrtsDefinitionGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = tempfile.TemporaryDirectory(prefix="framework-b03-")
        self.addCleanup(self.workspace.cleanup)
        self.root = Path(self.workspace.name)
        self.rules = self.root / "rules"
        self.tests = self.root / "ftw"
        self.rules.mkdir()
        self.tests.mkdir()
        self.generator = self.root / "generator.py"
        self.generator.write_text(GENERATOR, encoding="utf-8")

    def definition(self, name: str, document: object) -> Path:
        path = self.root / name
        path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        return path

    def run_guard(self, paths: list[Path]) -> int:
        return guard.run_guarded(
            self.generator, paths, self.rules, self.tests, self.root
        )

    def observation(self) -> dict:
        observed = yaml.safe_load((self.rules / "observed.yaml").read_text(encoding="utf-8"))
        self.assertIsInstance(observed, dict)
        return observed

    def assert_no_snapshots(self) -> None:
        self.assertEqual(list(self.root.glob("mrts-validated-*")), [])

    def test_supported_globals_and_regular_fields_are_preserved(self) -> None:
        document = {
            "global": {
                "version": "fixture/1",
                "baseid": 100000,
                "default_operator": "@rx",
                "templates": [],
                "default_test_phase_methods": {1: "get"},
                "default_tests_phase_methods": {2: "post"},
                "default_constants": {"fixture": "value"},
            },
            "rulefile": "fixture.conf",
            "objects": [],
        }
        path = self.definition("a.yaml", document)
        self.assertEqual(self.run_guard([path]), 0)
        observed = self.observation()
        self.assertEqual(observed["documents"], [document])
        self.assertEqual(observed["rules_out"], str(self.rules))
        self.assertEqual(observed["tests_out"], str(self.tests))
        self.assertEqual(observed["file_modes"], [0o600])
        self.assertEqual(observed["directory_modes"], [0o700])
        self.assertNotEqual(observed["paths"], [str(path)])
        self.assert_no_snapshots()

    def test_absent_and_null_globals_remain_supported(self) -> None:
        documents = [{"objects": []}, {"global": None, "objects": []}]
        paths = [self.definition(f"{i}.yaml", doc) for i, doc in enumerate(documents)]
        self.assertEqual(self.run_guard(paths), 0)
        self.assertEqual(self.observation()["documents"], documents)

    def test_undocumented_globals_never_reach_generator(self) -> None:
        keys = (
            "expdir", "testdir", "content", "testcontent",
            "confdata", "_load_global_config", "unknown_setting", 7,
        )
        for key in keys:
            with self.subTest(key=key):
                path = self.definition("invalid.yaml", {"global": {key: "fixture"}})
                with self.assertRaises(guard.DefinitionRejected):
                    self.run_guard([path])
                self.assertFalse((self.rules / "observed.yaml").exists())
                self.assert_no_snapshots()

    def test_non_mapping_inputs_are_rejected(self) -> None:
        for document in (None, [], "fixture", {"global": []}, {"global": "fixture"}):
            with self.subTest(document=document):
                path = self.definition("invalid.yaml", document)
                with self.assertRaises(guard.DefinitionRejected):
                    self.run_guard([path])
                self.assertFalse((self.rules / "observed.yaml").exists())

    def test_entire_input_set_is_checked_before_generator_runs(self) -> None:
        good = self.definition("a.yaml", {"objects": []})
        bad = self.definition("z.yaml", {"global": {"expdir": "fixture"}})
        with self.assertRaises(guard.DefinitionRejected):
            self.run_guard([good, bad])
        self.assertFalse((self.rules / "observed.yaml").exists())
        self.assert_no_snapshots()

    def test_lexical_order_matches_original_generator(self) -> None:
        last = self.definition("z.yaml", {"global": {"version": "last"}})
        first = self.definition("a.yaml", {"global": {"version": "first"}})
        self.assertEqual(self.run_guard([last, first]), 0)
        versions = [doc["global"]["version"] for doc in self.observation()["documents"]]
        self.assertEqual(versions, ["first", "last"])

    def test_original_replacement_cannot_change_validated_snapshot(self) -> None:
        document = {"global": {"version": "validated"}, "objects": []}
        path = self.definition("a.yaml", document)
        with mock.patch.dict(os.environ, {"GUARD_TEST_ORIGINAL": str(path)}):
            self.assertEqual(self.run_guard([path]), 0)
        self.assertNotEqual(yaml.safe_load(path.read_text()), document)
        self.assertEqual(self.observation()["documents"], [document])
        self.assert_no_snapshots()

    def test_child_failure_is_preserved_and_snapshots_are_removed(self) -> None:
        path = self.definition("a.yaml", {"objects": []})
        with mock.patch.dict(os.environ, {"GUARD_TEST_EXIT": "23"}):
            self.assertEqual(self.run_guard([path]), 23)
        self.assert_no_snapshots()

    def test_option_like_generator_name_runs_as_a_script(self) -> None:
        # -V is harmless, but if interpreted by Python it exits successfully
        # without running the selected script. Exit code alone is not evidence.
        option_like_generator = self.root / "-V"
        option_like_generator.write_text(GENERATOR, encoding="utf-8")
        document = {"objects": []}
        path = self.definition("a.yaml", document)
        with contextlib.chdir(self.root):
            result = guard.run_guarded(
                Path("-V"), [path], self.rules, self.tests, self.root
            )
        self.assertEqual(result, 0)
        self.assertTrue((self.rules / "observed.yaml").is_file())
        self.assertEqual(self.observation()["documents"], [document])
        self.assert_no_snapshots()

    def test_option_like_relative_output_and_snapshot_roots_are_data(self) -> None:
        document = {"objects": []}
        path = self.definition("a.yaml", document)
        rules = self.root / "-rules"
        tests = self.root / "-tests"
        snapshots = self.root / "-snapshots"
        for directory in (rules, tests, snapshots):
            directory.mkdir()
        with contextlib.chdir(self.root):
            result = guard.run_guarded(
                self.generator, [path], Path("-rules"), Path("-tests"),
                Path("-snapshots"),
            )
        self.assertEqual(result, 0)
        observed = yaml.safe_load((rules / "observed.yaml").read_text(encoding="utf-8"))
        self.assertEqual(observed["documents"], [document])
        self.assertEqual(observed["rules_out"], str(rules))
        self.assertEqual(observed["tests_out"], str(tests))
        self.assertTrue(all(Path(value).is_absolute() for value in observed["paths"]))
        self.assertEqual(list(snapshots.glob("mrts-validated-*")), [])

    def test_invalid_yaml_is_blocked_without_echoing_input(self) -> None:
        path = self.root / "a.yaml"
        path.write_text("global: [fixture-private-marker", encoding="utf-8")
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            result = guard.main([
                "--generator", str(self.generator),
                "--snapshot-root", str(self.root),
                "--rules-out", str(self.rules),
                "--tests-out", str(self.tests),
                "--", str(path),
            ])
        self.assertEqual(result, 77)
        self.assertIn("BLOCKED:", errors.getvalue())
        self.assertNotIn("fixture-private-marker", errors.getvalue())
        self.assertFalse((self.rules / "observed.yaml").exists())

    def test_shell_entrypoint_uses_guard_without_removing_path_checks(self) -> None:
        wrapper = (ROOT / "ci/provisioning/generate-mrts.sh").read_text()
        self.assertIn('"$SCRIPT_DIR/mrts_definition_guard.py"', wrapper)
        self.assertIn('--generator "$MRTS_ROOT/mrts/generate-rules.py"', wrapper)
        self.assertIn('assert_safe_runtime_path "$MRTS_RULES_OUT"', wrapper)
        self.assertIn('assert_runtime_path_under_root "$MRTS_FTW_OUT"', wrapper)
        self.assertNotIn('"${PYTHON:-python3}" "$MRTS_ROOT/mrts/generate-rules.py"', wrapper)


if __name__ == "__main__":
    unittest.main()
