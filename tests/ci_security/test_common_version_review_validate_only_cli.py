import importlib.util
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from tests.ci_security.common_version_review_fixtures import make_component_results


ROOT = Path(__file__).parents[2]
SPEC = importlib.util.spec_from_file_location(
    "review_reconciler_validate_only",
    ROOT / "ci/tools/reconcile-common-version-review-issues.py",
)
assert SPEC is not None
reconciler = importlib.util.module_from_spec(SPEC)
loader = SPEC.loader
assert loader is not None
loader.exec_module(reconciler)


def make_plan():
    results = make_component_results()
    checked = [item["component_id"] for item in results]
    plan = {
        "schema_version": "1",
        "maintenance_outcome": "safe_updates_with_manual_review",
        "global_inventory_complete": True,
        "scope": {"mode": "component", "checked_components": checked},
        "safe_updates": [
            {"variable": "LIGHTTPD_VERSION", "old": "1.4.79", "new": "1.4.80"}
        ],
        "manual_reviews": [],
        "checked_components": checked,
        "component_results": results,
        "generated_views": ["ci/provisioning/runtime-components.manifest.json"],
        "source_common_sha256": "a" * 64,
        "candidate_common_sha256": "b" * 64,
    }
    plan["plan_sha256"] = reconciler._plan_digest(plan)
    return plan


class ValidateOnlyCliTests(unittest.TestCase):
    def write_plan(self, plan):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / reconciler.PLAN_FILENAME
        with path.open("w", encoding="utf-8") as handle:
            json.dump(plan, handle)
        self._runner_temp = directory.name
        return str(path)

    def run_cli(self, plan_path, *extra):
        output = io.StringIO()
        with mock.patch.dict(
            os.environ, {"RUNNER_TEMP": self._runner_temp}, clear=True
        ):
            with redirect_stdout(output):
                code = reconciler.main(["--plan", plan_path, "--validate-only", *extra])
        return code, output.getvalue()

    def test_validate_only_is_deterministic_and_has_no_github_boundary(self):
        path = self.write_plan(make_plan())
        with mock.patch.object(
            reconciler, "urlopen", side_effect=AssertionError("network")
        ):
            first_code, first_output = self.run_cli(path)
            second_code, second_output = self.run_cli(path)
        self.assertEqual(first_code, 0)
        self.assertEqual(second_code, 0)
        self.assertEqual(first_output, second_output)
        result = json.loads(first_output)
        self.assertEqual(result["mode"], "validate-only")
        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["safe_update_count"], 1)
        self.assertNotIn(path, first_output)

    def test_validate_only_accepts_matching_expected_plan_digest(self):
        plan = make_plan()
        path = self.write_plan(plan)
        code, output = self.run_cli(path, "--expected-plan-sha256", plan["plan_sha256"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["plan_sha256"], plan["plan_sha256"])

    def test_expected_plan_digest_mismatch_fails_before_validation_result(self):
        plan = make_plan()
        path = self.write_plan(plan)
        with mock.patch.object(
            reconciler,
            "_validation_result",
            side_effect=AssertionError("mode-specific behavior must not run"),
        ):
            code, output = self.run_cli(path, "--expected-plan-sha256", "a" * 64)
        self.assertEqual(code, 2)
        self.assertEqual(output, "")

    def test_invalid_expected_plan_digest_fails_before_loading_or_mutating(self):
        path = self.write_plan(make_plan())
        with mock.patch.object(
            reconciler,
            "_read_validated_plan",
            side_effect=AssertionError("must reject syntax before loading"),
        ):
            code, output = self.run_cli(path, "--expected-plan-sha256", "not-a-sha")
        self.assertEqual(code, 2)
        self.assertEqual(output, "")

    def test_validate_only_requires_no_repository_or_token(self):
        path = self.write_plan(make_plan())
        code, output = self.run_cli(path, "--repository", "owner/repo")
        self.assertEqual(code, 2)
        self.assertEqual(output, "")

    def test_validate_only_rejects_digest_tampering(self):
        plan = make_plan()
        plan["candidate_common_sha256"] = "c" * 64
        path = self.write_plan(plan)
        code, output = self.run_cli(path)
        self.assertEqual(code, 2)
        self.assertEqual(output, "")

    def test_validate_only_rejects_unbounded_plan(self):
        path = self.write_plan({"x": "x" * (reconciler.MAX_PLAN_BYTES + 1)})
        code, output = self.run_cli(path)
        self.assertEqual(code, 2)
        self.assertEqual(output, "")

    def test_validate_only_rejects_arbitrary_regular_file_before_read(self):
        with (
            tempfile.TemporaryDirectory() as runner_temp,
            tempfile.TemporaryDirectory() as outside,
        ):
            outside_path = Path(outside) / reconciler.PLAN_FILENAME
            outside_path.write_text(json.dumps(make_plan()), encoding="utf-8")
            with mock.patch.object(
                reconciler.os,
                "open",
                side_effect=AssertionError("must reject before read"),
            ):
                with mock.patch.dict(
                    os.environ, {"RUNNER_TEMP": runner_temp}, clear=True
                ):
                    code = reconciler.main(
                        ["--plan", str(outside_path), "--validate-only"]
                    )
        self.assertEqual(code, 2)

    def test_validate_only_rejects_runner_temp_symlink_escape(self):
        with (
            tempfile.TemporaryDirectory() as runner_temp,
            tempfile.TemporaryDirectory() as outside,
        ):
            outside_path = Path(outside) / reconciler.PLAN_FILENAME
            outside_path.write_text(json.dumps(make_plan()), encoding="utf-8")
            plan_path = Path(runner_temp) / reconciler.PLAN_FILENAME
            plan_path.symlink_to(outside_path)
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": runner_temp}, clear=True):
                code = reconciler.main(["--plan", str(plan_path), "--validate-only"])
        self.assertEqual(code, 2)

    def test_safe_updates_are_schema_checked(self):
        plan = make_plan()
        plan["safe_updates"] = [
            {"variable": "LIGHTTPD_VERSION", "old": "1", "new": "2", "extra": "reject"}
        ]
        plan["plan_sha256"] = reconciler._plan_digest(plan)
        with self.assertRaises(reconciler.PlanError):
            reconciler.validate_plan(plan)


if __name__ == "__main__":
    unittest.main()
