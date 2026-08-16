"""Contract checks for the unified common-version maintenance workflow."""

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/check-common-versions.yml"


class UnifiedCommonMaintenanceWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = WORKFLOW.read_text(encoding="utf-8")
        self.workflow = yaml.safe_load(self.text)

    def test_workflow_is_valid_yaml_and_has_all_triggers(self) -> None:
        self.assertIsInstance(self.workflow, dict)
        # PyYAML 1.1 parses the YAML 1.2 key ``on`` as True.
        triggers = self.workflow.get("on", self.workflow.get(True))
        self.assertIn("schedule", triggers)
        self.assertIn("workflow_dispatch", triggers)
        self.assertIn("component", triggers["workflow_dispatch"]["inputs"])

    def test_unified_workflow_has_no_parallel_legacy_chain(self) -> None:
        self.assertIn("ci/tools/resolve-canonical-maintenance.py", self.text)
        self.assertIn("--plan", self.text)
        self.assertIn("--markdown", self.text)
        self.assertIn("--expected-plan-sha256", self.text)
        self.assertIn("global_inventory_complete", self.text)
        self.assertIn(
            "Go-FTW, Albedo, or canonical CI pin inventory is incomplete", self.text
        )
        self.assertIn("needs: canonical-maintenance", self.text)
        self.assertEqual(
            set(self.workflow["jobs"]),
            {
                "canonical-maintenance",
                "reconcile-trusted",
                "candidate",
                "publish",
                "result",
            },
        )
        self.assertNotIn("legacy-", self.text)

    def test_component_is_an_argv_element_and_globals_are_not_filtered(self) -> None:
        self.assertIn('args+=(--component "$REQUESTED_COMPONENT")', self.text)
        self.assertIn("mandatory global and selected runtime scopes", self.text)
        self.assertIn(
            "Go-FTW, Albedo, or canonical CI pin inventory is incomplete", self.text
        )

    def test_fatal_resolver_plan_is_summarized_before_failure_is_returned(self) -> None:
        resolver = self.workflow["jobs"]["canonical-maintenance"]["steps"][2]["run"]
        self.assertIn("resolver_exit=0", resolver)
        self.assertIn("|| resolver_exit=$?", resolver)
        self.assertIn(
            'cat "$RUNNER_TEMP/canonical-maintenance-plan.md" >> "$GITHUB_STEP_SUMMARY"',
            resolver,
        )
        self.assertIn("if (( resolver_exit != 0 )); then", resolver)
        self.assertIn('exit "$resolver_exit"', resolver)
        self.assertLess(
            resolver.index(
                'cat "$RUNNER_TEMP/canonical-maintenance-plan.md" >> "$GITHUB_STEP_SUMMARY"'
            ),
            resolver.index("if (( resolver_exit != 0 )); then"),
        )

    def test_issue_writes_are_trusted_default_branch_only(self) -> None:
        self.assertNotIn("pull_request_target", self.text)
        self.assertIn("--validate-only", self.text)
        self.assertIn("--apply --trusted-default-branch --token", self.text)
        trusted = self.workflow["jobs"]["reconcile-trusted"]
        self.assertEqual(trusted["permissions"], {"contents": "read"})
        self.assertTrue(
            all(
                job.get("permissions", {}).get("issues") != "write"
                for job in self.workflow["jobs"].values()
            )
        )
        self.assertIn("MAINTENANCE_ISSUE_APP_CLIENT_ID", self.text)
        self.assertIn("MAINTENANCE_ISSUE_APP_PRIVATE_KEY", self.text)
        self.assertIn("permission-issues: write", self.text)
        self.assertEqual(self.text.count("permission-issues: write"), 1)
        self.assertEqual(self.text.count("GITHUB_TOKEN: ${{ github.token }}"), 4)
        for job_name, step_index in (
            ("canonical-maintenance", 2),
            ("reconcile-trusted", 4),
            ("candidate", 2),
            ("publish", 2),
        ):
            self.assertEqual(
                self.workflow["jobs"][job_name]["steps"][step_index]["env"].get(
                    "GITHUB_TOKEN"
                ),
                "${{ github.token }}",
            )

    def test_candidate_and_publisher_are_bound_to_the_same_plan(self) -> None:
        self.assertIn("--expected-plan-sha256", self.text)
        self.assertIn("--apply-safe-updates", self.text)
        self.assertIn("generated views", self.text)
        self.assertIn("add-paths:", self.text)
        self.assertIn("draft: true", self.text)
        self.assertIn("No auto-merge is authorized", self.text)

    def test_result_summary_covers_required_outcomes(self) -> None:
        for label in ("Safe updates", "Reviews", "Issues", "Draft PR", "Fatal"):
            self.assertIn(label, self.text)


if __name__ == "__main__":
    unittest.main()
