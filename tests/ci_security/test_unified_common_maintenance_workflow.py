"""Contract checks for the unified common-version maintenance workflow."""

from pathlib import Path
import re
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/check-common-versions.yml"
RETIRED_WORKFLOW = ROOT / ".github/workflows/update-workflow-tools.yml"
QUALITY_WORKFLOW = ROOT / ".github/workflows/ci-security-quality.yml"


class UnifiedCommonMaintenanceWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = WORKFLOW.read_text(encoding="utf-8")
        self.workflow = yaml.safe_load(self.text)
        self.quality_text = QUALITY_WORKFLOW.read_text(encoding="utf-8")
        self.quality_workflow = yaml.safe_load(self.quality_text)

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
        self.assertFalse(RETIRED_WORKFLOW.exists())
        self.assertNotIn(".github/workflows/update-workflow-tools.yml", self.text)

    def test_native_workflow_tool_validation_is_bound_before_and_after_plan_application(
        self,
    ) -> None:
        candidate = self.workflow["jobs"]["candidate"]
        publisher = self.workflow["jobs"]["publish"]
        self.assertEqual(
            candidate["outputs"]["workflow_tool_candidate_sha256"],
            "${{ steps.workflow_tool_candidate.outputs.workflow_tool_candidate_sha256 }}",
        )
        for job, validation_name in (
            (candidate, "Validate generated workflow-tool candidate"),
            (publisher, "Revalidate generated workflow-tool candidate"),
        ):
            step = next(
                step for step in job["steps"] if step["name"] == validation_name
            )
            self.assertIn("validate-canonical-generated-candidate", step["run"])
            self.assertIn("--verify-tool-assets", step["run"])
            self.assertIn("--validate-proposed-tree", step["run"])
            self.assertIn(
                '--base-root "$RUNNER_TEMP/canonical-workflow-tool-base"', step["run"]
            )
        self.assertIn(
            "--expected-candidate-sha256",
            next(
                step["run"]
                for step in publisher["steps"]
                if step["name"] == "Revalidate generated workflow-tool candidate"
            ),
        )
        for job in (candidate, publisher):
            snapshot = next(
                step
                for step in job["steps"]
                if step["name"] == "Snapshot trusted workflow-tool validation inputs"
            )
            self.assertIn("snapshot-validation-inputs", snapshot["run"])

    def test_publisher_reuses_only_the_exact_scoped_draft_pr(self) -> None:
        publisher = self.workflow["jobs"]["publish"]
        state_check = next(
            step
            for step in publisher["steps"]
            if step["name"]
            == "Inspect matching Draft canonical maintenance pull request"
        )
        self.assertEqual(
            state_check["with"]["github-token"],
            "${{ steps.publisher_app_token.outputs.token }}",
        )
        script = state_check["with"]["script"]
        for required in (
            "pullRequests.length !== 1",
            "!pullRequest.draft",
            "pullRequest.base.ref !== defaultBranch",
            "!pullRequest.body?.includes(marker)",
            "compareCommitsWithBasehead",
            'comparison.data.status !== "ahead"',
            "allowedPaths.has(filename)",
        ):
            self.assertIn(required, script)
        subset_check = next(
            step
            for step in publisher["steps"]
            if step["name"]
            == "Verify matching Draft canonical maintenance native workflow-tool subset"
        )
        self.assertEqual(
            subset_check["if"],
            "steps.maintenance_pr.outputs.existing == 'true'",
        )
        self.assertEqual(
            subset_check["env"]["PUBLISHER_APP_TOKEN"],
            "${{ steps.publisher_app_token.outputs.token }}",
        )
        self.assertIn(
            "verify-existing-canonical-workflow-tool-subset", subset_check["run"]
        )
        self.assertIn("git fetch --no-tags origin", subset_check["run"])
        self.assertIn("unset PUBLISHER_APP_TOKEN", subset_check["run"])

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
        self.assertIn("--apply", self.text)
        self.assertIn("--trusted-default-branch", self.text)
        self.assertIn('--token "$ISSUE_APP_TOKEN"', self.text)
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
        self.assertEqual(self.text.count("GITHUB_TOKEN: ${{ github.token }}"), 1)
        canonical_resolver = next(
            step
            for step in self.workflow["jobs"]["canonical-maintenance"]["steps"]
            if step["name"] == "Resolve mandatory global and selected runtime scopes"
        )
        self.assertEqual(
            canonical_resolver["env"].get("GITHUB_TOKEN"), "${{ github.token }}"
        )
        for job_name in ("reconcile-trusted", "candidate", "publish"):
            self.assertNotIn("GITHUB_TOKEN", self.workflow["jobs"][job_name])
            self.assertNotIn(
                "GITHUB_TOKEN",
                "\n".join(
                    str(step.get("run", ""))
                    for step in self.workflow["jobs"][job_name]["steps"]
                ),
            )

    def test_caller_bound_plan_artifact_is_uploaded_once_and_consumed_by_downstream_jobs(
        self,
    ) -> None:
        canonical_steps = self.workflow["jobs"]["canonical-maintenance"]["steps"]
        uploads = [
            step
            for step in canonical_steps
            if step.get("name") == "Retain caller-bound canonical maintenance plan"
        ]
        self.assertEqual(len(uploads), 1)
        upload = uploads[0]
        self.assertEqual(
            upload["uses"],
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        )
        self.assertEqual(
            upload["with"]["name"],
            "canonical-maintenance-plan-${{ github.run_id }}-${{ github.run_attempt }}",
        )
        self.assertIn("canonical-maintenance-plan.json", upload["with"]["path"])
        self.assertIn("canonical-maintenance-plan.md", upload["with"]["path"])
        self.assertEqual(upload["with"]["retention-days"], 1)
        self.assertEqual(upload["with"]["if-no-files-found"], "error")

        expected_artifact = (
            "canonical-maintenance-plan-${{ github.run_id }}-${{ github.run_attempt }}"
        )
        expected_directory = "${{ runner.temp }}"
        expected_json = '"$RUNNER_TEMP/canonical-maintenance-plan.json"'
        for job_name in ("reconcile-trusted", "candidate", "publish"):
            steps = self.workflow["jobs"][job_name]["steps"]
            downloads = [
                step
                for step in steps
                if step.get("name")
                == "Download caller-bound canonical maintenance plan"
            ]
            self.assertEqual(len(downloads), 1, job_name)
            self.assertEqual(
                downloads[0]["uses"],
                "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
            )
            self.assertEqual(downloads[0]["with"]["name"], expected_artifact)
            self.assertEqual(downloads[0]["with"]["path"], expected_directory)

            run_text = "\n".join(str(step.get("run", "")) for step in steps)
            self.assertIn('--expected-plan-sha256 "$PLAN_SHA256"', run_text)
            self.assertIn(expected_json, run_text)
            self.assertNotIn("GITHUB_TOKEN", run_text)

        reconcile_steps = self.workflow["jobs"]["reconcile-trusted"]["steps"]
        validation = next(
            step
            for step in reconcile_steps
            if step.get("name") == "Validate caller-bound canonical maintenance plan"
        )
        token = next(
            index
            for index, step in enumerate(reconcile_steps)
            if step.get("name") == "Mint repository-limited issue reconciler App token"
        )
        self.assertLess(reconcile_steps.index(validation), token)

    def test_downstream_jobs_apply_only_the_downloaded_plan(self) -> None:
        plan_path = "$RUNNER_TEMP/canonical-maintenance-plan.json"
        for job_name in ("candidate", "publish"):
            run_text = "\n".join(
                str(step.get("run", ""))
                for step in self.workflow["jobs"][job_name]["steps"]
            )
            self.assertIn("--apply-safe-updates", run_text)
            self.assertIn(f'--plan "{plan_path}"', run_text)
            self.assertNotIn(
                "resolve-canonical-maintenance.py --root . --check", run_text
            )
        reconcile_text = "\n".join(
            str(step.get("run", ""))
            for step in self.workflow["jobs"]["reconcile-trusted"]["steps"]
        )
        self.assertIn(f'--plan "{plan_path}"', reconcile_text)
        self.assertIn("--apply", reconcile_text)
        self.assertNotIn("resolve-canonical-maintenance.py", reconcile_text)

    def test_candidate_and_publisher_are_bound_to_the_same_plan(self) -> None:
        self.assertIn("--expected-plan-sha256", self.text)
        self.assertIn("--apply-safe-updates", self.text)
        self.assertIn("caller-bound canonical plan", self.text)
        self.assertIn("add-paths:", self.text)
        self.assertIn("draft: true", self.text)
        self.assertIn("No auto-merge is authorized", self.text)

    def test_node_major_candidate_runs_literal_pin_pyright_quality_gate(self) -> None:
        """A common.sh Node pin update must run type analysis on the PR head."""

        common = (ROOT / "ci/lib/common.sh").read_text(encoding="utf-8")
        match = re.search(
            r'^CI_CANONICAL_NODE_VERSION="([0-9]+\.[0-9]+\.[0-9]+)"$',
            common,
            re.MULTILINE,
        )
        self.assertIsNotNone(match)
        node_version = match.group(1) if match is not None else ""
        triggers = self.quality_workflow.get("on", self.quality_workflow.get(True))
        self.assertIn("pull_request", triggers)
        self.assertIn("ci/lib/common.sh", triggers["pull_request"]["paths"])
        self.assertIn("actions/setup-node@", self.quality_text)
        self.assertIn(f'node-version: "{node_version}"', self.quality_text)
        self.assertNotIn("node-version: latest", self.quality_text)
        self.assertIn("node --version", self.quality_text)
        self.assertIn(
            'node "$TOOLS_DIR/pyright/index.js" --project pyrightconfig.json',
            self.quality_text,
        )

    def test_publisher_token_is_exactly_scoped_for_allowlisted_workflow_updates(
        self,
    ) -> None:
        publish = self.workflow["jobs"]["publish"]
        self.assertEqual(publish["permissions"], {"contents": "read"})
        publisher_token = next(
            step
            for step in publish["steps"]
            if step["name"] == "Mint repository-limited publisher App token"
        )
        self.assertEqual(
            publisher_token["with"],
            {
                "client-id": "${{ vars.WORKFLOW_UPDATER_APP_CLIENT_ID }}",
                "private-key": "${{ secrets.WORKFLOW_UPDATER_APP_PRIVATE_KEY }}",
                "owner": "${{ github.repository_owner }}",
                "repositories": "${{ github.event.repository.name }}",
                "permission-contents": "write",
                "permission-pull-requests": "write",
                "permission-workflows": "write",
            },
        )
        issue_token = next(
            step
            for step in self.workflow["jobs"]["reconcile-trusted"]["steps"]
            if step["name"] == "Mint repository-limited issue reconciler App token"
        )
        self.assertEqual(issue_token["with"]["permission-issues"], "write")
        self.assertNotIn("permission-workflows", issue_token["with"])
        create_pr = next(
            step
            for step in publish["steps"]
            if step["name"]
            == "Create or update Draft PR from the full generated allowlist"
        )
        self.assertIn(
            ".github/workflows/check-common-versions.yml",
            create_pr["with"]["add-paths"].splitlines(),
        )

    def test_result_summary_covers_required_outcomes(self) -> None:
        for label in ("Safe updates", "Reviews", "Issues", "Draft PR", "Fatal"):
            self.assertIn(label, self.text)


if __name__ == "__main__":
    unittest.main()
