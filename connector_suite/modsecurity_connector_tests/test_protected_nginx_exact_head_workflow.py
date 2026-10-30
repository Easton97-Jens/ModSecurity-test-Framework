from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
from pathlib import Path
import re
import unittest


ROOT = connector_root()
WORKFLOW = test_root() / '.github/workflows/connector-protected-nginx-exact-head.yml'
PARENT_WORKFLOW = ROOT / '.github/workflows/run-protected-nginx-exact-head.yml'
ACTIONLINT_CONFIG = source_path('.github/actionlint.yaml', root=ROOT)
HOST_GATE_DOC = source_path('docs/security/protected-exact-head-host-gate.md', root=ROOT)
HOST_GATE_DOC_DE = source_path('docs/security/protected-exact-head-host-gate.de.md', root=ROOT)


class ProtectedExactHeadWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")

    def test_dispatch_is_protected_and_exact_head_only(self) -> None:
        self.assertIn("workflow_call:", self.text)
        parent = PARENT_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", parent)
        self.assertIn("ModSecurity-test-Framework/.github/workflows/connector-protected-nginx-exact-head.yml@", parent)
        self.assertIn("github.ref_protected == true", self.text)
        self.assertIn("github.repository == 'Easton97-Jens/ModSecurity-conector'", self.text)
        self.assertIn("github.actor == 'Easton97-Jens'", self.text)
        self.assertIn("github.triggering_actor == 'Easton97-Jens'", self.text)
        self.assertIn("expected_head_sha:", self.text)
        self.assertIn("--expected-head-sha", self.text)
        self.assertIn("ref: ${{ needs.resolve.outputs.tested_pr_head }}", self.text)
        self.assertNotIn("pull_request_target", self.text)
        self.assertNotIn("pull_request:", self.text)

    def test_all_actions_are_full_sha_pinned_and_permissions_read_only(self) -> None:
        actions = re.findall(r"uses:\s+([^\s]+)", self.text)
        self.assertGreaterEqual(len(actions), 5)
        for action in actions:
            self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")
        self.assertGreaterEqual(self.text.count("contents: read"), 3)
        self.assertNotRegex(self.text, r"(?:contents|actions|packages|id-token):\s*write\b")
        self.assertNotIn("secrets.", self.text)
        self.assertNotIn("GITHUB_TOKEN", self.text)
        self.assertNotIn("continue-on-error", self.text)
        self.assertNotIn("|| true", self.text)

    def test_trust_boundary_jobs_and_base_owned_tools(self) -> None:
        self.assertIn("runs-on: [self-hosted, protected-exact-head-candidate-build]", self.text)
        self.assertIn("runs-on: [self-hosted, protected-exact-head-nginx]", self.text)
        self.assertIn("environment:\n      name: protected-exact-head-nginx", self.text)
        self.assertIn("--tool exact-dispatcher", self.text)
        self.assertIn("--tool exact-builder", self.text)
        self.assertIn("nginx_exact_head_root_launcher.py", self.text)
        self.assertIn("nginx_exact_head_result_collector.py", self.text)
        self.assertIn("--tool exact-preflight", self.text)
        lock = (ROOT / "ci/tooling/security-tools.lock.yml").read_text(encoding="utf-8")
        record = re.search(r"(?m)^  actions/download-artifact:\n(?:    [^\n]*\n)*?    commit_sha: ([0-9a-f]{40})$", lock)
        self.assertIsNotNone(record, "download-artifact must have one reviewed full-SHA lock")
        self.assertIn("actions/download-artifact@" + record.group(1), self.text)

    def test_dispatch_input_is_not_interpolated_into_shell_code(self) -> None:
        resolve = self.text.split("  resolve:", 1)[1].split("  candidate-build:", 1)[0]
        candidate = self.text.split("  candidate-build:", 1)[1].split("  privileged-runtime:", 1)[0]
        privileged = self.text.split("  privileged-runtime:", 1)[1]
        self.assertIn("PR_NUMBER: ${{ inputs.pr_number }}", resolve)
        self.assertIn("EXPECTED_HEAD_SHA: ${{ inputs.expected_head_sha }}", resolve)
        self.assertIn("--pr-number \"$PR_NUMBER\"", resolve)
        self.assertIn("--expected-head-sha \"$EXPECTED_HEAD_SHA\"", resolve)
        for job in (candidate, privileged):
            self.assertIn("REQUESTED_PR_NUMBER: ${{ inputs.pr_number }}", job)
            self.assertIn("--pr-number \"$REQUESTED_PR_NUMBER\"", job)
            self.assertIn("VALIDATED_PR_HEAD: ${{ needs.resolve.outputs.tested_pr_head }}", job)
            self.assertIn("--expected-head-sha \"$VALIDATED_PR_HEAD\"", job)
        self.assertNotIn("--pr-number \"${{ inputs.pr_number }}\"", self.text)
        self.assertNotIn("--expected-head-sha \"${{ inputs.expected_head_sha }}\"", self.text)

    def test_candidate_sha_comparison_uses_quoted_environment_data(self) -> None:
        candidate = self.text.split("  candidate-build:", 1)[1].split("  privileged-runtime:", 1)[0]
        verification = candidate.split(
            "      - name: Verify candidate SHA and protected Framework gitlink", 1
        )[1].split("      - name: Build and package the exact head without privilege", 1)[0]
        self.assertIn(
            "VALIDATED_PR_HEAD: ${{ needs.resolve.outputs.tested_pr_head }}", verification
        )
        self.assertIn(
            'test "$(git -C candidate rev-parse HEAD)" = "$VALIDATED_PR_HEAD"', verification
        )
        self.assertNotIn(
            "${{ needs.resolve.outputs.tested_pr_head }}", verification.split("run: |", 1)[1]
        )
        self.assertIn("ref: ${{ needs.resolve.outputs.tested_pr_head }}", candidate)

    def test_privilege_is_narrow_and_not_candidate_orchestration(self) -> None:
        privileged = self.text.split("  privileged-runtime:", 1)[1]
        self.assertIn("sudo -n -- /usr/local/libexec/modsecurity-protected-exact-head/run-exact-base-launcher", privileged)
        self.assertIn("--entrypoint-relative-path ci/runtime/broker/nginx_exact_head_root_launcher.py", privileged)
        self.assertIn("nginx_exact_head_root_launcher.py", privileged)
        self.assertIn("nginx_exact_head_result_collector.py", privileged)
        self.assertIn("--dispatcher-manifest", privileged)
        self.assertIn("--runner-uid", privileged)
        self.assertIn("--runner-gid", privileged)
        self.assertNotIn("sudo", self.text.split("  candidate-build:", 1)[1].split("  privileged-runtime:", 1)[0])
        self.assertNotIn("candidate/", privileged.split("Run the preinstalled protected host gate", 1)[0])
        self.assertNotIn("GITHUB_WORKSPACE/candidate", privileged)
        self.assertIn("GITHUB_WORKSPACE=\"$GITHUB_WORKSPACE\"", privileged)
        self.assertIn("--evidence-root", privileged)
        self.assertIn("--task-root \"$task_root\"", privileged)
        self.assertIn("--runner-uid \"$runner_uid\" --runner-gid \"$runner_gid\"", privileged)

    def test_both_privileged_entrypoints_use_the_exact_base_host_gate(self) -> None:
        privileged = self.text.split("  privileged-runtime:", 1)[1]
        self.assertEqual(privileged.count("--entrypoint-relative-path "), 2)
        self.assertIn(
            "--entrypoint-relative-path ci/runtime/broker/nginx_exact_head_result_collector.py",
            privileged,
        )
        self.assertNotRegex(
            privileged,
            r"sudo[^\n]*python3[^\n]*(?:task_root|trusted-nginx-exact-head-result-collector)",
        )
        self.assertNotIn("sudo -n -- /usr/bin/chown", privileged)

    def test_host_gate_contract_has_closed_entrypoint_allowlist_and_normalized_inputs(self) -> None:
        expected = (
            "ci/runtime/broker/nginx_exact_head_root_launcher.py",
            "ci/runtime/broker/nginx_exact_head_result_collector.py",
        )
        english = HOST_GATE_DOC.read_text(encoding="utf-8")
        german = HOST_GATE_DOC_DE.read_text(encoding="utf-8")
        for entrypoint in expected:
            self.assertIn(f"`{entrypoint}`", english)
            self.assertIn(f"`{entrypoint}`", german)
            self.assertEqual(self.text.count(f"--entrypoint-relative-path {entrypoint}"), 1)
        for document in (english, german):
            self.assertRegex(document, r"reject|ablehn")
            self.assertRegex(document, r"allowlist|Allowlist")
            self.assertRegex(document, r"normaliz|normalisiert")
            self.assertIn("--", document)

    def test_privilege_cannot_execute_checkout_resident_launcher_directly(self) -> None:
        privileged = self.text.split("  privileged-runtime:", 1)[1]
        self.assertNotRegex(
            privileged,
            r"sudo[^\n]*python3[^\n]*nginx_exact_head_root_launcher\.py",
        )
        self.assertIn("GITHUB_WORKSPACE=\"$GITHUB_WORKSPACE\"", privileged)
        self.assertIn("--trusted-base-sha \"$GITHUB_SHA\"", privileged)

    def test_preflight_contract_and_artifact_paths_are_explicit(self) -> None:
        self.assertNotIn("--role resolver", self.text)
        self.assertIn("--role candidate-build", self.text)
        self.assertIn("--role privileged", self.text)
        self.assertGreaterEqual(self.text.count("PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C"), 6)
        self.assertNotIn("pattern: protected-exact-head-*", self.text)
        self.assertIn("inputs/dispatcher", self.text)
        self.assertIn("inputs/candidate", self.text)
        self.assertIn("--output-root \"$task_root/package\"", self.text)
        self.assertNotIn("--output-root \"$task_root/artifacts\"", self.text)
        self.assertIn("submodule update --init --recursive -- modules/ModSecurity-test-Framework", self.text)

    def test_workflow_does_not_mount_or_load_pr_selected_host_controls(self) -> None:
        self.assertNotIn("container:", self.text)
        self.assertNotIn("services:", self.text)
        self.assertNotIn("docker.sock", self.text)
        self.assertNotIn("containerd.sock", self.text)
        self.assertNotIn("podman.sock", self.text)
        self.assertNotRegex(self.text, r"uses:\s+\./")
        self.assertNotIn("PYTHONPATH=", self.text)
        self.assertNotIn("LD_PRELOAD=", self.text)
        self.assertNotIn("LD_LIBRARY_PATH=", self.text)

    def test_actionlint_declares_only_dedicated_runner_labels(self) -> None:
        configuration = ACTIONLINT_CONFIG.read_text(encoding="utf-8")
        self.assertIn("protected-exact-head-candidate-build", configuration)
        self.assertIn("protected-exact-head-nginx", configuration)
        self.assertNotIn("ignore:", configuration)

    def test_mutation_removes_each_required_guard(self) -> None:
        guards = (
            "github.ref_protected == true",
            "github.repository == 'Easton97-Jens/ModSecurity-conector'",
            "github.actor == 'Easton97-Jens'",
            "github.triggering_actor == 'Easton97-Jens'",
            "--expected-head-sha",
            "--dispatcher-base-sha",
            "environment:\n      name: protected-exact-head-nginx",
        )
        for guard in guards:
            mutated = self.text.replace(guard, "")
            self.assertNotIn(guard, mutated, guard)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
