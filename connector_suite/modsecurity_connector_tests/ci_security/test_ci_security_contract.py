"""Connector-native regression coverage for the CI-security contract.

The former file was copied from the Framework and imported checker paths that
do not exist in this repository. These tests deliberately exercise the
existing Connector `make check-ci-security-contract` baseline and the
constrained workflow-tool updater instead of restoring a parallel checker.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import unittest

import yaml

from modsecurity_connector_tests import test_ci_security_workflows as native_contract


ROOT = connector_root()
UPDATER_PATH = source_path('ci/tools/update-workflow-tools.py', root=ROOT)
LOCK_PATH = source_path('ci/tooling/security-tools.lock.yml', root=ROOT)
WORKFLOW_PATH = source_path('.github/workflows/update-workflow-tools.yml', root=ROOT)
DOCUMENTATION_PATHS = (
    source_path('docs/security/ci-security-tooling.md', root=ROOT),
    source_path('docs/security/ci-security-tooling.de.md', root=ROOT),
)
APP_TOKEN_ACTION = "actions/create-github-app-token"
EXPECTED_APP_TOKEN_INPUTS = {
    "client-id": "${{ vars.WORKFLOW_UPDATER_APP_CLIENT_ID }}",
    "private-key": "${{ secrets.WORKFLOW_UPDATER_APP_PRIVATE_KEY }}",
    "owner": "${{ github.repository_owner }}",
    "repositories": "${{ github.repository }}",
    "permission-contents": "write",
    "permission-pull-requests": "write",
    "permission-workflows": "write",
}
EXPECTED_PUBLISHER_GATE = (
    "github.repository == 'Easton97-Jens/ModSecurity-conector' && "
    "github.event.repository.fork == false && "
    "github.event.repository.default_branch == 'master' && "
    "github.ref == 'refs/heads/master' && "
    "needs.resolver.outputs.has_updates == 'true'"
)


def load_updater():
    module = load_source(UPDATER_PATH)
    return module


UPDATER = load_updater()


def publisher_app_token_inputs(workflow: str) -> dict[str, str]:
    """Return the complete App-token input mapping from the publisher step."""

    publisher = native_contract.job_blocks(workflow)["publisher"]
    match = re.search(
        rf"^        uses: {re.escape(APP_TOKEN_ACTION)}@[^\n]+\n"
        r"        with:\n(?P<inputs>(?:          [A-Za-z0-9-]+: [^\n]+\n)+)",
        publisher,
        re.MULTILINE,
    )
    if match is None:
        raise AssertionError("publisher App-token action inputs are missing")
    return dict(
        re.findall(r"^          ([A-Za-z0-9-]+): ([^\n]+)$", match.group("inputs"), re.MULTILINE)
    )


def publisher_gate(workflow: str) -> str:
    """Return the publisher's normalized multi-line ``if`` expression."""

    publisher = native_contract.job_blocks(workflow)["publisher"]
    match = re.search(
        r"^    if: >-\n(?P<expression>(?:      [^\n]+\n)+)",
        publisher,
        re.MULTILINE,
    )
    if match is None:
        raise AssertionError("publisher default-branch gate is missing")
    return " ".join(line.strip() for line in match.group("expression").splitlines())


class CiSecurityContractTest(unittest.TestCase):
    def workflow(self) -> str:
        return WORKFLOW_PATH.read_text(encoding="utf-8")

    def jobs(self) -> dict[str, str]:
        return native_contract.job_blocks(self.workflow())

    def test_existing_connector_ci_security_baseline_passes(self) -> None:
        result = subprocess.run(
            ["make", f"PYTHON={sys.executable}", "check-ci-security-contract"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            encoding="utf-8",
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_lock_uses_the_connector_schema_and_contains_the_app_token_action(self) -> None:
        raw = yaml.safe_load(LOCK_PATH.read_text(encoding="utf-8"))
        self.assertIn("pinned_actions", raw)
        self.assertNotIn("actions", raw)
        self.assertIn("tools", raw)
        app_token = raw["pinned_actions"]["actions/create-github-app-token"]
        self.assertRegex(app_token["version"], r"\Av\d+(?:\.\d+){0,3}\Z")
        self.assertRegex(app_token["commit_sha"], r"\A[0-9a-f]{40}\Z")
        self.assertIn(
            f"{APP_TOKEN_ACTION}@{app_token['commit_sha']} # {app_token['version']}",
            self.workflow(),
        )
        self.assertEqual(
            app_token["upstream"], "https://github.com/actions/create-github-app-token"
        )
        self.assertIn("release_commit", raw["tools"]["actionlint"])
        self.assertIn("url", raw["tools"]["actionlint"])

    def test_updater_normalizes_without_migrating_the_checked_in_lock(self) -> None:
        before = LOCK_PATH.read_bytes()
        _path, lock, _digest = UPDATER.load_lock(ROOT)
        self.assertEqual(before, LOCK_PATH.read_bytes())
        self.assertEqual(
            lock["actions"]["actions/checkout"]["immutable_commit"],
            "3d3c42e5aac5ba805825da76410c181273ba90b1",
        )
        self.assertEqual(
            lock["tools"]["actionlint"]["immutable_commit"],
            "914e7df21a07ef503a81201c76d2b11c789d3fca",
        )
        self.assertEqual(
            lock["tools"]["actionlint"]["asset_url"],
            "https://github.com/rhysd/actionlint/releases/download/v1.7.12/"
            "actionlint_1.7.12_linux_amd64.tar.gz",
        )

    def test_explicit_parent_workflow_allowlist_is_complete_and_exact(self) -> None:
        _path, lock, _digest = UPDATER.load_lock(ROOT)
        references = UPDATER.locked_action_workflow_references(ROOT, lock)
        observed = set().union(*references.values())
        actual = {
            str(path.relative_to(ROOT))
            for path in (source_path('.github/workflows', root=ROOT)).glob("*.yml")
        }
        self.assertTrue(observed.issubset(actual))
        self.assertEqual(set(UPDATER.WORKFLOW_UPDATE_PATHS), actual)
        UPDATER.ensure_locked_action_workflow_coverage(ROOT, lock)

    def test_validator_uses_only_existing_connector_paths_and_make_baseline(self) -> None:
        updater = UPDATER_PATH.read_text(encoding="utf-8")
        workflow = self.workflow()
        self.assertIn('with_name("fetch_security_tool.py")', updater)
        self.assertNotIn("fetch-security-tool.py", updater)
        self.assertIn("check-ci-security-contract", updater)
        self.assertNotIn("check-github-actions-workflows.py", updater)
        self.assertNotIn("check-workflow-action-pins.py", updater)
        self.assertIn("Run Connector CI security contract", workflow)
        self.assertIn("run: make check-ci-security-contract", workflow)
        self.assertNotIn("check-ci-security-contract.py", workflow)

    def test_workflow_preserves_the_four_job_security_boundary(self) -> None:
        jobs = self.jobs()
        self.assertEqual(set(jobs), {"resolver", "validator", "publisher", "outcome"})
        for name in ("resolver", "validator"):
            with self.subTest(job=name):
                self.assertEqual(
                    native_contract.job_permissions(jobs[name]), {"contents": "read"}
                )
                self.assertNotIn("secrets.", jobs[name])
                self.assertNotIn("publisher_app_token", jobs[name])
        self.assertEqual(native_contract.job_permissions(jobs["publisher"]), {"contents": "read"})
        self.assertEqual(native_contract.job_permissions(jobs["outcome"]), {})
        self.assertIn("if: ${{ always() }}", jobs["outcome"])

    def test_publisher_uses_only_the_scoped_short_lived_app_token(self) -> None:
        publisher = self.jobs()["publisher"]
        workflow = self.workflow()
        self.assertIn(f"{APP_TOKEN_ACTION}@", publisher)
        self.assertEqual(publisher_app_token_inputs(workflow), EXPECTED_APP_TOKEN_INPUTS)

        elevated = workflow.replace(
            "          permission-workflows: write\n",
            "          permission-workflows: write\n          permission-issues: write\n",
            1,
        )
        self.assertNotEqual(
            publisher_app_token_inputs(elevated), EXPECTED_APP_TOKEN_INPUTS
        )
        self.assertIn("${{ steps.publisher_app_token.outputs.token }}", publisher)
        metadata_step = (
            "      - name: Re-resolve official immutable release candidates\n"
            "        env:\n"
            "          GITHUB_TOKEN: ${{ github.token }}\n"
            "        run: |\n"
            "          set -euo pipefail\n"
            "          python3 ci/tools/update-workflow-tools.py resolve --root . \\\n"
            '            --output "$RUNNER_TEMP/modsecurity-conector-workflow-tool-candidate.json"\n'
        )
        self.assertEqual(publisher.count(metadata_step), 1)
        self.assertNotIn("${{ github.token }}", publisher.replace(metadata_step, "", 1))
        self.assertNotRegex(publisher, r"git push\s+--force(?:\s|$)")
        self.assertNotIn("git push --force ", publisher)

    def test_publisher_default_branch_gate_rejects_a_loosened_mutation(self) -> None:
        workflow = self.workflow()
        self.assertEqual(publisher_gate(workflow), EXPECTED_PUBLISHER_GATE)
        loosened = workflow.replace(
            "needs.resolver.outputs.has_updates == 'true'",
            "needs.resolver.outputs.has_updates == 'true' || github.event_name == 'workflow_dispatch'",
            1,
        )
        self.assertNotEqual(publisher_gate(loosened), EXPECTED_PUBLISHER_GATE)

    def test_connector_fetcher_rejects_path_and_archive_escape_controls(self) -> None:
        fetcher = UPDATER.load_fetcher_module()
        _path, lock, _digest = UPDATER.load_lock(ROOT)
        record = dict(lock["tools"]["actionlint"])
        record["url"] = str(record.pop("asset_url"))
        record["asset"] = "../actionlint.tar.gz"
        with self.assertRaisesRegex(ValueError, "unsafe"):
            fetcher.validated_record("actionlint", record)

        archive_member = tarfile.TarInfo("../outside")
        archive_member.type = tarfile.REGTYPE
        self.assertFalse(fetcher.safe_member(archive_member))

    def test_candidate_binding_draft_pr_and_scope_checks_remain_fail_closed(self) -> None:
        workflow = self.workflow()
        for value in (
            "--expected-candidate-sha256",
            "--require-updates",
            "--verify-tool-assets",
            "--validate-proposed-tree",
            "verify-existing-branch --root .",
            "verify-scope --root . --staged",
            'git switch --detach "origin/$DEFAULT_BRANCH"',
            '"--force-with-lease=refs/heads/$UPDATE_BRANCH:$EXPECTED_REMOTE_TIP"',
            "draft: true",
            "git diff --cached --check",
            "automation/update-modsecurity-conector-workflow-tools",
            "<!-- modsecurity-conector-workflow-tool-updater -->",
        ):
            with self.subTest(value=value):
                self.assertIn(value, workflow)
        self.assertNotIn("|| true", workflow)
        self.assertNotIn("pull_request_target", workflow)

    def test_existing_draft_pr_is_rebuilt_from_the_bound_default_lock(self) -> None:
        """A prior updater commit cannot change the resolver candidate's base.

        Model L0 (default lock), L1 (a verified earlier updater result), and a
        candidate bound to L0.  The publisher deliberately detaches at L0
        before applying that candidate, then may replace only the verified
        remote maintenance branch using an exact force-with-lease.
        """

        with self.subTest("workflow uses the trusted default worktree"):
            workflow = self.workflow()
            self.assertIn('git switch --detach "origin/$DEFAULT_BRANCH"', workflow)
            self.assertIn('echo "reused=true" >> "$GITHUB_OUTPUT"', workflow)
            self.assertIn(
                '"--force-with-lease=refs/heads/$UPDATE_BRANCH:$EXPECTED_REMOTE_TIP"',
                workflow,
            )
            self.assertIn("verify-existing-branch --root .", workflow)

    def test_connector_identity_and_github_app_configuration_are_documented_bilingually(self) -> None:
        for path in DOCUMENTATION_PATHS:
            with self.subTest(path=path):
                text = path.read_text(encoding="utf-8")
                self.assertIn("WORKFLOW_UPDATER_APP_CLIENT_ID", text)
                self.assertIn("WORKFLOW_UPDATER_APP_PRIVATE_KEY", text)
                self.assertIn("Contents: write", text)
                self.assertIn("Pull requests: write", text)
                self.assertIn("Workflows: write", text)
                self.assertNotIn("framework-workflow-tool", text)

    def test_security_contract_rejects_yaml_indirection_in_lock_and_workflows(self) -> None:
        self.assertTrue(UPDATER.yaml_safety_errors("value: &anchor value\n"))
        self.assertTrue(UPDATER.yaml_safety_errors("value: *alias\n"))
        self.assertTrue(UPDATER.yaml_safety_errors("value: !tag value\n"))
        self.assertTrue(UPDATER.yaml_safety_errors("<<: {safe: false}\n"))
        self.assertEqual(UPDATER.yaml_safety_errors(LOCK_PATH.read_text(encoding="utf-8")), [])
        self.assertEqual(UPDATER.yaml_safety_errors(self.workflow()), [])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
