"""Focused safety tests for repository-owned Python update PR selection."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import io
import json
import unittest
from pathlib import Path


ROOT = connector_root()
SCRIPT_PATH = source_path('scripts/select-python-update-pr.py', root=ROOT)
MODULE = load_source(SCRIPT_PATH)


class SelectPythonUpdatePullRequestTests(unittest.TestCase):
    repository = "Easton97-Jens/ModSecurity-conector"
    owner = "Easton97-Jens"
    base = "master"
    branch = "automation/update-python-313"

    def response(self, **overrides: object) -> list[dict[str, object]]:
        record: dict[str, object] = {
            "number": 123,
            "draft": True,
            "head": {
                "ref": self.branch,
                "label": f"{self.owner}:{self.branch}",
                "repo": {
                    "full_name": self.repository,
                    "owner": {"login": self.owner},
                },
            },
            "base": {
                "ref": self.base,
                "repo": {"full_name": self.repository},
            },
        }
        record.update(overrides)
        return [record]

    def select(self, response: object) -> int | None:
        return MODULE.select_update_pull_request(
            response,
            repository=self.repository,
            owner=self.owner,
            base_branch=self.base,
            update_branch=self.branch,
        )

    def test_accepts_only_the_repository_owned_draft_default_branch_pr(self) -> None:
        self.assertEqual(self.select(self.response()), 123)
        self.assertIsNone(self.select([]))

    def test_rejects_same_name_fork_pr(self) -> None:
        response = self.response(
            head={
                "ref": self.branch,
                "label": f"attacker:{self.branch}",
                "repo": {
                    "full_name": "attacker/ModSecurity-conector",
                    "owner": {"login": "attacker"},
                },
            }
        )
        with self.assertRaises(MODULE.SelectionError):
            self.select(response)

    def test_rejects_wrong_base_or_non_draft_pr(self) -> None:
        for response in (
            self.response(base={"ref": "release", "repo": {"full_name": self.repository}}),
            self.response(draft=False),
        ):
            with self.assertRaises(MODULE.SelectionError):
                self.select(response)

    def test_rejects_multiple_or_malformed_matches(self) -> None:
        multiple_responses = self.response() + self.response(number=124)
        with self.assertRaises(MODULE.SelectionError):
            self.select(multiple_responses)
        with self.assertRaises(MODULE.SelectionError):
            self.select([{ "number": "123" }])

    def cli_arguments(self) -> list[str]:
        return [
            "--repository", self.repository,
            "--owner", self.owner, "--base", self.base, "--branch", self.branch,
        ]

    def test_cli_emits_only_a_numeric_identifier_and_rejects_bad_json(self) -> None:
        output = io.StringIO()
        errors = io.StringIO()
        self.assertEqual(
            MODULE.main(
                self.cli_arguments(),
                input_stream=io.BytesIO(json.dumps(self.response()).encode("utf-8")),
                output=output,
                error_output=errors,
            ),
            0,
        )
        self.assertEqual(output.getvalue(), "123\n")
        self.assertEqual(errors.getvalue(), "")

        output = io.StringIO()
        errors = io.StringIO()
        self.assertEqual(
            MODULE.main(
                self.cli_arguments(),
                input_stream=io.BytesIO(b"{not json"),
                output=output,
                error_output=errors,
            ),
            1,
        )
        self.assertEqual(output.getvalue(), "")
        self.assertIn("selection failed", errors.getvalue())

    def test_cli_rejects_an_oversized_response_before_parsing(self) -> None:
        output = io.StringIO()
        errors = io.StringIO()
        response = b"[" + (b" " * MODULE.MAX_RESPONSE_BYTES) + b"]"
        self.assertEqual(
            MODULE.main(
                self.cli_arguments(),
                input_stream=io.BytesIO(response),
                output=output,
                error_output=errors,
            ),
            1,
        )
        self.assertEqual(output.getvalue(), "")
        self.assertIn("size limit", errors.getvalue())



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
