"""Regression coverage for immutable GitHub Actions references."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "ci/checks/security/check-workflow-action-pins.py"
FULL_SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"


def load_checker():
    spec = importlib.util.spec_from_file_location("check_workflow_action_pins", CHECKER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class WorkflowActionPinTests(unittest.TestCase):
    @staticmethod
    def validate(files: dict[str, str]) -> list[str]:
        checker = load_checker()
        with tempfile.TemporaryDirectory() as temporary_directory:
            workflow_root = Path(temporary_directory) / ".github/workflows"
            for relative_path, contents in files.items():
                path = workflow_root / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(textwrap.dedent(contents).lstrip(), encoding="utf-8")
            return checker.validate_workflow_directory(workflow_root)

    def test_accepts_full_commit_sha(self) -> None:
        errors = self.validate(
            {
                "valid.yml": f"""
                    jobs:
                      verify:
                        steps:
                          - uses: actions/checkout@{FULL_SHA}
                """,
            }
        )

        self.assertEqual([], errors)

    def test_rejects_mutable_major_tags_in_yml_and_yaml(self) -> None:
        errors = self.validate(
            {
                "mutable.yml": "- uses: actions/checkout@v7\n",
                "nested/mutable.yaml": "- uses: actions/setup-python@v6\n",
            }
        )

        self.assertEqual(2, len(errors))
        self.assertTrue(any("actions/checkout@v7" in error for error in errors))
        self.assertTrue(any("actions/setup-python@v6" in error for error in errors))

    def test_rejects_branches_and_short_hashes(self) -> None:
        errors = self.validate(
            {
                "mutable.yml": """
                    - uses: actions/checkout@main
                    - uses: actions/checkout@11bd71901bbe
                """,
            }
        )

        self.assertEqual(2, len(errors))
        self.assertTrue(any("actions/checkout@main" in error for error in errors))
        self.assertTrue(any("actions/checkout@11bd71901bbe" in error for error in errors))

    def test_ignores_comments_and_accepts_quoted_full_sha(self) -> None:
        errors = self.validate(
            {
                "quoted.yml": f"""
                    # - uses: actions/checkout@v7
                    - uses: "actions/checkout@{FULL_SHA}" # reviewed pin
                    - uses: 'actions/setup-python@{FULL_SHA}'
                """,
            }
        )

        self.assertEqual([], errors)

    def test_ignores_uses_text_inside_a_literal_script_block(self) -> None:
        errors = self.validate(
            {
                "script.yml": f"""
                    jobs:
                      verify:
                        steps:
                          - run: |
                              const example = {{ uses: "actions/checkout@v7" }};
                          - uses: actions/checkout@{FULL_SHA}
                """,
            }
        )

        self.assertEqual([], errors)

    def test_rejects_yaml_node_properties_on_action_values(self) -> None:
        errors = self.validate(
            {
                "tagged.yml": f"- uses: !!str Docker://alpine@{FULL_SHA}\n",
                "anchored.yml": f"- uses: &action Docker://alpine@{FULL_SHA}\n",
                "flow.yaml": f"- {{ uses: !!str Docker://alpine@{FULL_SHA} }}\n",
            }
        )

        self.assertEqual(3, len(errors))
        self.assertTrue(
            all("unsupported YAML node property" in error for error in errors)
        )

    def test_rejects_yaml_node_properties_or_aliases_on_uses_keys(self) -> None:
        errors = self.validate(
            {
                "tagged-key.yml": "- !!str uses: actions/checkout@v7\n",
                "anchored-key.yml": "- &uses_key uses: actions/checkout@v7\n",
                "flow-tagged-key.yaml": "- { !!str uses: actions/checkout@v7 }\n",
                "alias-key.yml": """
                    key: &uses_key uses
                    jobs:
                      verify:
                        steps:
                          - *uses_key: actions/checkout@v7
                """,
                "flow-alias-key.yaml": """
                    key: &uses_key uses
                    jobs:
                      verify:
                        steps:
                          - { *uses_key: actions/checkout@v7 }
                """,
            }
        )

        self.assertEqual(5, len(errors))
        self.assertTrue(
            all("unsupported YAML node property or alias as mapping key" in error for error in errors)
        )

    def test_rejects_mutable_reference_with_quoted_uses_key(self) -> None:
        errors = self.validate(
            {
                "quoted-key.yml": '- "uses": actions/checkout@v7\n',
            }
        )

        self.assertEqual(1, len(errors))
        self.assertTrue(any("actions/checkout@v7" in error for error in errors))

    def test_rejects_mutable_reference_with_escaped_uses_key(self) -> None:
        errors = self.validate(
            {
                "escaped-key.yml": '- "\\x75ses": actions/checkout@v7\n',
                "escaped-flow.yaml": '- { "\\x75ses": actions/setup-python@v6 }\n',
            }
        )

        self.assertEqual(2, len(errors))
        self.assertTrue(any("actions/checkout@v7" in error for error in errors))
        self.assertTrue(any("actions/setup-python@v6" in error for error in errors))

    def test_rejects_mutable_reference_in_flow_mapping(self) -> None:
        errors = self.validate(
            {
                "flow.yaml": "- { uses: actions/checkout@v7 }\n",
            }
        )

        self.assertEqual(1, len(errors))
        self.assertTrue(any("actions/checkout@v7" in error for error in errors))

    def test_rejects_mutable_reference_in_flow_sequence_mapping(self) -> None:
        errors = self.validate(
            {
                "flow-sequence.yaml": (
                    "jobs:\n"
                    "  verify:\n"
                    "    steps: [uses: actions/setup-python@v6]\n"
                ),
                "flow-sequence-after-comma.yaml": (
                    "jobs:\n"
                    "  verify:\n"
                    "    steps: [name: setup, uses: actions/checkout@v7]\n"
                ),
            }
        )

        self.assertEqual(2, len(errors))
        self.assertTrue(any("actions/setup-python@v6" in error for error in errors))
        self.assertTrue(any("actions/checkout@v7" in error for error in errors))

    def test_accepts_full_sha_reference_in_flow_sequence_mapping(self) -> None:
        errors = self.validate(
            {
                "flow-sequence.yaml": (
                    "jobs:\n"
                    "  verify:\n"
                    f"    steps: [uses: actions/setup-python@{FULL_SHA}]\n"
                ),
            }
        )

        self.assertEqual([], errors)

    def test_accepts_flow_mapping_with_a_github_expression(self) -> None:
        errors = self.validate(
            {
                "expression-flow.yaml": (
                    f"- {{ if: ${{{{ !cancelled() }}}}, uses: actions/checkout@{FULL_SHA} }}\n"
                ),
            }
        )

        self.assertEqual([], errors)

    def test_closing_flow_delimiter_does_not_start_a_key_check(self) -> None:
        checker = load_checker()

        error = checker.flow_mapping_unsupported_key_syntax("} !not-a-mapping-key")

        self.assertIsNone(error)

    def test_rejects_multiline_flow_mapping(self) -> None:
        errors = self.validate(
            {
                "multiline-flow.yaml": """
                    - { name: check
                      , uses: actions/checkout@v7 }
                """,
            }
        )

        self.assertTrue(errors)
        self.assertTrue(any("unsupported multiline YAML flow mapping" in error for error in errors))

    def test_accepts_full_sha_with_quoted_key_and_flow_mapping(self) -> None:
        errors = self.validate(
            {
                "quoted-key.yml": f'- "uses": actions/checkout@{FULL_SHA}\n',
                "flow.yaml": f'- {{ uses: "actions/checkout@{FULL_SHA}" }}\n',
            }
        )

        self.assertEqual([], errors)

    def test_rejects_unsupported_explicit_uses_key_syntax(self) -> None:
        errors = self.validate(
            {
                "explicit.yaml": """
                    - ? uses
                      : actions/checkout@v7
                """,
            }
        )

        self.assertEqual(1, len(errors))
        self.assertTrue(any("unsupported explicit uses key syntax" in error for error in errors))

    def test_rejects_unsupported_explicit_uses_key_syntax_in_flow_mappings(
        self,
    ) -> None:
        errors = self.validate(
            {
                "flow-explicit.yaml": "- { ? uses : actions/checkout@v7 }\n",
                "flow-tagged-explicit.yaml": (
                    "- { ? !!str uses : actions/checkout@v7 }\n"
                ),
            }
        )

        self.assertEqual(2, len(errors))
        self.assertTrue(
            all("unsupported explicit uses key syntax" in error for error in errors)
        )

    def test_rejects_multiline_explicit_yaml_key(self) -> None:
        errors = self.validate(
            {
                "multiline-explicit.yaml": (
                    '- ? "us\\\n'
                    '    es"\n'
                    '  : actions/checkout@v7\n'
                ),
            }
        )

        self.assertTrue(errors)
        self.assertTrue(any("unsupported explicit uses key syntax" in error for error in errors))

    def test_accepts_local_actions_and_local_reusable_workflows(self) -> None:
        errors = self.validate(
            {
                "local.yml": """
                    jobs:
                      action:
                        steps:
                          - uses: ./actions/local-action
                      reusable:
                        uses: ./.github/workflows/reusable.yml
                """,
            }
        )

        self.assertEqual([], errors)

    def test_rejects_docker_references(self) -> None:
        errors = self.validate(
            {
                "docker.yml": """
                    - uses: docker://alpine:3.20
                    - uses: docker://alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                """,
            }
        )

        self.assertEqual(2, len(errors))
        self.assertTrue(any("docker://alpine:3.20" in error for error in errors))
        self.assertTrue(any("docker://alpine@sha256:" in error for error in errors))

    def test_rejects_case_variant_docker_references(self) -> None:
        errors = self.validate(
            {
                "docker-case.yml": f"- uses: Docker://alpine@{FULL_SHA}\n",
            }
        )

        self.assertEqual(1, len(errors))
        self.assertTrue(any("Docker://alpine" in error for error in errors))

    def test_rejects_escaped_docker_scheme(self) -> None:
        errors = self.validate(
            {
                "docker-escape.yml": f'- uses: "Docker\\x3a//alpine@{FULL_SHA}"\n',
                "docker-flow.yaml": f'- {{ uses: "Docker\\x3a//alpine@{FULL_SHA}" }}\n',
            }
        )

        self.assertEqual(2, len(errors))
        self.assertTrue(all("Docker://alpine" in error for error in errors))

    def test_accepts_reusable_workflow_pinned_to_full_commit_sha(self) -> None:
        errors = self.validate(
            {
                "reusable.yaml": f"""
                    jobs:
                      reusable:
                        uses: owner/repository/.github/workflows/reusable.yml@{FULL_SHA}
                """,
            }
        )

        self.assertEqual([], errors)

    def test_rejects_mutable_external_reusable_workflow(self) -> None:
        errors = self.validate(
            {
                "reusable.yaml": """
                    jobs:
                      reusable:
                        uses: owner/repository/.github/workflows/reusable.yml@v1
                """,
            }
        )

        self.assertEqual(1, len(errors))
        self.assertTrue(any("reusable.yml@v1" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
