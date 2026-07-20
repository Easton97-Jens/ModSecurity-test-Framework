"""Regression coverage for bounded YAML and Markdown parser handling."""

from __future__ import annotations

import importlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNNERS = ROOT / "tests" / "runners"
CHECK_DOC_LINKS = ROOT / "ci" / "checks" / "documentation" / "check-doc-links.py"

if str(RUNNERS) not in sys.path:
    sys.path.insert(0, str(RUNNERS))

runner_core = importlib.import_module("runner_core")


def load_doc_link_checker():
    spec = importlib.util.spec_from_file_location("check_doc_links", CHECK_DOC_LINKS)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FallbackYamlParserHardeningTests(unittest.TestCase):
    def parse_content(self, content: str) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            case_path = Path(temporary_directory) / "case.yaml"
            case_path.write_text(content, encoding="utf-8")
            return dict(runner_core._load_minimal_yaml(case_path))

    def parse_header(self, header: str) -> dict[str, object]:
        return self.parse_content(f"rules: {header}\n  SecRuleEngine On\n")

    def test_preserves_inline_sequence_mapping_and_rejects_overindentation(self) -> None:
        parsed = self.parse_content(
            "headers:\n"
            "  - name: Content-Type\n"
            "    value: application/json\n"
            "  - Accept\n"
        )
        self.assertEqual(
            {"headers": [{"name": "Content-Type", "value": "application/json"}, "Accept"]},
            parsed,
        )

        with self.assertRaisesRegex(ValueError, "unexpected indentation"):
            self.parse_content("headers:\n  - name: Content-Type\n      value: json\n")

    def test_preserves_colon_containing_plain_sequence_scalars(self) -> None:
        parsed = self.parse_content(
            "known_limitations:\n"
            "  - ARGS:foo.\n"
            "  - https://example.invalid/path\n"
        )
        self.assertEqual(
            {"known_limitations": ["ARGS:foo.", "https://example.invalid/path"]},
            parsed,
        )

    def test_preserves_mapping_value_forms(self) -> None:
        parsed = self.parse_content(
            "name: parser-hardening\n"
            "rules: |-\n"
            "  SecRuleEngine On\n"
            "metadata:\n"
            "  enabled: true\n"
        )

        self.assertEqual(
            {
                "name": "parser-hardening",
                "rules": "SecRuleEngine On\n",
                "metadata": {"enabled": True},
            },
            parsed,
        )

    def test_accepts_documented_block_scalar_header_forms(self) -> None:
        headers: list[str] = []
        for style in "|>":
            headers.extend((style, f"{style}+", f"{style}-"))
            for indentation in "123456789":
                headers.extend(
                    (
                        f"{style}{indentation}",
                        f"{style}+{indentation}",
                        f"{style}-{indentation}",
                        f"{style}{indentation}+",
                        f"{style}{indentation}-",
                    )
                )

        for header in headers:
            with self.subTest(header=header):
                self.assertEqual("SecRuleEngine On\n", self.parse_header(header)["rules"])

    def test_rejects_invalid_block_scalar_headers(self) -> None:
        for header in ("|0", "|10", "|++", "|--", "|+-", "|-+", "|1+2"):
            with self.subTest(header=header):
                with self.assertRaisesRegex(ValueError, "unsupported block scalar header"):
                    self.parse_header(header)

    def test_rejects_a_long_invalid_block_scalar_header_without_backtracking(self) -> None:
        header = "|" + ("9" * 10_000) + "x"
        started = time.perf_counter()
        with self.assertRaisesRegex(ValueError, "unsupported block scalar header"):
            self.parse_header(header)
        self.assertLess(time.perf_counter() - started, 0.5)


class MarkdownHeadingHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.checker = load_doc_link_checker()

    def anchors_for(self, content: str) -> set[str]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            markdown_path = Path(temporary_directory) / "headings.md"
            markdown_path.write_text(content, encoding="utf-8")
            return self.checker.heading_anchors(markdown_path)

    def test_preserves_heading_anchor_forms_used_by_documentation(self) -> None:
        anchors = self.anchors_for(
            "# Getting *Started* ###\n"
            "## `FRAMEWORK_ROOT`\n"
            "### Duplicate Heading\n"
            "### Duplicate Heading\n"
            "# Inline `formatting` *and* ~strike~\n"
            '<a id="manual-anchor"></a>\n'
        )

        self.assertEqual(
            {
                "getting-started",
                "framework_root",
                "duplicate-heading",
                "duplicate-heading-1",
                "inline-formatting-and-strike",
                "manual-anchor",
            },
            anchors,
        )

    def test_handles_the_previous_malformed_heading_shape_in_linear_time(self) -> None:
        prefix = "a" * 1_000
        started = time.perf_counter()
        anchors = self.anchors_for(f"# {prefix}{' ' * 1_000}x\n")
        self.assertLess(time.perf_counter() - started, 0.5)
        self.assertEqual({f"{prefix}-x"}, anchors)

    def test_preserves_a_long_legitimate_heading(self) -> None:
        heading = "legitimate-" + ("a" * 10_000)
        started = time.perf_counter()
        self.assertEqual({heading}, self.anchors_for(f"# {heading}\n"))
        self.assertLess(time.perf_counter() - started, 0.5)

    def test_rejects_non_atx_heading_markers(self) -> None:
        self.assertEqual(set(), self.anchors_for("####### too deep\n#\n# \n"))


if __name__ == "__main__":
    unittest.main()
