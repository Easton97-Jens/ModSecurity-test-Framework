import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def absolute_path(*parts: str) -> str:
    return "/" + "/".join(parts)


def load_utils():
    spec = importlib.util.spec_from_file_location(
        "generated_report_utils_sonar_test", ROOT / "ci/lib/generated_report_utils.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class GeneratedReportUtilsSonarTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.utils = load_utils()

    def test_portable_path_reference_redacts_lexical_local_roots(self):
        verified_name = "ModSecurity-conector-verified"
        cases = {
            absolute_path("var", "tmp", verified_name, "reports", "result.json"): "<verified-run-root>/reports/result.json",
            absolute_path("tmp", verified_name, "reports", "result.json"): "<verified-run-root>/reports/result.json",
            absolute_path("var", "tmp", "ModSecurity-conector-run-123", "evidence"): "<historical-run-root:ModSecurity-conector-run-123>/evidence",
            absolute_path("var", "tmp", "ModSecurity-conector-"): "<temporary-work-root>/ModSecurity-conector-",
            absolute_path("var", "tmp", "workspace", "report.md"): "<temporary-work-root>/workspace/report.md",
            absolute_path("tmp", "workspace", "report.md"): "<temporary-work-root>/workspace/report.md",
            absolute_path("root", ".local", "state", "ModSecurity-conector-build", "cache"): "<local-state-root>/cache",
            absolute_path("root", "secret"): "<local-home-root>/secret",
            absolute_path("home", "alice", "secret"): "<local-home-root>/secret",
            absolute_path("Users", "alice", "secret"): "<local-home-root>/secret",
        }
        for raw_path, expected in cases.items():
            with self.subTest(raw_path=raw_path):
                self.assertEqual(self.utils.portable_path_reference(raw_path), expected)

    def test_portable_path_reference_preserves_nonmatching_paths(self):
        near_temporary_root = absolute_path("var", "tmp-sibling", "secret")
        near_short_root = absolute_path("tmpdir", "secret")
        relative_path = "reports/testing/generated/report.md"

        self.assertEqual(self.utils.portable_path_reference(near_temporary_root), near_temporary_root)
        self.assertEqual(self.utils.portable_path_reference(near_short_root), near_short_root)
        self.assertEqual(self.utils.portable_path_reference(relative_path), relative_path)

    def test_portable_path_reference_keeps_lexical_escapes_inert_and_redacted(self):
        escaped_temporary_path = absolute_path("var", "tmp", "..", "outside", "secret")

        rendered = self.utils.portable_path_reference(escaped_temporary_path)

        self.assertEqual(rendered, "<temporary-work-root>/../outside/secret")
        self.assertNotIn(absolute_path("var", "tmp"), rendered)

    def test_portable_markdown_text_redacts_multiple_paths_and_preserves_punctuation(self):
        verified = absolute_path("var", "tmp", "ModSecurity-conector-verified", "report.md")
        historical = absolute_path("var", "tmp", "ModSecurity-conector-run-123", "evidence")
        markdown = f"Verified {verified}, historical {historical}."

        rendered = self.utils.portable_markdown_text(markdown)

        self.assertEqual(
            rendered,
            "Verified <verified-run-root>/report.md, historical <historical-run-root:ModSecurity-conector-run-123>/evidence.",
        )
        self.assertNotIn(verified, rendered)
        self.assertNotIn(historical, rendered)

    def test_redaction_uses_lexical_components_not_public_temp_absolute_literals(self):
        source = (ROOT / "ci/lib/generated_report_utils.py").read_text(encoding="utf-8")
        public_temp_root = absolute_path("tmp")
        alternate_public_temp_root = absolute_path("var", "tmp")

        self.assertIn("PurePosixPath", source)
        self.assertNotIn(public_temp_root, source)
        self.assertNotIn(alternate_public_temp_root, source)

    def test_language_switch_retains_english_and_german_links(self):
        self.assertEqual(
            self.utils.language_switch("runtime-matrix.generated.md"),
            ("**Language:**", "**Language:** English | [Deutsch](runtime-matrix.generated.de.md)"),
        )
        self.assertEqual(
            self.utils.language_switch("runtime-matrix.generated.de.md"),
            ("**Sprache:**", "**Sprache:** [English](runtime-matrix.generated.md) | Deutsch"),
        )

    def test_generated_markdown_rejects_an_untrusted_run_id_with_markdown_syntax(self):
        unsafe_run_id = "run`\n| injected | <script>alert(1)</script> |"
        rendered = self.utils.generated_markdown_text(
            "# Generated report",
            {
                "verified_run_id": unsafe_run_id,
                "inputs": [
                    {
                        "path": "reports/testing/input.json",
                        "source_hash": "a" * 64,
                        "verified_run_id": unsafe_run_id,
                        "status": "present",
                        "notes": "input file available",
                    }
                ],
            },
        )
        self.assertIn("> Verified run id: `invalid`", rendered)
        self.assertNotIn(unsafe_run_id, rendered)
        self.assertNotIn("<script>", rendered)


if __name__ == "__main__":
    unittest.main()
