"""Path-containment regressions for the RESPONSE_BODY promotion guard."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


SCRIPT_PATH = (
    Path(__file__).resolve().parents[2]
    / "ci"
    / "checks"
    / "evidence"
    / "check-response-body-promotion.py"
)


def load_module():
    specification = importlib.util.spec_from_file_location(
        "check_response_body_promotion", SCRIPT_PATH
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("could not load check-response-body-promotion.py")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class ResponseBodyPromotionPathSafetyTests(unittest.TestCase):
    def test_generated_markdown_rejects_plain_response_body_pass(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "runtime.md"
            report.write_text(
                "| case_id | matrix_status |\n"
                "|---|---|\n"
                "| response_body_fixture | PASS |\n",
                encoding="utf-8",
            )
            cases = {
                "response_body_fixture": {
                    "name": "response_body_fixture",
                    "variables": ["RESPONSE_BODY"],
                }
            }

            errors = module.validate_generated_markdown(report, cases)

            self.assertEqual(len(errors), 1)
            self.assertIn("must not render plain PASS", errors[0])

    def test_report_root_is_contained_by_selected_repository(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            framework_root = root / "framework"
            connector_root = root / "connector"
            framework_root.mkdir()
            connector_root.mkdir()

            self.assertEqual(
                module.report_root_for(
                    framework_root, connector_root, framework_root
                ),
                framework_root / "docs" / "testing",
            )
            self.assertEqual(
                module.report_root_for(
                    framework_root, connector_root, connector_root
                ),
                connector_root / "reports" / "testing",
            )

    def test_rejects_report_directory_symlink_escape(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            framework_root = root / "framework"
            connector_root = root / "connector"
            outside = root / "outside"
            framework_root.mkdir()
            connector_root.mkdir()
            outside.mkdir()
            (framework_root / "docs").symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "must stay under"):
                module.report_root_for(
                    framework_root, connector_root, framework_root
                )

    def test_rejects_unapproved_output_root(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            framework_root = root / "framework"
            connector_root = root / "connector"
            framework_root.mkdir()
            connector_root.mkdir()

            with self.assertRaisesRegex(ValueError, "unsupported output root"):
                module.report_root_for(framework_root, connector_root, root)


if __name__ == "__main__":
    unittest.main()
