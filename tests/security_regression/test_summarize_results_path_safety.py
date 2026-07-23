"""Controls for the summary CLI's read-only input containment boundary."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


SCRIPT_PATH = Path(__file__).resolve().parents[2] / "ci" / "reporting" / "summarize-results.py"


def load_module():
    specification = importlib.util.spec_from_file_location("summarize_results", SCRIPT_PATH)
    if specification is None or specification.loader is None:
        raise RuntimeError("could not load summarize-results.py")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class SummarizeResultsPathSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.environment = os.environ.copy()

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self.environment)

    def test_accepts_a_summary_under_the_configured_build_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            summary = root / "results" / "connector-summary.json"
            summary.parent.mkdir()
            summary.write_text('{"apache": {}, "nginx": {}}', encoding="utf-8")
            os.environ["BUILD_ROOT"] = str(root)

            self.assertEqual(self.module.main(["summarize-results.py", "results/connector-summary.json"]), 0)

    def test_rejects_external_or_symlink_escaped_summary_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "build"
            root.mkdir()
            outside = Path(temporary) / "outside.json"
            outside.write_text("{}", encoding="utf-8")
            link = root / "summary-link.json"
            link.symlink_to(outside)
            os.environ["BUILD_ROOT"] = str(root)

            self.assertEqual(self.module.main(["summarize-results.py", str(outside)]), 2)
            self.assertEqual(self.module.main(["summarize-results.py", str(link)]), 2)

    def test_requires_an_explicit_approved_root(self) -> None:
        os.environ.pop("BUILD_ROOT", None)
        os.environ.pop("VERIFIED_RUN_ROOT", None)
        self.assertEqual(self.module.main(["summarize-results.py", "connector-summary.json"]), 2)
