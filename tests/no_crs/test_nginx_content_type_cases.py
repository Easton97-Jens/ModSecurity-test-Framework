"""Executable MIME variants must retain distinct, sourced native operations."""

from pathlib import Path
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
CASES = ROOT / "tests/cases/no-crs-baseline"
sys.path.insert(0, str(ROOT / "tests/runners"))
from runner_core import load_case, write_nginx_runtime_files, write_response_fixture
VARIANTS = {
    "phase4_in_scope_content_type": ("text/plain", 200),
    "phase4_content_type_with_charset": ("text/plain; charset=utf-8", 200),
    "phase4_out_of_scope_content_type": ("image/png", 200),
    "phase4_missing_content_type": (None, 200),
}


class NginxContentTypeCaseTests(unittest.TestCase):
    def test_native_materializer_preserves_each_distinct_operation(self):
        external = Path("/var/tmp/codex/ModSecurity-conector/analysis")
        with tempfile.TemporaryDirectory(prefix="mime-cases-", dir=external) as temporary:
            output = Path(temporary)
            for case_id, (content_type, _) in VARIANTS.items():
                with self.subTest(case_id=case_id):
                    case = load_case(CASES / f"{case_id}.yaml")
                    invocation = output / case_id
                    invocation.mkdir()
                    directives = invocation / "location.conf"
                    log = invocation / "phase4.jsonl"
                    write_nginx_runtime_files(case, directives, invocation / "config",
                                              output_root=output, phase4_log_file=log)
                    self.assertIn(f'default_type "{content_type or ""}";', directives.read_text())
                    self.assertIn(str(log), directives.read_text())
                    self.assertNotIn("@@", directives.read_text())
                    write_response_fixture(case, invocation / "docroot", output_root=output)
                    leaf = invocation / "docroot" / "index.html"
                    self.assertEqual(leaf.read_text(), "no-crs-response-body-marker")

    def test_each_variant_has_distinct_executable_case(self):
        for case_id, (content_type, status) in VARIANTS.items():
            with self.subTest(case_id=case_id):
                source = CASES / f"{case_id}.yaml"
                self.assertTrue(source.is_file(), f"missing executable case: {case_id}")
                case = yaml.safe_load(source.read_text(encoding="utf-8"))
                self.assertEqual(case["name"], case_id)
                self.assertEqual(case["phase"], 4)
                self.assertEqual(case["request"]["path"], f"/no-crs/content-type/{case_id}")
                self.assertEqual(case["response"]["content_type"], content_type)
                self.assertEqual(case["expect"]["status"], status)
                self.assertNotIn("SecResponseBodyMimeTypesClear", case["rules"])
                self.assertIn("SecResponseBodyMimeType text/plain application/json", case["rules"])
                self.assertIn("id:1100301,phase:4,deny", (ROOT / "tests/rules/no-crs-baseline.conf").read_text())
                self.assertNotIn("modsecurity_phase4_content_types_file", str(case))
                self.assertEqual(case["response"]["body"], "no-crs-response-body-marker")
                directives = case["nginx"]["location_directives"]
                self.assertIn("types { }", directives)
                self.assertIn(f'default_type "{content_type or ""}";', directives)
                if content_type is None:
                    self.assertEqual(case["response"]["omit_headers"], ["Content-Type"])


if __name__ == "__main__":
    unittest.main()
