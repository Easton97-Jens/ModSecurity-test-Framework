"""Byte-level framework coverage for the v3.0.16 multipart line-break cases."""

from __future__ import annotations

import importlib
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNNERS = ROOT / "tests" / "runners"
CASES = ROOT / "tests" / "cases" / "body" / "multipart"

if str(RUNNERS) not in sys.path:
    sys.path.insert(0, str(RUNNERS))

runner_core = importlib.import_module("runner_core")


class MultipartNewlineRuntimeDifferenceTests(unittest.TestCase):
    def test_current_case_catalog_remains_loadable(self) -> None:
        case_paths = sorted((ROOT / "tests" / "cases").rglob("*.yaml"))
        self.assertGreater(len(case_paths), 0)

        for case_path in case_paths:
            with self.subTest(case=case_path.relative_to(ROOT)):
                runner_core.load_case(case_path)

    def test_materialized_part_bytes_and_expected_outcomes(self) -> None:
        expected_cases = {
            "multipart_crlf_field_deny_v3_0_16.yaml": (
                b"A\r\nB", 403, "deny", "@rx ^A\\r\\nB$"
            ),
            "multipart_lf_field_deny_v3_0_16.yaml": (
                b"A\nB", 403, "deny", "@rx ^A\\nB$"
            ),
            "multipart_ab_field_allow_v3_0_16.yaml": (
                b"AB", 200, "pass", "@rx ^A(?:\\r\\n|\\n)B$"
            ),
        }

        for filename, (payload, status, intervention, operator) in expected_cases.items():
            with self.subTest(case=filename):
                case = runner_core.load_case(CASES / filename)
                self.assertTrue(case["former_xfail"])
                self.assertFalse(case["capabilities"]["runtime_verified"])
                self.assertEqual(case["expect"]["status"], status)
                self.assertEqual(case["expect"]["intervention"], intervention)
                self.assertIn(operator, case["rules"])
                self.assertNotIn("@contains", case["rules"])

                boundary = case["request"]["multipart"]["boundary"]
                expected_body = (
                    f"--{boundary}\r\n"
                    'Content-Disposition: form-data; name="payload"\r\n'
                    "\r\n"
                ).encode("utf-8") + payload + (
                    f"\r\n--{boundary}--\r\n"
                ).encode("utf-8")
                self.assertEqual(runner_core.request_body_bytes(case), expected_body)


if __name__ == "__main__":
    unittest.main()
