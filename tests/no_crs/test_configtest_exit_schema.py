"""Failure receipts retain signed Python subprocess exits without granting PASS."""

from __future__ import annotations

import json
from pathlib import Path
import unittest

from tests.no_crs import test_configtest_receipt as receipt_tests


ROOT = Path(__file__).resolve().parents[2]


class ConfigtestExitSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads((ROOT / "tests/schemas/no-crs-baseline/configtest-receipt.schema.json")
                                .read_text(encoding="utf-8"))

    def schema_errors(self, receipt: dict[str, object]) -> list[str]:
        return receipt_tests.no_crs.json_schema_errors(receipt, self.schema)

    def test_exec_error_and_timeout_are_structurally_valid_failure_receipts(self) -> None:
        for exit_code, error_class in ((-1, "execution_error"), (-9, "timeout")):
            with self.subTest(exit_code=exit_code):
                receipt = receipt_tests.ConfigtestReceiptTest.receipt()
                receipt.update(observed_exit_code=exit_code, observed_outcome="unexpected_outcome",
                               error_class=error_class, diagnostic_fragments=[])
                self.assertEqual(self.schema_errors(receipt), [])

    def test_signed_failure_exit_never_satisfies_required_config_rejection(self) -> None:
        no_crs = receipt_tests.no_crs
        fixture = receipt_tests.ConfigtestReceiptTest()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        baseline = no_crs.normalize_case_record(
            fixture.valid_raw(), "nginx", fixture.cases, [], "native-nginx-http-module",
            configtest_artifact_root=fixture.artifact_root,
        )
        self.assertEqual(baseline["status"], "PASS", baseline["reason"])
        for exit_code in (-1, -9):
            with self.subTest(exit_code=exit_code):
                raw = fixture.valid_raw()
                # Even a claimed rejection and matching diagnostic cannot turn a
                # failed host launch or signal termination into expected exit 1.
                receipt = raw["configtest_receipt"]
                receipt["observed_exit_code"] = exit_code
                raw["configtest_receipt"] = receipt
                record = no_crs.normalize_case_record(
                    raw, "nginx", fixture.cases, [], "native-nginx-http-module",
                    configtest_artifact_root=fixture.artifact_root,
                )
                self.assertEqual(record["status"], "FAIL", record)
                self.assertIn("configuration receipt observed exit", record["reason"])
                self.assertNotIn("artifact", record["reason"])

    def test_expected_exit_and_bounded_integer_constraints_remain_strict(self) -> None:
        for field, value in (("expected_exit_code", -1), ("expected_exit_code", -9),
                             ("expected_exit_code", 0), ("observed_exit_code", -256),
                             ("observed_exit_code", 256), ("observed_exit_code", True),
                             ("observed_exit_code", "-9")):
            with self.subTest(field=field, value=value):
                receipt = receipt_tests.ConfigtestReceiptTest.receipt()
                receipt[field] = value
                self.assertTrue(self.schema_errors(receipt))


if __name__ == "__main__":
    unittest.main()
