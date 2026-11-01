"""Compile actual Common boundary guards; never claim native HTTP evidence."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = connector_root()


class CommonInputValidationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="common-input-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "probe"
        subprocess.run(["/usr/bin/cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-ffunction-sections", "-Wl,--gc-sections", "-I", str(source_path('common/include', root=ROOT)),
                        str(source_path('tests/fixtures/nginx_common_input_validation.c', root=ROOT)),
                        str(source_path('common/src/request_helpers.c', root=ROOT)),
                        str(source_path('common/src/request_mapper_contract.c', root=ROOT)), "-o", str(cls.binary)],
                       check=True, capture_output=True, timeout=30)

    def probe(self, mode):
        result = subprocess.run([str(self.binary), mode], check=True, capture_output=True, text=True, timeout=5)
        return result.stdout.splitlines()

    def test_nonzero_body_with_null_data_rejected_at_actual_common_mapper_boundary(self):
        result = self.probe("body")
        self.assertEqual(result[:2], ["0", "0"])
        self.assertEqual(result[2], "missing body data")

    def test_nonzero_headers_with_null_array_rejected_at_actual_common_mapper_boundary(self):
        self.assertEqual(self.probe("headers"), ["0", "0", "missing headers"])

    def test_valid_and_truly_empty_inputs_remain_accepted(self):
        for mode in ("valid", "empty"):
            with self.subTest(mode=mode):
                self.assertEqual(self.probe(mode), ["1", "1", ""])

    def test_unsupported_body_policy_error_precedes_pointer_validation(self):
        self.assertEqual(self.probe("unsupported"), ["0", "0", "body unsupported"])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
