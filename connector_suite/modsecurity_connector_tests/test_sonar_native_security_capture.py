"""Pure negative control for the compiler invocation environment boundary."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch


ROOT = connector_root()
CAPTURE = load_source(source_path('ci/checks/analysis/sonar-native-security/capture.py', root=ROOT))


class NativeCompilerEnvironmentTest(unittest.TestCase):
    def assert_environment_rejected(self, name, value):
        with patch.dict(os.environ, {name: value}, clear=True):
            with patch.object(CAPTURE.subprocess, "run", side_effect=AssertionError("compiler must not start")):
                with self.assertRaisesRegex(ValueError, "undeclared implicit compiler environment"):
                    CAPTURE.capture("unused-compiler", [], Path("unused-capture-root"))

    def test_implicit_environment_rejected_before_compiler(self):
        self.assert_environment_rejected("CPATH", "/unit-only-unadmitted-include")

    def test_clang_override_environment_rejected_before_compiler(self):
        self.assert_environment_rejected("CCC_OVERRIDE_OPTIONS", "+-DUNIT_UNDECLARED_FLAG")


if os.environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)


if __name__ == "__main__":
    unittest.main()
