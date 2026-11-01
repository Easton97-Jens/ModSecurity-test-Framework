"""Validate the public adapter before any connector test child may start."""
from contextlib import redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from modsecurity_test_framework import connector
from modsecurity_test_framework.connector_context import ConnectorContext


class ConnectorAdapterCliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def test_help_is_available_without_connector_or_test_environment(self):
        with patch.dict(os.environ, {}, clear=True), redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(SystemExit) as result:
                connector.main(["--help"])
        self.assertEqual(result.exception.code, 0)
        self.assertIn("--connector-revision", output.getvalue())

    def test_missing_explicit_checkout_rejects_before_engine(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(connector, "_run_engine") as child:
            with redirect_stderr(io.StringIO()) as error:
                status = connector.main(["--check"])
        self.assertEqual(status, 2)
        self.assertIn("CONNECTOR_ROOT is required explicitly", error.getvalue())
        child.assert_not_called()

    def test_non_checkout_directory_rejects_before_engine(self):
        product = self.directory / "product"
        (product / "connectors").mkdir(parents=True)
        (product / "common/include").mkdir(parents=True)
        with patch.dict(os.environ, {}, clear=True), patch.object(connector, "_run_engine") as child:
            with redirect_stderr(io.StringIO()) as error:
                status = connector.main(["--connector-root", str(product),
                                         "--connector-revision", "1" * 40, "--check"])
        self.assertEqual(status, 2)
        self.assertIn("CONNECTOR_TEST_REJECTED", error.getvalue())
        child.assert_not_called()

    def test_validated_values_define_child_namespace_and_do_not_leak_environment_changes(self):
        context = ConnectorContext(self.directory / "product", self.directory / "framework",
                                   "a" * 40, "nginx-native", self.directory / "results")
        baseline = {"PATH": os.defpath, "PYTHONPATH": "/unrelated/colliding/tests"}
        arguments = ["--connector-root", str(context.connector),
                     "--connector-revision", context.revision, "--test-root", str(context.tests),
                     "--profile", context.profile, "--output-root", str(context.output),
                     "--check", "--case", "existing.case"]
        with (patch.dict(os.environ, baseline, clear=True), patch.object(
                connector.ConnectorContext, "from_environment", return_value=context) as validate,
                patch.object(connector, "framework_revision", return_value="b" * 40),
                patch.object(connector, "_run_engine", return_value=7) as child):
            self.assertEqual(connector.main(arguments), 7)
            self.assertEqual(dict(os.environ), baseline)
        validate.assert_called_once_with()
        passed_context, selection, environment = child.call_args.args
        self.assertEqual(passed_context, context)
        self.assertEqual(selection, ["--check", "--case", "existing.case"])
        self.assertEqual(environment["PYTHONPATH"], os.pathsep.join(
            (str(context.tests), str(context.tests / "connector_suite"))))
        self.assertEqual(environment["PYTHONSAFEPATH"], "1")
        self.assertEqual(environment["PYTHONNOUSERSITE"], "1")
        self.assertEqual(environment["FRAMEWORK_REVISION"], "b" * 40)
        self.assertEqual(environment["CONNECTOR_REVISION"], context.revision)
        self.assertEqual(environment["CONNECTOR_TEST_PROFILE"], "nginx-native")
        self.assertEqual(environment["CONNECTOR_TEST_OUTPUT_ROOT"], str(context.output))




def load_tests(loader, standard_tests, pattern):
    import os
    if os.environ.get("ON_DEMAND_TESTS") == "1":
        return standard_tests
    return unittest.TestSuite()

if __name__ == "__main__":
    unittest.main()
