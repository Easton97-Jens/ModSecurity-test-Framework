"""Response-inspection fixtures own both native policy directives explicitly."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import re
import unittest

ROOT = connector_root()


class ResponseLimitFixtureContract(unittest.TestCase):
    def test_each_inspecting_rule_fixture_has_limit_and_action(self):
        paths = list((source_path('common/rules', root=ROOT)).glob("*.conf"))
        paths += list((source_path('examples', root=ROOT)).glob("*/rules/*.conf"))
        paths += list((source_path('ci/runtime/lifecycle/cases/apache-phase4-response', root=ROOT)).glob("*.yaml"))
        inspecting = 0
        for path in paths:
            text = path.read_text()
            if not re.search(r"^\s*SecResponseBodyAccess On\s*$", text, re.M):
                continue
            inspecting += 1
            with self.subTest(fixture=str(path.relative_to(ROOT))):
                self.assertRegex(text, r"(?m)^\s*SecResponseBodyLimit [1-9][0-9]*\s*$")
                self.assertRegex(text, r"(?m)^\s*SecResponseBodyLimitAction (Reject|ProcessPartial)\s*$")
        self.assertGreater(inspecting, 0)

    def test_examples_do_not_reintroduce_removed_connector_options(self):
        removed = re.compile(r"(?m)^\s*(response_body_limit|response-body-limit)\s*=|\"max_response_body_bytes\"\s*:")
        for path in (source_path('examples', root=ROOT)).rglob("*"):
            if path.is_file() and path.suffix in (".conf", ".json"):
                with self.subTest(example=str(path.relative_to(ROOT))):
                    self.assertIsNone(removed.search(path.read_text()))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
