from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = connector_root()
SCRIPT = source_path('common/scripts/run_blocked_runtime_smoke.sh', root=ROOT)


class RunBlockedRuntimeSmokeTest(unittest.TestCase):
    def test_unknown_connector_uses_controlled_blocked_dependency_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="blocked-runtime-smoke-") as temporary:
            temporary_root = Path(temporary)
            connector_root = temporary_root / "connector-root"
            (connector_root / "connectors" / "custom").mkdir(parents=True)
            helper = connector_root / "framework" / "ci" / "lib" / "connector-smoke-common.sh"
            helper.parent.mkdir(parents=True)
            helper.write_text(
                """\
connector_skip_missing_dependency() {
    printf '%s|%s|%s|%s|%s\\n' "$1" "$2" "$3" "$4" "$6"
    exit 0
}
find_runtime_binary() { printf '%s\\n' /bin/true; }
connector_smoke_decision_backend_value() { printf '%s\\n' native; }
connector_smoke_normalize_decision_backend() { printf '%s\\n' "$1"; }
connector_smoke_modsecurity_rule_file() { printf '%s\\n' unused; }
""",
                encoding="utf-8",
            )
            environment = os.environ | {
                "CONNECTOR_ROOT": str(connector_root),
                "FRAMEWORK_ROOT": str(connector_root / "framework"),
            }

            completed = subprocess.run(
                [
                    "sh",
                    str(SCRIPT),
                    "custom",
                    "local",
                    "CUSTOM_BIN",
                    "custom-bin",
                    "missing binary",
                    "unsupported connector",
                    "custom dependency",
                    "native",
                    "1",
                ],
                check=False,
                capture_output=True,
                env=environment,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                completed.stdout,
                "custom|local|unsupported connector|custom dependency|/bin/true\n",
            )

    def test_selected_connector_configuration_case_has_fail_closed_default(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        marker = '        case "$CONNECTOR_NAME" in\n'
        _, found, remaining = source.partition(marker)
        self.assertTrue(found, "selected-connector configuration case is missing")
        selected_case, _, _ = remaining.partition("        esac\n")
        self.assertIn(
            "            *)\n"
            "                connector_skip_missing_dependency \\\n"
            '                    "$CONNECTOR_NAME" \\\n'
            '                    "$INTEGRATION_MODE" \\\n'
            '                    "$POST_LOOKUP_BLOCKED_REASON" \\\n'
            '                    "$POST_LOOKUP_MISSING_DEPENDENCY"',
            selected_case,
        )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
