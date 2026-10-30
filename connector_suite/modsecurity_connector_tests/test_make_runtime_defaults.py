from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = connector_root()


# This test supplies its own VERIFIED_RUN_ROOT and verifies the Makefile's
# derived defaults.  Clear parent path overrides so ambient CI settings do not
# turn that default-path assertion into an override test.
RUNTIME_PATH_OVERRIDES = (
    "VERIFIED_BUILD_ROOT",
    "BUILD_ROOT",
    "TMP_ROOT",
    "LOG_ROOT",
)


class MakeRuntimeDefaultsTest(unittest.TestCase):
    def test_default_tmp_root_is_below_build_root(self) -> None:
        """Default connector roots remain build-contained under CI overrides."""
        with tempfile.TemporaryDirectory(prefix="make-runtime-defaults-") as temporary:
            run_root = Path(temporary) / "verified-run"
            recipe = 'print-runtime-roots: ; @printf "%s\\n%s\\n" "$(TMP_ROOT)" "$(LOG_ROOT)"'
            environment = os.environ.copy()
            for name in RUNTIME_PATH_OVERRIDES:
                environment.pop(name, None)
            result = subprocess.run(
                [
                    "make",
                    "-s",
                    "--no-print-directory",
                    "--eval",
                    recipe,
                    "print-runtime-roots",
                    f"VERIFIED_RUN_ROOT={run_root}",
                ],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=environment,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                result.stdout.splitlines(),
                [
                    str(run_root / "build" / "tmp"),
                    str(run_root / "build" / "logs"),
                ],
            )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
