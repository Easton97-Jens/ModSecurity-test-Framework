"""Compile the exact native Engine response-limit rejection predicate."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = connector_root()


class NginxResponseBodyLimitTests(unittest.TestCase):
    def test_exact_signature_and_negative_controls(self) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        self.assertTrue(compiler and shutil.which(compiler[0]), "C compiler is required")
        with tempfile.TemporaryDirectory(prefix="nginx-response-limit-",
                                         dir=os.environ.get("RUNNER_TEMP")) as temporary:
            for sanity in (0, 1):
                with self.subTest(sanity_checks=sanity):
                    binary = Path(temporary) / f"response-limit-{sanity}"
                    command = compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror",
                                          "-pedantic-errors",
                                          f"-DMODSECURITY_SANITY_CHECKS={sanity}",
                                          "-I", str(source_path('common/include', root=ROOT)),
                                          "-I", str(source_path('connectors/nginx/src', root=ROOT)),
                                          str(source_path('tests/fixtures/nginx_response_body_limit.c', root=ROOT)),
                                          "-o", str(binary)]
                    compiled = subprocess.run(command, capture_output=True, text=True,
                                              timeout=30, check=False)
                    self.assertEqual(compiled.returncode, 0, compiled.stderr[-6000:])
                    executed = subprocess.run([str(binary)], capture_output=True, text=True,
                                              timeout=5, check=False)
                    self.assertEqual(executed.returncode, 0, executed.stderr[-2000:])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
