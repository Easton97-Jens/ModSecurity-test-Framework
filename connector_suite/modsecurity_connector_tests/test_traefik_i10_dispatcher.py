"""Compile the productive Traefik dispatcher with controlled Common error seams."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import ctypes.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = connector_root()


class TraefikI10DispatcherTest(unittest.TestCase):
    def test_technical_failure_and_terminal_reentry(self) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("requires a C compiler")
        if ctypes.util.find_library("modsecurity") is None:
            self.skipTest("requires installed libmodsecurity to link retained Common runtime")

        common_sources = sorted((source_path('common/src', root=ROOT)).glob("*.c"))
        runtime_sources = sorted((source_path('common/runtime', root=ROOT)).glob("*.c"))
        with tempfile.TemporaryDirectory(
            prefix="traefik-i10-dispatcher-",
            dir=os.environ.get("TMPDIR"),
        ) as temporary_directory:
            binary = Path(temporary_directory) / "dispatcher"
            compile_result = subprocess.run(
                [
                    compiler,
                    "-std=c17",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-ffunction-sections",
                    "-fdata-sections",
                    "-I",
                    str(ROOT),
                    "-I",
                    str(test_root() / "connector_native_tests"),
                    "-I",
                    str(source_path('common/include', root=ROOT)),
                    "-I",
                    str(source_path('common/runtime', root=ROOT)),
                    "-I",
                    str(source_path('connectors/traefik', root=ROOT)),
                    "-I",
                    str(source_path('connectors/traefik/src', root=ROOT)),
                    str(source_path('tests/traefik_i10_dispatcher_test.c', root=ROOT)),
                    *(str(source) for source in common_sources),
                    *(str(source) for source in runtime_sources),
                    str(source_path('connectors/profile_registry.c', root=ROOT)),
                    "-Wl,--gc-sections",
                    "-lmodsecurity",
                    "-pthread",
                    "-o",
                    str(binary),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            config_paths = []
            example = (source_path('connectors/traefik/config/traefik-engine-service.conf', root=ROOT)).read_text()
            example = "\n".join("rules_file=" + str(source_path('common/rules/modsecurity_targeted_smoke.conf', root=ROOT)) if line.startswith("rules_file=") else line for line in example.splitlines()) + "\n"
            for mode in ("off", "safe", "strict"):
                config_path = Path(temporary_directory) / (mode + ".conf")
                config_path.write_text(example.replace("phase4_mode=off", "phase4_mode=" + mode))
                config_paths.append(str(config_path))
            run_result = subprocess.run(
                [str(binary), *config_paths],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=10.0,
                check=False,
            )
            self.assertEqual(run_result.returncode, 0, run_result.stderr)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
