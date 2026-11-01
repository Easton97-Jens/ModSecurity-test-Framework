"""Envoy productive gRPC seam negative controls in task-owned module copies."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = connector_root()
MODULE = source_path('connectors/envoy/ext_proc', root=ROOT)


class EnvoyCallerMutationTests(unittest.TestCase):
    def test_postcommit_second_response_and_terminal_reentry_mutations_are_detected(self):
        environment = dict(os.environ, GOTOOLCHAIN="local", GOWORK="off")
        cases = (
            ("compositeenvoy", "server.go", "if state.responseCommitted {", "if false {",
             "TestI10CompanionPostCommitProtocolFailureStopsWithoutSecondResponse"),
            ("compositeenvoy", "server.go", "\tif state.responseDone {\n\t\treturn nil\n\t}\n", "",
             "TestI10CompanionHeaderEOSStopsBeforeReenteredBody"),
            ("processor", "processor.go", "if state.responseHeadersSeen && !state.responseDone && !state.immediateResponse {", "if false {",
             "TestI10IncompleteResponseEOFIsTerminal"),
            ("processor", "processor.go", "if reporter, ok := state.transaction.(CleanupFailureReporter); ok {", "if reporter, ok := state.transaction.(CleanupFailureReporter); ok && false {",
             "TestI10FinishFailurePropagatesAfterResponseEOS"),
            ("../cmd/msconnector-envoy-ext-proc", "main.go", "return listener.closeErr", "return listener.Listener.Close()",
             "TestI10ListenerConcurrentCleanupIsOnceOnly"),
        )
        for package, filename, old, new, test in cases:
            with self.subTest(test=test), tempfile.TemporaryDirectory(
                prefix="i10-envoy-mutation-", dir=os.environ.get("RUNNER_TEMP")
            ) as directory:
                copy = Path(directory) / "module"
                shutil.copytree(MODULE, copy)
                source = copy / "internal" / package / filename
                content = source.read_text()
                self.assertEqual(content.count(old), 1)
                source.write_text(content.replace(old, new, 1))
                result = subprocess.run(
                    ["go", "test", "-mod=readonly", "-count=1", "-run", f"^{test}$", f"./internal/{package}"],
                    cwd=copy, env=environment, capture_output=True, text=True, timeout=120, check=False,
                )
                self.assertNotEqual(result.returncode, 0, "mutation unexpectedly survived")
                self.assertIn(f"--- FAIL: {test}", result.stdout + result.stderr)
                self.assertNotIn("[build failed]", result.stdout + result.stderr)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
