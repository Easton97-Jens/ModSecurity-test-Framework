"""Compile native completion metadata through the genuine Common serializer."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = connector_root()


class Phase4ObservationTests(unittest.TestCase):
    def test_closed_actual_counters_and_invalid_completion_controls(self):
        compiler = shlex.split(os.environ.get("CC", "cc"))
        self.assertTrue(compiler and shutil.which(compiler[0]), "C compiler required")
        with tempfile.TemporaryDirectory(prefix="nginx-p4-observation-",
                                         dir=os.environ.get("RUNNER_TEMP")) as temporary:
            for sanity in (0, 1):
                with self.subTest(sanity=sanity):
                    binary = Path(temporary) / f"observation-{sanity}"
                    command = compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror",
                        "-pedantic-errors", "-ffunction-sections", "-Wl,--gc-sections",
                        f"-DMODSECURITY_SANITY_CHECKS={sanity}",
                        "-I", str(source_path('common/include', root=ROOT)), "-I", str(source_path('connectors/nginx/src', root=ROOT)),
                        str(source_path('tests/fixtures/nginx_phase4_observation.c', root=ROOT))]
                    command += [str(source_path('common/src', root=ROOT) / source) for source in
                                ("event.c", "event_jsonl.c", "http_status.c", "json_escape.c", "status.c", "transaction_state.c")]
                    command += ["-o", str(binary)]
                    compiled = subprocess.run(command, capture_output=True, text=True, timeout=30)
                    self.assertEqual(compiled.returncode, 0, compiled.stderr[-5000:])
                    observed = subprocess.run([str(binary)], capture_output=True, text=True, timeout=5)
                    self.assertEqual(observed.returncode, 0, observed.stderr)
                    event = json.loads(observed.stdout)
                    self.assertEqual(event["event"], "phase4_completion")
                    self.assertEqual(event["phase"], "response_body")
                    self.assertEqual(event["reason"], "engine_retained_bytes=64;append_calls=2")
                    self.assertEqual(event["body_bytes_seen"], 65)
                    self.assertEqual(event["body_bytes_inspected"], 65)
                    self.assertEqual(event["content_type"], "text/plain")
                    self.assertTrue(event["eos_seen"])
                    self.assertNotIn("marker_split", event)
                    self.assertNotIn("content_type_scope", event)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
