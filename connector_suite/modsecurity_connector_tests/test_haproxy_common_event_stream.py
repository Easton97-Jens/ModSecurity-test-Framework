"""Shared checked stdio helper: real cookie write/flush/close faults."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = connector_root()


class CommonEventStream(unittest.TestCase):
    def run_probe(self, sanitizers=False, mutation=None):
        parent = Path(os.environ.get("TMPDIR", "/var/tmp/codex/ModSecurity-conector/tmp"))
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="haproxy-common-event-", dir=parent) as directory:
            binary = Path(directory) / "stream"
            sources = ["event_jsonl.c", "transaction_state.c", "transaction_id.c", "log_sanitize.c", "rule_id.c", "late_intervention.c", "event.c", "json_escape.c", "status.c", "http_status.c", "error.c"]
            if mutation:
                sources.remove("event_jsonl.c")
                state = Path(directory) / "event_jsonl.c"
                text = (source_path('common/src/event_jsonl.c', root=ROOT)).read_text()
                self.assertIn(mutation[0], text)
                state.write_text(text.replace(*mutation, 1))
            command = ["cc", "-std=c17", "-Wall", "-Wextra", "-Werror", "-ffunction-sections", "-Wl,--gc-sections",
                "-I", str(source_path('common/include', root=ROOT)), str(source_path('tests/haproxy_common_event_stream_test.c', root=ROOT)),
                *(str(source_path('common/src', root=ROOT) / name) for name in sources), *([str(state)] if mutation else []), "-o", str(binary)]
            if sanitizers:
                command[1:1] = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)

    def test_real_physical_stream_and_sink_faults(self):
        result = self.run_probe()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_physical_sink_asan_ubsan(self):
        result = self.run_probe(sanitizers=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_write_close_and_sticky_mutations_are_detected(self):
        mutations = [
            ('if (fputs(serialized, file) == EOF || ferror(file) ||\n            fflush(file) != 0 || ferror(file)) {',
             'if (fputs(serialized, file) == EOF || fflush(file) != 0) {'),
            ('return event_stream_error(error, MSCONNECTOR_ERROR_IO,\n            "event stream write or flush failed");', 'return 1;'),
            ('if (fclose(owned) != 0) { failed = 1; }', '(void)fclose(owned);'),
            ('if (error != NULL && error->code != MSCONNECTOR_ERROR_NONE) { return 0; }', ''),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation[0]):
                result = self.run_probe(mutation=mutation)
                self.assertNotEqual(result.returncode, 0, "unchecked sink mutation survived")

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
