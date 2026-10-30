"""Exercise checked ext_proc finalization with the complete productive C bridge."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from modsecurity_connector_tests.test_envoy_bridge_failures import FIXTURE, ROOT

BRIDGE = source_path('connectors/envoy/ext_proc/internal/processor/common_runtime_bridge.c', root=ROOT)


class EnvoyFinishCallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="i10-envoy-finish-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        cls.binary = cls.compile(BRIDGE, "original")

    @classmethod
    def compile(cls, bridge, name):
        fixture = FIXTURE.replace(
            '#include "connectors/envoy/ext_proc/internal/processor/common_runtime_bridge.c"',
            '#include ' + json.dumps(str(bridge)),
        ).replace('strcmp(stage, "host") == 0 ?', '(strcmp(stage, "host") == 0 || strcmp(stage, "finish") == 0) ?').replace(
            '(void)t; (void)error; ++calls_finish; return 1;',
            '(void)t; ++calls_finish; return boundary_result("finish", error);',
        ).replace(
            '''if (strcmp(argv[1], "void-close") == 0) {
        msc_envoy_ext_proc_transaction_close(transaction);
        close_result = 1;
    } else {
        close_result = msc_envoy_ext_proc_transaction_close_checked(transaction, error, sizeof(error), &close_code);
    }''',
            '''scenario = "finish";
    close_result = msc_envoy_ext_proc_transaction_close_checked(transaction, error, sizeof(error), &close_code);
    int first_cause_retained = cause == MSCONNECTOR_ERROR_NONE ||
        strcmp(error, msconnector_error_default_message(cause)) == 0;
    int null_close = msc_envoy_ext_proc_transaction_close_checked(NULL, error, sizeof(error), NULL);
    printf("{\\\"close\\\":%d,\\\"finish\\\":%d,\\\"destroy\\\":%d,\\\"first_cause\\\":%d,\\\"null_close\\\":%d}\\n",
        close_result, calls_finish, calls_destroy, first_cause_retained, null_close);
    return 0;''',
        )
        source = cls.directory / (name + ".c")
        source.write_text(fixture)
        binary = cls.directory / (name + ".bin")
        result = subprocess.run([
            os.environ.get("CC", "cc"), "-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread",
            "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
            "-I", str(ROOT), "-I", str(source_path('common/include', root=ROOT)),
            "-I", str(BRIDGE.parent), str(source),
            *(str(path) for path in sorted((source_path('common/src', root=ROOT)).glob("*.c"))),
            str(source_path('connectors/profile_registry.c', root=ROOT)), "-o", str(binary),
        ], capture_output=True, text=True, timeout=120, check=False)
        if result.returncode:
            raise AssertionError(result.stderr)
        return binary

    def case(self, scenario, raw, binary=None):
        result = subprocess.run([str(binary or self.binary), scenario, str(raw), "1", "1"],
                                capture_output=True, text=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout.splitlines()[0])

    def test_finish_failure_is_not_success_and_cleanup_consumes_once(self):
        for raw in (0, -1, 2):
            with self.subTest(raw=raw):
                result = self.case("normal", raw)
                self.assertEqual(result, {"close": 0, "finish": 1, "destroy": 1,
                                          "first_cause": 1, "null_close": 1})

    def test_cleanup_failure_preserves_first_technical_cause(self):
        for raw in (0, -1, 2):
            with self.subTest(raw=raw):
                result = self.case("append", raw)
                self.assertEqual((result["close"], result["first_cause"], result["destroy"]), (0, 1, 1))

    def test_legitimate_finish_remains_success(self):
        self.assertEqual(self.case("normal", 1)["close"], 1)

    def test_invalid_finish_return_mutation_is_detected(self):
        original = BRIDGE.read_text()
        old = 'msconnector_runtime_transaction_finish(transaction->transaction,\n                &runtime_error) != 1'
        self.assertEqual(original.count(old), 1)
        mutated = self.directory / "mutated_bridge.c"
        mutated.write_text(original.replace(old, old.replace("!= 1", "== 0"), 1))
        binary = self.compile(mutated, "mutated")
        result = subprocess.run([str(Path(os.sys.executable)), "-c",
            'import json, subprocess, sys; result = subprocess.run([sys.argv[1], "normal", "-1", "1", "1"], capture_output=True, text=True, check=True); assert json.loads(result.stdout.splitlines()[0])["close"] == 0, "invalid finish became success"',
            str(binary)], capture_output=True, text=True, timeout=5, check=False)
        self.assertNotEqual(result.returncode, 0, "mutation survived")
        self.assertIn("AssertionError: invalid finish became success", result.stderr)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
