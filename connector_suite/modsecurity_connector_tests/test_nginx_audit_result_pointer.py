"""The NGINX case record must point to the audit file used by the host."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = connector_root()
HARNESS = source_path('connectors/nginx/harness/run_nginx_smoke.sh', root=ROOT)


class NginxAuditResultPointerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / "case-logs/result.json"
        self.output.parent.mkdir()
        self.capture = self.root / "case-info-args.json"
        self.case_cli = self.root / "capture-case-info.py"
        self.case_cli.write_text(
            "import json, os, sys\n"
            "with open(os.environ['CASE_INFO_CAPTURE'], 'w', encoding='utf-8') as stream:\n"
            "    json.dump(sys.argv[1:], stream)\n",
            encoding="utf-8",
        )

    def case_info_args(self, actual_status: str, audit_log: Path | None) -> list[str]:
        harness = HARNESS.read_text(encoding="utf-8")
        match = re.search(r"^write_case_result\(\) \{\n.*?^\}", harness, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(match)
        env = os.environ.copy()
        env.update(
            PYTHON_BIN=sys.executable,
            CASE_CLI=str(self.case_cli),
            CASE_INFO_CAPTURE=str(self.capture),
        )
        env.pop("AUDIT_LOG_FILE", None)
        if audit_log is not None:
            env["AUDIT_LOG_FILE"] = str(audit_log)
        completed = subprocess.run(
            ["sh", "-c", f'{match.group(0)}\nwrite_case_result "$1" pass "$2" "$3"',
             "audit-pointer-test", str(self.root / "case.yaml"), actual_status, str(self.output)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return json.loads(self.capture.read_text(encoding="utf-8"))

    def test_result_uses_the_distinct_server_audit_log(self) -> None:
        audit_log = self.root / "server-logs/audit.log"
        audit_log.parent.mkdir()
        audit_log.write_text("real host audit\n", encoding="utf-8")
        (self.output.parent / "audit.log").write_text("wrong case log\n", encoding="utf-8")

        args = self.case_info_args("200", audit_log)

        self.assertEqual(args[args.index("--audit-log-file") + 1], str(audit_log))
        self.assertEqual(audit_log.read_text(encoding="utf-8"), "real host audit\n")

    def test_early_result_without_audit_assignment_keeps_case_log_fallback(self) -> None:
        args = self.case_info_args("", None)

        self.assertEqual(
            args[args.index("--audit-log-file") + 1],
            str(self.output.parent / "audit.log"),
        )

    def test_result_without_status_still_uses_assigned_server_audit_log(self) -> None:
        audit_log = self.root / "server-logs/audit.log"
        args = self.case_info_args("", audit_log)

        self.assertEqual(args[args.index("--audit-log-file") + 1], str(audit_log))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
