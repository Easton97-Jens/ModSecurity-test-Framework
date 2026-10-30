from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.request import urlopen

from modsecurity_connector_tests.framework_test_trust import trusted_framework_root


ROOT = connector_root()
FRAMEWORK_ROOT = Path(
    os.environ.get("PARENT_TEST_FRAMEWORK_ROOT", source_path('modules/ModSecurity-test-Framework', root=ROOT))
)
BACKEND = source_path('ci/runtime/common/response-header-test-backend.py', root=ROOT)
METADATA = source_path('ci/runtime/common/harness-case-metadata.py', root=ROOT)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class ResponseHeaderBackendTest(unittest.TestCase):
    def trusted_framework_root(self) -> Path:
        framework_root, error = trusted_framework_root(ROOT, FRAMEWORK_ROOT)
        if framework_root is None:
            self.skipTest(error)
        return framework_root

    def metadata(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(METADATA), *arguments],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_phase3_cases_materialize_their_declared_upstream_markers(self) -> None:
        framework_root = self.trusted_framework_root()
        fixtures = {
            "phase3_deny_before_commit.yaml": "block",
            "phase3_redirect_before_commit.yaml": "redirect",
        }
        for filename, marker in fixtures.items():
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                case = (
                    framework_root
                    / "tests"
                    / "cases"
                    / "no-crs-baseline"
                    / "full-lifecycle"
                    / filename
                )
                output = Path(temporary) / "fixture.json"
                result = self.metadata(
                    "response-header-fixture",
                    "--case",
                    str(case),
                    "--framework-root",
                    str(framework_root),
                    "--output",
                    str(output),
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                fixture = json.loads(output.read_text(encoding="utf-8"))
                self.assertEqual(fixture["status"], 200)
                self.assertEqual(fixture["headers"], [["X-Modsec-Upstream", marker]])

    def test_backend_uses_declarative_status_and_marker_header(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            body_file = root / "body.txt"
            fixture_file = root / "fixture.json"
            body_file.write_text("phase3 <marker>", encoding="utf-8")
            fixture_file.write_text(
                json.dumps(
                    {
                        "status": 201,
                        "headers": [
                            ["X-Modsec-Upstream", "block"],
                            ["Content-Type", "text/plain; charset=utf-8"],
                        ],
                    }
                ),
                encoding="utf-8",
            )
            port = free_port()
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(BACKEND),
                    "--port",
                    str(port),
                    "--body-file",
                    str(body_file),
                    "--safe-root",
                    str(root),
                    "--fixture-file",
                    str(fixture_file),
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                last_error: Exception | None = None
                for _ in range(40):
                    try:
                        with urlopen(f"http://127.0.0.1:{port}/", timeout=0.25) as response:
                            self.assertEqual(response.status, 201)
                            self.assertEqual(response.headers["X-Modsec-Upstream"], "block")
                            self.assertEqual(response.headers["Content-Type"], "text/plain; charset=utf-8")
                            self.assertEqual(response.read(), b"phase3 &lt;marker&gt;")
                        break
                    except OSError as exc:
                        last_error = exc
                        time.sleep(0.05)
                else:
                    self.fail(f"response-header backend did not start: {last_error}")
            finally:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=5)
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()

    def test_invalid_fixture_headers_are_rejected_before_listening(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            body_file = root / "body.txt"
            fixture_file = root / "fixture.json"
            body_file.write_text("body", encoding="utf-8")
            fixture_file.write_text(
                json.dumps({"status": 200, "headers": [["X-Test", "ok\r\nInjected: yes"]]}),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(BACKEND),
                    "--port",
                    "1",
                    "--body-file",
                    str(body_file),
                    "--safe-root",
                    str(root),
                    "--fixture-file",
                    str(fixture_file),
                ],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid response header value", result.stderr)

    def test_apache_phase4_mode_is_case_metadata_and_is_validated(self) -> None:
        framework_root = self.trusted_framework_root()
        with tempfile.TemporaryDirectory() as temporary:
            case = Path(temporary) / "apache-mode.yaml"
            case.write_text(
                """\
name: apache_mode_metadata
rules: |
  SecRuleEngine On
request:
  method: GET
  path: /
response:
  body: body
apache:
  phase4_mode: strict
expect:
  status: 200
""",
                encoding="utf-8",
            )
            result = self.metadata(
                "apache-phase4-mode",
                "--case",
                str(case),
                "--framework-root",
                str(framework_root),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "strict\n")

            case.write_text(case.read_text(encoding="utf-8").replace("strict", "unsafe"), encoding="utf-8")
            invalid = self.metadata(
                "apache-phase4-mode",
                "--case",
                str(case),
                "--framework-root",
                str(framework_root),
            )
        self.assertNotEqual(invalid.returncode, 0)
        self.assertIn("apache.phase4_mode", invalid.stderr)

    def test_both_host_harnesses_use_the_fixture_for_any_response_headers_rule(self) -> None:
        apache = (source_path('connectors/apache/harness/run_apache_smoke.sh', root=ROOT)).read_text(
            encoding="utf-8"
        )
        nginx = (source_path('connectors/nginx/harness/run_nginx_smoke.sh', root=ROOT)).read_text(
            encoding="utf-8"
        )
        for name, harness in (("apache", apache), ("nginx", nginx)):
            with self.subTest(harness=name):
                self.assertIn("RESPONSE_HEADERS([[:space:]:]|$)", harness)
                self.assertIn('--fixture-file "$RESPONSE_HEADER_FIXTURE_FILE"', harness)
                self.assertIn("response-header-fixture", harness)

        template = (source_path('connectors/apache/harness/apache_smoke.conf', root=ROOT)).read_text(
            encoding="utf-8"
        )
        self.assertIn("@@APACHE_PHASE4_MODE@@", template)
        self.assertNotIn("modsecurity_phase4_mode safe", template)
        self.assertIn("resolve_apache_phase4_mode", apache)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
