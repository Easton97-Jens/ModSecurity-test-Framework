"""Exercise the NGINX case request command at its shell function boundary."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import hashlib
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


class NginxH1RequestProtocolTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.capture = self.root / "curl-args.json"
        self.curl = self.root / "capture-curl"
        self.curl.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "with open(os.environ['CURL_CAPTURE'], 'w', encoding='utf-8') as stream:\n"
            "    json.dump(sys.argv[1:], stream)\n"
            "print('200', end='')\n",
            encoding="utf-8",
        )
        self.curl.chmod(0o700)
        self.headers = self.root / "request-headers.txt"
        self.headers.write_text("X-Smoke: first\nX-Smoke: second\n", encoding="utf-8")
        self.body = self.root / "request-body.bin"
        self.body.write_bytes(b"probe body")

    def run_request(self, protocol: str) -> subprocess.CompletedProcess[str]:
        harness = HARNESS.read_text(encoding="utf-8")
        match = re.search(r"^send_case_request\(\) \{\n.*?^\}", harness, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(match)
        # These controlled collaborators only capture the function's curl
        # command; the host path validator and path encoder are separate seams.
        script = (
            "set -eu\n"
            "validate_nginx_request_output_path() { :; }\n"
            "quote_request_path() { printf '%s\\n' \"$1\"; }\n"
            "blocked() { printf '%s\\n' \"$*\" >&2; exit 77; }\n"
            f"{match.group(0)}\n"
            "send_case_request\n"
        )
        environment = os.environ.copy()
        environment.update(
            PYTHON_BIN=sys.executable,
            CASE_CLI=str(test_root() / "tests/runners/case_cli.py"),
            TEST_CASE=str(test_root() / "tests/cases/no-crs-baseline/allow_without_marker.yaml"),
            NGINX_HARNESS_WORK_ROOT=str(self.root),
            RESULT_RUN_ID="nginx-h1-request-unit",
            CONNECTOR_REVISION=os.environ["CONNECTOR_REVISION"],
            CURL_BIN=str(self.curl),
            CURL_CAPTURE=str(self.capture),
            NGINX_DOWNSTREAM_PROTOCOL=protocol,
            RESPONSE_BODY=str(self.root / "response.txt"),
            LOG_DIR=str(self.root),
            REQUEST_METHOD="POST",
            REQUEST_HEADERS_FILE=str(self.headers),
            REQUEST_BODY_FILE=str(self.body),
            REQUEST_HAS_BODY="1",
            REQUEST_PATH="/no-crs/allow",
            SEND_CASE_MAX_TIME_SECONDS="2",
            PORT="18080",
        )
        completed = subprocess.run(
            ["sh", "-c", script],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        if protocol == "http1" and completed.returncode == 0:
            receipt = json.loads((self.root / "request-window.json").read_text())
            anchor = (self.root / "request-window.json.start.json").read_bytes()
            self.assertEqual(receipt["state"], "completed")
            self.assertEqual(receipt["run_id"], "nginx-h1-request-unit")
            self.assertEqual(receipt["source_revision"], os.environ["CONNECTOR_REVISION"])
            self.assertEqual(receipt["begin_sha256"], hashlib.sha256(anchor).hexdigest())
            self.assertEqual(receipt["request_id"], json.loads(anchor)["request_id"])
            self.assertEqual(receipt["case_sha256"], hashlib.sha256(
                Path(environment["TEST_CASE"]).read_bytes()).hexdigest())
            self.assertEqual(receipt["start_offset"], 0)
            self.assertEqual(receipt["end_offset"], 0)
            self.assertEqual(receipt["interval_sha256"], hashlib.sha256(b"").hexdigest())
        return completed

    def test_h1_request_forces_http11_without_curlrc_and_preserves_payload(self) -> None:
        completed = self.run_request("http1")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "200")
        args = json.loads(self.capture.read_text(encoding="utf-8"))
        self.assertEqual(args[:2], ["-q", "--http1.1"])
        self.assertEqual(args[args.index("-X") + 1], "POST")
        self.assertEqual(args[args.index("-o") + 1], str(self.root / "response.txt"))
        self.assertEqual(args[args.index("-w") + 1], "%{http_code}")
        self.assertEqual(args[args.index("--max-time") + 1], "2")
        self.assertEqual(
            [args[position + 1] for position, value in enumerate(args) if value == "-H"],
            ["X-Smoke: first", "X-Smoke: second"],
        )
        self.assertEqual(args[args.index("--data-binary") + 1], f"@{self.body}")
        self.assertEqual(args[-1], "http://127.0.0.1:18080/no-crs/allow")

    def test_header_defaults_preserve_curl_semantics(self) -> None:
        headers = ["X-Empty:", "X-Space: ", "X-Ordinary: value", "X-Explicit;", "X-Suppressed"]
        self.headers.write_text("\n".join(headers) + "\n", encoding="utf-8")
        completed = self.run_request("http1")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        args = json.loads(self.capture.read_text(encoding="utf-8"))
        self.assertEqual(
            [args[position + 1] for position, value in enumerate(args) if value == "-H"],
            ["X-Empty;", "X-Space;", "X-Ordinary: value", "X-Explicit;", "X-Suppressed"],
        )

    def test_non_h1_profile_never_sends_legacy_case_request(self) -> None:
        for protocol in ("h2", "h3"):
            with self.subTest(protocol=protocol):
                completed = self.run_request(protocol)
                self.assertEqual(completed.returncode, 77, completed.stderr)
                self.assertIn("requires NGINX_DOWNSTREAM_PROTOCOL=http1", completed.stderr)
                self.assertFalse(self.capture.exists())



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
