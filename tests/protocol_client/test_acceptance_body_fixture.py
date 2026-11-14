"""Opt-in real compiled-client controls for bounded P2 request fixtures.

Select an already provisioned libcurl prefix with
PROTOCOL_ACCEPTANCE_CURL_PREFIX. Native host tests establish H2 POST behavior;
these controls establish that hostile fixture inputs fail before networking.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

@unittest.skipUnless(os.environ.get("PROTOCOL_ACCEPTANCE_CURL_PREFIX"),
                     "requires explicitly provisioned acceptance libcurl")
class AcceptanceBodyFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.runners.protocol_acceptance_client import build_client
        cls.directory = tempfile.TemporaryDirectory(
            prefix="body-fixture-", dir=os.environ["CODEX_RUN_ROOT"])
        cls.root = Path(cls.directory.name)
        cls.client = build_client(Path(os.environ["PROTOCOL_ACCEPTANCE_CURL_PREFIX"]),
                                  cls.root / "build")

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def run_client(self, *arguments):
        return subprocess.run(
            [str(self.client), "--protocol", "h2", "--base-url", "https://127.0.0.1:1",
             "--ca", "/unused/ca", "--scenario", "multiplex", *arguments],
            capture_output=True, text=True, timeout=5, check=False)

    def test_hostile_body_files_fail_before_requests_start(self):
        regular = self.root / "regular"
        regular.write_bytes(b"synthetic-form=value")
        symlink = self.root / "symlink"
        symlink.symlink_to(regular)
        hardlink = self.root / "hardlink"
        os.link(regular, hardlink)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        oversized = self.root / "oversized"
        with oversized.open("wb") as stream:
            stream.truncate(1024 * 1024 + 1)
        for path in (self.root / "missing", self.root, symlink, hardlink, fifo, oversized):
            with self.subTest(path=path.name):
                result = self.run_client("--method", "POST", "--body-file", str(path))
                self.assertEqual(result.returncode, 2, result)
                self.assertEqual(result.stdout, "")

    def test_inconsistent_method_options_fail_before_requests_start(self):
        for arguments in (("--method", "POST"), ("--method", "DELETE"),
                          ("--body-file", "/unused"),
                          ("--method", "GET", "--body-file", "/unused")):
            with self.subTest(arguments=arguments):
                result = self.run_client(*arguments)
                self.assertEqual(result.returncode, 2, result)
                self.assertEqual(result.stdout, "")

    def test_post_applies_only_to_target_and_never_logs_body(self):
        body = self.root / "bounded-form"
        payload = b"synthetic-private-form=one\x00two"
        body.write_bytes(payload)
        result = self.run_client("--method", "POST", "--body-file", str(body))
        self.assertEqual(result.returncode, 0, result)
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        started = {row["name"]: row for row in rows if row["event"] == "request_started"}
        self.assertEqual(set(started), {"target", "peer", "followup"})
        self.assertEqual(started["target"]["method"], "POST")
        self.assertEqual(started["target"]["upload_bytes"], len(payload))
        for name in ("peer", "followup"):
            self.assertEqual(started[name]["method"], "GET")
            self.assertEqual(started[name]["upload_bytes"], 0)
        self.assertNotIn("synthetic-private-form", result.stdout + result.stderr)
        completed = [row for row in rows if row["event"] == "completed"]
        self.assertEqual(len(completed), 3)
        self.assertTrue(all(row["curl_code"] != 0 for row in completed))


if __name__ == "__main__":
    unittest.main()
