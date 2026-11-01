from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = connector_root()
BACKEND = source_path('ci/runtime/common/response-header-test-backend.py', root=ROOT)
BACKEND_MODULE = load_source(BACKEND)


class ResponseHeaderBackendFixturePathTest(unittest.TestCase):
    def test_fixture_outside_the_safe_root_is_rejected_before_listening(self) -> None:
        with tempfile.TemporaryDirectory() as trusted_directory, tempfile.TemporaryDirectory() as outside_directory:
            trusted_root = Path(trusted_directory)
            body_file = trusted_root / "body.txt"
            fixture_file = Path(outside_directory) / "fixture.json"
            body_file.write_text("body", encoding="utf-8")
            fixture_file.write_text('{"status": 200, "headers": []}', encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(BACKEND),
                    "--port",
                    "1",
                    "--body-file",
                    str(body_file),
                    "--safe-root",
                    str(trusted_root),
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
        self.assertIn("fixture file is outside the allowed fixture roots", result.stderr)

    def test_fixture_symlink_outside_the_safe_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as trusted_directory, tempfile.TemporaryDirectory() as outside_directory:
            trusted_root = Path(trusted_directory)
            outside_fixture = Path(outside_directory) / "fixture.json"
            fixture_link = trusted_root / "fixture.json"
            outside_fixture.write_text('{"status": 200, "headers": []}', encoding="utf-8")
            fixture_link.symlink_to(outside_fixture)

            with self.assertRaisesRegex(ValueError, "fixture file is outside the allowed fixture roots"):
                BACKEND_MODULE.load_fixture_file(fixture_link, [trusted_root])

    def test_fixture_parent_traversal_outside_the_safe_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            trusted_root = temporary_root / "safe"
            outside_fixture = temporary_root / "outside" / "fixture.json"
            trusted_root.mkdir()
            outside_fixture.parent.mkdir()
            outside_fixture.write_text('{"status": 200, "headers": []}', encoding="utf-8")
            traversal = trusted_root / ".." / "outside" / "fixture.json"

            with self.assertRaisesRegex(ValueError, "fixture file is outside the allowed fixture roots"):
                BACKEND_MODULE.load_fixture_file(traversal, [trusted_root])

    def test_in_root_fixture_does_not_inherit_the_body_size_limit(self) -> None:
        with tempfile.TemporaryDirectory() as trusted_directory:
            trusted_root = Path(trusted_directory)
            fixture_file = trusted_root / "fixture.json"
            fixture_file.write_text(
                '{"status": 201, "headers": [], "padding": "'
                + "x" * (BACKEND_MODULE.MAX_BODY_BYTES + 1)
                + '"}',
                encoding="utf-8",
            )

            fixture = BACKEND_MODULE.load_fixture_file(fixture_file, [trusted_root])

        self.assertEqual(fixture.status, 201)
        self.assertEqual(fixture.headers, ())

    def test_body_file_limit_remains_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as trusted_directory:
            trusted_root = Path(trusted_directory)
            body_file = trusted_root / "body.txt"
            body_file.write_bytes(b"x" * (BACKEND_MODULE.MAX_BODY_BYTES + 1))

            with self.assertRaisesRegex(ValueError, "body file is too large"):
                BACKEND_MODULE.resolve_body_file(body_file, [trusted_root])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
