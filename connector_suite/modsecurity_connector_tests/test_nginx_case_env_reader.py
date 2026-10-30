"""Regression coverage for the root-safe NGINX case environment reader."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = connector_root()
SCRIPT = source_path('connectors/nginx/harness/read_case_env.py', root=ROOT)


def load_reader_module():
    module = load_source(SCRIPT)
    return module


READER = load_reader_module()


def valid_environment(**overrides: str) -> str:
    values = {
        "CASE_NAME": "phase4_deny_after_commit_log_only",
        "REQUEST_METHOD": "GET",
        "REQUEST_PATH": "/no-crs/response-body",
        "REQUEST_HAS_BODY": "0",
        "REQUEST_HEADERS_FILE": "/runtime/request-headers.txt",
        "REQUEST_BODY_FILE": "/runtime/request-body.bin",
        "AUDIT_LOG_FILE": "/runtime/audit.log",
        "AUDIT_LOG_DIR": "/runtime/audit",
        "EXPECT_STATUS": "200",
        "EXPECT_INTERVENTION": "",
        "EXPECT_RULE_ID": "1100301",
        "EXPECT_RESPONSE_CONTAINS": "no-crs-response-body-marker",
        "EXPECT_TRANSPORT": "http_status",
        "EXPECT_AUDIT_LOG_REQUIRED": "0",
        "NGINX_PHASE4_MODE": "safe",
    }
    values.update(overrides)
    return "".join(
        ["# Generated from common test case. Do not edit.\n"]
        + [f"{key}={shlex.quote(value)}\n" for key, value in values.items()]
    )


class NginxCaseEnvironmentReaderTest(unittest.TestCase):
    def read(self, content: str) -> dict[str, str]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runtime"
            path = root / "conf" / "case.env"
            path.parent.mkdir(parents=True)
            path.write_text(content, encoding="utf-8")
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                return READER.read_case_environment_from_descriptor(descriptor)
            finally:
                os.close(descriptor)

    def test_reads_the_framework_data_fragment_without_shell_evaluation(self) -> None:
        values = self.read(valid_environment(REQUEST_PATH="/a path?query=literal;$(not-run)"))
        self.assertEqual(values["REQUEST_PATH"], "/a path?query=literal;$(not-run)")
        self.assertEqual(values["EXPECT_RULE_ID"], "1100301")
        self.assertEqual(set(values), READER._ALLOWED_KEYS)

    def test_rejects_unknown_assignment_and_shell_command_suffix(self) -> None:
        content = valid_environment().replace(
            "REQUEST_PATH=/no-crs/response-body\n",
            "REQUEST_PATH=/no-crs/response-body; /usr/bin/id\n",
        )
        with self.assertRaisesRegex(READER.CaseEnvironmentError, "exactly one quoted value"):
            self.read(content)

        unknown_assignment = valid_environment() + "UNSAFE=1\n"
        with self.assertRaisesRegex(READER.CaseEnvironmentError, "unexpected key"):
            self.read(unknown_assignment)

    def test_rejects_duplicate_missing_and_control_character_values(self) -> None:
        duplicate = valid_environment() + "CASE_NAME=second\n"
        with self.assertRaisesRegex(READER.CaseEnvironmentError, "duplicate key"):
            self.read(duplicate)

        missing = valid_environment().replace("NGINX_PHASE4_MODE=safe\n", "")
        with self.assertRaisesRegex(READER.CaseEnvironmentError, "missing required keys"):
            self.read(missing)

        control_character = valid_environment(REQUEST_PATH="/ok\x00not-ok")
        with self.assertRaisesRegex(READER.CaseEnvironmentError, "forbidden control character"):
            self.read(control_character)

    def test_rejects_invalid_runtime_capabilities_and_case_file_substitution(self) -> None:
        with self.assertRaisesRegex(READER.CaseEnvironmentError, "cannot open private case environment"):
            READER.read_case_environment_from_descriptor(-1)

        with tempfile.TemporaryDirectory() as temporary:
            not_a_directory = Path(temporary) / "not-a-directory"
            not_a_directory.write_text("not a runtime root\n", encoding="utf-8")
            descriptor = os.open(not_a_directory, os.O_RDONLY)
            try:
                with self.assertRaisesRegex(
                    READER.CaseEnvironmentError, "private owner-controlled directory"
                ):
                    READER.read_case_environment_from_descriptor(descriptor)
            finally:
                os.close(descriptor)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runtime"
            conf = root / "conf"
            conf.mkdir(parents=True)
            target = Path(temporary) / "outside-case.env"
            target.write_text(valid_environment(), encoding="utf-8")
            (conf / "case.env").symlink_to(target)
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(READER.CaseEnvironmentError):
                    READER.read_case_environment_from_descriptor(descriptor)
            finally:
                os.close(descriptor)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runtime"
            conf = root / "conf"
            conf.mkdir(parents=True)
            os.mkfifo(conf / "case.env")
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaisesRegex(READER.CaseEnvironmentError, "bounded private regular"):
                    READER.read_case_environment_from_descriptor(descriptor)
            finally:
                os.close(descriptor)

    def test_cli_uses_only_the_inherited_runtime_directory_capability(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runtime"
            path = root / "conf" / "case.env"
            path.parent.mkdir(parents=True)
            path.write_text(valid_environment(REQUEST_PATH="/capability-only"), encoding="utf-8")
            completed = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    'exec 3< "$1"; exec "$2" "$3" --key REQUEST_PATH',
                    "sh",
                    str(root),
                    sys.executable,
                    str(SCRIPT),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout.strip(), "/capability-only")

            rejected = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--runtime-root",
                    str(root),
                    "--key",
                    "REQUEST_PATH",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("unrecognized arguments", rejected.stderr)

            missing_capability = subprocess.run(
                [sys.executable, str(SCRIPT), "--key", "REQUEST_PATH"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(missing_capability.returncode, 2)
            self.assertIn("cannot open private case environment", missing_capability.stderr)

    def test_harness_uses_reader_only_for_the_root_functional_path(self) -> None:
        harness = (
            source_path('connectors/nginx/harness/run_nginx_smoke.sh', root=ROOT)
        ).read_text(encoding="utf-8")
        self.assertIn('NGINX_HOSTED_FUNCTIONAL_A="${NGINX_HOSTED_FUNCTIONAL_A:-0}"', harness)
        self.assertIn("load_functional_case_environment", harness)
        self.assertIn('if [ "$NGINX_HOSTED_FUNCTIONAL_A" = "1" ]; then\n    load_functional_case_environment', harness)
        self.assertIn('else\n    . "$CASE_ENV_FILE"', harness)
        reader_invocation = harness.split("read_functional_case_value()", 1)[1].split(
            "load_functional_case_environment()", 1
        )[0]
        self.assertIn('exec 3< "$RUNTIME_ROOT"', reader_invocation)
        self.assertIn('exec "$PYTHON_BIN" "$NGINX_CASE_ENV_READER" --key "$case_key"', reader_invocation)
        self.assertNotIn("--runtime-root", reader_invocation)
        self.assertNotIn('--env-file "$CASE_ENV_FILE"', reader_invocation)
        functional_section = harness.split("load_functional_case_environment()", 1)[1].split(
            "write_harness_status()", 1
        )[0]
        self.assertNotIn("eval", functional_section)
        self.assertNotIn('. "$CASE_ENV_FILE"', functional_section)
        for path_key in (
            "REQUEST_HEADERS_FILE",
            "REQUEST_BODY_FILE",
            "AUDIT_LOG_FILE",
            "AUDIT_LOG_DIR",
        ):
            self.assertNotIn(
                f"{path_key}=$(read_functional_case_value {path_key})", functional_section
            )
            self.assertIn(
                f'assert_functional_case_path_match {path_key} "${path_key}"', harness
            )
        functional_call = (
            'if [ "$NGINX_HOSTED_FUNCTIONAL_A" = "1" ]; then\n'
            "    load_functional_case_environment"
        )
        self.assertLess(
            harness.index("validate_nginx_generated_path_authority"), harness.index(functional_call)
        )
        self.assertLess(
            harness.index("lock_private_runtime_paths"), harness.index(functional_call)
        )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
