"""The Parent's portable First-Byte route must explicitly retain Safe policy."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from modsecurity_connector_tests.framework_test_trust import trusted_framework_root
from modsecurity_connector_tests.test_nginx_phase4_runner_wiring import load_framework_runner_core

ROOT = connector_root()
HARNESS = source_path('connectors/nginx/harness/run_nginx_smoke.sh', root=ROOT)
HARNESS_TEMPLATE = HARNESS.parent / "nginx_smoke.conf"
CALLER = source_path('ci/runtime/lifecycle/run-native-first-byte.sh', root=ROOT)
FRAMEWORK = source_path('modules/ModSecurity-test-Framework', root=ROOT)


def shell_function(source: str, name: str) -> str:
    start = source.index(f"{name}() {{\n")
    return source[start:source.index("\n}\n", start) + 3]


class NginxSynchronizedPhase4PolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        framework, error = trusted_framework_root(ROOT, FRAMEWORK)
        if framework is None:
            raise AssertionError(error)
        cls.framework = framework
        cls.runner = load_framework_runner_core(framework)
        cls.case_file = framework / "tests/cases/no-crs-baseline/full-lifecycle/phase4_first_byte_before_response_end.yaml"
        cls.case = cls.runner.load_case(cls.case_file)

    def test_portable_fixture_materializes_empty_host_mode(self) -> None:
        self.assertNotIn("nginx", self.case)
        self.assertEqual(self.case["expect"]["status"], 200)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "case.env"
            self.runner.write_shell_env(self.case, target, output_root=directory)
            self.assertIn("NGINX_PHASE4_MODE=''", target.read_text())

    def run_policy(self, sync: str, trusted: str, generated: str = "", *, tamper: bool = False):
        source = HARNESS.read_text()
        has_policy = "apply_synchronized_phase4_policy() {" in source
        capture = re.search(r"(?m)^NGINX_TRUSTED_SYNCHRONIZED_PHASE4_MODE=.*$", source)
        readonly = re.search(r"(?m)^readonly NGINX_TRUSTED_SYNCHRONIZED_PHASE4_MODE$", source)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            env_file = base / "case.env"
            self.runner.write_shell_env(self.case, env_file, output_root=directory)
            if generated:
                env_file.write_text(env_file.read_text().replace(
                    "NGINX_PHASE4_MODE=''", f"NGINX_PHASE4_MODE={generated}"))
            if tamper:
                env_file.write_text(env_file.read_text()
                                    + "\nNGINX_TRUSTED_SYNCHRONIZED_PHASE4_MODE=strict\n")
            config = base / "nginx.conf"
            marker = base / "started"
            injected = base / "injected"
            environment = {
                "PATH": os.defpath, "CURRENT_UID": "65534", "PORT": "19881",
                "NGINX_USE_ERROR_LOG": "on", "case_name": "first-byte-policy-test",
                "MSCONNECTOR_FULL_LIFECYCLE_SYNC": sync,
                "NGINX_SYNCHRONIZED_PHASE4_MODE": trusted.replace("INJECTED", str(injected)),
                "CASE_ENV_FILE": str(env_file), "CONFIG_FILE": str(config),
                "TEMPLATE": str(HARNESS_TEMPLATE),
                "NGINX_PHASE4_LOG_SCOPE": "server_with_location_override" if sync == "1" else "location",
                "NGINX_PHASE4_LOG_FILE": str(base / "phase4.log"),
                "NGINX_PHASE4_LOG_SERVER_FILE": str(base / "phase4-server.log"),
            }
            render = shell_function(source, "render_config")
            # Fixed, harmless paths for unrelated rendering placeholders;
            # the actual mode policy and template are not mocked.
            for name in re.findall(r'escape_sed "\$([A-Z_]+)"', render):
                environment.setdefault(name, str(base / name.lower()))
            commands = (
                "set -eu\nblocked() { printf '%s\\n' \"$*\" >&2; exit 77; }\n"
                "fail() { printf '%s\\n' \"$*\" >&2; exit 1; }\n"
                + shell_function(source, "escape_sed") + "\n"
                + (shell_function(source, "apply_synchronized_phase4_policy") if has_policy else "") + "\n"
                + render + "\n" + (capture.group(0) if capture else "") + "\n"
                + (readonly.group(0) + "\n" if readonly else "")
                + '. "$CASE_ENV_FILE"\n'
                + ("apply_synchronized_phase4_policy\n" if has_policy else "")
                + "render_config\n"
                + 'printf "%s\\n" "$REQUEST_PATH" "$CASE_NAME" "$EXPECT_STATUS"\n'
                + f': > "{marker}"\n'
            )
            result = subprocess.run(["/bin/sh", "-c", commands], env=environment,
                                    capture_output=True, text=True, check=False)
            return result, config.read_text() if config.exists() else "", marker.exists(), injected.exists()

    def test_direct_default_remains_off(self) -> None:
        result, config, started, _ = self.run_policy("0", "")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(started)
        self.assertNotIn("modsecurity_phase4_mode ", config)

    def test_sync_safe_survives_empty_generated_mode_and_renders_native_sink(self) -> None:
        result, config, started, _ = self.run_policy("1", "safe")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(started)
        self.assertEqual(config.count("modsecurity_phase4_mode safe;"), 1)
        self.assertRegex(config, r'modsecurity_phase4_log "[^"\n]+/phase4\.log";')
        self.assertEqual(result.stdout.splitlines(), [
            "/no-crs/full-lifecycle/first-byte",
            "phase4_first_byte_before_response_end_fixture", "200",
        ])

    def test_invalid_missing_off_and_strict_modes_fail_before_start(self) -> None:
        for trusted in ("", "off", "strict", "SAFE", "safe ", "safe; touch INJECTED",
                        "$(touch INJECTED)", "safe\nstrict"):
            with self.subTest(trusted=trusted):
                result, config, started, injected = self.run_policy("1", trusted)
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertIn("safe", result.stderr)
                self.assertFalse(started)
                self.assertFalse(injected)
                self.assertEqual(config, "")

    def test_override_outside_sync_is_rejected_not_applied(self) -> None:
        result, _, started, _ = self.run_policy("0", "safe")
        self.assertEqual(result.returncode, 77)
        self.assertFalse(started)

    def test_case_environment_cannot_replace_trusted_selection(self) -> None:
        result, _, started, _ = self.run_policy("1", "safe", tamper=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertRegex(result.stderr, r"read ?only")
        self.assertFalse(started)

    def test_ordinary_case_selected_modes_remain_unchanged(self) -> None:
        for generated in ("safe", "strict", "off"):
            with self.subTest(generated=generated):
                result, config, _, _ = self.run_policy("0", "", generated)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"modsecurity_phase4_mode {generated};", config)

    def test_caller_selects_policy_only_for_nginx(self) -> None:
        source = CALLER.read_text()
        nginx = source.split("    nginx)\n", 1)[1].split("    *)", 1)[0]
        apache = source.split("    apache)\n", 1)[1].split("    nginx)", 1)[0]
        self.assertIn("NGINX_SYNCHRONIZED_PHASE4_MODE=safe", nginx)
        self.assertIn("NGINX_PHASE4_LOG_SCOPE=server_with_location_override", nginx)
        self.assertNotIn("NGINX_SYNCHRONIZED_PHASE4_MODE", apache)

    def test_policy_is_applied_after_case_load_before_start(self) -> None:
        source = HARNESS.read_text()
        load = source.index('    . "$CASE_ENV_FILE"')
        calls = list(re.finditer(r"(?m)^apply_synchronized_phase4_policy$", source))
        self.assertEqual(len(calls), 1)
        self.assertGreater(calls[0].start(), load)
        self.assertIn("        render_config\n", shell_function(source, "start_server"))
        self.assertLess(calls[0].start(), source.index("\nstart_server\n", load))

    def test_complete_payload_does_not_hide_transport_failure(self) -> None:
        source = HARNESS.read_text()
        function = shell_function(source, "send_synchronized_first_byte_request")
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            curl = base / "curl"
            curl.write_text("#!/bin/sh\nwhile [ $# -gt 0 ]; do\n"
                            "if [ \"$1\" = -o ]; then shift; body=$1; fi\nshift\ndone\n"
                            "printf 'first-byte-prefixno-crs-response-body-marker' > \"$body\"\n"
                            "printf 200\n"
                            "while [ ! -e \"$SYNCHRONIZED_RELEASE_FILE\" ]; do sleep 0.01; done\n"
                            "exit 18\n")
            curl.chmod(0o700)
            paused = base / "paused"
            paused.touch()
            body = base / "body"
            environment = {
                "PATH": os.defpath, "MSCONNECTOR_FULL_LIFECYCLE_SYNC": "1",
                "FULL_LIFECYCLE_EVIDENCE_OUTPUT": str(base / "evidence.json"),
                "REQUEST_PATH": "/no-crs/full-lifecycle/first-byte", "PORT": "19881",
                "RESPONSE_BODY": str(body), "CURL_BIN": str(curl), "LOG_DIR": str(base),
                "SYNCHRONIZED_PAUSED_FILE": str(paused),
                "SYNCHRONIZED_RELEASE_FILE": str(base / "release"),
            }
            commands = ("set -eu\nfail() { printf '%s\\n' \"$*\" >&2; exit 1; }\n"
                        "quote_request_path() { printf '%s' \"$1\"; }\n"
                        + function + "\nsend_synchronized_first_byte_request\n")
            result = subprocess.run(["/bin/sh", "-c", commands], env=environment,
                                    capture_output=True, text=True, timeout=5, check=False)
            self.assertEqual(body.stat().st_size, 44)
            self.assertEqual((base / "first-byte-status.txt").read_text(), "200")
            self.assertEqual(result.returncode, 1)
            self.assertIn("rc=18", result.stderr)
            self.assertFalse((base / "evidence.json").exists())

    def test_framework_and_portable_case_remain_pinned_and_clean(self) -> None:
        framework, error = trusted_framework_root(ROOT, FRAMEWORK)
        self.assertIsNotNone(framework, error)
        self.assertNotIn("nginx", self.runner.load_case(self.case_file))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
