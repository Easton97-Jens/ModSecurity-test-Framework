"""Render the real NGINX harness template with pinned no-CRS case includes."""
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
FRAMEWORK = source_path('modules/ModSecurity-test-Framework', root=ROOT)
HARNESS = source_path('connectors/nginx/harness/run_nginx_smoke.sh', root=ROOT)
TEMPLATE = HARNESS.parent / "nginx_smoke.conf"
CALLER = source_path('ci/runtime/lifecycle/run-connector-stage.sh', root=ROOT)


def shell_function(source: str, name: str) -> str:
    start = source.index(f"{name}() {{\n")
    return source[start:source.index("\n}\n", start) + 3]


class NginxNoCrsEventSinkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        framework, error = trusted_framework_root(ROOT, FRAMEWORK)
        if framework is None:
            raise AssertionError(error)
        cls.runner = load_framework_runner_core(framework)

    def render_case(self, case_path: Path, scope: str) -> tuple[subprocess.CompletedProcess[str], str, str]:
        source = HARNESS.read_text(encoding="utf-8")
        case = self.runner.load_case(case_path)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            include = base / "nginx-location-directives.conf"
            sink = base / "phase4.log"
            self.runner.write_nginx_runtime_files(
                case, include, base, output_root=base, phase4_log_file=sink
            )
            config = base / "nginx.conf"
            render = shell_function(source, "render_config")
            environment = {
                "PATH": os.defpath,
                "CURRENT_UID": "65534",
                "PORT": "19881",
                "case_name": case_path.stem,
                "NGINX_USE_ERROR_LOG": "on",
                "NGINX_PHASE4_MODE": self.runner.nginx_phase4_mode(case),
                "NGINX_PHASE4_LOG_SCOPE": scope,
                "NGINX_PHASE4_LOG_FILE": str(sink),
                "NGINX_PHASE4_LOG_SERVER_FILE": str(base / "phase4-server.log"),
                "NGINX_LOCATION_DIRECTIVES_FILE": str(include),
                "CONFIG_FILE": str(config),
                "TEMPLATE": str(TEMPLATE),
            }
            for name in re.findall(r'escape_sed "\$([A-Z_]+)"', render):
                environment.setdefault(name, str(base / name.lower()))
            commands = (
                "set -eu\n"
                "blocked() { printf '%s\\n' \"$*\" >&2; exit 77; }\n"
                "fail() { printf '%s\\n' \"$*\" >&2; exit 1; }\n"
                + shell_function(source, "escape_sed") + "\n"
                + render + "\nrender_config\n"
            )
            result = subprocess.run(
                ["/bin/sh", "-c", commands], env=environment,
                capture_output=True, text=True, check=False,
            )
            return result, config.read_text() if config.exists() else "", include.read_text()

    def test_generic_case_gets_one_case_local_native_sink(self) -> None:
        for relative in (
            "deny_header_marker_403.yaml",
            "deny_request_body_marker_403.yaml",
            "full-lifecycle/phase3_deny_before_commit.yaml",
        ):
            with self.subTest(case=relative):
                case = FRAMEWORK / "tests/cases/no-crs-baseline" / relative
                result, config, include = self.render_case(case, "location_if_missing")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("modsecurity_phase4_log", include)
                self.assertRegex(config, r'modsecurity_phase4_log "[^"\n]+/phase4\.log";')
                self.assertEqual((config + include).count("modsecurity_phase4_log "), 1)
                self.assertNotIn("phase4-server.log", config)

    def test_fixture_owned_sink_is_not_duplicated(self) -> None:
        cases = sorted((FRAMEWORK / "tests/cases/connector-specific/nginx").glob("nginx_phase4_*.yaml"))
        self.assertTrue(cases)
        for case in cases:
            with self.subTest(case=case.name):
                result, config, include = self.render_case(case, "location_if_missing")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("modsecurity_phase4_log", config)
                self.assertIn('modsecurity_phase4_log "', include)
                self.assertEqual((config + include).count("modsecurity_phase4_log "), 1)

    def test_direct_harness_location_scope_stays_opt_in(self) -> None:
        case = FRAMEWORK / "tests/cases/no-crs-baseline/deny_header_marker_403.yaml"
        result, config, include = self.render_case(case, "location")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("modsecurity_phase4_log", config + include)

    def test_only_nginx_no_crs_stage_selects_new_scope(self) -> None:
        source = CALLER.read_text(encoding="utf-8")
        nginx = source.split("    nginx:no_crs_baseline)", 1)[1].split("    apache:no_crs_baseline)", 1)[0]
        self.assertIn("NGINX_PHASE4_LOG_SCOPE=location_if_missing", nginx)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
