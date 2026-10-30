"""Regression coverage for hosted NGINX case-materialization containment."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = connector_root()
DEFAULT_FRAMEWORK_ROOT = source_path('modules/ModSecurity-test-Framework', root=ROOT)
FRAMEWORK_ROOT = Path(
    os.environ.get("MSCONNECTOR_TEST_FRAMEWORK_ROOT", DEFAULT_FRAMEWORK_ROOT)
).resolve()
CASE_CLI = FRAMEWORK_ROOT / "tests" / "runners" / "case_cli.py"
CASE_FILE = (
    FRAMEWORK_ROOT
    / "tests"
    / "cases"
    / "connector-specific"
    / "nginx"
    / "nginx_phase4_deny_after_commit_log_only.yaml"
)
RULE_PREAMBLE = FRAMEWORK_ROOT / "tests" / "rules" / "no-crs-baseline.conf"
CASE_NAME = "nginx_phase4_deny_after_commit_log_only"


class NginxFunctionalMaterializationLayoutTest(unittest.TestCase):
    def setUp(self) -> None:
        for required in (CASE_CLI, CASE_FILE, RULE_PREAMBLE):
            self.assertTrue(required.is_file(), f"missing Framework test input: {required}")

    def materialize(
        self,
        *,
        output_root: Path,
        runtime_root: Path,
        log_root: Path,
        server_log_root: Path,
    ) -> subprocess.CompletedProcess[str]:
        audit_dir = server_log_root / "audit"
        audit_dir.mkdir(parents=True, mode=0o700)
        environment = os.environ.copy()
        environment.update(
            {
                "BUILD_ROOT": str(output_root),
                "PYTHONDONTWRITEBYTECODE": "1",
            }
        )
        return subprocess.run(
            [
                sys.executable,
                str(CASE_CLI),
                "materialize",
                "--case",
                str(CASE_FILE),
                "--rules-file",
                str(runtime_root / "conf" / "modsecurity-smoke.conf"),
                "--env-file",
                str(runtime_root / "conf" / "case.env"),
                "--headers-file",
                str(runtime_root / "conf" / "request-headers.txt"),
                "--body-file",
                str(runtime_root / "conf" / "request-body.bin"),
                "--docroot",
                str(runtime_root / "htdocs"),
                "--audit-log-file",
                str(server_log_root / "audit.log"),
                "--audit-log-dir",
                str(audit_dir),
                "--rules-preamble-file",
                str(RULE_PREAMBLE),
                "--nginx-location-directives-file",
                str(runtime_root / "conf" / "nginx-location-directives.conf"),
                "--nginx-runtime-config-dir",
                str(runtime_root / "conf"),
                "--nginx-phase4-log-file",
                str(log_root / "phase4.log"),
            ],
            cwd=ROOT,
            check=False,
            text=True,
            capture_output=True,
            env=environment,
        )

    def test_common_case_root_accepts_runtime_and_log_children(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-functional-materialize-") as temporary:
            case_root = Path(temporary) / "on" / "phase4"
            case_root.mkdir(parents=True, mode=0o700)
            runtime_root = case_root / "runtime"
            log_root = case_root / "logs"
            server_log_root = case_root / "harness" / "server-logs" / CASE_NAME

            result = self.materialize(
                output_root=case_root,
                runtime_root=runtime_root,
                log_root=log_root,
                server_log_root=server_log_root,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            expected_outputs = (
                runtime_root / "conf" / "modsecurity-smoke.conf",
                runtime_root / "conf" / "case.env",
                runtime_root / "conf" / "request-headers.txt",
                runtime_root / "conf" / "request-body.bin",
                runtime_root / "conf" / "nginx-location-directives.conf",
                runtime_root / "htdocs" / "index.html",
            )
            for output in expected_outputs:
                self.assertTrue(output.is_file(), output)
                output.resolve().relative_to(case_root.resolve())
            directives = (
                runtime_root / "conf" / "nginx-location-directives.conf"
            ).read_text(encoding="utf-8")
            self.assertIn(str(log_root / "phase4.log"), directives)
            case_environment = (
                runtime_root / "conf" / "case.env"
            ).read_text(encoding="utf-8")
            generated_paths = (
                runtime_root / "conf" / "request-headers.txt",
                runtime_root / "conf" / "request-body.bin",
                server_log_root / "audit.log",
                server_log_root / "audit",
            )
            for generated_path in generated_paths:
                self.assertIn(str(generated_path), case_environment)
                generated_path.resolve().relative_to(case_root.resolve())
            self.assertFalse((server_log_root / "audit.log").exists())

    def test_sibling_runtime_root_is_rejected_by_framework_containment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-functional-materialize-") as temporary:
            case_root = Path(temporary) / "on" / "phase4"
            output_root = case_root / "build"
            output_root.mkdir(parents=True, mode=0o700)
            runtime_root = case_root / "runtime"
            log_root = case_root / "logs"
            server_log_root = case_root / "harness" / "server-logs" / CASE_NAME

            result = self.materialize(
                output_root=output_root,
                runtime_root=runtime_root,
                log_root=log_root,
                server_log_root=server_log_root,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("write path escapes output root", result.stderr)
            self.assertFalse((runtime_root / "conf" / "modsecurity-smoke.conf").exists())

    def parent_stage_paths(self, invocation: Path) -> dict[str, str]:
        """Execute the Parent's actual child assignments without starting a host."""
        runner = source_path('ci/runtime/lifecycle/run-no-crs-baseline.sh', root=ROOT)
        script = runner.read_text(encoding="utf-8")
        assignments = script.split("BUILD_ROOT=$CONNECTOR_BUILD_ROOT\n", 1)[1]
        assignments = "BUILD_ROOT=$CONNECTOR_BUILD_ROOT\n" + assignments.split(
            "PLAN=$CONNECTOR_RUN_ROOT/plan.json\n", 1
        )[0]
        names = (
            "BUILD_ROOT", "STAGE_BUILD_ROOT", "STAGE_TMP_ROOT", "STAGE_LOG_ROOT",
            "STAGE_RESULTS_DIR", "STAGE_RUNTIME_ROOT", "NGINX_RUN_ROOT",
            "STAGE_NGINX_HARNESS_PARENT", "SHARED_COMPONENT_CACHE",
        )
        capture = "import json,os; print(json.dumps({k:os.environ.get(k,'') for k in " + repr(names) + "}))"
        environment = {
            "PATH": os.defpath,
            "PYTHON": sys.executable,
            "connector": "nginx",
            "CONNECTOR_BUILD_ROOT": str(invocation / "build/nginx/path-test"),
            "CONNECTOR_RUN_ROOT": str(invocation / "runs/nginx/path-test"),
            "CONNECTOR_LOG_ROOT": str(invocation / "run-logs/nginx/path-test"),
            "EVIDENCE_RUN_ROOT": str(invocation / "evidence/no-crs-evidence/nginx/path-test"),
            "SHARED_COMPONENT_CACHE": str(invocation / "cache-v2/shared"),
        }
        result = subprocess.run(
            ["sh", "-eu", "-c", assignments + "\nexport " + " ".join(names)
             + '\nexec "$PYTHON" -c "$1"', "capture", capture],
            env=environment, check=False, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_parent_nginx_stage_materializes_inside_raw_host_work(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-lifecycle-paths-") as temporary:
            invocation = Path(temporary)
            paths = self.parent_stage_paths(invocation)
            output_root = Path(paths["STAGE_BUILD_ROOT"])
            output_root.mkdir(parents=True, mode=0o700)
            runtime = Path(paths["STAGE_RUNTIME_ROOT"]) / CASE_NAME
            result = self.materialize(
                output_root=output_root, runtime_root=runtime,
                log_root=Path(paths["NGINX_RUN_ROOT"]) / "logs" / CASE_NAME,
                server_log_root=Path(paths["NGINX_RUN_ROOT"]) / "server-logs" / CASE_NAME,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            raw_root = invocation / "runs/nginx/path-test"
            output_root.relative_to(raw_root)
            for name in ("STAGE_TMP_ROOT", "STAGE_LOG_ROOT", "STAGE_RESULTS_DIR",
                         "STAGE_RUNTIME_ROOT", "NGINX_RUN_ROOT"):
                Path(paths[name]).relative_to(output_root)
            self.assertEqual(Path(paths["STAGE_NGINX_HARNESS_PARENT"]), output_root)
            self.assertEqual(Path(paths["BUILD_ROOT"]), invocation / "build/nginx/path-test")
            self.assertEqual(Path(paths["SHARED_COMPONENT_CACHE"]), invocation / "cache-v2/shared")

    def test_parent_first_byte_call_materializes_under_same_child_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-first-byte-paths-") as temporary:
            invocation = Path(temporary)
            paths = self.parent_stage_paths(invocation)
            connector = invocation / "connector"
            connector.mkdir()
            (connector / "Makefile").write_text("# fixture repository boundary\n", encoding="utf-8")
            common = connector / "ci/runtime/common"
            common.mkdir(parents=True)
            shutil.copyfile(source_path('ci/runtime/common/validate-nginx-harness-paths.py', root=ROOT),
                            common / "validate-nginx-harness-paths.py")
            library = connector / "ci/lib"
            library.mkdir(parents=True)
            shutil.copyfile(source_path('ci/lib/runtime_path_utils.py', root=ROOT), library / "runtime_path_utils.py")
            projection_parent = invocation / "external-projection"
            projection_parent.mkdir(mode=0o711)
            wrapper = connector / "ci/provisioning/cache/with-runtime-components.sh"
            wrapper.parent.mkdir(parents=True)
            wrapper.write_text(
                '#!/bin/sh\nset -eu\n'
                'RUNTIME_REPORT_OUTPUT_ROOT=${RUNTIME_REPORT_OUTPUT_ROOT:-$BUILD_ROOT/runtime-component-reports}\n'
                'case "$RUNTIME_COMPONENT_ENV_SNAPSHOT" in\n'
                '    "$RUNTIME_REPORT_OUTPUT_ROOT"/*) ;;\n'
                '    *) echo "snapshot escapes report root" >&2; exit 1 ;;\n'
                'esac\nexec "$@"\n',
                encoding="utf-8",
            )
            wrapper.chmod(0o700)
            first_byte = connector / "ci/runtime/lifecycle/run-native-first-byte.sh"
            first_byte.parent.mkdir(parents=True)
            first_byte.write_text(
                (source_path('ci/runtime/lifecycle/run-native-first-byte.sh', root=ROOT)).read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            # Stop at the host seam after calling the real Framework materializer.
            # This proves paths without creating a server, sending a request or
            # claiming runtime evidence from a test double.
            harness = connector / "connectors/nginx/harness/run_nginx_smoke.sh"
            harness.parent.mkdir(parents=True)
            check_control = (
                "import os,sys; from pathlib import Path; "
                "sys.path.insert(0, str(Path(os.environ['FRAMEWORK_ROOT']) / 'tests/runners')); "
                "from synchronized_upstream import _require_control_root, _resolve_control_path; "
                "root=_require_control_root(os.environ['SYNCHRONIZED_UPSTREAM_CONTROL_ROOT']); "
                "_resolve_control_path(os.environ['FULL_LIFECYCLE_EVIDENCE_OUTPUT'], "
                "control_root=root, label='evidence output'); print('control-root=' + str(root))"
            )
            harness.write_text(
                '#!/bin/sh\nset -eu\n'
                'mkdir -p "$BUILD_ROOT"\n'
                '"$PYTHON" "$FRAMEWORK_ROOT/tests/runners/case_cli.py" materialize '
                '--case "$TEST_CASE" --rules-file "$RUNTIME_ROOT/conf/modsecurity-smoke.conf" '
                '--env-file "$RUNTIME_ROOT/conf/case.env" '
                '--headers-file "$RUNTIME_ROOT/conf/request-headers.txt" '
                '--body-file "$RUNTIME_ROOT/conf/request-body.bin" '
                '--docroot "$RUNTIME_ROOT/htdocs" '
                '--rules-preamble-file "$NO_CRS_RULES_FILE" '
                '--nginx-location-directives-file "$RUNTIME_ROOT/conf/nginx-location-directives.conf" '
                '--nginx-runtime-config-dir "$RUNTIME_ROOT/conf"\n'
                'printf "materialized-first-byte=%s\\n" "$RUNTIME_ROOT"\n'
                '"$PYTHON" -c "$CONTROL_CHECK"\nexit 78\n',
                encoding="utf-8",
            )
            harness.chmod(0o700)
            script = (source_path('ci/runtime/lifecycle/run-no-crs-baseline.sh', root=ROOT)).read_text(encoding="utf-8")
            call = script.split("native_first_byte_rc=0\n", 1)[1].split(
                " || native_first_byte_rc=$?", 1
            )[0]
            environment = {
                "PATH": os.defpath, "PYTHON": sys.executable,
                "PYTHONDONTWRITEBYTECODE": "1",
                "CONNECTOR_ROOT": str(connector), "FRAMEWORK_ROOT": str(FRAMEWORK_ROOT),
                "VERIFIED_RUN_ROOT": str(invocation), "connector": "nginx",
                "CANONICAL_VERIFIED_RUN_ROOT": str(invocation),
                "NO_CRS_RULES_FILE": str(RULE_PREAMBLE),
                "RESULTS_DIR": str(invocation / "runs/nginx/path-test/results"),
                "HOST_RUNTIME_ROOT": str(invocation / "runs/nginx/path-test/host-runtime"),
                "HOST_LOG_ROOT": str(invocation / "run-logs/nginx/path-test/host"),
                "FIRST_BYTE_EVIDENCE": str(invocation / "runs/nginx/path-test/first-byte-evidence.json"),
                "CONNECTOR_RUN_ROOT": str(invocation / "runs/nginx/path-test"),
                "RUNTIME_REPORT_OUTPUT_ROOT": str(invocation / "build/nginx/path-test/runtime-component-reports"),
                "RUNTIME_COMPONENT_ENV_SNAPSHOT": str(invocation / "build/nginx/path-test/runtime-component-reports/runtime-env.sh"),
                "CONTROL_CHECK": check_control,
                "NGINX_DOCROOT_PROJECTION_PARENT": str(invocation / "external-projection"),
                "NGINX_DOCROOT_PROJECTION_ROOT": str(invocation / "external-projection/docroot"),
                **paths,
            }
            result = subprocess.run(
                ["sh", "-eu", "-c", call], env=environment,
                check=False, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 78, result.stderr)
            self.assertIn("materialized-first-byte=", result.stdout)
            self.assertIn("control-root=" + environment["CONNECTOR_RUN_ROOT"], result.stdout)
            output_root = Path(paths["STAGE_BUILD_ROOT"])
            rules = Path(paths["STAGE_RUNTIME_ROOT"]) / "first-byte-nginx/conf/modsecurity-smoke.conf"
            self.assertTrue(rules.is_file())
            rules.relative_to(output_root)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
