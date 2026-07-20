import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP_ENTRYPOINTS = (
    "ci/provisioning/build-v3-under-src.sh",
    "ci/provisioning/check-v3-api-smoke-prereqs.sh",
    "ci/provisioning/fetch-crs.sh",
    "ci/provisioning/fetch-smoke-sources.sh",
    "ci/provisioning/find-modsecurity-v3.sh",
    "ci/provisioning/generate-mrts.sh",
    "ci/provisioning/materialize-connector-source.sh",
    "ci/provisioning/prepare-apache-build.sh",
    "ci/provisioning/prepare-crs.sh",
    "ci/provisioning/prepare-envoy-runtime.sh",
    "ci/provisioning/prepare-haproxy-runtime.sh",
    "ci/provisioning/prepare-lighttpd-runtime.sh",
    "ci/provisioning/prepare-nginx-build.sh",
    "ci/provisioning/prepare-traefik-runtime.sh",
    "ci/provisioning/write-mrts-load.sh",
    "ci/runtime/probe-response-body-blocking.sh",
    "ci/runtime/run-apache-smoke.sh",
    "ci/runtime/run-connector-smokes.sh",
    "ci/runtime/run-connector-starter-checks.sh",
    "ci/runtime/run-envoy-smoke.sh",
    "ci/runtime/run-haproxy-runtime-matrix.sh",
    "ci/runtime/run-haproxy-smoke.sh",
    "ci/runtime/run-lighttpd-smoke.sh",
    "ci/runtime/run-nginx-smoke.sh",
    "ci/runtime/run-runtime-matrix.sh",
    "ci/runtime/run-traefik-smoke.sh",
    "ci/runtime/run-v3-api-smoke.sh",
    "ci/runtime/smoke-installed.sh",
)
CATALOG_BOOTSTRAP_ENTRYPOINTS = (
    "ci/checks/catalog/check-adapter-helpers.sh",
    "ci/checks/catalog/check-adapter-metadata-drift.sh",
    "ci/checks/catalog/check-common-helpers.sh",
    "ci/checks/catalog/check-crs-version-pinning.sh",
    "ci/checks/catalog/check-open-runtime-provisioning-contract.sh",
)


class CiRootBootstrapHardeningTests(unittest.TestCase):
    def run_script(self, script: Path, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(environment)
        return subprocess.run(
            ["sh", str(script)],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def run_shell(self, script: str, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(environment)
        return subprocess.run(
            ["sh", "-c", script],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def write_foreign_ci(self, root: Path, marker: Path, *, common_body: str) -> Path:
        foreign_ci = root / "foreign" / "ci"
        lib = foreign_ci / "lib"
        lib.mkdir(parents=True)
        (lib / "path-bootstrap.sh").write_text(
            f"touch {shlex.quote(str(marker))}\n",
            encoding="utf-8",
        )
        (lib / "path.sh").write_text(
            f"touch {shlex.quote(str(marker))}\n"
            "ci_init_paths() { return 0; }\n",
            encoding="utf-8",
        )
        (lib / "common.sh").write_text(common_body, encoding="utf-8")
        (lib / "connector-smoke-common.sh").write_text(common_body, encoding="utf-8")
        return foreign_ci

    def test_all_direct_entrypoints_source_bootstrap_relative_to_their_script(self) -> None:
        entrypoints = [
            (relative_path, '. "$SCRIPT_DIR/../lib/path-bootstrap.sh"')
            for relative_path in BOOTSTRAP_ENTRYPOINTS
        ]
        entrypoints.extend(
            (relative_path, '. "$SCRIPT_DIR/../../lib/path-bootstrap.sh"')
            for relative_path in CATALOG_BOOTSTRAP_ENTRYPOINTS
        )
        for relative_path, expected_source in entrypoints:
            with self.subTest(entrypoint=relative_path):
                source = (ROOT / relative_path).read_text(encoding="utf-8")
                self.assertIn(expected_source, source)
                self.assertNotIn('. "$CI_ROOT/lib/path-bootstrap.sh"', source)

    def test_common_workflow_materializes_inside_the_verified_run_root(self) -> None:
        workflow = (ROOT / ".github/workflows/test-common.yml").read_text(encoding="utf-8")
        self.assertIn('out="$VERIFIED_RUN_ROOT/case-runner"', workflow)
        self.assertNotIn('out="$RUNNER_TEMP/case-runner"', workflow)

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            verified_root = temporary_root / "verified"
            case_output = verified_root / "case-runner" / "audit-log"
            case_output.mkdir(parents=True)
            environment = os.environ.copy()
            environment.update(
                {
                    "BUILD_ROOT": "",
                    "MODSECURITY_RULE_PREAMBLE_FILE": "",
                    "VERIFIED_RUN_ROOT": str(verified_root),
                }
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tests/runners/case_cli.py"),
                    "materialize",
                    "--case",
                    str(ROOT / "tests/cases/audit-log/audit_log_phase1_block.yaml"),
                    "--rules-file",
                    str(case_output / "rules.conf"),
                    "--env-file",
                    str(case_output / "case.env"),
                    "--headers-file",
                    str(case_output / "request-headers.txt"),
                    "--body-file",
                    str(case_output / "request-body.bin"),
                    "--docroot",
                    str(case_output / "htdocs"),
                    "--audit-log-file",
                    str(case_output / "audit.log"),
                    "--audit-log-dir",
                    str(case_output / "audit"),
                ],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue((case_output / "rules.conf").is_file())

    def test_prepare_crs_rejects_source_and_runtime_paths_outside_task_roots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temporary_root = Path(tmp)
            verified_root = temporary_root / "verified"
            source_root = verified_root / "source"
            build_root = verified_root / "build"
            approved_source = source_root / "coreruleset"
            (approved_source / "rules").mkdir(parents=True)
            (approved_source / "crs-setup.conf.example").write_text("SecRuleEngine On\n", encoding="utf-8")
            (approved_source / "rules" / "REQUEST-901-INITIALIZATION.conf").write_text("# rules\n", encoding="utf-8")
            base_environment = {
                "VERIFIED_RUN_ROOT": str(verified_root),
                "SOURCE_ROOT": str(source_root),
                "BUILD_ROOT": str(build_root),
                "TMP_ROOT": str(build_root / "tmp"),
                "LOG_ROOT": str(build_root / "logs"),
                "CRS_RUNTIME_DIR": str(build_root / "crs"),
            }

            for label, source_dir, runtime_dir in (
                ("source", verified_root / "unapproved-source", build_root / "crs"),
                ("runtime", approved_source, verified_root / "unapproved-runtime"),
            ):
                with self.subTest(path=label):
                    result = self.run_script(
                        ROOT / "ci/provisioning/prepare-crs.sh",
                        {
                            **base_environment,
                            "CRS_SOURCE_DIR": str(source_dir),
                            "CRS_RUNTIME_DIR": str(runtime_dir),
                        },
                    )
                    self.assertEqual(77, result.returncode, result.stderr)
                    self.assertFalse(runtime_dir.exists())

    def test_nested_catalog_bootstrap_ignores_foreign_root_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            marker = tmp_path / "foreign-path-helper-sourced"
            foreign_ci = self.write_foreign_ci(tmp_path, marker, common_body=":\n")
            result = self.run_shell(
                "\n".join(
                    (
                        f"SCRIPT_DIR={shlex.quote(str(ROOT / 'ci/checks/catalog'))}",
                        f"CI_ROOT={shlex.quote(str(foreign_ci))}",
                        f"FRAMEWORK_ROOT={shlex.quote(str(tmp_path / 'foreign-framework'))}",
                        f". {shlex.quote(str(ROOT / 'ci/lib/path-bootstrap.sh'))}",
                        f"[ \"$CI_ROOT\" = {shlex.quote(str(ROOT / 'ci'))} ]",
                        f"[ \"$FRAMEWORK_ROOT\" = {shlex.quote(str(ROOT))} ]",
                    )
                ),
                {},
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertFalse(marker.exists())

    def test_bootstrap_fails_closed_before_sourcing_a_foreign_helper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            marker = tmp_path / "foreign-path-helper-sourced"
            foreign_ci = self.write_foreign_ci(tmp_path, marker, common_body=":\n")
            invalid_script_dir = tmp_path / "not-a-framework" / "runtime"
            invalid_script_dir.mkdir(parents=True)
            result = self.run_shell(
                "\n".join(
                    (
                        f"SCRIPT_DIR={shlex.quote(str(invalid_script_dir))}",
                        f"CI_ROOT={shlex.quote(str(foreign_ci))}",
                        f"FRAMEWORK_ROOT={shlex.quote(str(tmp_path / 'foreign-framework'))}",
                        f". {shlex.quote(str(ROOT / 'ci/lib/path-bootstrap.sh'))}",
                    )
                ),
                {},
            )
            self.assertNotEqual(0, result.returncode)
            self.assertFalse(marker.exists())

    def test_runtime_entrypoint_ignores_foreign_ci_root_and_preserves_legitimate_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            marker = tmp_path / "foreign-runtime-helper-sourced"
            foreign_ci = self.write_foreign_ci(
                tmp_path,
                marker,
                common_body=(
                    f"touch {shlex.quote(str(marker))}\n"
                    "connector_smoke_run() { return 0; }\n"
                ),
            )
            verified_root = tmp_path / "verified"
            connector_root = tmp_path / "connector-root"
            harness = connector_root / "connectors/envoy/harness/run_envoy_smoke.sh"
            harness.parent.mkdir(parents=True)
            harness.write_text(
                "#!/bin/sh\nprintf '%s\\n' '{}' > \"$RESULTS_DIR/envoy-results.jsonl\"\n",
                encoding="utf-8",
            )
            harness.chmod(0o755)
            source_root = verified_root / "src"
            build_root = verified_root / "build"
            source_root.mkdir(parents=True)
            build_root.mkdir(parents=True)
            result = self.run_script(
                ROOT / "ci/runtime/run-envoy-smoke.sh",
                {
                    "CI_ROOT": str(foreign_ci),
                    "FRAMEWORK_ROOT": str(tmp_path / "foreign-framework"),
                    "CONNECTOR_ROOT": str(connector_root),
                    "VERIFIED_RUN_ROOT": str(verified_root),
                    "SOURCE_ROOT": str(source_root),
                    "BUILD_ROOT": str(build_root),
                    "TMP_ROOT": str(build_root / "tmp"),
                    "LOG_ROOT": str(build_root / "logs"),
                    "RESULTS_DIR": str(build_root / "results"),
                    "PYTHON": "sh",
                },
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertFalse(marker.exists())
            self.assertTrue((build_root / "results/envoy-results.jsonl").is_file())

    def test_provisioning_entrypoint_ignores_foreign_ci_root_and_finds_valid_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            marker = tmp_path / "foreign-provisioning-helper-sourced"
            foreign_ci = self.write_foreign_ci(
                tmp_path,
                marker,
                common_body=(
                    f"touch {shlex.quote(str(marker))}\n"
                    f"SOURCE_ROOT={shlex.quote(str(tmp_path / 'foreign-source'))}\n"
                ),
            )
            source = tmp_path / "modsecurity-source"
            source.mkdir()
            result = self.run_script(
                ROOT / "ci/provisioning/find-modsecurity-v3.sh",
                {
                    "CI_ROOT": str(foreign_ci),
                    "FRAMEWORK_ROOT": str(tmp_path / "foreign-framework"),
                    "CONNECTOR_ROOT": str(tmp_path / "connector-root"),
                    "SOURCE_ROOT": str(tmp_path / "source-root"),
                    "MODSECURITY_V3_SOURCE_DIR": str(source),
                },
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(f"{source}\n", result.stdout)
            self.assertFalse(marker.exists())

    def test_starter_checks_reject_results_path_traversal_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            connector_root = root / "connector"
            (connector_root / "connectors").mkdir(parents=True)
            build_root = root / "build"
            escaped_root = root / "escaped"
            results_dir = build_root / "results" / ".." / ".." / "escaped"
            result = self.run_script(
                ROOT / "ci/runtime/run-connector-starter-checks.sh",
                {
                    "CONNECTOR_ROOT": str(connector_root),
                    "VERIFIED_RUN_ROOT": str(root / "verified"),
                    "SOURCE_ROOT": "/src",
                    "BUILD_ROOT": str(build_root),
                    "TMP_ROOT": str(build_root / "tmp"),
                    "LOG_ROOT": str(build_root / "logs"),
                    "RESULTS_DIR": str(results_dir),
                    "PYTHON": "/bin/true",
                },
            )
            self.assertEqual(77, result.returncode, result.stdout + result.stderr)
            self.assertFalse(escaped_root.exists())

    def test_haproxy_runtime_rejects_a_shared_component_cache_binary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            verified = root / "verified"
            build_root = verified / "build"
            source_root = verified / "src"
            connector_root = root / "connector"
            cache_entry = (
                root
                / "cache"
                / "builds"
                / "connectors"
                / "haproxy"
                / ("a" * 64)
            )
            for directory in (
                build_root,
                source_root,
                connector_root,
                cache_entry / "haproxy-runtime-build",
                cache_entry / "haproxy-runtime" / "haproxy" / "sbin",
            ):
                directory.mkdir(parents=True, exist_ok=True)
            result = self.run_script(
                ROOT / "ci/provisioning/prepare-haproxy-runtime.sh",
                {
                    "CONNECTOR_ROOT": str(connector_root),
                    "VERIFIED_RUN_ROOT": str(verified),
                    "SOURCE_ROOT": str(source_root),
                    "BUILD_ROOT": str(build_root),
                    "TMP_ROOT": str(build_root / "tmp"),
                    "LOG_ROOT": str(build_root / "logs"),
                    "CONNECTOR_COMPONENT_CACHE": str(root / "cache"),
                    "HAPROXY_RUNTIME_BUILD_DIR": str(cache_entry / "haproxy-runtime-build"),
                    "HAPROXY_RUNTIME_BUILD_WORKTREE": str(
                        cache_entry / "haproxy-runtime-build" / "worktree"
                    ),
                    "HAPROXY_RUNTIME_DIR": str(cache_entry / "haproxy-runtime" / "haproxy"),
                    "HAPROXY_BIN": str(
                        cache_entry / "haproxy-runtime" / "haproxy" / "sbin" / "haproxy"
                    ),
                },
            )
        self.assertEqual(77, result.returncode, result.stderr)
        self.assertIn("HAPROXY_RUNTIME_BUILD_DIR must be under BUILD_ROOT", result.stdout)


if __name__ == "__main__":
    unittest.main()
